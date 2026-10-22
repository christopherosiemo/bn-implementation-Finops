package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func (a *API) capacityGet(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(parts) != 3 || parts[0] != "workloads" || (parts[2] != "capacity-assessments" && parts[2] != "native-capacity-results") {
		return nil, false, nil
	}
	w, err := tx.Get(ctx, "workloads", parts[1])
	if err != nil {
		return nil, true, err
	}
	if err = workloadAccess(identity, w); err != nil {
		return nil, true, err
	}
	after, limit, err := nativeCursor(r, identity.Tenant, parts[2], parts[1])
	if err != nil {
		return nil, true, err
	}
	var rows []model.Document
	if parts[2] == "native-capacity-results" {
		rows, err = tx.NativeCapacityResultPage(ctx, parts[1], after, limit+1)
	} else {
		rows, err = tx.CapacityAssessmentPage(ctx, parts[1], after, limit+1)
	}
	if err == nil {
		for n := range rows {
			rows[n], err = a.capacityResultCurrentness(ctx, tx, rows[n])
			if err != nil { return nil, true, err }
		}
	}
	return nativePage(rows, limit, identity.Tenant, parts[2], parts[1]), true, err
}

func (a *API) capacityMutate(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if len(parts) != 3 || parts[0] != "workloads" || parts[2] != "capacity-assessments" {
		return nil, 0, false, nil
	}
	if err := requireRole(identity, "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"); err != nil {
		return nil, 0, true, err
	}
	var request struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := telemetryStrict(in, &request); err != nil || request.ConnectionID == "" {
		return nil, 0, true, problem(422, "CAPACITY_SELECTION_INVALID", "select a registered connection; metrics, prices, history and source authority are server-selected")
	}
	// This lock is also taken by source revisions, revocations, inventory and
	// safety profile updates. Hold it through private selection and publication.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":dependency-graph"); err != nil {
		return nil, 0, true, err
	}
	w, err := tx.Get(ctx, "workloads", parts[1])
	if err != nil {
		return nil, 0, true, err
	}
	if err = workloadAccess(identity, w); err != nil {
		return nil, 0, true, err
	}
	profile, err := tx.WorkloadSafetyLatest(ctx, parts[1])
	if err != nil {
		return nil, 0, true, problem(422, "SAFETY_PROFILE_REQUIRED", "declare explicit workload requirements before assessment")
	}
	if err = match(r, profile); err != nil {
		return nil, 0, true, err
	}
	c, err := tx.TelemetryConnection(ctx, request.ConnectionID)
	if err != nil {
		return nil, 0, true, err
	}
	typed, err := telemetry.ParseConnection(c)
	if err != nil {
		return nil, 0, true, err
	}
	if typed.Binding.TenantID != identity.Tenant || typed.Binding.WorkloadID != parts[1] || model.Bool(c, "revoked") || !typed.Enabled {
		return nil, 0, true, problem(422, "CAPACITY_SOURCE_BINDING_INVALID", "use an active connection bound to this workload")
	}
	selected, err := a.nativeCapacityPopulation(ctx, native.CapacityInputRequest{TenantID: identity.Tenant, ConnectionID: typed.ID, ConfigHash: model.String(c, "config_hash"), SafetyProfileID: model.String(profile, "id"), SafetyProfileVersion: model.Number(profile, "version")})
	if err != nil {
		return nil, 0, true, err
	}
	if selected.Binding != typed.Binding || selected.ConfigHash != model.String(c, "config_hash") || selected.ConnectionID != typed.ID || selected.ConnectionVersion != typed.Version || selected.SafetyProfileID != model.String(profile, "id") || selected.SafetyProfileVersion != model.Number(profile, "version") || selected.SafetyProfileHash != model.String(profile, "hash") || selected.SchemaVersion != "1" || selected.PopulationHash != native.CapacityPopulationHash(selected) || selected.PopulationHash == "" || selected.SourceRefs == nil || selected.Segments == nil || selected.ReceiptIDs == nil || len(selected.ReceiptIDs) != len(selected.SourceRefs) || len(selected.ReceiptIDs) > 2048 || len(selected.Segments) > telemetry.MaxSamples || selected.AsOf.Before(a.now().Add(-2*time.Minute)) || selected.AsOf.After(a.now().Add(30*time.Second)) || !selected.End.After(selected.Start) {
		return nil, 0, true, problem(503, "CAPACITY_POPULATION_BINDING_INVALID", "native selection did not preserve current source and requirements")
	}
	// Provider hardware is selected independently from current immutable ingester
	// receipts. The public contract remains connection_id only. No source receipt
	// preserves the prior explicit unavailable-catalogue assessment behavior.
	var hasHardware bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM source_receipts WHERE tenant_id=$1 AND kind='AWS_EC2_HARDWARE' AND document->'binding'->>'resource_id'=$2)", identity.Tenant, typed.Binding.ResourceID).Scan(&hasHardware); err != nil {
		return nil, 0, true, err
	}
	if hasHardware {
		p, e := parseSafetyProfile(profile)
		if e != nil {
			return nil, 0, true, e
		}
		out, e := a.capacityWithNativeHardware(ctx, tx, selected, p)
		if e == nil {
			e = tx.Audit(ctx, identity.Subject, "capacity.native_assessment_recorded", model.String(out, "id"), model.Document{"connection_id": typed.ID, "population_hash": selected.PopulationHash, "model_evaluated": out["model_evaluated"], "status": "BLOCKED"})
		}
		return out, 201, true, e
	}
	reasons := append([]string{"BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED", "NATIVE_PRICE_UNAVAILABLE", capacityFleetAvoidabilityUnproven}, selected.ReasonCodes...)
	if selected.Evaluation.Status != "READY" {
		reasons = append(reasons, selected.Evaluation.ReasonCodes...)
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, reason := range reasons {
		if reason != "" && !seen[reason] {
			seen[reason] = true
			unique = append(unique, reason)
		}
	}
	sort.Strings(unique)
	metadata := model.Document{"schema_version": "1", "workload_id": parts[1], "resource_id": typed.Binding.ResourceID, "connection_id": typed.ID, "connection_version": typed.Version, "revision_id": c["revision_id"], "config_hash": c["config_hash"], "safety_profile_id": profile["id"], "safety_profile_version": profile["version"], "safety_profile_hash": profile["hash"], "population_hash": selected.PopulationHash, "receipt_ids": selected.ReceiptIDs, "source_refs": selected.SourceRefs, "history": model.Document{"start": selected.Start, "end": selected.End, "days": selected.HistoryDays, "timezone": selected.Timezone, "environment": selected.Environment}, "native_evaluation": selected.Evaluation, "status": "BLOCKED", "reason_codes": unique, "execution_authorized": false, "hardware_catalog_status": "UNAVAILABLE", "native_price_status": "UNAVAILABLE", "estimated_saving": nil, "verified_saving": nil}
	out, err := tx.CapacityAssessmentCreate(ctx, metadata)
	if err == nil {
		err = tx.Audit(ctx, identity.Subject, "capacity.assessment_recorded", model.String(out, "id"), model.Document{"connection_id": typed.ID, "population_hash": selected.PopulationHash, "status": "BLOCKED"})
	}
	return out, 201, true, err
}

func (a *API) nativeCapacityPopulation(ctx context.Context, input native.CapacityInputRequest) (native.CapacityPopulation, error) {
	var population native.CapacityPopulation
	token := os.Getenv("TELEMETRY_READER_TOKEN")
	if token == "" {
		return population, problem(503, "CAPACITY_READER_NOT_CONFIGURED", "independent native selection is unavailable")
	}
	raw, _ := json.Marshal(input)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(env("TELEMETRY_READER_URL", "http://telemetry-reader:8095"), "/")+"/capacity-input", bytes.NewReader(raw))
	if err != nil {
		return population, err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	response, err := client.Do(r)
	if err != nil {
		return population, problem(503, "CAPACITY_NATIVE_EVIDENCE_UNAVAILABLE", "native observations could not be selected")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return population, problem(503, "CAPACITY_NATIVE_EVIDENCE_UNAVAILABLE", "inspect source revision, persisted evidence and workload requirements")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(body) > 64<<20 {
		return population, problem(503, "CAPACITY_POPULATION_LIMIT", "native selection exceeds the bounded assessment transport")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&population) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return population, problem(503, "CAPACITY_POPULATION_INVALID", "native reader returned an invalid or oversized selection")
	}
	return population, nil
}
