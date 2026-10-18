package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// capacityWithNativeHardware selects immutable ingester hardware receipts.
// Public callers select a connection only, never capacities or prices.
func (a *API) capacityWithNativeHardware(ctx context.Context, tx *store.Tx, p native.CapacityPopulation, profile workload.Profile) (model.Document, error) {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tx.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	if p.Binding.TenantID != tx.Tenant || p.PopulationHash != native.CapacityPopulationHash(p) || p.AsOf.Before(a.now().Add(-2*time.Minute)) || p.AsOf.After(a.now().Add(5*time.Second)) {
		return nil, problem(422, "CAPACITY_POPULATION_BINDING_INVALID", "select current immutable native evidence")
	}
	resource, err := tx.Get(ctx, "resources", p.Binding.ResourceID)
	if err != nil {
		return nil, err
	}
	latest, err := tx.WorkloadSafetyLatest(ctx, p.Binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	if model.String(latest, "id") != profile.ID || model.Number(latest, "version") != profile.Version || profile.ID != p.SafetyProfileID || profile.Version != p.SafetyProfileVersion || model.String(latest, "hash") != p.SafetyProfileHash {
		return nil, problem(422, "CAPACITY_SAFETY_PROFILE_CHANGED", "refresh the current workload requirements")
	}
	connection, err := tx.TelemetryConnection(ctx, p.ConnectionID)
	if err != nil {
		return nil, err
	}
	typed, err := telemetry.ParseConnection(connection)
	if err != nil || typed.Binding != p.Binding || model.String(connection, "config_hash") != p.ConfigHash || typed.Version != p.ConnectionVersion || !typed.Enabled || model.Bool(connection, "revoked") {
		return nil, problem(422, "CAPACITY_TELEMETRY_SOURCE_CHANGED", "refresh the current native source revision")
	}
	if len(p.SourceRefs) != len(p.ReceiptIDs) || len(p.SourceRefs) > 2048 {
		return nil, problem(422, "CAPACITY_TELEMETRY_PROVENANCE_INVALID", "select the immutable native receipt set")
	}
	refs := map[string]native.CapacityReceiptRef{}
	for _, ref := range p.SourceRefs {
		if _, exists := refs[ref.ReceiptID]; exists {
			return nil, problem(422, "CAPACITY_TELEMETRY_PROVENANCE_INVALID", "duplicate native receipt reference")
		}
		refs[ref.ReceiptID] = ref
	}
	for _, id := range p.ReceiptIDs {
		ref, ok := refs[id]
		if !ok {
			return nil, problem(422, "CAPACITY_TELEMETRY_PROVENANCE_INVALID", "native receipt set changed")
		}
		receipt, e := tx.TelemetryReceipt(ctx, id)
		if e != nil || !model.Bool(receipt, "active_source") || model.String(receipt, "config_hash") != p.ConfigHash || model.String(receipt, "batch_id") != ref.BatchID || model.String(receipt, "raw_sha256") != ref.RawSHA256 || model.String(receipt, "canonical_hash") != ref.CanonicalHash {
			return nil, problem(422, "CAPACITY_TELEMETRY_PROVENANCE_INVALID", "native receipt provenance no longer matches")
		}
		delete(refs, id)
	}
	var raw []byte
	err = tx.QueryRow(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_receipts WHERE tenant_id=$1 AND kind='AWS_EC2_HARDWARE' AND document->'binding'->>'resource_id'=$2 ORDER BY created_at DESC,id DESC LIMIT 1", tx.Tenant, p.Binding.ResourceID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	hardware := model.Document{}
	if json.Unmarshal(raw, &hardware) != nil {
		return nil, problem(422, "CAPACITY_HARDWARE_RECEIPT_INVALID", "native hardware receipt is unavailable")
	}
	var bound telemetry.Binding
	bindingRaw, _ := json.Marshal(hardware["binding"])
	_ = json.Unmarshal(bindingRaw, &bound)
	collected, parseErr := time.Parse(time.RFC3339Nano, model.String(hardware, "collected_at"))
	if model.String(hardware, "writer_role") != "finops_ingester" || bound != p.Binding || parseErr != nil || collected.Before(a.now().Add(-2*time.Minute)) || collected.After(a.now().Add(5*time.Second)) || model.String(hardware, "resource_snapshot_hash") != telemetry.Hash(resource) || model.Number(hardware, "resource_version") != model.Number(resource, "version") {
		return nil, problem(422, "CAPACITY_NATIVE_HARDWARE_STALE_OR_CHANGED", "native hardware must match the current exact resource snapshot")
	}
	// Block source revocation/configuration changes through result publication.
	var registrationVersion int64
	if err = tx.QueryRow(ctx, "SELECT version FROM source_registrations WHERE tenant_id=$1 AND id=$2 FOR SHARE", tx.Tenant, model.String(hardware, "source_id")).Scan(&registrationVersion); err != nil {
		return nil, err
	}
	registration, err := tx.SourceGet(ctx, model.String(hardware, "source_id"))
	if err != nil {
		return nil, err
	}
	if !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || registrationVersion != model.Number(hardware, "registration_version") || source.ConfigurationHash(registration) != model.String(hardware, "config_hash") {
		return nil, problem(422, "CAPACITY_HARDWARE_SOURCE_CHANGED", "hardware source registration changed or was revoked")
	}
	mapping, err := native.BuildCapacityModelInput(p, profile, hardware)
	if err != nil {
		return nil, err
	}
	reasons := append([]string{"NATIVE_PRICE_UNAVAILABLE", "EXECUTION_AUTHORITY_NOT_GRANTED"}, mapping.ReasonCodes...)
	var result any
	inputKind := "MAPPING_OBSERVATION"
	inputHash := telemetry.Hash(mapping)
	requested := mapping.Request != nil
	if requested {
		inputKind = "MODEL_REQUEST"
		inputHash = telemetry.Hash(mapping.Request)
		calculated, e := a.nativeCapacityCalculation(ctx, *mapping.Request)
		if e != nil {
			code := e.Error()
			if !strings.HasPrefix(code, "CAPACITY_MODEL_") {
				code = "CAPACITY_MODEL_UNAVAILABLE"
			}
			reasons = append(reasons, code)
		} else {
			result = telemetry.Document(calculated)
		}
	}
	document := model.Document{"schema_version": "1", "binding": p.Binding, "workload_id": p.Binding.WorkloadID, "resource_id": p.Binding.ResourceID, "connection_id": p.ConnectionID, "connection_version": p.ConnectionVersion, "revision_id": connection["revision_id"], "config_hash": p.ConfigHash, "safety_profile_id": profile.ID, "safety_profile_version": profile.Version, "safety_profile_hash": p.SafetyProfileHash, "hardware_receipt_id": hardware["id"], "hardware_raw_sha256": model.String(telemetry.Document(hardware["native"]), "raw_sha256"), "resource_snapshot_hash": hardware["resource_snapshot_hash"], "population_hash": p.PopulationHash, "receipt_ids": p.ReceiptIDs, "source_refs": p.SourceRefs, "input_kind": inputKind, "input_hash": inputHash, "model_requested": requested, "model_evaluated": result != nil, "model_evaluation": result, "hardware_mapping": mapping, "status": "BLOCKED", "reason_codes": uniqueCapacityReasons(reasons), "native_price_status": "UNAVAILABLE", "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil, "change_plan_id": nil}
	document["history"] = model.Document{"start": p.Start, "end": p.End, "days": p.HistoryDays, "timezone": p.Timezone, "environment": p.Environment}
	document["native_evaluation"] = p.Evaluation
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 1<<20 {
		return nil, problem(422, "CAPACITY_MODEL_RESULT_LIMIT", "bounded model summary exceeds storage limits")
	}
	var saved []byte
	err = tx.QueryRow(ctx, "INSERT INTO native_capacity_results(tenant_id,id,workload_id,resource_id,connection_id,revision_id,safety_profile_id,hardware_receipt_id,input_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING document", tx.Tenant, model.ID(), p.Binding.WorkloadID, p.Binding.ResourceID, p.ConnectionID, connection["revision_id"], profile.ID, hardware["id"], inputHash, telemetry.Hash(document), encoded).Scan(&saved)
	if err != nil {
		return nil, err
	}
	out := model.Document{}
	err = json.Unmarshal(saved, &out)
	return out, err
}
func uniqueCapacityReasons(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (a *API) nativeCapacityCalculation(ctx context.Context, input native.CapacityModelRequest) (native.CapacityModelResult, error) {
	var result native.CapacityModelResult
	if a.Config.EconomicsURL == "" {
		return result, errors.New("CAPACITY_MODEL_NOT_CONFIGURED")
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 64<<20 {
		return result, errors.New("CAPACITY_MODEL_INPUT_LIMIT")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.Config.EconomicsURL, "/")+"/v4/capacity", bytes.NewReader(raw))
	if err != nil {
		return result, errors.New("CAPACITY_MODEL_REQUEST_INVALID")
	}
	r.Header.Set("Content-Type", "application/json")
	if a.Config.EconomicsToken != "" {
		r.Header.Set("Authorization", "Bearer "+a.Config.EconomicsToken)
	}
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := bounded.Do(r)
	if err != nil {
		return result, errors.New("CAPACITY_MODEL_UNAVAILABLE")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return result, errors.New("CAPACITY_MODEL_RESPONSE_LIMIT")
	}
	if response.StatusCode != 200 {
		return result, errors.New("CAPACITY_MODEL_EVIDENCE_REJECTED")
	}
	return native.DecodeCapacityModelResult(body, input)
}
