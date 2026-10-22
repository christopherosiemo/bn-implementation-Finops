package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Same platform queue, object archive and private economics boundary as the
// other analytical workers. The dedicated LOGIN cannot sign or execute plans.
func RunStorageAssessor(ctx context.Context, cfg Config, db *store.Store) error {
	if cfg.AWSReadRole != "" || cfg.AWSExecutionRole != "" || cfg.PrivateKey != "" || cfg.SignerToken != "" || cfg.ExecutorToken != "" {
		return errors.New("STORAGE_ANALYST_IDENTITY_MUST_BE_READ_ONLY")
	}
	if cfg.EconomicsToken == "" {
		return errors.New("STORAGE_ECONOMICS_IDENTITY_REQUIRED")
	}
	archive, e := native.StorageFromEnvironment(ctx, cfg.Fixture)
	if e != nil {
		return e
	}
	a := &API{Store: db, Config: cfg, Client: &http.Client{Timeout: HTTPTimeout}}
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		rows, e := db.Pool.Query(ctx, "SELECT tenant_id FROM tenant_registry ORDER BY tenant_id")
		if e != nil {
			return e
		}
		tenants := []string{}
		for rows.Next() {
			var tenant string
			if e = rows.Scan(&tenant); e != nil {
				break
			}
			tenants = append(tenants, tenant)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return e
		}
		for _, tenant := range tenants {
			if e = db.Do(ctx, tenant, func(tx *store.Tx) error { return storageAssessmentOne(ctx, a, tx, archive.Read) }); e != nil {
				slog.Error("storage assessment retry required", "code", "STORAGE_ASSESSMENT_RETRY")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func storageAssessmentOne(ctx context.Context, a *API, t *store.Tx, read databaseArchiveRead) error {
	var id, rid, snapshotID, profileID string
	e := t.QueryRow(ctx, `SELECT id,resource_id,coalesce(snapshot_id,''),coalesce(safety_profile_id,'') FROM storage_assessments WHERE tenant_id=$1 AND status='QUEUED' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, t.Tenant).Scan(&id, &rid, &snapshotID, &profileID)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return e
	}
	resource, e := t.Get(ctx, "resources", rid)
	if e != nil {
		return e
	}
	var snapshot, canonical, profile, input, assessment model.Document
	reasons := []string{}
	refs := []model.Document{}
	if snapshotID == "" {
		reasons = append(reasons, "STORAGE_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		snapshot, e = t.StorageEvidenceGet(ctx, snapshotID)
		if e != nil {
			return e
		}
		at, ae := time.Parse(time.RFC3339Nano, model.String(snapshot, "observed_at"))
		if ae != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 24*time.Hour {
			reasons = append(reasons, "STORAGE_INVENTORY_STALE")
		}
		if model.String(snapshot, "config_hash") != StorageConfigurationHash(resource) {
			reasons = append(reasons, "STORAGE_CONFIGURATION_CHANGED")
		}
		raw, re := read(ctx, t.Tenant, storageObject(snapshot["archive"]))
		if re != nil {
			return re
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if e = decoder.Decode(&canonical); e != nil {
			return e
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return errors.New("STORAGE_ARCHIVE_JSON_INVALID")
		}
		if model.String(canonical, "schema_version") != "1" || StorageConfigurationHash(storageObject(canonical["resource"])) != StorageConfigurationHash(resource) {
			reasons = append(reasons, "STORAGE_ARCHIVE_RESOURCE_MISMATCH")
		}
	}
	if profileID != "" {
		profile, e = t.WorkloadSafetyGet(ctx, profileID)
		if e != nil {
			return e
		}
		latest, pe := t.WorkloadSafetyLatest(ctx, model.String(resource, "workload_id"))
		if pe != nil {
			return pe
		}
		if model.String(latest, "id") != profileID {
			reasons = append(reasons, "STORAGE_SAFETY_POLICY_CHANGED")
		}
	}
	if canonical != nil && len(reasons) == 0 {
		var rs []string
		input, refs, rs, e = a.storageAssessmentInput(ctx, t, resource, snapshot, canonical, profile)
		if e != nil {
			return e
		}
		reasons = append(reasons, rs...)
	}
	if input != nil {
		assessment, e = a.economics(ctx, "v8/storage-assessment", input)
		if e != nil {
			return e
		}
		if e = storageValidateResult(assessment, input); e != nil {
			return e
		}
		authorityCurrent, ae := storageAuthorityReferencesCurrent(ctx, t, resource, refs, a.now())
		if ae != nil {
			return ae
		}
		if !authorityCurrent {
			reasons = append(reasons, "STORAGE_REVIEW_OR_AUTHORITY_CHANGED")
		}
		if len(reasons) > 0 {
			assessment["blockers"] = databaseSortedReasons(append(model.Strings(assessment, "blockers"), reasons...))
			assessment["status"] = "BLOCKED"
			assessment["decision_code"] = "STORAGE_SERVER_EVIDENCE_BLOCKED"
			assessment["candidate_configuration"] = nil
			assessment["confidence"] = model.Document{"status": "UNAVAILABLE", "meaning": "SERVER_EVIDENCE_BLOCKED", "reasons": assessment["blockers"]}
			assessment["candidates"] = []model.Document{}
			costs := storageObject(assessment["economics"])
			costs["status"] = "UNAVAILABLE"
			for _, key := range []string{"candidate_hourly_cost", "candidate_monthly_cost", "estimated_monthly_saving", "estimated_annual_saving"} {
				costs[key] = nil
			}
			assessment["economics"] = costs
		}
	} else {
		assessment = storageBlocked(resource, snapshot, reasons)
	}
	if review := storageObject(assessment["unattached_review"]); len(review) > 0 {
		if context, ref := storageRecordedPriorAttachments(canonical, resource, a.now()); ref != nil {
			review["prior_attachment_context"] = context
			assessment["unattached_review"] = review
			refs = append(refs, ref)
		}
	}
	if assessment["binding"] == nil {
		assessment["binding"] = storageBinding(t.Tenant, resource)
	}
	assessment["source_refs"] = append(storageRows(assessment["source_refs"]), refs...)
	if h := model.String(assessment, "assessment_hash"); h != "" {
		assessment["model_assessment_hash"] = h
	}
	delete(assessment, "assessment_hash")
	assessment["assessment_hash"] = evidence.Hash(assessment)
	status := "ASSESSED"
	if model.String(assessment, "status") == "BLOCKED" {
		status = "BLOCKED"
	}
	body, _ := json.Marshal(model.Document{"assessment": assessment})
	if _, e = t.Exec(ctx, "UPDATE storage_assessments SET status=$3,document=$4 WHERE tenant_id=$1 AND id=$2", t.Tenant, id, status, body); e != nil {
		return e
	}
	costs := storageObject(assessment["economics"])
	name := model.String(resource, "name")
	if name == "" {
		name = model.String(resource, "provider_resource_id")
	}
	pub := model.Document{"id": "storage-" + id, "model_kind": "STORAGE_ASSESSMENT_V1", "storage_assessment_id": id, "resource_id": rid, "workload_id": resource["workload_id"], "assessment": assessment, "status": assessment["status"], "action_type": assessment["recommendation_kind"], "reason_code": assessment["decision_code"], "title": "Review block storage: " + name, "pre_execution_ready": false, "execution_authorized": false, "risk_class": "R3", "verified_saving": nil, "monthly_saving": costs["estimated_monthly_saving"], "currency": costs["currency"], "created_at": model.Now(), "version": 1}
	raw, _ := json.Marshal(pub)
	if _, e = t.Exec(ctx, "INSERT INTO storage_recommendation_publications(tenant_id,assessment_id,resource_id,document,current_hourly_cost,candidate_hourly_cost,currency) VALUES($1,$2,$3,$4,$5,$6,$7)", t.Tenant, id, rid, raw, costs["current_hourly_cost"], costs["candidate_hourly_cost"], costs["currency"]); e != nil {
		return e
	}
	if e = t.Audit(ctx, "storage-assessor", "storage.assessment.published", id, model.Document{"resource_id": rid, "status": status, "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "storage.assessment.published", model.Document{"id": id, "resource_id": rid, "status": status})
}
func storageBlocked(resource, snapshot model.Document, reasons []string) model.Document {
	if len(reasons) == 0 {
		reasons = []string{"STORAGE_EVIDENCE_UNAVAILABLE"}
	}
	return model.Document{"schema_version": "1", "model_version": "storage-observed-demand-v1", "resource_kind": resource["resource_type"], "current_configuration": storageObject(resource["storage_configuration"]), "candidate_configuration": nil, "evidence_window": nil, "metric_distributions": []any{}, "economics": model.Document{"component_costs": []any{}, "current_hourly_cost": nil, "current_monthly_cost": nil, "candidate_hourly_cost": nil, "candidate_monthly_cost": nil, "estimated_monthly_saving": nil, "estimated_annual_saving": nil, "currency": nil, "basis": "UNAVAILABLE", "status": "UNAVAILABLE", "verified_saving": nil}, "blockers": reasons, "checks": []any{}, "confidence": model.Document{"status": "UNAVAILABLE", "meaning": "INSUFFICIENT_SERVER_SELECTED_EVIDENCE", "reasons": reasons}, "proposal": model.Document{"risk_class": "R3", "executable": false, "execution_authorized": false}, "configuration_authority": resource["configuration_authority"], "implementation_method": "REVIEW_ONLY", "unattached_review": nil, "snapshot_reviews": []any{}, "source_refs": []any{}, "candidates": []any{}, "model_assumptions": []string{"Missing evidence remains unavailable; this record authorizes no provider action."}, "verified_saving": nil, "recommendation_kind": "STORAGE_UNSUPPORTED_CONFIGURATION", "status": "BLOCKED", "decision_code": "STORAGE_EVIDENCE_BLOCKED"}
}
func storageValidateResult(result, input model.Document) error {
	invalid := errors.New("STORAGE_ECONOMICS_RESPONSE_INVALID")
	p := storageObject(result["proposal"])
	if model.String(result, "schema_version") != "1" || evidence.Hash(result["binding"]) != evidence.Hash(input["binding"]) || p["executable"] != false || p["execution_authorized"] != false || model.String(p, "risk_class") != "R3" {
		return invalid
	}
	v, ok := result["verified_saving"]
	if !ok || v != nil {
		return invalid
	}
	switch model.String(result, "status") {
	case "RECOMMENDED", "NO_CHANGE", "BLOCKED", "OBSERVATION_ONLY":
	default:
		return invalid
	}
	costs := storageObject(result["economics"])
	for _, key := range []string{"current_hourly_cost", "current_monthly_cost", "candidate_hourly_cost", "candidate_monthly_cost", "estimated_monthly_saving", "estimated_annual_saving"} {
		if v := costs[key]; v != nil {
			text, ok := v.(string)
			if !ok || !databaseMoney.MatchString(text) {
				return invalid
			}
		}
	}
	currency := model.String(costs, "currency")
	expectedCurrency := model.String(storageObject(input["current_pricing"]), "currency")
	if model.String(input, "resource_kind") == "EBS_SNAPSHOT" {
		expectedCurrency = model.String(storageObject(input["continuing_costs"]), "currency")
	}
	if currency != "" && (!databaseCoverageCurrency.MatchString(currency) || currency != expectedCurrency) {
		return invalid
	}
	current, candidate := storageObject(input["current_configuration"]), storageObject(result["candidate_configuration"])
	if len(candidate) > 0 {
		size, ok := databaseDecimal(candidate["size_gib"])
		old, ook := databaseDecimal(current["size_gib"])
		if !ok || !ook || size.Cmp(old) != 0 {
			return invalid
		}
	}
	return nil
}
