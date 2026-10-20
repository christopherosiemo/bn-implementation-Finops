package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

func ObjectStorageConfigurationHash(r model.Document) string {
	var b objectstorage.Bucket
	raw, _ := json.Marshal(r["object_storage_configuration"])
	_ = json.Unmarshal(raw, &b)
	return objectstorage.ConfigurationHash(b)
}
func RunObjectStorageAssessor(ctx context.Context, cfg Config, db *store.Store) error {
	if cfg.AWSReadRole != "" || cfg.AWSExecutionRole != "" || cfg.PrivateKey != "" || cfg.SignerToken != "" || cfg.ExecutorToken != "" {
		return errors.New("OBJECT_STORAGE_ANALYST_IDENTITY_MUST_BE_READ_ONLY")
	}
	if cfg.EconomicsToken == "" {
		return errors.New("OBJECT_STORAGE_ECONOMICS_IDENTITY_REQUIRED")
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
			if e = db.Do(ctx, tenant, func(t *store.Tx) error { return objectStorageAssessmentOne(ctx, a, t, archive.Read) }); e != nil {
				slog.Error("object storage assessment retry required", "code", "OBJECT_STORAGE_ASSESSMENT_RETRY")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func (a *API) objectStorageCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	if model.String(d, "status") == "QUEUED" || model.String(d, "status") == "RUNNING" {
		return d, nil
	}
	r, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
	if e != nil {
		return nil, e
	}
	reasons := []string{}
	var sid, did string
	var resourceVersion int64
	var dv *int64
	if e = t.QueryRow(ctx, "SELECT coalesce(snapshot_id,''),coalesce(dataset_id,''),dataset_version,resource_version FROM object_storage_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, d["id"]).Scan(&sid, &did, &dv, &resourceVersion); e != nil {
		return nil, e
	}
	if model.Number(r, "version") != resourceVersion {
		reasons = append(reasons, "OBJECT_STORAGE_RESOURCE_CONTEXT_CHANGED")
	}
	if sid == "" {
		reasons = append(reasons, "OBJECT_STORAGE_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		s, e := t.ObjectStorageEvidenceGet(ctx, sid)
		if e != nil {
			return nil, e
		}
		latest, e := t.ObjectStorageEvidenceLatest(ctx, model.String(r, "id"))
		if e != nil {
			return nil, e
		}
		if model.String(latest, "source_version") != model.String(s, "source_version") || model.String(latest, "content_hash") != model.String(s, "content_hash") || model.String(s, "config_hash") != ObjectStorageConfigurationHash(r) {
			reasons = append(reasons, "OBJECT_STORAGE_POPULATION_OR_CONFIGURATION_CHANGED")
		}
		at, ae := time.Parse(time.RFC3339Nano, model.String(s, "observed_at"))
		if ae != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 8*24*time.Hour {
			reasons = append(reasons, "OBJECT_STORAGE_INVENTORY_STALE")
		}
		if sourceID := model.String(s, "source_id"); sourceID != "" {
			src, e := t.SourceGet(ctx, sourceID)
			if e != nil {
				return nil, e
			}
			if !model.Bool(src, "enabled") || model.String(src, "status") != "HEALTHY" || model.Number(src, "version") != model.Number(s, "source_registration_version") || model.String(src, "latest_receipt_id") != "receipt-"+model.String(s, "source_version") {
				reasons = append(reasons, "OBJECT_STORAGE_SOURCE_CHANGED_OR_REVOKED")
			}
		}
	}
	if did != "" {
		latest, e := t.ObjectStorageDatasetGet(ctx, did)
		if e != nil {
			return nil, e
		}
		if dv == nil || model.Number(latest, "version") != *dv {
			reasons = append(reasons, "OBJECT_STORAGE_DATASET_POLICY_CHANGED")
		}
	}
	assessment := storageObject(d["assessment"])
	if old := objectStorageModelRef(assessment["configuration_authority_ref"]); old != nil {
		_, ref, e := objectStorageAuthority(ctx, t, r)
		if e != nil {
			return nil, e
		}
		if ref == nil || evidence.Hash(ref) != evidence.Hash(old) {
			reasons = append(reasons, "OBJECT_STORAGE_CONFIGURATION_AUTHORITY_CHANGED")
		}
	}
	if rs, e := objectStorageBindingsCurrent(ctx, t, storageRows(assessment["source_bindings"]), a.now()); e != nil {
		return nil, e
	} else {
		reasons = append(reasons, rs...)
	}
	if evidence.Hash(assessment["binding"]) != evidence.Hash(storageBinding(t.Tenant, r)) {
		reasons = append(reasons, "OBJECT_STORAGE_RESOURCE_BINDING_CHANGED")
	}
	refs := storageRows(assessment["financial_references"])
	if len(refs) > 0 {
		ok, e := databaseBillingReferencesCurrent(ctx, t, refs)
		if e != nil {
			return nil, e
		}
		if !ok {
			reasons = append(reasons, "OBJECT_STORAGE_BILLING_CORRECTED_OR_REVOKED")
		}
	}
	out := model.Clone(d)
	out["current"], out["currentness_blockers"] = len(reasons) == 0, databaseSortedReasons(reasons)
	return out, nil
}
func objectStorageAssessmentOne(ctx context.Context, a *API, t *store.Tx, read databaseArchiveRead) error {
	var id, rid, sid, did string
	var dv *int64
	e := t.QueryRow(ctx, "SELECT id,resource_id,coalesce(snapshot_id,''),coalesce(dataset_id,''),dataset_version FROM object_storage_assessments WHERE tenant_id=$1 AND status='QUEUED' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED", t.Tenant).Scan(&id, &rid, &sid, &did, &dv)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	r, e := t.Get(ctx, "resources", rid)
	if e != nil {
		return e
	}
	reasons := []string{}
	var canonical, snapshot, dataset model.Document
	if sid == "" {
		reasons = append(reasons, "OBJECT_STORAGE_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		snapshot, e = t.ObjectStorageEvidenceGet(ctx, sid)
		if e != nil {
			return e
		}
		raw, e := read(ctx, t.Tenant, storageObject(snapshot["archive"]))
		if e != nil {
			return e
		}
		if e = json.Unmarshal(raw, &canonical); e != nil {
			return e
		}
		if evidence.Hash(canonical) != model.String(snapshot, "content_hash") {
			return errors.New("OBJECT_STORAGE_CANONICAL_HASH_MISMATCH")
		}
		if model.String(canonical, "resource_id") != rid || model.String(canonical, "account_id") != model.String(r, "account_id") || model.String(canonical, "region") != model.String(r, "region") || model.String(canonical, "config_hash") != ObjectStorageConfigurationHash(r) {
			reasons = append(reasons, "OBJECT_STORAGE_NATIVE_SCOPE_MISMATCH")
		}
	}
	if did != "" && dv != nil {
		dataset, e = t.ObjectStorageDatasetVersion(ctx, did, *dv)
		if e != nil {
			return e
		}
	}
	binding := storageBinding(t.Tenant, r)
	input := model.Document{"schema_version": "1", "model_version": "object-storage-v1", "binding": binding, "as_of": a.now().Format(time.RFC3339Nano), "configuration": objectStorageModelConfiguration(r, canonical), "policy": storageObject(dataset["policy"]), "cohorts": []model.Document{}, "source_refs": objectStorageModelRefs(canonical["source_refs"])}
	authority, authorityRef, e := objectStorageAuthority(ctx, t, r)
	if e != nil {
		return e
	}
	configuration := storageObject(input["configuration"])
	if authorityRef == nil {
		reasons = append(reasons, "OBJECT_STORAGE_REGISTERED_CONFIGURATION_AUTHORITY_REQUIRED")
		configuration["configuration_authority"] = "UNKNOWN"
	} else {
		configuration["configuration_authority"] = authority
		input["source_refs"] = append(objectStorageModelRefs(input["source_refs"]), authorityRef)
	}
	input["configuration"] = configuration
	if dataset != nil {
		policy := storageObject(dataset["policy"])
		delete(policy, "dependencies_reviewed")
		policy["source_ref"] = storageRef("DECLARED_OBJECT_STORAGE_DATASET_POLICY", did, strconv.FormatInt(*dv, 10), objectStorageDatasetHash(dataset))
		input["policy"] = policy
	}
	cohorts, projectionReasons := objectStorageProjectCohorts(canonical, dataset, storageObject(input["configuration"]))
	reasons = append(reasons, projectionReasons...)
	if canonical != nil {
		rs, e := objectStorageBindingsCurrent(ctx, t, storageRows(canonical["source_bindings"]), a.now())
		if e != nil {
			return e
		}
		reasons = append(reasons, rs...)
	}
	input["cohorts"] = cohorts
	financial, fr, e := a.objectStorageFinancialInput(ctx, t, r, input, canonical)
	if e != nil {
		return e
	}
	reasons = append(reasons, fr...)
	var result model.Document
	modelEvaluated := false
	if canonical != nil && len(cohorts) > 0 {
		result, e = a.economics(ctx, "v9/object-storage-assessment", input)
		if e != nil {
			return e
		}
		if e = validateObjectStorageResult(result, input); e != nil {
			return e
		}
		modelEvaluated = true
	} else {
		reasons = append(reasons, "OBJECT_STORAGE_COHORT_EVIDENCE_UNAVAILABLE")
		result = objectStorageBlocked(binding, reasons)
	}
	result["financial_references"] = financial
	result["source_bindings"] = canonical["source_bindings"]
	result["configuration_authority_ref"] = authorityRef
	if dataset != nil {
		result["declared_policy"] = dataset["policy"]
		result["declared_policy_ref"] = storageRef("DECLARED_OBJECT_STORAGE_DATASET_POLICY", did, strconv.FormatInt(*dv, 10), objectStorageDatasetHash(dataset))
	}
	// A correction between enqueueing and evaluation is a persisted refusal,
	// not an indefinitely retried queue item. Recheck all frozen bindings before
	// the one terminal append under this transaction.
	prospective, e := t.ObjectStorageAssessmentGet(ctx, id)
	if e != nil {
		return e
	}
	prospective["status"] = "ASSESSED"
	prospective["assessment"] = result
	current, e := a.objectStorageCurrent(ctx, t, prospective)
	if e != nil {
		return e
	}
	if current["current"] != true {
		reasons = append(reasons, model.Strings(current, "currentness_blockers")...)
	}
	result["server_evidence_blockers"] = databaseSortedReasons(reasons)
	if len(reasons) > 0 {
		result["status"] = "BLOCKED"
		result["blockers"] = databaseSortedReasons(append(model.Strings(result, "blockers"), reasons...))
		result["economics"] = objectStorageUnavailableEconomics()
		blockedCandidates := []model.Document{}
		for _, c := range storageRows(result["candidates"]) {
			c["status"] = "BLOCKED"
			c["blockers"] = result["blockers"]
			c["economics"] = objectStorageUnavailableEconomics()
			blockedCandidates = append(blockedCandidates, c)
		}
		result["candidates"] = blockedCandidates
	}
	if h := model.String(result, "assessment_hash"); modelEvaluated && h != "" {
		result["model_assessment_hash"] = h
	}
	delete(result, "assessment_hash")
	result["assessment_hash"] = evidence.Hash(result)
	// Currentness is checked again under the same transaction before publication.
	body, _ := json.Marshal(model.Document{"assessment": result})
	status := "ASSESSED"
	if model.String(result, "status") == "BLOCKED" {
		status = "BLOCKED"
	}
	if _, e = t.Exec(ctx, "UPDATE object_storage_assessments SET status=$3,document=$4 WHERE tenant_id=$1 AND id=$2", t.Tenant, id, status, body); e != nil {
		return e
	}
	record, e := t.ObjectStorageAssessmentGet(ctx, id)
	if e != nil {
		return e
	}
	record, e = a.objectStorageCurrent(ctx, t, record)
	if e != nil {
		return e
	}
	economics := storageObject(result["economics"])
	pub := model.Document{"id": "object-storage-" + id, "object_storage_assessment_id": id, "model_kind": "OBJECT_STORAGE_ASSESSMENT_V1", "resource_id": rid, "workload_id": r["workload_id"], "assessment": result, "status": result["status"], "action_type": "OBJECT_STORAGE_POLICY_REVIEW", "title": "Review S3 storage policy: " + model.String(r, "name"), "reason_code": "OBJECT_STORAGE_READ_ONLY_ASSESSMENT", "pre_execution_ready": false, "execution_authorized": false, "risk_class": "R3", "verified_saving": nil, "monthly_saving": economics["estimated_monthly_saving"], "currency": economics["currency"], "created_at": model.Now(), "version": 1}
	raw, _ := json.Marshal(pub)
	if _, e = t.Exec(ctx, "INSERT INTO object_storage_recommendation_publications(tenant_id,assessment_id,resource_id,document,currency,current_monthly_cost,candidate_monthly_cost) VALUES($1,$2,$3,$4,$5,$6,$7)", t.Tenant, id, rid, raw, economics["currency"], economics["current_monthly_cost"], economics["candidate_monthly_cost"]); e != nil {
		return e
	}
	if e = t.Audit(ctx, "object-storage-assessor", "object_storage.assessment.published", id, model.Document{"resource_id": rid, "status": status, "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "object_storage.assessment.published", model.Document{"id": id, "resource_id": rid, "status": status})
}
func objectStorageUnavailableEconomics() model.Document {
	out := model.Document{"status": "UNAVAILABLE", "basis": "UNAVAILABLE", "currency": nil, "component_costs": []model.Document{}, "verified_saving": nil}
	for _, k := range []string{"current_monthly_cost", "candidate_monthly_cost", "estimated_monthly_saving", "estimated_annual_saving", "transition_cost", "baseline_minimum_duration_penalty", "current_minimum_duration_penalty", "candidate_minimum_duration_penalty", "tier_initialization_cost", "net_horizon_saving", "horizon_days", "current_horizon_cost", "candidate_horizon_cost", "recurring_monthly_saving"} {
		out[k] = nil
	}
	return out
}
func objectStorageBlocked(binding model.Document, reasons []string) model.Document {
	out := model.Document{"schema_version": "1", "model_kind": "OBJECT_STORAGE_ASSESSMENT_V1", "model_version": "object-storage-v1", "binding": binding, "status": "BLOCKED", "reason_code": "OBJECT_STORAGE_SERVER_EVIDENCE_BLOCKED", "blockers": databaseSortedReasons(reasons), "cohorts": []model.Document{}, "candidates": []any{}, "economics": objectStorageUnavailableEconomics(), "confidence": model.Document{"status": "UNAVAILABLE", "meaning": "INSUFFICIENT_SERVER_SELECTED_EVIDENCE", "reasons": databaseSortedReasons(reasons)}, "proposal": model.Document{"risk_class": "R3", "executable": false, "execution_authorized": false}, "configuration_authority": "UNKNOWN", "implementation_method": "REVIEW_ONLY", "source_refs": []model.Document{}, "model_assumptions": []string{"Missing evidence remains unknown. No provider action or verified savings is authorized."}, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}
	out["assessment_hash"] = evidence.Hash(out)
	return out
}
func validateObjectStorageResult(result, input model.Document) error {
	p := storageObject(result["proposal"])
	v, ok := result["verified_saving"]
	if model.String(result, "schema_version") != "1" || model.String(result, "model_kind") != "OBJECT_STORAGE_ASSESSMENT_V1" || evidence.Hash(result["binding"]) != evidence.Hash(input["binding"]) || p["executable"] != false || p["execution_authorized"] != false || model.String(p, "risk_class") != "R3" || !ok || v != nil {
		return errors.New("OBJECT_STORAGE_ECONOMICS_RESPONSE_INVALID")
	}
	switch model.String(result, "status") {
	case "RECOMMENDED", "NO_CHANGE", "BLOCKED", "OBSERVATION_ONLY":
		return nil
	}
	return errors.New("OBJECT_STORAGE_ECONOMICS_STATUS_INVALID")
}
func objectStorageModelConfiguration(r, canonical model.Document) model.Document {
	cfg := storageObject(storageObject(r["object_storage_configuration"])["configurations"])
	ref := storageRef("AWS_S3_NATIVE_CONFIGURATION", model.String(r, "id"), "1", ObjectStorageConfigurationHash(r))
	out := model.Document{"owner": r["owner"], "configuration_authority": r["configuration_authority"], "versioning": "UNKNOWN", "lifecycle_state": "UNKNOWN", "replication_state": "UNKNOWN", "object_lock_state": "UNKNOWN", "source_ref": ref}
	if model.String(out, "configuration_authority") == "" {
		out["configuration_authority"] = "UNKNOWN"
	}
	for _, pair := range []struct{ name, field string }{{"versioning", "versioning"}, {"lifecycle", "lifecycle_state"}, {"replication", "replication_state"}, {"object_lock", "object_lock_state"}} {
		o := storageObject(cfg[pair.name])
		switch model.String(o, "status") {
		case "ABSENT":
			if pair.name == "versioning" || pair.name == "object_lock" {
				out[pair.field] = "DISABLED"
			} else if pair.name == "replication" {
				out[pair.field] = "NONE"
			} else {
				out[pair.field] = "KNOWN"
			}
		case "OBSERVED":
			out[pair.field] = "KNOWN"
			if pair.name == "versioning" {
				v := model.String(storageObject(o["value"]), "Status")
				switch v {
				case "Enabled":
					out[pair.field] = "ENABLED"
				case "Suspended":
					out[pair.field] = "SUSPENDED"
				default:
					out[pair.field] = "DISABLED"
				}
			}
		}
	}
	return out
}
