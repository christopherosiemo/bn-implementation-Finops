package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

func RunLambdaAssessor(ctx context.Context, cfg Config, db *store.Store) error {
	if cfg.AWSReadRole != "" || cfg.AWSExecutionRole != "" || cfg.PrivateKey != "" || cfg.SignerToken != "" || cfg.ExecutorToken != "" {
		return errors.New("LAMBDA_ANALYST_IDENTITY_MUST_BE_READ_ONLY")
	}
	if cfg.EconomicsToken == "" {
		return errors.New("LAMBDA_ECONOMICS_IDENTITY_REQUIRED")
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
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			tenants = append(tenants, id)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return e
		}
		for _, tenant := range tenants {
			if e = db.Do(ctx, tenant, func(t *store.Tx) error { return lambdaAssessmentOne(ctx, a, t, archive.Read) }); e != nil {
				slog.Error("lambda assessment retry required", "code", "LAMBDA_ASSESSMENT_RETRY")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func (a *API) lambdaCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	if model.String(d, "status") == "QUEUED" || model.String(d, "status") == "RUNNING" {
		return d, nil
	}
	r, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
	if e != nil {
		return nil, e
	}
	reasons := []string{}
	var sid, pid string
	var pv *int64
	if e = t.QueryRow(ctx, "SELECT coalesce(snapshot_id,''),coalesce(policy_id,''),policy_version FROM lambda_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, d["id"]).Scan(&sid, &pid, &pv); e != nil {
		return nil, e
	}
	if sid == "" {
		reasons = append(reasons, "LAMBDA_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		s, e := t.LambdaEvidenceGet(ctx, sid)
		if e != nil {
			return nil, e
		}
		latest, e := t.LambdaEvidenceLatest(ctx, model.String(r, "id"), model.String(d, "qualifier"))
		if e != nil {
			return nil, e
		}
		if cloudID := model.String(s, "cloud_account_id"); cloudID != "" {
			cloud, e := t.Get(ctx, "cloud_accounts", cloudID)
			if errors.Is(e, pgx.ErrNoRows) {
				reasons = append(reasons, "LAMBDA_CLOUD_ACCOUNT_REMOVED_OR_REVOKED")
			} else if e != nil {
				return nil, e
			} else if model.String(s, "cloud_account_authority_hash") != store.LambdaCloudAccountAuthorityHash(cloud) || model.Bool(cloud, "revoked") || cloud["enabled"] == false {
				reasons = append(reasons, "LAMBDA_CLOUD_ACCOUNT_CHANGED_OR_REVOKED")
			}
		}
		if model.String(s, "config_hash") != LambdaConfigurationHash(r) || latest["content_hash"] != s["content_hash"] {
			reasons = append(reasons, "LAMBDA_TOPOLOGY_POPULATION_OR_SOURCE_CHANGED")
		}
		if source := model.String(s, "source_id"); source != "" {
			registration, err := t.SourceGet(ctx, source)
			if err != nil {
				return nil, err
			}
			if !model.Bool(registration, "enabled") || model.Number(registration, "version") != model.Number(s, "source_registration_version") {
				reasons = append(reasons, "LAMBDA_SOURCE_CHANGED_OR_REVOKED")
			}
		}
		at, err := time.Parse(time.RFC3339Nano, model.String(s, "observed_at"))
		if err != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 30*time.Minute {
			reasons = append(reasons, "LAMBDA_TOPOLOGY_STALE")
		}
	}
	if pid != "" {
		p, e := t.LambdaPolicyGet(ctx, pid)
		if e != nil {
			return nil, e
		}
		if pv == nil || model.Number(p, "version") != *pv {
			reasons = append(reasons, "LAMBDA_POLICY_CHANGED")
		}
	}
	result := storageObject(d["assessment"])
	proofReasons, proofError := lambdaNativeComparabilityCurrent(ctx, t, result)
	if proofError != nil {
		return nil, proofError
	}
	reasons = append(reasons, proofReasons...)
	if model.String(result, "resource_authority_hash") != lambdaResourceAuthorityHash(r) {
		reasons = append(reasons, "LAMBDA_RESOURCE_AUTHORITY_CHANGED")
	}
	perf, err := t.LambdaPerformanceForResource(ctx, model.String(r, "id"), model.String(d, "qualifier"))
	if err != nil {
		return nil, err
	}
	if model.String(result, "performance_set_hash") != evidence.Hash(perf["receipts"]) {
		reasons = append(reasons, "LAMBDA_PERFORMANCE_EVIDENCE_CHANGED_OR_REVOKED")
	}
	for _, binding := range storageRows(result["source_bindings"]) {
		src, e := t.SourceGet(ctx, model.String(binding, "source_id"))
		if e != nil {
			return nil, e
		}
		if !model.Bool(src, "enabled") || model.Bool(src, "revoked") || model.Number(src, "version") != model.Number(binding, "version") || (model.String(binding, "receipt_id") != "" && (model.String(src, "status") != "HEALTHY" || model.String(src, "latest_receipt_id") != model.String(binding, "receipt_id"))) {
			reasons = append(reasons, "LAMBDA_SOURCE_CHANGED_OR_REVOKED")
		}
	}
	if refs := storageRows(result["financial_references"]); len(refs) > 0 {
		ok, e := databaseBillingReferencesCurrent(ctx, t, refs)
		if e != nil {
			return nil, e
		}
		if !ok {
			reasons = append(reasons, "LAMBDA_BILLING_CORRECTED_OR_REVOKED")
		}
	}
	if evidence.Hash(result["binding"]) != evidence.Hash(storageBinding(t.Tenant, r)) {
		reasons = append(reasons, "LAMBDA_RESOURCE_BINDING_CHANGED")
	}
	out := model.Clone(d)
	out["current"], out["currentness_blockers"] = len(reasons) == 0, databaseSortedReasons(reasons)
	return out, nil
}
func lambdaAssessmentOne(ctx context.Context, a *API, t *store.Tx, read databaseArchiveRead) error {
	var id, rid, sid, pid, qualifier string
	var pv *int64
	e := t.QueryRow(ctx, "SELECT id,resource_id,coalesce(snapshot_id,''),coalesce(policy_id,''),policy_version,qualifier FROM lambda_assessments WHERE tenant_id=$1 AND status='QUEUED' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED", t.Tenant).Scan(&id, &rid, &sid, &pid, &pv, &qualifier)
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
	canonical := model.Document{}
	var snapshot, policy model.Document
	if sid == "" {
		reasons = append(reasons, "LAMBDA_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		snapshot, e = t.LambdaEvidenceGet(ctx, sid)
		if e != nil {
			return e
		}
		raw, e := read(ctx, t.Tenant, storageObject(snapshot["archive"]))
		if e != nil {
			return e
		}
		if lambdacost.BytesHash(raw) != model.String(snapshot, "content_hash") {
			return errors.New("LAMBDA_CANONICAL_HASH_MISMATCH")
		}
		canonical = storageObject(json.RawMessage(raw))
		if canonical == nil {
			return errors.New("LAMBDA_CANONICAL_HASH_MISMATCH")
		}
		if canonical["resource_id"] != rid || canonical["account_id"] != r["account_id"] || canonical["region"] != r["region"] || canonical["config_hash"] != LambdaConfigurationHash(r) {
			reasons = append(reasons, "LAMBDA_NATIVE_SCOPE_MISMATCH")
		}
	}
	if pid != "" && pv != nil {
		policy, e = t.LambdaPolicyVersion(ctx, pid, *pv)
		if e != nil {
			return e
		}
	}
	performance, e := t.LambdaPerformanceForResource(ctx, rid, qualifier)
	if e != nil {
		return e
	}
	trustedPerformance := model.Document{"receipts": []model.Document{}}
	nativePerformanceRefs := []model.Document{}
	performanceWarnings := []string{}
	if sid != "" {
		trustedPerformance, nativePerformanceRefs, performanceWarnings, e = a.lambdaTrustedPerformance(ctx, t, r, canonical, performance, read)
		if e != nil {
			return e
		}
	}
	input, financial, inputReasons, e := a.lambdaInput(ctx, t, r, canonical, policy, trustedPerformance)
	if e != nil {
		return e
	}
	reasons = append(reasons, inputReasons...)
	result := lambdaBlocked(storageBinding(t.Tenant, r), reasons)
	result["qualifier"] = qualifier
	if sid != "" {
		result, e = a.economics(ctx, "v11/lambda-assessment", input)
		if e != nil {
			return e
		}
		if e = validateLambdaResult(result, input); e != nil {
			return e
		}
	} else {
		result["cohorts"] = input["cohorts"]
		result["observed_components"] = storageObject(input["billing"])["components"]
	}
	result["qualifier"] = qualifier
	result["resource_authority_hash"] = lambdaResourceAuthorityHash(r)
	result["financial_references"], result["source_bindings"] = financial, canonical["source_bindings"]
	result["performance_set_hash"] = evidence.Hash(performance["receipts"])
	lambdaApplyPerformanceAuthority(result, performance, trustedPerformance, nativePerformanceRefs, performanceWarnings)
	if policy != nil {
		result["declared_policy"], result["declared_policy_ref"] = policy["policy"], storageRef("LAMBDA_POLICY", pid, strconv.FormatInt(*pv, 10), lambdaPolicyHash(policy))
	}
	prospective, e := t.LambdaAssessmentGet(ctx, id)
	if e != nil {
		return e
	}
	prospective["status"], prospective["assessment"] = "ASSESSED", result
	current, e := a.lambdaCurrent(ctx, t, prospective)
	if e != nil {
		return e
	}
	reasons = append(reasons, model.Strings(current, "currentness_blockers")...)
	if len(reasons) > 0 {
		lambdaBlockForEvidence(result, reasons)
	}
	if h := model.String(result, "assessment_hash"); h != "" {
		result["model_assessment_hash"] = h
	}
	delete(result, "assessment_hash")
	result["assessment_hash"] = evidence.Hash(result)
	status := "ASSESSED"
	if model.String(result, "status") == "BLOCKED" {
		status = "BLOCKED"
	}
	body, _ := json.Marshal(model.Document{"assessment": result})
	if _, e = t.Exec(ctx, "UPDATE lambda_assessments SET status=$3,document=$4 WHERE tenant_id=$1 AND id=$2", t.Tenant, id, status, body); e != nil {
		return e
	}
	econ := storageObject(result["economics"])
	pub := model.Document{"id": "lambda-" + id, "lambda_assessment_id": id, "model_kind": "LAMBDA_ASSESSMENT_V1", "resource_id": rid, "qualifier": prospective["qualifier"], "workload_id": r["workload_id"], "assessment": result, "status": result["status"], "action_type": "LAMBDA_CONFIGURATION_REVIEW", "title": "Review Lambda configuration: " + model.String(r, "name"), "reason_code": "LAMBDA_READ_ONLY_ASSESSMENT", "pre_execution_ready": false, "execution_authorized": false, "risk_class": "R3", "verified_saving": nil, "monthly_saving": econ["estimated_monthly_saving"], "currency": econ["currency"], "created_at": model.Now(), "version": 1}
	raw, _ := json.Marshal(pub)
	if _, e = t.Exec(ctx, "INSERT INTO lambda_recommendation_publications(tenant_id,assessment_id,resource_id,document,currency,current_monthly_cost,candidate_monthly_cost) VALUES($1,$2,$3,$4,$5,$6,$7)", t.Tenant, id, rid, raw, econ["currency"], econ["current_monthly_cost"], econ["candidate_monthly_cost"]); e != nil {
		return e
	}
	if e = t.Audit(ctx, "lambda-assessor", "lambda.assessment.published", id, model.Document{"resource_id": rid, "status": status, "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "lambda.assessment.published", model.Document{"id": id, "resource_id": rid, "status": status})
}

func lambdaResourceAuthorityHash(r model.Document) string {
	return evidence.Hash(model.Document{"owner": r["owner"], "workload_id": r["workload_id"], "configuration_authority": r["configuration_authority"], "environment": r["environment"]})
}
