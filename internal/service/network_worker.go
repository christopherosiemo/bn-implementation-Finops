package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

func RunNetworkAssessor(ctx context.Context, cfg Config, db *store.Store) error {
	if cfg.AWSReadRole != "" || cfg.AWSExecutionRole != "" || cfg.PrivateKey != "" || cfg.SignerToken != "" || cfg.ExecutorToken != "" {
		return errors.New("NETWORK_ANALYST_IDENTITY_MUST_BE_READ_ONLY")
	}
	if cfg.EconomicsToken == "" {
		return errors.New("NETWORK_ECONOMICS_IDENTITY_REQUIRED")
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
			if e = db.Do(ctx, tenant, func(t *store.Tx) error { return networkAssessmentOne(ctx, a, t, archive.Read) }); e != nil {
				slog.Error("network assessment retry required", "code", "NETWORK_ASSESSMENT_RETRY")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func (a *API) networkCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
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
	if e = t.QueryRow(ctx, "SELECT coalesce(snapshot_id,''),coalesce(policy_id,''),policy_version FROM network_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, d["id"]).Scan(&sid, &pid, &pv); e != nil {
		return nil, e
	}
	if sid == "" {
		reasons = append(reasons, "NETWORK_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		s, e := t.NetworkEvidenceGet(ctx, sid)
		if e != nil {
			return nil, e
		}
		latest, e := t.NetworkEvidenceLatest(ctx, model.String(r, "id"))
		if e != nil {
			return nil, e
		}
		if model.String(s, "config_hash") != NetworkConfigurationHash(r) || latest["content_hash"] != s["content_hash"] {
			reasons = append(reasons, "NETWORK_TOPOLOGY_POPULATION_OR_SOURCE_CHANGED")
		}
		at, err := time.Parse(time.RFC3339Nano, model.String(s, "observed_at"))
		if err != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 30*time.Minute {
			reasons = append(reasons, "NETWORK_TOPOLOGY_STALE")
		}
	}
	if pid != "" {
		p, e := t.NetworkPolicyGet(ctx, pid)
		if e != nil {
			return nil, e
		}
		if pv == nil || model.Number(p, "version") != *pv {
			reasons = append(reasons, "NETWORK_POLICY_CHANGED")
		}
	}
	result := storageObject(d["assessment"])
	for _, binding := range storageRows(result["source_bindings"]) {
		src, e := t.SourceGet(ctx, model.String(binding, "source_id"))
		if e != nil {
			return nil, e
		}
		if !model.Bool(src, "enabled") || model.String(src, "status") != "HEALTHY" || model.Number(src, "version") != model.Number(binding, "version") || model.String(src, "latest_receipt_id") != model.String(binding, "receipt_id") {
			reasons = append(reasons, "NETWORK_SOURCE_CHANGED_OR_REVOKED")
		}
	}
	if refs := storageRows(result["financial_references"]); len(refs) > 0 {
		ok, e := databaseBillingReferencesCurrent(ctx, t, refs)
		if e != nil {
			return nil, e
		}
		if !ok {
			reasons = append(reasons, "NETWORK_BILLING_CORRECTED_OR_REVOKED")
		}
	}
	if evidence.Hash(result["binding"]) != evidence.Hash(storageBinding(t.Tenant, r)) {
		reasons = append(reasons, "NETWORK_RESOURCE_BINDING_CHANGED")
	}
	out := model.Clone(d)
	out["current"], out["currentness_blockers"] = len(reasons) == 0, databaseSortedReasons(reasons)
	return a.recommendationCurrentness(ctx, t, "NETWORK", out)
}
func networkAssessmentOne(ctx context.Context, a *API, t *store.Tx, read databaseArchiveRead) error {
	var id, rid, sid, pid string
	var pv *int64
	e := t.QueryRow(ctx, "SELECT id,resource_id,coalesce(snapshot_id,''),coalesce(policy_id,''),policy_version FROM network_assessments WHERE tenant_id=$1 AND status='QUEUED' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED", t.Tenant).Scan(&id, &rid, &sid, &pid, &pv)
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
		reasons = append(reasons, "NETWORK_PERSISTED_NATIVE_EVIDENCE_REQUIRED")
	} else {
		snapshot, e = t.NetworkEvidenceGet(ctx, sid)
		if e != nil {
			return e
		}
		raw, e := read(ctx, t.Tenant, storageObject(snapshot["archive"]))
		if e != nil {
			return e
		}
		if network.BytesHash(raw) != model.String(snapshot, "content_hash") {
			return errors.New("NETWORK_CANONICAL_HASH_MISMATCH")
		}
		canonical = storageObject(json.RawMessage(raw))
		if canonical == nil {
			return errors.New("NETWORK_CANONICAL_HASH_MISMATCH")
		}
		if canonical["resource_id"] != rid || canonical["account_id"] != r["account_id"] || canonical["region"] != r["region"] || canonical["config_hash"] != NetworkConfigurationHash(r) {
			reasons = append(reasons, "NETWORK_NATIVE_SCOPE_MISMATCH")
		}
	}
	if pid != "" && pv != nil {
		policy, e = t.NetworkPolicyVersion(ctx, pid, *pv)
		if e != nil {
			return e
		}
	}
	input, financial, inputReasons, e := a.networkInput(ctx, t, r, canonical, policy)
	if e != nil {
		return e
	}
	reasons = append(reasons, inputReasons...)
	result := networkBlocked(storageBinding(t.Tenant, r), reasons)
	if sid != "" && databaseCoverageCurrency.MatchString(model.String(storageObject(input["billing"]), "currency")) && len(storageRows(input["cohorts"])) > 0 {
		result, e = a.economics(ctx, "v10/network-assessment", input)
		if e != nil {
			return e
		}
		if e = validateNetworkResult(result, input); e != nil {
			return e
		}
	} else {
		result["cohorts"] = input["cohorts"]
		result["observed_components"] = storageObject(input["billing"])["components"]
	}
	result["financial_references"], result["source_bindings"] = financial, canonical["source_bindings"]
	if policy != nil {
		result["declared_policy"], result["declared_policy_ref"] = policy["policy"], storageRef("NETWORK_POLICY", pid, strconv.FormatInt(*pv, 10), networkPolicyHash(policy))
	}
	prospective, e := t.NetworkAssessmentGet(ctx, id)
	if e != nil {
		return e
	}
	prospective["status"], prospective["assessment"] = "ASSESSED", result
	current, e := a.networkCurrent(recommendationPendingContext(ctx), t, prospective)
	if e != nil {
		return e
	}
	reasons = append(reasons, model.Strings(current, "currentness_blockers")...)
	if len(reasons) > 0 {
		networkBlockForEvidence(result, reasons)
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
	if _, e = t.Exec(ctx, "UPDATE network_assessments SET status=$3,document=$4 WHERE tenant_id=$1 AND id=$2", t.Tenant, id, status, body); e != nil {
		return e
	}
	econ := storageObject(result["economics"])
	pub := model.Document{"id": "network-" + id, "network_assessment_id": id, "model_kind": "NETWORK_ASSESSMENT_V1", "resource_id": rid, "workload_id": r["workload_id"], "assessment": result, "status": result["status"], "action_type": "NETWORK_POLICY_REVIEW", "title": "Review network path: " + model.String(r, "name"), "reason_code": "NETWORK_READ_ONLY_ASSESSMENT", "pre_execution_ready": false, "execution_authorized": false, "risk_class": "R3", "verified_saving": nil, "monthly_saving": econ["estimated_monthly_saving"], "currency": econ["currency"], "created_at": model.Now(), "version": 1}
	raw, _ := json.Marshal(pub)
	if _, e = t.Exec(ctx, "INSERT INTO network_recommendation_publications(tenant_id,assessment_id,resource_id,document,currency,current_monthly_cost,candidate_monthly_cost) VALUES($1,$2,$3,$4,$5,$6,$7)", t.Tenant, id, rid, raw, econ["currency"], econ["current_monthly_cost"], econ["candidate_monthly_cost"]); e != nil {
		return e
	}
	if e = t.Audit(ctx, "network-assessor", "network.assessment.published", id, model.Document{"resource_id": rid, "status": status, "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "network.assessment.published", model.Document{"id": id, "resource_id": rid, "status": status})
}
func networkUnavailableEconomics() model.Document {
	return model.Document{"status": "ECONOMICS_UNAVAILABLE", "basis": "UNAVAILABLE", "pricing_basis": "UNAVAILABLE", "allocation_basis": "UNAVAILABLE", "currency": nil, "observed_allocated_cost": nil, "current_window_cost": nil, "candidate_window_cost": nil, "estimated_window_saving": nil, "current_monthly_cost": nil, "candidate_monthly_cost": nil, "estimated_monthly_saving": nil, "estimated_annual_saving": nil, "nat_hourly_retained": true, "component_costs": []model.Document{}, "verified_saving": nil}
}
func networkBlocked(binding model.Document, reasons []string) model.Document {
	return model.Document{"schema_version": "1", "contract_version": 1, "model_kind": "NETWORK_ASSESSMENT_V1", "model_version": "network-v1", "binding": binding, "status": "BLOCKED", "reason_code": "NETWORK_SERVER_EVIDENCE_BLOCKED", "blockers": databaseSortedReasons(reasons), "cohorts": []model.Document{}, "candidates": []model.Document{}, "economics": networkUnavailableEconomics(), "confidence": model.Document{"status": "UNAVAILABLE"}, "proposal": model.Document{"risk_class": "R3", "executable": false, "execution_authorized": false}, "read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}
}
func networkBlockForEvidence(result model.Document, reasons []string) {
	blockers := databaseSortedReasons(append(model.Strings(result, "blockers"), reasons...))
	result["status"], result["reason_code"], result["blockers"], result["economics"] = "BLOCKED", "NETWORK_SERVER_EVIDENCE_BLOCKED", blockers, networkUnavailableEconomics()
	result["confidence"] = model.Document{"status": "UNAVAILABLE", "reasons": blockers, "meaning": "EVIDENCE_COVERAGE_NOT_A_CALIBRATED_PROBABILITY"}
	candidates := storageRows(result["candidates"])
	for _, c := range candidates {
		c["status"], c["decision"], c["blockers"], c["economics"] = "BLOCKED", "REVIEW_REQUIRED", blockers, networkUnavailableEconomics()
		c["confidence"] = model.Document{"status": "UNAVAILABLE", "reasons": blockers, "meaning": "EVIDENCE_COVERAGE_NOT_A_CALIBRATED_PROBABILITY"}
		c["pre_execution_ready"], c["execution_authorized"], c["verified_saving"] = false, false, nil
	}
	// storageRows returns independent copies; replace the source array so no
	// positive candidate claim survives a server-side authority/source block.
	result["candidates"] = candidates
}
func validateNetworkResult(result, input model.Document) error {
	p := storageObject(result["proposal"])
	v, ok := result["verified_saving"]
	if model.String(result, "schema_version") != "1" || model.String(result, "model_kind") != "NETWORK_ASSESSMENT_V1" || model.String(result, "model_version") != "network-v1" || result["read_only"] != true || evidence.Hash(result["binding"]) != evidence.Hash(input["binding"]) || p["executable"] != false || p["execution_authorized"] != false || model.String(p, "risk_class") != "R3" || !ok || v != nil || result["pre_execution_ready"] != false || result["execution_authorized"] != false {
		return errors.New("NETWORK_ECONOMICS_RESPONSE_INVALID")
	}
	for _, candidate := range storageRows(result["candidates"]) {
		saving, present := candidate["verified_saving"]
		if !present || saving != nil || candidate["pre_execution_ready"] != false || candidate["execution_authorized"] != false || candidate["read_only"] != true {
			return errors.New("NETWORK_ECONOMICS_CANDIDATE_AUTHORITY_INVALID")
		}
	}
	switch model.String(result, "status") {
	case "RECOMMENDED", "NO_CHANGE", "BLOCKED", "OBSERVATION_ONLY":
		return nil
	}
	return errors.New("NETWORK_ECONOMICS_STATUS_INVALID")
}
