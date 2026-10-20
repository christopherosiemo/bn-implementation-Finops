package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	evidencepkg "github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func BuildPlan(ctx context.Context, t *store.Tx, recID, scheduleID string, fixture bool) (model.Document, error) {
	rec, e := t.Get(ctx, "recommendations", recID)
	if e != nil {
		return nil, e
	}
	if IsCommitmentAdvice(rec) {
		return nil, problem(422, "COMMITMENT_ADVICE_NOT_EXECUTABLE", "commitment advice cannot become a scheduling or provider plan")
	}
	if model.String(rec, "model_kind") == "DATABASE_ASSESSMENT_V1" {
		return nil, problem(422, "DATABASE_ADVICE_NOT_EXECUTABLE", "database advice cannot authorize provider actions")
	}
	if model.String(rec, "status") != "VALIDATED" || !model.Bool(rec, "pre_execution_ready") {
		return nil, problem(422, "RECOMMENDATION_NOT_VALIDATED", "recommendation must be validated")
	}
	if scheduleID == "" {
		schedules, e := t.List(ctx, "schedules")
		if e != nil {
			return nil, e
		}
		for _, s := range schedules {
			if model.String(s, "workload_id") == model.String(rec, "workload_id") {
				scheduleID = model.String(s, "id")
				break
			}
		}
	}
	s, e := t.Get(ctx, "schedules", scheduleID)
	if e != nil {
		return nil, e
	}
	if model.String(s, "workload_id") != model.String(rec, "workload_id") {
		return nil, problem(422, "WORKLOAD_MISMATCH", "schedule and recommendation must target same workload")
	}
	if model.Bool(s, "paused") {
		return nil, problem(422, "SCHEDULE_PAUSED", "schedule is paused")
	}
	if mode := model.String(s, "mode"); mode != "ASSISTED_EXECUTION" && mode != "AUTOPILOT" {
		return nil, problem(422, "BLOCKED_EXECUTION_MODE", "this schedule mode does not allow execution")
	}
	res, e := t.Get(ctx, "resources", model.String(rec, "resource_id"))
	if e != nil {
		return nil, e
	}
	if databaseResource(res) {
		return nil, problem(422, "DATABASE_ADVICE_NOT_EXECUTABLE", "database resources are observation-only")
	}
	ready, e := t.EvidenceGet(ctx, "readiness", model.String(rec, "readiness_id"))
	if e != nil {
		return nil, problem(422, "READINESS_REQUIRED", "refresh execution readiness before planning")
	}
	checked, err := time.Parse(time.RFC3339Nano, model.String(ready, "checked_at"))
	if err != nil || time.Since(checked) > 5*time.Minute || !model.Bool(ready, "pre_execution_ready") {
		return nil, problem(422, "READINESS_STALE", "refresh execution readiness before planning")
	}
	baseline, e := t.EvidenceGet(ctx, "baseline", model.String(ready, "baseline_id"))
	if e != nil {
		return nil, e
	}
	actualSnapshotHash := safety.SnapshotHash(res)
	res["commitment_known"], res["uncovered_on_demand"], res["observation_days"] = true, true, 14
	w, e := t.Get(ctx, "workloads", model.String(rec, "workload_id"))
	if e != nil {
		return nil, e
	}
	if model.Bool(w, "observation_only") {
		return nil, problem(422, "OBSERVATION_ONLY_WORKLOAD", "this workload does not delegate execution")
	}
	if model.String(baseline, "schema_version") == "3" {
		w, e = trustedWorkload(ctx, t, res, w)
		if e != nil {
			return nil, evidenceProblem(e)
		}
	}
	policy, e := t.Get(ctx, "policies", "policy-default")
	if e != nil {
		return nil, e
	}
	org, e := t.Get(ctx, "org", t.Tenant)
	if e != nil {
		return nil, e
	}
	if model.Bool(org, "paused") {
		return nil, problem(422, "BLOCKED_AUTOPILOT_PAUSED", "organisation is paused")
	}
	if blocked := safety.Eligibility(res, w, policy, time.Now()); len(blocked) > 0 {
		return nil, problem(422, blocked[0], "safety checks prevent plan creation")
	}
	if model.String(res, "state") != "running" {
		return nil, problem(422, "RESOURCE_NOT_RUNNING", "only a currently running instance can begin a stop occurrence")
	}
	var days []int
	switch v := s["days"].(type) {
	case []any:
		for _, x := range v {
			if n, ok := x.(float64); ok {
				days = append(days, int(n))
			}
		}
	case []int:
		days = v
	}
	stop, start, e := safety.NextWindow(time.Now(), model.String(s, "timezone"), model.String(s, "stop_time"), model.String(s, "ready_time"), days)
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	if fixture {
		stop = now
		start = now.Add(8 * time.Second)
	}
	expiry := stop.Add(15 * time.Minute)
	if expiry.After(now.Add(24 * time.Hour)) {
		return nil, problem(422, "PLAN_TOO_EARLY", "create the plan within 24 hours of its stop window")
	}
	op := model.Operation{Type: "EC2_STOP", ResourceID: model.String(res, "id"), ProviderResourceID: model.String(res, "provider_resource_id"), Region: model.String(res, "region"), AccountID: model.String(res, "account_id")}
	restore := op
	restore.Type = "EC2_START"
	p := model.Plan{ID: model.ID(), TenantID: t.Tenant, RecommendationID: recID, ScheduleID: scheduleID, WorkloadID: model.String(w, "id"), PolicyID: model.String(policy, "id"), PolicyVersion: model.Number(policy, "version"), ResourceVersion: model.Number(res, "version"), ResourceSnapshotHash: safety.SnapshotHash(res), RiskClass: "R1", Nonce: model.ID(), Operations: []model.Operation{op, restore}, CreatedAt: now, ExpiresAt: expiry, StopAt: stop, RestoreAt: start, HealthURL: model.String(w, "health_url"), Fixture: fixture}
	p.ResourceSnapshotHash = actualSnapshotHash
	m, e := reserveMeasurement(ctx, t, model.String(baseline, "id"), model.String(res, "id"), model.String(baseline, "activation_at"))
	if e != nil {
		return nil, e
	}
	p.SchemaVersion, p.ReadinessID, p.BaselineID, p.MeasurementID, p.ActivationAt = "2", model.String(ready, "id"), model.String(baseline, "id"), model.String(m, "id"), model.String(m, "activation_at")
	if model.String(baseline, "schema_version") == "3" {
		p.SchemaVersion, p.ProofSetID = "3", model.String(ready, "proof_set_id")
		p.DependencyReviewID, p.DependencyGraphHash = model.String(ready, "dependency_review_id"), model.String(ready, "dependency_graph_hash")
		p.SLOObjectiveID, p.SLOObjectiveVersion, p.SLOObjectiveHash = model.String(ready, "slo_objective_id"), model.Number(ready, "slo_objective_version"), model.String(ready, "slo_objective_hash")
		p.SLOEvaluationID, p.SLOEvaluationHash = model.String(ready, "slo_evaluation_id"), model.String(ready, "slo_evaluation_hash")
	}
	if e = readinessPlanCheck(ctx, t, p, res); e != nil {
		return nil, e
	}
	b, _ := json.Marshal(p)
	var payload any
	_ = json.Unmarshal(b, &payload)
	d := model.Document{"id": p.ID, "recommendation_id": recID, "schedule_id": scheduleID, "resource_id": res["id"], "workload_id": w["id"], "policy_version": p.PolicyVersion, "risk_class": "R1", "status": "AWAITING_APPROVAL", "operations": p.Operations, "payload": payload, "stop_at": stop.Format(time.RFC3339Nano), "restore_at": start.Format(time.RFC3339Nano), "expires_at": expiry.Format(time.RFC3339Nano), "created_at": model.Now(), "restoration_authorized": true, "fixture": fixture}
	d["readiness_id"], d["baseline_id"], d["measurement_id"], d["activation_at"] = p.ReadinessID, p.BaselineID, p.MeasurementID, p.ActivationAt
	d["proof_set_id"] = p.ProofSetID
	d["dependency_review_id"], d["dependency_graph_hash"] = p.DependencyReviewID, p.DependencyGraphHash
	d["slo_objective_id"], d["slo_objective_version"], d["slo_objective_hash"], d["slo_evaluation_id"], d["slo_evaluation_hash"] = p.SLOObjectiveID, p.SLOObjectiveVersion, p.SLOObjectiveHash, p.SLOEvaluationID, p.SLOEvaluationHash
	return t.Create(ctx, "change_plans", d)
}
func decodePlan(d model.Document) (model.Plan, error) {
	if IsCommitmentAdvice(d) {
		return model.Plan{}, problem(422, "COMMITMENT_ADVICE_NOT_EXECUTABLE", "commitment advice cannot become an execution envelope")
	}
	b, e := json.Marshal(d["payload"])
	if e != nil {
		return model.Plan{}, e
	}
	var p model.Plan
	e = json.Unmarshal(b, &p)
	return p, e
}
func (a *API) economics(ctx context.Context, endpoint string, input model.Document) (model.Document, error) {
	b, e := json.Marshal(input)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", a.Config.EconomicsURL+"/"+endpoint, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Config.EconomicsToken)
	res, e := a.Client.Do(req)
	if e != nil {
		return nil, problem(503, "ECONOMICS_UNAVAILABLE", "economics service unavailable")
	}
	defer res.Body.Close()
	limit := int64(4 << 20)
	if endpoint == "v3/normalize" {
		limit = 64 << 20
	}
	raw, readErr := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if readErr != nil || int64(len(raw)) > limit {
		return nil, problem(503, "ECONOMICS_RESPONSE_LIMIT", "economics response exceeded bounded ingestion capacity")
	}
	if res.StatusCode/100 != 2 {
		return nil, problem(422, "ECONOMICS_REJECTED", string(raw))
	}
	var d model.Document
	e = json.Unmarshal(raw, &d)
	return d, e
}
func (a *API) verifySavings(ctx context.Context, t *store.Tx, i interface{}, in model.Document) (model.Document, int, error) {
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, 0, e
	}
	blocked, disqualified, e := reconcileSLOClaims(ctx, t)
	if e != nil {
		return nil, 0, e
	}
	executions, e := t.List(ctx, "executions")
	if e != nil {
		return nil, 0, e
	}
	results := []model.Document{}
	requestedMeasurement := ""
	if filter := model.String(in, "execution_id"); filter != "" {
		for _, x := range executions {
			if model.String(x, "id") == filter {
				if plan, err := t.Get(ctx, "change_plans", model.String(x, "change_plan_id")); err == nil {
					if payload, err := decodePlan(plan); err == nil {
						requestedMeasurement = payload.MeasurementID
					}
				}
			}
		}
	}
	for _, row := range blocked {
		if filter := model.String(in, "execution_id"); filter == "" || filter == model.String(row, "execution_id") || requestedMeasurement != "" && requestedMeasurement == model.String(row, "measurement_id") {
			results = append(results, row)
		}
	}
	for _, x := range executions {
		if filter := model.String(in, "execution_id"); filter != "" && filter != model.String(x, "id") {
			continue
		}
		if plan, err := t.Get(ctx, "change_plans", model.String(x, "change_plan_id")); err == nil {
			if payload, err := decodePlan(plan); err == nil && disqualified[payload.MeasurementID] {
				continue
			}
		}
		if model.String(x, "status") != "COMPLETED" {
			continue
		}
		evidence, e := a.measurementInput(ctx, t, x)
		var d model.Document
		if e != nil {
			d, e = a.invalidatedTrustedClaim(ctx, t, x, e)
			if e != nil {
				var p *Problem
				if errors.As(e, &p) {
					return nil, 0, p
				}
				return nil, 0, problem(422, "BILLING_EVIDENCE_REQUIRED", e.Error())
			}
		} else {
			d, e = a.economics(ctx, "v2/evaluate", evidence)
			if e != nil {
				d, e = a.invalidatedTrustedClaim(ctx, t, x, e)
				if e != nil {
					return nil, 0, e
				}
			}
		}
		d["id"], d["execution_id"], d["recommendation_id"], d["created_at"], d["fixture"] = model.ID(), x["id"], x["recommendation_id"], model.Now(), a.Config.Fixture
		if evidence != nil {
			d["baseline_id"], d["measurement_id"], d["measurement_snapshot_id"], d["activation_at"], d["financial_clock"] = evidence["baseline_id"], evidence["measurement_id"], evidence["measurement_snapshot_id"], evidence["activation_at"], evidence["financial_clock"]
		}
		fingerprint := model.String(d, "fingerprint")
		if fingerprint == "" {
			return nil, 0, errors.New("economics response missing evidence fingerprint")
		}
		d["fingerprint"] = fingerprint
		d["resource_id"] = x["resource_id"]
		// Attribution is independent of execution ID and source revision. Replayed
		// evidence cannot claim the same window again; corrected source evidence
		// appends a revision superseding the prior claim for that resource/window.
		windows := evidencepkg.Rows(d["coverage_intervals"])
		if windows == nil {
			windows = []model.Document{}
		}
		attribution, _ := json.Marshal(model.Document{"resource_id": x["resource_id"], "windows": windows, "model": d["baseline_model"]})
		sum := sha256.Sum256(attribution)
		key := model.String(d, "claim_key")
		if key == "" {
			key = hex.EncodeToString(sum[:])
		}
		d["attribution_key"], d["claim_key"], d["coverage_intervals"], d["is_current"] = key, key, windows, true
		if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":savings:"+model.String(x, "resource_id")); e != nil {
			return nil, 0, e
		}
		var existing []byte
		var existingCurrent bool
		existingErr := t.QueryRow(ctx, "SELECT l.document,"+store.SavingsCurrentPredicate+" FROM savings_ledger l WHERE l.tenant_id=$1 AND l.fingerprint=$2", t.Tenant, fingerprint).Scan(&existing, &existingCurrent)
		if existingErr == nil {
			var prior model.Document
			if e = json.Unmarshal(existing, &prior); e != nil {
				return nil, 0, e
			}
			if existingCurrent {
				prior["is_current"] = true
				results = append(results, prior)
				continue
			}
			// Returning an obsolete identical payload must not leave a newer,
			// different financial head in force. Revivals append a correction.
			headID, _, err := previousSavingsRevision(ctx, t, key, model.String(d, "measurement_id"))
			if err != nil {
				return nil, 0, err
			}
			var headRaw []byte
			if e = t.QueryRow(ctx, "SELECT document FROM savings_ledger WHERE tenant_id=$1 AND id=$2", t.Tenant, headID).Scan(&headRaw); e != nil {
				return nil, 0, e
			}
			var head model.Document
			if e = json.Unmarshal(headRaw, &head); e != nil {
				return nil, 0, e
			}
			if model.String(head, "evidence_fingerprint") == fingerprint {
				head["is_current"] = true
				results = append(results, head)
				continue
			}
			d["evidence_fingerprint"] = fingerprint
			fingerprint = evidencepkg.Hash(model.Document{"evidence_fingerprint": fingerprint, "supersedes_id": headID})
			d["fingerprint"] = fingerprint
		}
		if existingErr != nil && existingErr != pgx.ErrNoRows {
			return nil, 0, existingErr
		}
		coverage, _ := json.Marshal(windows)
		var overlaps bool
		if e = t.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM savings_ledger l CROSS JOIN LATERAL jsonb_array_elements(l.document->'coverage_intervals') prior CROSS JOIN jsonb_array_elements($4::jsonb) proposed WHERE l.tenant_id=$1 AND l.document->>'resource_id'=$2 AND l.document->>'attribution_key'<>$3 AND `+store.SavingsCurrentPredicate+` AND (prior->>'start')::timestamptz < (proposed->>'end')::timestamptz AND (proposed->>'start')::timestamptz < (prior->>'end')::timestamptz)`, t.Tenant, model.String(x, "resource_id"), key, coverage).Scan(&overlaps); e != nil {
			return nil, 0, e
		}
		if overlaps {
			return nil, 0, problem(409, "DOUBLE_CLAIM", "billing window overlaps an existing savings claim for this resource")
		}
		oldID, oldFingerprint, err := previousSavingsRevision(ctx, t, key, model.String(d, "measurement_id"))
		if err == nil {
			if oldFingerprint == fingerprint {
				continue
			}
			d["supersedes_id"] = oldID
		} else if err != pgx.ErrNoRows {
			return nil, 0, err
		}
		b, _ := json.Marshal(d)
		_, e = t.Exec(ctx, "INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,fingerprint) DO NOTHING", t.Tenant, d["id"], x["id"], fingerprint, b)
		if e != nil {
			return nil, 0, e
		}
		_ = t.Audit(ctx, "verification-engine", "savings."+model.String(d, "status"), model.String(x, "id"), d)
		if model.String(d, "status") == "VERIFIED" {
			_ = t.Event(ctx, "savings.verified", d)
		}
		results = append(results, d)
	}
	return model.Document{"savings": results}, 200, nil
}

func previousSavingsRevision(ctx context.Context, t *store.Tx, key, measurement string) (string, string, error) {
	var id, fingerprint string
	// Exact claim identity wins over an unrelated empty-coverage provisional row
	// for the same measurement. Otherwise the old verified head would survive.
	e := t.QueryRow(ctx, "SELECT l.id,l.fingerprint FROM savings_ledger l WHERE l.tenant_id=$1 AND (l.document->>'attribution_key'=$2 OR ($3<>'' AND l.document->>'measurement_id'=$3)) AND "+store.SavingsCurrentPredicate+" ORDER BY CASE WHEN l.document->>'attribution_key'=$2 THEN 0 ELSE 1 END,l.created_at DESC,l.id DESC LIMIT 1", t.Tenant, key, measurement).Scan(&id, &fingerprint)
	return id, fingerprint, e
}
func CoverageOverlaps(windows []model.Document, prior any) bool {
	var old []model.Document
	b, _ := json.Marshal(prior)
	_ = json.Unmarshal(b, &old)
	for _, a := range windows {
		as, e1 := time.Parse(time.RFC3339Nano, model.String(a, "start"))
		ae, e2 := time.Parse(time.RFC3339Nano, model.String(a, "end"))
		if e1 != nil || e2 != nil {
			continue
		}
		for _, b := range old {
			bs, e1 := time.Parse(time.RFC3339Nano, model.String(b, "start"))
			be, e2 := time.Parse(time.RFC3339Nano, model.String(b, "end"))
			if e1 == nil && e2 == nil && as.Before(be) && bs.Before(ae) {
				return true
			}
		}
	}
	return false
}
