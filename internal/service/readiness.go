package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"net/http"
	"time"
)

func evidenceProblem(e error) error {
	var p *Problem
	if errors.As(e, &p) {
		return p
	}
	return problem(422, e.Error(), "financial evidence does not meet immutable source and workload requirements")
}
func inputTime(d model.Document, k string) (time.Time, error) {
	x, e := time.Parse(time.RFC3339Nano, model.String(d, k))
	if e != nil {
		return x, problem(422, "EVIDENCE_TIME_REQUIRED", k+" must be an RFC3339 timestamp")
	}
	return x, nil
}
func baselineInput(b model.Document) model.Document {
	clock := evidence.Object(b["financial_clock"])
	asof := model.String(b, "created_at")
	if model.String(b, "schema_version") == "3" {
		asof = model.String(b, "evidence_as_of")
	}
	if asof == "" {
		asof = model.Now()
	}
	activation := model.String(b, "activation_at")
	if model.String(clock, "mode") == "DETERMINISTIC_LOGICAL" {
		asof = model.String(clock, "as_of")
		activation = model.String(clock, "activation_at")
	}
	version := "2"
	if model.String(b, "schema_version") == "3" {
		version = "3"
	}
	return model.Document{"schema_version": version, "phase": "BASELINE", "binding": b["binding"], "baseline_id": b["id"], "proof_set_id": b["proof_set_id"], "activation_at": activation, "as_of": asof, "baseline": b, "financial_clock": clock}
}
func (a *API) createBaseline(ctx context.Context, t *store.Tx, in model.Document) (model.Document, error) {
	if model.String(in, "schema_version") == "3" {
		return a.createTrustedBaseline(ctx, t, in)
	}
	if !a.Config.Fixture {
		return nil, problem(422, "EVIDENCE_V3_REQUIRED", "live baselines require server-selected authenticated receipts")
	}
	res, e := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if e != nil {
		return nil, e
	}
	job, e := t.Get(ctx, "ingestion_jobs", model.String(in, "ingestion_job_id"))
	if e != nil {
		return nil, e
	}
	binding, records, e := evidence.Source(job, res, t.Tenant)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	if e = trustedSource(job, a.Config.Fixture); e != nil {
		return nil, e
	}
	start, e := inputTime(in, "start")
	if e != nil {
		return nil, e
	}
	end, e := inputTime(in, "end")
	if e != nil {
		return nil, e
	}
	if !start.Before(end) || end.After(time.Now()) {
		return nil, problem(422, "BASELINE_WINDOW_INCOMPLETE", "baseline requires fourteen complete historical days")
	}
	records, e = evidence.PeriodRecords(records, start, end)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	samples, e := evidence.Samples(binding, in["workload_samples"], start, end)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	schedule, e := t.Get(ctx, "schedules", model.String(in, "schedule_id"))
	if e != nil {
		return nil, e
	}
	if model.String(schedule, "workload_id") != model.String(res, "workload_id") {
		return nil, problem(422, "WORKLOAD_BINDING_INVALID", "schedule workload differs from resource")
	}
	b := model.Document{"id": model.ID(), "resource_id": res["id"], "binding": binding, "ingestion_job_id": job["id"], "source_id": job["source_id"], "source_version": evidence.Object(job["raw"])["source_version"], "source_hash": evidence.Hash(job["raw"]), "canonical_hash": evidence.Hash(job["canonical"]), "billing_records": records, "workload_samples": samples, "start": start.Format(time.RFC3339Nano), "end": end.Format(time.RFC3339Nano), "schedule": schedule, "schedule_id": schedule["id"], "activation_at": model.Now()}
	b["source_refs"] = []model.Document{evidence.SourceReference(job, binding)}
	result, e := a.economics(ctx, "v2/evaluate", baselineInput(b))
	if e != nil {
		return nil, e
	}
	b["evaluation"] = result
	if !model.Bool(result, "pre_execution_ready") {
		return nil, problem(422, model.String(result, "reason_code"), "baseline is not ready for execution")
	}
	b, e = t.EvidenceCreate(ctx, "baseline", b)
	if e != nil {
		return nil, e
	}
	_ = t.Audit(ctx, "evidence-engine", "baseline.sealed", model.String(b, "id"), model.Document{"resource_id": res["id"], "source_hash": b["source_hash"], "canonical_hash": b["canonical_hash"]})
	return b, nil
}

func latestBaseline(ctx context.Context, t *store.Tx, resource string, fixture bool) (model.Document, error) {
	rows, e := t.EvidenceList(ctx, "baseline", resource)
	if e != nil {
		return nil, e
	}
	if len(rows) == 0 {
		return nil, errors.New("BASELINE_REQUIRED")
	}
	if fixture {
		org, e := t.Get(ctx, "org", t.Tenant)
		if e != nil {
			return nil, e
		}
		generation := model.String(org, "fixture_generation")
		if generation == "" {
			generation = "initial"
		}
		expected := "fixture-baseline-v2-" + generation
		for _, row := range rows {
			if model.String(row, "id") == expected {
				return row, nil
			}
		}
		return nil, errors.New("BASELINE_REQUIRED")
	}
	return rows[len(rows)-1], nil
}

// readiness re-evaluates persisted baseline evidence and current operational gates.
// A financial MEASURING result can still authorize the first supervised cycle.
func (a *API) readiness(ctx context.Context, t *store.Tx, resource string, seal bool) (model.Document, error) {
	res, e := t.Get(ctx, "resources", resource)
	if e != nil {
		return nil, e
	}
	now := a.now()
	d := model.Document{"id": model.ID(), "resource_id": resource, "tenant_id": t.Tenant, "workload_id": res["workload_id"], "status": "BLOCKED", "pre_execution_ready": false, "verification_status": "MEASURING", "reason_code": "BASELINE_REQUIRED", "checked_at": now.Format(time.RFC3339Nano), "expires_at": now.Add(5 * time.Minute).Format(time.RFC3339Nano), "baseline_id": nil, "measurement_id": nil, "activation_at": nil, "binding": evidence.Binding(t.Tenant, res, model.String(res, "currency")), "blockers": []string{}, "evidence_refs": []string{}}
	if !a.Config.Fixture {
		d["reason_code"] = "TRUSTED_SOURCE_REQUIRED"
		d["blockers"] = []string{"TRUSTED_SOURCE_REQUIRED", "TRUSTED_WORKLOAD_SOURCE_REQUIRED"}
		d["verification_status"] = "BLOCKED"
	}
	b, e := latestBaseline(ctx, t, resource, a.Config.Fixture)
	if e == nil {
		binding, _, sourceErr := sourceForBaseline(ctx, t, b, res, a.Config.Fixture)
		if sourceErr != nil {
			var p *Problem
			if errors.As(sourceErr, &p) {
				d["reason_code"] = p.Code
			} else {
				d["reason_code"] = sourceErr.Error()
			}
		} else {
			d["baseline_id"], d["binding"], d["activation_at"], d["evidence_refs"] = b["id"], binding, b["activation_at"], []string{model.String(b, "ingestion_job_id"), model.String(b, "source_hash"), model.String(b, "canonical_hash")}
			d["source_refs"] = b["source_refs"]
			result, err := a.economics(ctx, "v2/evaluate", baselineInput(b))
			if err != nil {
				return nil, err
			}
			d["economics"], d["verification_status"], d["reason_code"] = result, result["status"], result["reason_code"]
			if model.Bool(result, "pre_execution_ready") {
				w, err := t.Get(ctx, "workloads", model.String(res, "workload_id"))
				if err != nil {
					return nil, err
				}
				if model.String(b, "schema_version") == "3" {
					if trusted, err := trustedWorkload(ctx, t, res, w); err == nil {
						w = trusted
					}
				}
				p, err := t.Get(ctx, "policies", "policy-default")
				if err != nil {
					return nil, err
				}
				effective := model.Clone(res)
				effective["commitment_known"], effective["uncovered_on_demand"], effective["observation_days"] = true, true, 14
				blocked := safety.Eligibility(effective, w, p, now)
				org, orgErr := t.Get(ctx, "org", t.Tenant)
				if orgErr != nil {
					return nil, orgErr
				}
				if model.Bool(org, "paused") {
					blocked = append(blocked, "BLOCKED_AUTOPILOT_PAUSED")
				}
				if !a.Config.Fixture {
					if err := validateHealthURL(model.String(w, "health_url"), a.Config); err != nil {
						blocked = append(blocked, "LIVE_HTTPS_HEALTH_REQUIRED")
					}
				}
				d["blockers"] = blocked
				if model.String(b, "schema_version") == "3" {
					if err := trustedActivityGate(ctx, t, res, now); err != nil {
						blocked = append(blocked, err.Error())
					}
					d["blockers"] = blocked
					d["source_proof"], d["commitment_scope"] = b["source_proof"], b["commitment_scope"]
					if scope, err := currentSourceGate(ctx, t, model.String(b, "source_connection_id"), binding, now); err != nil {
						blocked = append(blocked, err.Error())
						d["blockers"] = blocked
					} else {
						d["commitment_scope"] = scope
					}
					if latest, err := t.ActivityLatest(ctx, resource); err == nil {
						d["activity_signal"] = activity.FreshActivity(now, latest, 2*time.Minute)
					}
					d["pricing_basis"] = result["pricing_basis"]
				}
				if len(blocked) == 0 {
					d["status"], d["pre_execution_ready"], d["reason_code"] = "READY", true, "BASELINE_READY"
				} else {
					d["reason_code"] = blocked[0]
				}
			}
		}
	}
	if seal {
		if model.Bool(d, "pre_execution_ready") {
			if model.String(b, "schema_version") == "3" {
				proof, err := sealProofSet(ctx, t, b, res, now)
				if err != nil {
					return nil, err
				}
				d["proof_set_id"] = proof["id"]
			}
			m, err := reserveMeasurement(ctx, t, model.String(d, "baseline_id"), resource, model.String(d, "activation_at"))
			if err != nil {
				return nil, err
			}
			d["measurement_id"] = m["id"]
		}
		return t.EvidenceCreate(ctx, "readiness", d)
	}
	prior, err := t.EvidenceList(ctx, "readiness", resource)
	if err != nil {
		return nil, err
	}
	if len(prior) > 0 {
		last := prior[len(prior)-1]
		if model.String(last, "baseline_id") == model.String(d, "baseline_id") {
			for _, k := range []string{"id", "checked_at", "expires_at", "measurement_id", "proof_set_id"} {
				d[k] = last[k]
			}
			checked, err := time.Parse(time.RFC3339Nano, model.String(last, "checked_at"))
			if err != nil || now.Sub(checked) > 5*time.Minute {
				d["pre_execution_ready"], d["status"], d["reason_code"] = false, "BLOCKED", "READINESS_EXPIRED"
			}
		}
	}
	return d, nil
}
func sourceForBaseline(ctx context.Context, t *store.Tx, b, res model.Document, fixture bool) (model.Document, []model.Document, error) {
	if !fixture && len(evidence.Object(b["financial_clock"])) > 0 {
		return nil, nil, errors.New("LIVE_LOGICAL_CLOCK_FORBIDDEN")
	}
	if model.String(b, "schema_version") == "3" {
		e := validateSnapshotSources(ctx, t, b, res)
		return evidence.Object(b["binding"]), evidence.Rows(b["billing_records"]), e
	}
	job, e := t.Get(ctx, "ingestion_jobs", model.String(b, "ingestion_job_id"))
	if e != nil {
		return nil, nil, e
	}
	if model.String(b, "schema_version") == "3" {
		if _, e = trustedJob(ctx, t, job, res); e != nil {
			return nil, nil, e
		}
	} else if e = trustedSource(job, fixture); e != nil {
		return nil, nil, e
	}
	binding, records, e := evidence.Source(job, res, t.Tenant)
	if e != nil {
		return nil, nil, e
	}
	if !evidence.SameBinding(binding, evidence.Object(b["binding"])) || evidence.Hash(job["raw"]) != model.String(b, "source_hash") || evidence.Hash(job["canonical"]) != model.String(b, "canonical_hash") {
		return nil, nil, errors.New("BASELINE_SOURCE_CHANGED")
	}
	return binding, records, nil
}

func reserveMeasurement(ctx context.Context, t *store.Tx, baseline, resource, activation string) (model.Document, error) {
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":measurement:"+baseline); e != nil {
		return nil, e
	}
	rows, e := t.EvidenceList(ctx, "measurement", resource)
	if e != nil {
		return nil, e
	}
	for _, r := range rows {
		if model.String(r, "baseline_id") == baseline {
			return r, nil
		}
	}
	b, e := t.EvidenceGet(ctx, "baseline", baseline)
	if e != nil {
		return nil, e
	}
	return t.EvidenceCreate(ctx, "measurement", model.Document{"baseline_id": baseline, "resource_id": resource, "binding": b["binding"], "activation_at": activation, "status": "MEASURING"})
}

func readinessPlanCheck(ctx context.Context, t *store.Tx, p model.Plan, res model.Document) error {
	if (p.SchemaVersion != "2" && p.SchemaVersion != "3") || (!p.Fixture && p.SchemaVersion != "3") || p.BaselineID == "" || p.MeasurementID == "" || p.ReadinessID == "" || p.ActivationAt == "" {
		return problem(422, "READINESS_V2_REQUIRED", "new stops require a sealed baseline and measurement contract")
	}
	b, e := t.EvidenceGet(ctx, "baseline", p.BaselineID)
	if e != nil {
		return e
	}
	if model.String(b, "schema_version") == "3" && (p.SchemaVersion != "3" || p.ProofSetID == "") {
		return problem(422, "PROOF_SET_REQUIRED", "version 3 baselines require an exact signed version 3 proof set")
	}
	if p.SchemaVersion == "3" && model.String(b, "schema_version") != "3" {
		return problem(422, "BASELINE_SCHEMA_MISMATCH", "version 3 plans cannot reference legacy baselines")
	}
	if _, _, e = sourceForBaseline(ctx, t, b, res, p.Fixture); e != nil {
		return evidenceProblem(e)
	}
	if !model.Bool(evidence.Object(b["evaluation"]), "pre_execution_ready") {
		return problem(422, "BASELINE_NOT_READY", "sealed baseline did not pass execution readiness")
	}
	ready, e := t.EvidenceGet(ctx, "readiness", p.ReadinessID)
	if e != nil {
		return e
	}
	if !model.Bool(ready, "pre_execution_ready") || model.String(ready, "baseline_id") != p.BaselineID || model.String(ready, "resource_id") != p.Operations[0].ResourceID {
		return problem(422, "READINESS_BINDING_INVALID", "readiness report differs from plan")
	}
	if p.SchemaVersion == "3" {
		if e = proofPlanCheck(ctx, t, p, b, res, ready); e != nil {
			return evidenceProblem(e)
		}
	}
	checked, err := time.Parse(time.RFC3339Nano, model.String(ready, "checked_at"))
	expires, expiryErr := time.Parse(time.RFC3339Nano, model.String(ready, "expires_at"))
	now := time.Now()
	if err != nil || expiryErr != nil || checked.After(now.Add(30*time.Second)) || now.Sub(checked) > 5*time.Minute || !now.Before(expires) {
		return problem(422, "READINESS_STALE", "new stops require a readiness report checked within five minutes")
	}
	m, e := t.EvidenceGet(ctx, "measurement", p.MeasurementID)
	if e != nil {
		return e
	}
	if model.String(m, "baseline_id") != p.BaselineID || model.String(m, "resource_id") != p.Operations[0].ResourceID || model.String(m, "activation_at") != p.ActivationAt || !evidence.SameBinding(evidence.Object(m["binding"]), evidence.Object(b["binding"])) {
		return problem(422, "MEASUREMENT_BINDING_INVALID", "measurement contract differs from plan")
	}
	// The schedule defining idle eligibility is part of the sealed baseline.
	schedule, e := t.Get(ctx, "schedules", p.ScheduleID)
	if e != nil {
		return e
	}
	old := evidence.Object(b["schedule"])
	for _, k := range []string{"timezone", "stop_time", "ready_time", "days"} {
		if evidence.Hash(schedule[k]) != evidence.Hash(old[k]) {
			return problem(422, "BASELINE_SCHEDULE_CHANGED", "new baseline required for changed idle windows")
		}
	}
	return nil
}

// A customer upload proves immutability, not AWS or workload-source authenticity.
// Live authorization awaits independently authenticated source collectors.
func trustedSource(job model.Document, fixture bool) error {
	if fixture && model.String(job, "source_provenance") == "DETERMINISTIC_FIXTURE" {
		return nil
	}
	return problem(422, "TRUSTED_SOURCE_REQUIRED", "customer imports are provisional; trusted provider and workload-source provenance is required")
}

func (a *API) readinessMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if len(parts) == 4 && parts[0] == "resources" && parts[2] == "readiness" && parts[3] == "refresh" {
		if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		d, e := a.readiness(ctx, t, parts[1], true)
		return d, 201, true, e
	}
	if len(parts) == 2 && parts[0] == "evidence" {
		if e := requireRole(i, "FINANCE", "FINOPS_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		switch parts[1] {
		case "baselines":
			d, e := a.createBaseline(ctx, t, in)
			return d, 201, true, e
		case "measurements":
			d, e := a.createMeasurement(ctx, t, in)
			return d, 201, true, e
		}
	}
	return nil, 0, false, nil
}
