package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func strictSLO(in model.Document, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return problem(422, "SLO_FIELDS_INVALID", "use the versioned objective or source contract")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return problem(422, "SLO_FIELDS_INVALID", "one versioned object required")
	}
	return nil
}

func sloObjectiveHistory(ctx context.Context, t *store.Tx, workload string) (model.Document, error) {
	if _, err := t.Get(ctx, "workloads", workload); err != nil {
		return nil, err
	}
	rows, err := t.SLOObjectives(ctx)
	if err != nil {
		return nil, err
	}
	history := []model.Document{}
	var latest model.Document
	var version int64
	for _, d := range rows {
		if model.String(d, "workload_id") == workload {
			history = append(history, d)
			if model.Number(d, "version") > version {
				latest, version = d, model.Number(d, "version")
			}
		}
	}
	return model.Document{"version": version, "latest": latest, "history": history}, nil
}

func (a *API) sloMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	isObjective := len(parts) == 3 && parts[0] == "workloads" && parts[2] == "slo-objectives"
	isSource := len(parts) == 1 && parts[0] == "slo-sources"
	if !isObjective && !isSource {
		return nil, 0, false, nil
	}
	if err := requireRole(i, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return nil, 0, true, err
	}
	if isObjective {
		for _, key := range []string{"schema_version", "limits", "evaluation_minutes", "availability", "regression"} {
			if v, ok := in[key]; !ok || v == nil {
				return nil, 0, true, problem(422, "SLO_FIELDS_REQUIRED", "every objective field must be explicitly supplied")
			}
		}
		for group, keys := range map[string][]string{"limits": {"max_error_rate_ppm", "min_availability_ppm", "max_p95_latency_ms", "max_p99_latency_ms", "min_latency_samples"}, "availability": {"mode", "timezone", "windows"}, "regression": {"enabled", "max_percent"}} {
			nested := evidence.Object(in[group])
			for _, key := range keys {
				if v, ok := nested[key]; !ok || v == nil {
					return nil, 0, true, problem(422, "SLO_FIELDS_REQUIRED", "objective limits and scope must be explicit")
				}
			}
		}
		for key := range in {
			if key != "schema_version" && key != "limits" && key != "evaluation_minutes" && key != "availability" && key != "regression" {
				return nil, 0, true, problem(422, "SLO_OBJECTIVE_FIELDS_INVALID", "objective identity and version are server selected")
			}
		}
		history, err := sloObjectiveHistory(ctx, t, parts[1])
		if err != nil {
			return nil, 0, true, err
		}
		if err = match(r, history); err != nil {
			return nil, 0, true, err
		}
		in = model.Clone(in)
		in["id"], in["workload_id"], in["version"] = model.ID(), parts[1], model.Number(history, "version")+1
		var typed slo.Objective
		if err = strictSLO(in, &typed); err != nil {
			return nil, 0, true, err
		}
		obj, err := slo.ParseObjective(in)
		if err != nil {
			return nil, 0, true, evidenceProblem(err)
		}
		doc := evidence.Object(obj)
		out, err := t.SLOObjectiveAppend(ctx, parts[1], model.Number(history, "version"), doc)
		if err == nil {
			err = t.Audit(ctx, i.Subject, "slo_objective.revised", parts[1], model.Document{"objective_id": out["id"], "version": out["version"], "hash": out["hash"]})
		}
		return out, 201, true, err
	}
	for key := range in {
		if key != "objective_id" && key != "resource_id" && key != "subject" {
			return nil, 0, true, problem(422, "SLO_SOURCE_FIELDS_INVALID", "resource, current objective and registered machine subject required")
		}
	}
	res, err := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if err != nil {
		return nil, 0, true, err
	}
	obj, err := t.SLOObjectiveLatest(ctx, model.String(res, "workload_id"))
	if err != nil {
		return nil, 0, true, err
	}
	if model.String(obj, "id") != model.String(in, "objective_id") {
		return nil, 0, true, problem(422, "SLO_OBJECTIVE_CHANGED", "register against the current workload objective")
	}
	source := slo.Source{ID: model.ID(), SchemaVersion: "1", ObjectiveID: model.String(obj, "id"), WorkloadID: model.String(res, "workload_id"), ResourceID: model.String(res, "id"), ProviderResourceID: model.String(res, "provider_resource_id"), AccountID: model.String(res, "account_id"), Region: model.String(res, "region"), Issuer: env("ACTIVITY_OIDC_ISSUER", a.Config.Issuer), Subject: model.String(in, "subject"), Enabled: true}
	out, err := t.SLORegister(ctx, source)
	if err == nil {
		err = t.Audit(ctx, i.Subject, "slo_source.registered", out.ID, model.Document{"resource_id": res["id"], "objective_id": obj["id"]})
	}
	return evidence.Object(out), 201, true, err
}

// currentSLO always selects observations server-side. Console input can define
// an objective, but cannot submit a current value, histogram or passing result.
func currentSLO(ctx context.Context, t *store.Tx, res model.Document, baseline *slo.Evaluation, capture bool, stop, ready time.Time) (model.Document, error) {
	d := model.Document{"resource_id": res["id"], "workload_id": res["workload_id"], "objective": nil, "source": nil, "evaluation": model.Document{"status": "BLOCKED", "reason_codes": []string{"SLO_OBJECTIVE_REQUIRED"}}}
	objDoc, err := t.SLOObjectiveLatest(ctx, model.String(res, "workload_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d["objective"] = objDoc
	obj, err := slo.ParseObjective(objDoc)
	if err != nil {
		return nil, err
	}
	sources, err := t.SLOSources(ctx)
	if err != nil {
		return nil, err
	}
	var source slo.Source
	for _, s := range sources {
		if s.ObjectiveID == model.String(objDoc, "id") && s.ResourceID == model.String(res, "id") {
			source = s
			break
		}
	}
	if source.ID == "" {
		d["evaluation"] = model.Document{"status": "BLOCKED", "reason_codes": []string{"SLO_SOURCE_REQUIRED"}}
		return d, nil
	}
	d["source"] = source
	if source.WorkloadID != model.String(res, "workload_id") || source.ProviderResourceID != model.String(res, "provider_resource_id") || source.AccountID != model.String(res, "account_id") || source.Region != model.String(res, "region") {
		d["evaluation"] = model.Document{"status": "BLOCKED", "reason_codes": []string{"SLO_SOURCE_BINDING_CHANGED"}}
		return d, nil
	}
	now := time.Now().UTC()
	end := now.Truncate(time.Minute)
	start := end.Add(-time.Duration(model.Number(objDoc, "evaluation_minutes")) * time.Minute)
	rows, err := t.SLOReceipts(ctx, model.String(res, "id"), model.String(objDoc, "id"), start, end)
	if err != nil {
		return nil, err
	}
	result := slo.Evaluate(slo.Input{Now: now, Objective: obj, Source: source, Receipts: rows, Baseline: baseline, CaptureBaseline: capture, StopAt: stop, RequiredReadyAt: ready})
	d["evaluation"] = result
	return d, nil
}

func sloReasons(state model.Document) []string {
	eval := evidence.Object(state["evaluation"])
	if model.String(eval, "status") == "CLEAR" {
		return nil
	}
	reasons := model.Strings(eval, "reason_codes")
	if len(reasons) == 0 {
		return []string{"SLO_EVIDENCE_REQUIRED"}
	}
	return reasons
}

func sloScheduleReasons(state, schedule model.Document, fixture bool) []string {
	obj, err := slo.ParseObjective(evidence.Object(state["objective"]))
	if err != nil {
		return []string{"SLO_OBJECTIVE_REQUIRED"}
	}
	var days []int
	b, _ := json.Marshal(schedule["days"])
	if json.Unmarshal(b, &days) != nil {
		return []string{"SLO_SCHEDULE_REQUIRED"}
	}
	stop, start, err := safety.NextWindow(time.Now(), model.String(schedule, "timezone"), model.String(schedule, "stop_time"), model.String(schedule, "ready_time"), days)
	if fixture {
		stop = time.Now()
		start = stop.Add(8 * time.Second)
	} else if err != nil {
		return []string{"SLO_SCHEDULE_REQUIRED"}
	}
	return slo.StopAllowed(obj, stop, start.Add(15*time.Minute))
}

func sealSLO(ctx context.Context, t *store.Tx, state model.Document) (model.Document, error) {
	obj := evidence.Object(state["objective"])
	source := evidence.Object(state["source"])
	d := model.Document{"resource_id": state["resource_id"], "workload_id": state["workload_id"], "objective_id": obj["id"], "objective_version": obj["version"], "objective_hash": obj["hash"], "source_id": source["id"], "evaluation": state["evaluation"]}
	return t.SLOEvaluationCreate(ctx, d)
}

func SLOPlanState(ctx context.Context, t *store.Tx, p model.Plan) (model.Document, error) {
	if len(p.Operations) != 2 {
		return nil, errors.New("SLO_PLAN_BINDING_INVALID")
	}
	if p.SLOObjectiveID == "" || p.SLOObjectiveVersion < 1 || p.SLOObjectiveHash == "" || p.SLOEvaluationID == "" || p.SLOEvaluationHash == "" {
		return nil, errors.New("SLO_AUTHORITY_REQUIRED")
	}
	res, err := t.Get(ctx, "resources", p.Operations[0].ResourceID)
	if err != nil {
		return nil, err
	}
	obj, err := t.SLOObjectiveLatest(ctx, p.WorkloadID)
	if err != nil {
		return nil, errors.New("SLO_OBJECTIVE_REQUIRED")
	}
	if model.String(obj, "id") != p.SLOObjectiveID || model.Number(obj, "version") != p.SLOObjectiveVersion || model.String(obj, "hash") != p.SLOObjectiveHash {
		return nil, errors.New("SLO_OBJECTIVE_CHANGED")
	}
	snapshot, err := t.SLOEvaluationGet(ctx, p.SLOEvaluationID)
	if err != nil {
		return nil, errors.New("SLO_EVALUATION_REQUIRED")
	}
	if model.String(snapshot, "writer_role") != "finops_api" || model.String(snapshot, "hash") != p.SLOEvaluationHash || model.String(snapshot, "objective_id") != p.SLOObjectiveID || model.String(snapshot, "objective_hash") != p.SLOObjectiveHash || model.String(snapshot, "resource_id") != p.Operations[0].ResourceID || model.String(snapshot, "workload_id") != p.WorkloadID {
		return nil, errors.New("SLO_EVALUATION_BINDING_INVALID")
	}
	baseline, err := slo.ParseEvaluation(evidence.Object(snapshot["evaluation"]))
	if err != nil {
		return nil, err
	}
	baseline.ID = p.SLOEvaluationID
	return currentSLO(ctx, t, res, &baseline, false, p.StopAt, p.RestoreAt.Add(15*time.Minute))
}

func SLOPlanReady(ctx context.Context, t *store.Tx, p model.Plan) error {
	state, err := SLOPlanState(ctx, t, p)
	if err != nil {
		return err
	}
	if reasons := sloReasons(state); len(reasons) > 0 {
		return errors.New(reasons[0])
	}
	return nil
}

// ObserveSLO can only record failures while the signed occurrence owns a stop.
// The immutable violation latches financial disqualification for the entire
// signed measurement; later good observations cannot erase a failed change.
func ObserveSLO(ctx context.Context, t *store.Tx, p model.Plan, executionID string) (string, error) {
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return "", err
	}
	if p.MeasurementID != "" {
		previous, err := t.SLOViolations(ctx, p.MeasurementID)
		if err != nil {
			return "", err
		}
		for _, v := range previous {
			if model.String(v, "execution_id") == executionID {
				return model.String(v, "reason_code"), nil
			}
		}
	}
	state, err := SLOPlanState(ctx, t, p)
	reason := ""
	if err != nil {
		reason = err.Error()
	} else if reasons := sloReasons(state); len(reasons) > 0 {
		reason = reasons[0]
	}
	if reason == "" {
		return "", nil
	}
	if !safeReasonCode(reason) {
		reason = "SLO_OBSERVATION_UNAVAILABLE"
	}
	return latchSLOFailure(ctx, t, p, executionID, reason, state)
}

func RecordSLOFailure(ctx context.Context, t *store.Tx, p model.Plan, executionID, reason string) error {
	if !safeReasonCode(reason) {
		reason = "SLO_OBSERVATION_UNAVAILABLE"
	}
	_, err := latchSLOFailure(ctx, t, p, executionID, reason, nil)
	return err
}

func latchSLOFailure(ctx context.Context, t *store.Tx, p model.Plan, executionID, reason string, state model.Document) (string, error) {
	if len(p.Operations) != 2 {
		return "SLO_PLAN_BINDING_INVALID", nil
	}
	if p.SLOObjectiveID == "" {
		return reason, nil
	} // migration restores without fabricating a historical breach
	var owned bool
	if err := t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2 AND stop_intent AND NOT restored)", t.Tenant, executionID).Scan(&owned); err != nil {
		return "", err
	}
	if !owned {
		return reason, nil
	}
	d := model.Document{"resource_id": p.Operations[0].ResourceID, "workload_id": p.WorkloadID, "objective_id": p.SLOObjectiveID, "objective_version": p.SLOObjectiveVersion, "objective_hash": p.SLOObjectiveHash, "baseline_evaluation_id": p.SLOEvaluationID, "baseline_evaluation_hash": p.SLOEvaluationHash, "reason_code": reason, "state": state}
	v, inserted, err := t.SLOViolationAppend(ctx, executionID, p.ID, p.MeasurementID, d)
	if err != nil {
		return "", err
	}
	if inserted {
		w, err := t.Get(ctx, "workloads", p.WorkloadID)
		if err != nil {
			return "", err
		}
		payload := model.Document{"execution_id": executionID, "resource_id": p.Operations[0].ResourceID, "workload_id": p.WorkloadID, "owner": w["owner"], "reason_code": reason, "violation_id": v["id"], "measurement_id": p.MeasurementID, "restoration_required": true, "savings_disqualified": true}
		if err = t.Audit(ctx, "slo-observer", "execution.slo_violation", executionID, payload); err != nil {
			return "", err
		}
		if err = t.Event(ctx, "execution.slo_violation", payload); err != nil {
			return "", err
		}
	}
	return reason, nil
}
