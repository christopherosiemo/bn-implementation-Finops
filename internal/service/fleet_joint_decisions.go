package service

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func fleetJointDecisionRoute(p []string) bool {
	return len(p) == 3 && p[0] == "workloads" && p[2] == "fleet-joint-decisions" || len(p) > 0 && p[0] == "fleet-joint-decisions"
}
func (a *API) fleetJointDecisionGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !fleetJointDecisionRoute(p) {
		return nil, false, nil
	}
	if e := allocationRole(i, false); e != nil {
		return nil, true, e
	}
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, i.Tenant+":dependency-graph"); e != nil {
		return nil, true, e
	}
	if len(p) == 3 && p[0] == "workloads" {
		if e := fleetHistoryWorkload(ctx, t, i, p[1]); e != nil {
			return nil, true, e
		}
		after, limit, e := nativeCursor(r, i.Tenant, "fleet-joint-decisions", p[1])
		if e != nil {
			return nil, true, e
		}
		rows, e := t.FleetJointDecisionPage(ctx, p[1], after, limit+1)
		return nativePage(rows, limit, i.Tenant, "fleet-joint-decisions", p[1]), true, e
	}
	if len(p) != 2 {
		return nil, true, problem(404, "NOT_FOUND", "joint decision route not found")
	}
	d, e := t.FleetJointDecisionGet(ctx, p[1])
	if e == nil {
		e = fleetHistoryWorkload(ctx, t, i, model.String(d, "workload_id"))
	}
	return d, true, e
}
func (a *API) fleetJointDecisionMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, p []string) (model.Document, int, bool, error) {
	if !fleetJointDecisionRoute(p) {
		return nil, 0, false, nil
	}
	if e := allocationRole(i, true); e != nil {
		return nil, 0, true, e
	}
	if len(p) != 3 || p[0] != "workloads" {
		return nil, 0, true, problem(404, "NOT_FOUND", "joint decision route not found")
	}
	if len(in) != 2 || model.String(in, "assessment_request_id") == "" || model.String(in, "capacity_batch_request_id") == "" {
		return nil, 0, true, problem(422, "JOINT_DECISION_IDS_REQUIRED", "select an issued native assessment and capacity batch; observations and money are server resolved")
	}
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, i.Tenant+":dependency-graph"); e != nil {
		return nil, 0, true, e
	}
	if e := fleetHistoryWorkload(ctx, t, i, p[1]); e != nil {
		return nil, 0, true, e
	}
	latest, e := t.WorkloadSafetyLatest(ctx, p[1])
	if e != nil {
		return nil, 0, true, e
	}
	if e = match(r, latest); e != nil {
		return nil, 0, true, e
	}
	d, e := t.FleetJointDecisionCreate(ctx, p[1], i.Subject, model.String(in, "assessment_request_id"), model.String(in, "capacity_batch_request_id"), model.Number(latest, "version"))
	if e == nil {
		e = t.Audit(ctx, i.Subject, "fleet.joint_decision_requested", model.String(d, "id"), model.Document{"workload_id": p[1], "assessment_request_id": in["assessment_request_id"], "capacity_batch_request_id": in["capacity_batch_request_id"]})
	}
	if errors.Is(e, store.ErrFleetJointDecision) {
		e = problem(409, "JOINT_DECISION_INPUTS_CHANGED", "select complete assessments with the same current pair, profile, roster and native evidence; recompute changed inputs")
	}
	return d, http.StatusAccepted, true, fleetNativeAssessmentProblem(e)
}
