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

func fleetNativeAssessmentRoute(p []string) bool {
	return len(p) == 3 && p[0] == "workloads" && p[2] == "fleet-native-assessments" || len(p) > 0 && p[0] == "fleet-native-assessments"
}
func fleetNativeAssessmentProblem(e error) error {
	if errors.Is(e, store.ErrFleetFixtureBusy) {
		return problem(409, "FLEET_NATIVE_SOURCE_BUSY", "a native source is being synchronized; retry the same request after synchronization")
	}
	if errors.Is(e, store.ErrFleetNativeCurrent) || errors.Is(e, store.ErrFleetNativeEvidence) {
		return problem(409, "FLEET_NATIVE_SELECTION_NOT_CURRENT", "select current group proposals and the current workload safety profile")
	}
	return e
}
func (a *API) fleetNativeAssessmentGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !fleetNativeAssessmentRoute(p) {
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
		after, limit, e := nativeCursor(r, i.Tenant, "fleet-native-assessments", p[1])
		if e != nil {
			return nil, true, e
		}
		rows, e := t.FleetNativeAssessmentPage(ctx, p[1], after, limit+1)
		if e == nil {
			for n := range rows {
				rows[n], e = a.fleetSelectionCurrentness(ctx, t, rows[n])
				if e != nil { return nil, true, e }
			}
		}
		return nativePage(rows, limit, i.Tenant, "fleet-native-assessments", p[1]), true, e
	}
	if len(p) != 2 {
		return nil, true, problem(404, "NOT_FOUND", "group assessment route not found")
	}
	d, e := t.FleetNativeAssessmentGet(ctx, p[1])
	if e == nil {
		e = fleetHistoryWorkload(ctx, t, i, model.String(d, "workload_id"))
	}
	if e == nil { d, e = a.fleetSelectionCurrentness(ctx, t, d) }
	return d, true, e
}
func (a *API) fleetNativeAssessmentMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, p []string) (model.Document, int, bool, error) {
	if !fleetNativeAssessmentRoute(p) {
		return nil, 0, false, nil
	}
	if e := allocationRole(i, true); e != nil {
		return nil, 0, true, e
	}
	if len(p) != 3 || p[0] != "workloads" {
		return nil, 0, true, problem(404, "NOT_FOUND", "group assessment mutation not found")
	}
	if len(in) != 2 || model.String(in, "old_configuration_proposal_id") == "" || model.String(in, "candidate_configuration_proposal_id") == "" {
		return nil, 0, true, problem(422, "FLEET_NATIVE_SELECTION_REQUIRED", "select two current configuration proposal IDs; evidence and monetary fields are server selected")
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
	out, e := t.FleetNativeAssessmentRequestCreate(ctx, p[1], i.Subject, model.String(in, "old_configuration_proposal_id"), model.String(in, "candidate_configuration_proposal_id"), model.Number(latest, "version"))
	if e == nil {
		e = t.Audit(ctx, i.Subject, "fleet.native_assessment_requested", model.String(out, "id"), model.Document{"workload_id": p[1], "old_configuration_proposal_id": in["old_configuration_proposal_id"], "candidate_configuration_proposal_id": in["candidate_configuration_proposal_id"]})
	}
	return out, http.StatusAccepted, true, fleetNativeAssessmentProblem(e)
}
