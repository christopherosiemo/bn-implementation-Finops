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

func fleetCapacityRoute(p []string) bool {
	return len(p) == 3 && p[0] == "workloads" && p[2] == "fleet-native-capacity-batches" || len(p) > 0 && (p[0] == "fleet-native-capacity-batches" || p[0] == "fleet-native-capacity-members")
}
func fleetCapacityProblem(e error) error {
	if errors.Is(e, store.ErrFleetFixtureBusy) {
		return problem(409, "FLEET_CAPACITY_SOURCE_BUSY", "a selected source is synchronizing; retry the same request after synchronization")
	}
	if errors.Is(e, store.ErrFleetNativeCurrent) || errors.Is(e, store.ErrFleetCapacityEvidence) {
		return problem(409, "FLEET_CAPACITY_SELECTION_NOT_CURRENT", "select current group proposals and workload requirements")
	}
	return e
}
func (a *API) fleetCapacityGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !fleetCapacityRoute(p) {
		return nil, false, nil
	}
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, i.Tenant+":dependency-graph"); e != nil {
		return nil, true, e
	}
	if len(p) == 3 && p[0] == "workloads" {
		if e := fleetHistoryWorkload(ctx, t, i, p[1]); e != nil {
			return nil, true, e
		}
		after, limit, e := nativeCursor(r, i.Tenant, "fleet-native-capacity-batches", p[1])
		if e != nil {
			return nil, true, e
		}
		rows, e := t.FleetCapacityBatchPage(ctx, p[1], after, limit+1)
		if e == nil {
			for n := range rows {
				rows[n], e = a.fleetSelectionCurrentness(ctx, t, rows[n])
				if e != nil { return nil, true, e }
			}
		}
		return nativePage(rows, limit, i.Tenant, "fleet-native-capacity-batches", p[1]), true, e
	}
	if p[0] == "fleet-native-capacity-members" && len(p) == 2 {
		d, e := t.FleetCapacityBatchMemberGet(ctx, p[1])
		if e != nil {
			return nil, true, e
		}
		request, e := t.FleetCapacityBatchGet(ctx, model.String(d, "request_id"))
		if e == nil {
			e = fleetHistoryWorkload(ctx, t, i, model.String(request, "workload_id"))
		}
		if e == nil {
			request, e = a.fleetSelectionCurrentness(ctx, t, request)
			if e == nil { d = recommendationCurrentnessCopy(d, request) }
		}
		return d, true, e
	}
	if p[0] != "fleet-native-capacity-batches" || (len(p) != 2 && !(len(p) == 3 && p[2] == "members")) {
		return nil, true, problem(404, "NOT_FOUND", "fleet capacity route not found")
	}
	d, e := t.FleetCapacityBatchGet(ctx, p[1])
	if e != nil {
		return nil, true, e
	}
	if e = fleetHistoryWorkload(ctx, t, i, model.String(d, "workload_id")); e != nil {
		return nil, true, e
	}
	if len(p) == 2 {
		d, e = a.fleetSelectionCurrentness(ctx, t, d)
		return d, true, e
	}
	after, limit, e := nativeCursor(r, i.Tenant, "fleet-native-capacity-members", p[1])
	if e != nil {
		return nil, true, e
	}
	rows, e := t.FleetCapacityBatchMemberPage(ctx, p[1], after, limit+1)
	if e == nil {
		d, e = a.fleetSelectionCurrentness(ctx, t, d)
		if e == nil {
			for n := range rows { rows[n] = recommendationCurrentnessCopy(rows[n], d) }
		}
	}
	return nativePage(rows, limit, i.Tenant, "fleet-native-capacity-members", p[1]), true, e
}
func (a *API) fleetCapacityMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, p []string) (model.Document, int, bool, error) {
	if !fleetCapacityRoute(p) {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if len(p) != 3 || p[0] != "workloads" {
		return nil, 0, true, problem(404, "NOT_FOUND", "fleet capacity mutation not found")
	}
	var selected struct {
		Old       string `json:"old_configuration_proposal_id"`
		Candidate string `json:"candidate_configuration_proposal_id"`
	}
	if telemetryStrict(in, &selected) != nil || selected.Old == "" || selected.Candidate == "" {
		return nil, 0, true, problem(422, "FLEET_CAPACITY_SELECTION_REQUIRED", "select the original and candidate proposal IDs; observations, hardware and capacity are server selected")
	}
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, i.Tenant+":dependency-graph"); e != nil {
		return nil, 0, true, e
	}
	if e := fleetHistoryWorkload(ctx, t, i, p[1]); e != nil {
		return nil, 0, true, e
	}
	profile, e := t.WorkloadSafetyLatest(ctx, p[1])
	if e != nil {
		return nil, 0, true, e
	}
	if e = match(r, profile); e != nil {
		return nil, 0, true, e
	}
	d, e := t.FleetCapacityBatchRequestCreate(ctx, p[1], i.Subject, selected.Old, selected.Candidate, model.Number(profile, "version"))
	if e == nil {
		e = t.Audit(ctx, i.Subject, "fleet.native_capacity_batch_requested", model.String(d, "id"), model.Document{"workload_id": p[1], "old_configuration_proposal_id": selected.Old, "candidate_configuration_proposal_id": selected.Candidate})
	}
	return d, http.StatusAccepted, true, fleetCapacityProblem(e)
}
