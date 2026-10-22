package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func fleetFixtureRoute(parts []string) bool {
	return len(parts) > 0 && (parts[0] == "fleet-fixture-profiles" || parts[0] == "fleet-fixture-proposals")
}
func fleetFixtureProblem(e error) error {
	switch {
	case errors.Is(e, fleetfixture.ErrProgram):
		return problem(409, "PROGRAM_NOT_PREPARED", "A private fixture producer must prepare the exact program and Git manifest before independent approval.")
	case errors.Is(e, fleetfixture.ErrSelfApproval):
		return problem(403, "FLEET_FIXTURE_INDEPENDENT_APPROVER_REQUIRED", "The approver must be a different authenticated person from the proposal creator.")
	case errors.Is(e, store.ErrFleetFixtureBusy):
		return problem(503, "FLEET_FIXTURE_SOURCE_BUSY", "Source synchronization is in progress. Retry this same request after it completes.")
	case errors.Is(e, fleetfixture.ErrCurrent):
		return problem(422, "FLEET_FIXTURE_CURRENT_BINDING_REQUIRED", "Refresh both registered groups, declarations, sealed scopes and source bindings before preparing or approving a new program.")
	case e != nil && (strings.HasPrefix(e.Error(), "FLEET_FIXTURE_") || strings.HasPrefix(e.Error(), "GROUP_")):
		return problem(422, e.Error(), "Select current group proposals and the installed isolated fixture profile. Artifact and authority fields are private producer inputs.")
	}
	return e
}
func fleetFixtureAccess(ctx context.Context, t *store.Tx, i auth.Identity, id string) (model.Document, error) {
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":dependency-graph"); e != nil {
		return nil, e
	}
	d, e := t.FleetFixtureProposalGet(ctx, id)
	if e != nil {
		return nil, e
	}
	p, e := store.FleetFixtureProposalDocument(d)
	if e == nil {
		e = fleetHistoryWorkload(ctx, t, i, p.WorkloadID)
	}
	return d, e
}
func (a *API) fleetFixtureGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !fleetFixtureRoute(p) {
		return nil, false, nil
	}
	if p[0] == "fleet-fixture-profiles" {
		if len(p) != 1 {
			return nil, true, problem(404, "NOT_FOUND", "route not found")
		}
		after, limit, e := nativeCursor(r, i.Tenant, "fleet-fixture-profiles", "")
		if e != nil {
			return nil, true, e
		}
		rows, e := t.FleetFixtureProfilePage(ctx, after, limit+1)
		return nativePage(rows, limit, i.Tenant, "fleet-fixture-profiles", ""), true, e
	}
	if len(p) == 1 {
		workload := r.URL.Query().Get("workload_id")
		if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":dependency-graph"); e != nil {
			return nil, true, e
		}
		if e := fleetHistoryWorkload(ctx, t, i, workload); e != nil {
			return nil, true, e
		}
		after, limit, e := nativeCursor(r, i.Tenant, "fleet-fixture-proposals", workload)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.FleetFixtureProposalPage(ctx, workload, after, limit+1)
		return nativePage(rows, limit, i.Tenant, "fleet-fixture-proposals", workload), true, e
	}
	if len(p) > 3 {
		return nil, true, problem(404, "NOT_FOUND", "route not found")
	}
	d, e := fleetFixtureAccess(ctx, t, i, p[1])
	if e != nil {
		return nil, true, e
	}
	if len(p) == 2 {
		return d, true, nil
	}
	switch p[2] {
	case "prepared-program":
		out, e := t.FleetFixturePreparedProgramGet(ctx, p[1])
		return out, true, e
	case "readiness":
		return d["readiness"], true, nil
	case "runs":
		after, limit, e := nativeCursor(r, i.Tenant, "fleet-fixture-runs", p[1])
		if e != nil {
			return nil, true, e
		}
		rows, _, e := t.FleetFixtureRunPage(ctx, p[1], after, limit+1)
		out := nativePage(rows, limit, i.Tenant, "fleet-fixture-runs", p[1])
		out["status"], out["reason_codes"] = "UNAVAILABLE", []string{"FLEET_FIXTURE_RUNTIME_NOT_CONNECTED"}
		if len(rows) > 0 {
			out["status"], out["reason_codes"] = "OBSERVABLE", []string{"ISOLATED_FIXTURE", "CUSTOMER_EXECUTION_DISABLED"}
		}
		return out, true, e
	}
	return nil, true, problem(404, "NOT_FOUND", "route not found")
}
func (a *API) fleetFixtureMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if !fleetFixtureRoute(parts) {
		return nil, 0, false, nil
	}
	if parts[0] != "fleet-fixture-proposals" {
		return nil, 0, true, problem(404, "NOT_FOUND", "route not found")
	}
	var out model.Document
	var e error
	if len(parts) == 1 {
		if e = requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		if e = match(r, model.Document{"version": int64(0)}); e != nil {
			return nil, 0, true, e
		}
		raw, _ := json.Marshal(in)
		var selected fleetfixture.SelectionRequest
		selected, e = fleetfixture.DecodeSelection(raw)
		if e != nil {
			return nil, 0, true, fleetFixtureProblem(e)
		}
		// Authorize the real current workload before selecting source metadata.
		for _, id := range []string{selected.OldConfigurationProposalID, selected.CandidateConfigurationProposalID} {
			d, err := t.FleetConfigurationProposalGet(ctx, id)
			if err != nil {
				return nil, 0, true, err
			}
			if err = fleetHistoryWorkload(ctx, t, i, model.String(sourceObject(d["binding"]), "workload_id")); err != nil {
				return nil, 0, true, err
			}
		}
		out, e = t.FleetFixtureProposalCreate(ctx, i.Subject, selected)
	} else if len(parts) == 3 && (parts[2] == "approvals" || parts[2] == "runs") {
		if parts[2] == "approvals" {
			e = requireRole(i, "APPROVER")
		} else {
			e = requireRole(i, "PLATFORM_ADMIN")
		}
		if e != nil {
			return nil, 0, true, e
		}
		var current model.Document
		current, e = fleetFixtureAccess(ctx, t, i, parts[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, current); e != nil {
			return nil, 0, true, e
		}
		if in == nil || len(in) != 0 {
			return nil, 0, true, problem(422, "FLEET_FIXTURE_SELECTION_INVALID", "This operation accepts an empty object; identity, program and evidence are server-selected.")
		}
		if parts[2] == "runs" {
			return nil, 0, true, problem(503, "FLEET_FIXTURE_RUNTIME_NOT_CONNECTED", "The durable group fixture runtime is unavailable. No run or action was created.")
		}
		out, e = t.FleetFixtureApprove(ctx, parts[1], model.Number(current, "version"), i.Subject)
	} else {
		return nil, 0, true, problem(404, "NOT_FOUND", "route not found")
	}
	if e != nil {
		return nil, 0, true, fleetFixtureProblem(e)
	}
	if e = t.Audit(ctx, i.Subject, "fleet.fixture_recorded", model.String(out, "id"), model.Document{"status": out["status"], "proposal_hash": out["hash"], "customer_execution_authorized": false}); e != nil {
		return nil, 0, true, e
	}
	return out, http.StatusCreated, true, nil
}

func sourceObject(v any) model.Document {
	b, _ := json.Marshal(v)
	var d model.Document
	_ = json.Unmarshal(b, &d)
	return d
}
