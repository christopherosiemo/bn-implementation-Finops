package service

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func fleetGroupAuthorityAccess(ctx context.Context, t *store.Tx, i auth.Identity, id string) (model.Document, error) {
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	d, err := t.FleetGroupAuthorityReview(ctx, id)
	if err == nil {
		err = fleetHistoryWorkload(ctx, t, i, model.String(d, "workload_id"))
	}
	return d, err
}

func (a *API) fleetGroupAuthorityGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(p) == 3 && p[0] == "fleet-fixture-proposals" && p[2] == "authorization-drafts" {
		if _, err := fleetFixtureAccess(ctx, t, i, p[1]); err != nil {
			return nil, true, err
		}
		after, limit, err := nativeCursor(r, i.Tenant, "fleet-group-authorizations", p[1])
		if err != nil {
			return nil, true, err
		}
		rows, err := t.FleetGroupAuthorityReviewPage(ctx, p[1], after, limit+1)
		return nativePage(rows, limit, i.Tenant, "fleet-group-authorizations", p[1]), true, err
	}
	if len(p) > 0 && p[0] == "fleet-group-authorizations" {
		if len(p) != 2 || p[1] == "" {
			return nil, true, problem(404, "NOT_FOUND", "route not found")
		}
		d, err := fleetGroupAuthorityAccess(ctx, t, i, p[1])
		return d, true, err
	}
	return nil, false, nil
}

func (a *API) fleetGroupAuthorityMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, p []string) (model.Document, int, bool, error) {
	if len(p) == 0 || p[0] != "fleet-group-authorizations" {
		return nil, 0, false, nil
	}
	if len(p) != 3 || p[1] == "" || p[2] != "approvals" {
		return nil, 0, true, problem(404, "NOT_FOUND", "route not found")
	}
	if err := requireRole(i, "APPROVER"); err != nil {
		return nil, 0, true, err
	}
	d, err := fleetGroupAuthorityAccess(ctx, t, i, p[1])
	if err != nil {
		return nil, 0, true, err
	}
	if err = match(r, d); err != nil {
		return nil, 0, true, err
	}
	if in == nil || len(in) != 0 {
		return nil, 0, true, problem(422, "FLEET_GROUP_APPROVAL_BODY_INVALID", "Approve the server-selected immutable body with an empty object.")
	}
	if model.String(d, "creator_id") == i.Subject {
		return nil, 0, true, problem(403, "FLEET_GROUP_INDEPENDENT_APPROVER_REQUIRED", "A different authenticated approver must review this authorization.")
	}
	if model.String(d, "status") != "AWAITING_APPROVAL" {
		return nil, 0, true, store.ErrConflict
	}
	_, err = t.FleetGroupJournalApproveAuthority(ctx, p[1], model.String(d, "authorization_sha256"), i.Subject)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && (pg.Code == "P0001" || pg.Code == "23505") || errors.Is(err, store.ErrGroupJournalConflict) || errors.Is(err, store.ErrGroupJournalInvalid) {
			return nil, 0, true, problem(409, "FLEET_GROUP_AUTHORIZATION_NOT_CURRENT", "The exact draft is no longer eligible for approval. Refresh its source bindings, review window and current journal state.")
		}
		return nil, 0, true, err
	}
	if err = t.Audit(ctx, i.Subject, "fleet.group_authorization_approved", p[1], model.Document{"kind": d["kind"], "authorization_sha256": d["authorization_sha256"], "proposal_id": d["proposal_id"], "customer_execution_authorized": false}); err != nil {
		return nil, 0, true, err
	}
	d, err = t.FleetGroupAuthorityReview(ctx, p[1])
	return d, http.StatusCreated, true, err
}
