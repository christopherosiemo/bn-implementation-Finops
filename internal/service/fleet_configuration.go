package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func fleetConfigurationRoute(parts []string) bool {
	return len(parts) >= 3 && parts[0] == "fleet-history-registrations" && (parts[2] == "configuration-authorities" || parts[2] == "configuration-proposals")
}

// These are immutable group declarations and blocked reviews. They do not
// borrow a member resource, enroll a pipeline or enter any execution workflow.
func (a *API) fleetConfigurationGet(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !fleetConfigurationRoute(parts) {
		return nil, false, nil
	}
	if len(parts) > 4 || parts[2] == "configuration-authorities" && len(parts) != 3 {
		return nil, true, problem(404, "NOT_FOUND", "route not found")
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":dependency-graph"); err != nil {
		return nil, true, err
	}
	if _, _, err := fleetHistoryRegistered(ctx, tx, identity, parts[1]); err != nil {
		return nil, true, err
	}
	if len(parts) == 4 {
		out, err := tx.FleetConfigurationProposalGet(ctx, parts[3])
		if err == nil && model.String(out, "registration_id") != parts[1] {
			return nil, true, problem(404, "NOT_FOUND", "proposal not found in this fleet registration")
		}
		return out, true, err
	}
	collection := "fleet-" + parts[2]
	after, limit, err := nativeCursor(r, identity.Tenant, collection, parts[1])
	if err != nil {
		return nil, true, err
	}
	var rows []model.Document
	if parts[2] == "configuration-proposals" {
		rows, err = tx.FleetConfigurationProposalPage(ctx, parts[1], after, limit+1)
		return nativePage(rows, limit, identity.Tenant, collection, parts[1]), true, err
	}
	latest, err := tx.FleetConfigurationLatest(ctx, parts[1])
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, true, err
	}
	rows, err = tx.FleetConfigurationPage(ctx, parts[1], after, limit+1)
	out := nativePage(rows, limit, identity.Tenant, collection, parts[1])
	out["version"], out["latest"] = model.Number(latest, "version"), latest
	return out, true, err
}

func fleetConfigurationError(err error) error {
	if errors.Is(err, store.ErrFleetConfigurationBinding) || errors.Is(err, store.ErrFleetHistorySource) {
		return problem(422, "FLEET_CONFIGURATION_CURRENT_BINDING_REQUIRED", "refresh the fleet registration, source and independent workload evidence before recording a new declaration or review")
	}
	if err != nil && (strings.HasPrefix(err.Error(), "FLEET_CONFIGURATION_") || strings.HasPrefix(err.Error(), "CONFIGURATION_")) {
		return problem(422, err.Error(), "provide fleet configuration metadata or existing declaration and scope identifiers; authoritative evidence and amounts are server-selected")
	}
	return err
}

func (a *API) fleetConfigurationMutate(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if !fleetConfigurationRoute(parts) {
		return nil, 0, false, nil
	}
	if len(parts) != 3 {
		return nil, 0, true, problem(404, "NOT_FOUND", "route not found")
	}
	if err := requireRole(identity, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":dependency-graph"); err != nil {
		return nil, 0, true, err
	}
	if _, _, err := fleetHistoryRegistered(ctx, tx, identity, parts[1]); err != nil {
		return nil, 0, true, err
	}
	latest, err := tx.FleetConfigurationLatest(ctx, parts[1])
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, true, err
	}
	if latest == nil {
		latest = model.Document{"version": int64(0)}
	}
	if err = match(r, latest); err != nil {
		return nil, 0, true, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, 0, true, err
	}
	var out model.Document
	if parts[2] == "configuration-authorities" {
		var metadata configuration.FleetDeclaration
		metadata, err = configuration.DecodeFleetDeclaration(raw)
		if err == nil {
			out, err = tx.FleetConfigurationAppend(ctx, parts[1], model.Number(latest, "version"), identity.Subject, metadata)
		}
	} else {
		var selected configuration.FleetProposalSelection
		selected, err = configuration.DecodeFleetProposalSelection(raw)
		if err == nil {
			out, err = tx.FleetConfigurationProposalCreate(ctx, parts[1], selected.DeclarationID, selected.ScopeID, model.Number(latest, "version"), identity.Subject)
		}
	}
	if err != nil {
		return nil, 0, true, fleetConfigurationError(err)
	}
	if err = tx.Audit(ctx, identity.Subject, "fleet.configuration_recorded", model.String(out, "id"), model.Document{"registration_id": parts[1], "collection": parts[2], "hash": out["hash"], "status": out["status"], "execution_authorized": false}); err != nil {
		return nil, 0, true, err
	}
	return out, http.StatusCreated, true, nil
}
