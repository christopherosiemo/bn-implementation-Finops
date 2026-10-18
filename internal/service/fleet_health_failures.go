package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Expected loss of authority after an owned apply is durable safety evidence,
// not a transient HTTP error which could disappear on the next healthy check.
// SQL/transport failures retain the original error and never invent a verdict.
func (a *API) buildFleetCohortHealth(ctx context.Context, tx *store.Tx, commandID string) (model.Document, error) {
	d, err := a.evaluateFleetCohortHealth(ctx, tx, commandID)
	if err == nil {
		return d, nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) || !(strings.HasPrefix(err.Error(), "COHORT_") || errors.Is(err, pgx.ErrNoRows)) {
		return nil, err
	}
	command, getErr := tx.FleetCommand(ctx, commandID)
	if getErr != nil || !model.Bool(command, "dispatch_intent") || model.String(command, "outcome") != "APPLIED" || model.String(command, "owned_receipt_id") == "" || model.Bool(command, "restored") {
		return nil, err
	}
	child, getErr := tx.FleetChild(ctx, model.String(command, "child_id"))
	if getErr != nil || child.Plan.Binding.TenantID != tx.Tenant || model.String(command, "child_sha256") != fleet.Digest(child.Plan) {
		return nil, err
	}
	mode := "FORWARD"
	if model.String(command, "operation") == "ROLLBACK" {
		mode = "OWNED_RECOVERY"
	}
	reason := err.Error()
	if errors.Is(err, pgx.ErrNoRows) {
		reason = "COHORT_REQUIRED_TRUSTED_EVIDENCE_UNAVAILABLE"
	}
	end := a.now().UTC().Truncate(time.Minute)
	empty := fleetHealthPopulation{MemberWindowIDs: []string{}, NativeIDs: []string{}, SLOIDs: []string{}}
	return a.persistFleetCohortHealth(ctx, tx, command, child.Plan, mode, "BLOCKED", []string{reason}, nil, nil, []string{}, empty, empty, end.Add(-2*time.Minute), end, model.Document{"authority_failure": reason}, true)
}
