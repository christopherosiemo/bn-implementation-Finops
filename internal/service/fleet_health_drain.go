package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// The final stateless drain has a natively observed empty old cohort. Its
// concurrent control cannot be invented: require the same execution's earlier
// accepted100%-traffic blue+green comparison and freeze exactly those green IDs.
func fleetPriorDrainControl(ctx context.Context, tx *store.Tx, command model.Document, child fleet.ChildPlan, objective slo.Objective, profile model.Document, greenIDs []string, now time.Time) (model.Document, error) {
	d, err := fleetHealthOne(ctx, tx, `SELECT w.document
 FROM fleet_cohort_windows w JOIN fleet_commands c ON c.tenant_id=w.tenant_id AND c.id=w.command_id
 JOIN fleet_children ch ON ch.tenant_id=c.tenant_id AND ch.id=c.child_id
 JOIN fleet_plans parent ON parent.tenant_id=c.tenant_id AND parent.id=c.parent_id
 JOIN fleet_command_states state ON state.tenant_id=c.tenant_id AND state.command_id=c.id
 JOIN fleet_reservations reservation ON reservation.tenant_id=c.tenant_id AND reservation.command_id=c.id
 JOIN fleet_callbacks callback ON callback.tenant_id=c.tenant_id AND callback.id=state.owned_receipt_id
 WHERE w.tenant_id=$1 AND c.execution_id=$2 AND (ch.document->'plan'->>'sequence')::numeric<$3
 AND w.mode='FORWARD' AND w.status='CLEAR' AND c.operation='APPLY'
 AND (ch.document->'plan'->'transition'->>'traffic_after')::integer=100
 AND (ch.document->'plan'->'transition'->>'old_after')::integer>0
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(parent.document->'stages') stage WHERE stage->>'id'=ch.document->'plan'->>'stage_id' AND stage->>'kind'='EXPAND_100')
 AND w.document->'comparison'->'full_window' IS NOT NULL
 AND reservation.released_at IS NOT NULL AND jsonb_array_length(callback.document->'old_instance_ids')>0
 AND (SELECT jsonb_agg(v ORDER BY v) FROM jsonb_array_elements_text(callback.document->'candidate_instance_ids') v)=$4::jsonb
 ORDER BY (ch.document->'plan'->>'sequence')::numeric DESC,w.created_at DESC LIMIT 1`, tx.Tenant, command["execution_id"], child.Sequence, evidenceFleetIDs(greenIDs))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, errors.New("COHORT_PRIOR_ACCEPTED_FULL_TRAFFIC_CONTROL_REQUIRED")
	}
	if model.String(d, "objective_id") != objective.ID || model.String(d, "objective_hash") != slo.ObjectiveHash(objective) || model.Number(d, "objective_version") != objective.Version || model.String(d, "safety_profile_id") != model.String(profile, "id") || model.String(d, "safety_profile_hash") != model.String(profile, "hash") {
		return nil, errors.New("COHORT_PRIOR_CONTROL_REQUIREMENTS_CHANGED")
	}
	var unresolved bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fleet_commands c
 JOIN fleet_children ch ON ch.tenant_id=c.tenant_id AND ch.id=c.child_id
 JOIN fleet_command_states state ON state.tenant_id=c.tenant_id AND state.command_id=c.id
 JOIN fleet_reservations reservation ON reservation.tenant_id=c.tenant_id AND reservation.command_id=c.id
 WHERE c.tenant_id=$1 AND c.execution_id=$2 AND (ch.document->'plan'->>'sequence')::numeric<$3
 AND (state.outcome NOT IN('APPLIED','NO_OP','DEFINITELY_NOT_APPLIED') OR state.dispatch_intent AND reservation.released_at IS NULL))
 OR EXISTS(SELECT 1 FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2)`, tx.Tenant, command["execution_id"], child.Sequence).Scan(&unresolved)
	if err != nil {
		return nil, err
	}
	if unresolved {
		return nil, errors.New("COHORT_PRIOR_CONTROL_UNRESOLVED_CHANGE_OR_FAILURE")
	}
	if _, err = fleetHealthMembership(ctx, tx, model.String(d, "membership_receipt_id"), child.Binding, now, 24*time.Hour); err != nil {
		return nil, err
	}
	for _, id := range model.Strings(d, "native_evaluation_ids") {
		native, e := tx.TelemetryEvaluation(ctx, id)
		if e != nil {
			return nil, e
		}
		active, e := fleetHealthNativeAuthority(ctx, tx, native)
		if e != nil {
			return nil, e
		}
		if !active {
			return nil, errors.New("COHORT_PRIOR_CONTROL_NATIVE_SOURCE_CHANGED")
		}
	}
	return d, nil
}

func evidenceFleetIDs(ids []string) string {
	raw, _ := json.Marshal(fleetHealthSorted(ids))
	return string(raw)
}
