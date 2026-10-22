package service

import (
	"context"
	"errors"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// The SQL predicate shares the signing/dispatch authority and workload lock.
// Expected domain refusal becomes durable BLOCKED recovery evidence through
// buildFleetCohortHealth. SQL/transport failures retain their actual error.
func fleetForwardObservationAuthority(ctx context.Context, tx *store.Tx, parentID string) error {
	var available bool
	if err := tx.QueryRow(ctx, "SELECT fleet_forward_observation_available($1,$2)", tx.Tenant, parentID).Scan(&available); err != nil {
		return err
	}
	if !available {
		return errors.New("COHORT_FORWARD_AUTHORITY_EXPIRED_PAUSED_REVOKED_OR_EXHAUSTED")
	}
	return nil
}
