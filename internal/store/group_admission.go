package store

import (
	"context"
	"errors"
)

var ErrGroupWorkloadBusy = errors.New("FLEET_WORKLOAD_MUTATION_PENDING")
var ErrGroupAdmissionUnavailable = errors.New("FLEET_GROUP_ADMISSION_UNAVAILABLE")

// GroupForwardAdmission serializes new R1/V4 actions with the group family's
// durable obligations. Call only after any resource/scheduling/execution locks,
// and before acquiring a provider receipt row. Owned restoration never calls it.
// A pre-group database cannot contain a group duty; an installed table without
// its admission function is an incomplete migration and fails closed.
func (t *Tx) GroupForwardAdmission(ctx context.Context, workload, family string) error {
	if workload == "" || len(workload) > 256 || (family != "R1" && family != "V4") {
		return ErrGroupAdmissionUnavailable
	}
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return err
	}
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":fleet-workload:"+workload); err != nil {
		return err
	}
	var installed, tablePresent bool
	if err := t.QueryRow(ctx, `SELECT to_regprocedure('public.fleet_group_admission(text,text,text,text)') IS NOT NULL,
 to_regclass('public.fleet_group_journal_reservations') IS NOT NULL`).Scan(&installed, &tablePresent); err != nil {
		return err
	}
	if installed != tablePresent {
		return ErrGroupAdmissionUnavailable
	}
	if !installed {
		return nil
	}
	var allowed bool
	if err := t.QueryRow(ctx, "SELECT public.fleet_group_admission($1,$2,$3,NULL)", t.Tenant, workload, family).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrGroupWorkloadBusy
	}
	return nil
}
