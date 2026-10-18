package service

import (
	"errors"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

func TestFleetOwnedRecoveryUsesFreshGreenZeroHealthAfterLegacyExpiryPauseAndRevocation(t *testing.T) {
	f := newFleetCohortProtocolFixture(t)
	parent := f.parent(nil, true)
	execution := f.execution(parent)
	prepared := f.child(parent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	f.apply(parent, prepared, execution, "NO_OP")
	original := f.child(parent, 1, 2, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	command := f.apply(parent, original, execution, "APPLIED")
	// No fabricated original healthy window: the changed frozen authority
	// creates a permanent failure, retaining uncertainty and owned recovery.
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(command, "id"))
		if e != nil {
			return e
		}
		if model.String(d, "status") != "BLOCKED" {
			return errors.New("legacy protocol parent gained forward authority without frozen baseline")
		}
		return nil
	})
	f.must("finops_api", func(tx *store.Tx) error {
		_, _, e := tx.TelemetryRevocationAppend(f.ctx, model.String(f.connections[f.blue[0]], "revision_id"), "old native source revoked")
		if e != nil {
			return e
		}
		if _, e = tx.FleetControlAppend(f.ctx, parent.Plan.ID, 0, "PAUSED", "private recovery acceptance"); e != nil {
			return e
		}
		_, e = tx.FleetControlAppend(f.ctx, parent.Plan.ID, 1, "REVOKED", "historical forward policy revoked")
		return e
	})
	// A new immutable objective/connection version is legitimate current health,
	// never a relabelled original forward evaluation or resurrected old source.
	f.installObjective()
	f.must("finops_api", func(tx *store.Tx) error {
		c, e := telemetry.ParseConnection(f.connections[f.blue[0]])
		if e != nil {
			return e
		}
		d, e := tx.TelemetryConnectionAppend(f.ctx, c.ID, c.Version, telemetry.Document(c))
		if e == nil {
			f.connections[f.blue[0]] = d
		}
		return e
	})
	recovery := f.recovery(parent, original)
	recoveryCommand := f.apply(parent, recovery, execution, "APPLIED")
	advanceProfile := func(cpuFree int64) {
		f.must("finops_api", func(tx *store.Tx) error {
			current, e := tx.WorkloadSafetyLatest(f.ctx, f.binding.WorkloadID)
			if e != nil {
				return e
			}
			var p workload.Profile
			if e = fleetHealthDecode(current, &p); e != nil {
				return e
			}
			// Reclassification after inverse APPLIED changes eligibility for new
			// actions, not the obligation to recognize a genuinely restored fleet.
			p.Statefulness, p.Headroom.CPUFreePPM = "STATEFUL", cpuFree
			_, e = tx.WorkloadSafetyAppend(f.ctx, f.binding.WorkloadID, p.Version, p)
			return e
		})
	}
	advanceProfile(300000)
	var appliedAt time.Time
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := fleetHealthOne(f.ctx, tx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND id=$2", f.tenant, recoveryCommand["owned_receipt_id"])
		if e == nil {
			e = fleetHealthDecode(d["received_at"], &appliedAt)
		}
		return e
	})
	end := fleetCeilMinute(appliedAt).Add(2 * time.Minute)
	last := time.Time{}
	for {
		now := time.Now().UTC()
		minute := now.Truncate(time.Minute)
		if !minute.Equal(last) {
			f.observe(minute)
			f.membership(&recovery, f.blue, []string{})
			last = minute
		}
		if now.After(end.Add(100 * time.Millisecond)) {
			break
		}
		delay := time.Until(minute.Add(time.Minute).Add(100 * time.Millisecond))
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		time.Sleep(delay)
	}
	if time.Now().UTC().Before(parent.Plan.ExpiresAt) {
		t.Fatal("compatibility test did not cross actual parent expiry")
	}
	var healthID string
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(recoveryCommand, "id"))
		if e != nil {
			return e
		}
		if model.String(d, "status") != "HEALTHY" || model.String(d, "mode") != "OWNED_RECOVERY" {
			return errors.New("fresh green-zero owned recovery health was blocked: " + model.String(d, "status"))
		}
		healthID = model.String(d, "id")
		return nil
	})
	advanceProfile(800000)
	if err := f.run("finops_worker", func(tx *store.Tx) error {
		_, _, e := tx.FleetReservationRelease(f.ctx, model.String(recoveryCommand, "id"), healthID)
		return e
	}); err == nil {
		t.Fatal("obsolete profile health released reservation after stricter requirements")
	}
	advanceProfile(300000)
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(recoveryCommand, "id"))
		if e != nil {
			return e
		}
		if model.String(d, "status") != "HEALTHY" {
			return errors.New("fresh current profile did not permit genuine owned recovery")
		}
		healthID = model.String(d, "id")
		return nil
	})
	f.must("finops_worker", func(tx *store.Tx) error {
		if _, _, e := tx.FleetReservationRelease(f.ctx, model.String(recoveryCommand, "id"), healthID); e != nil {
			return e
		}
		d, e := tx.FleetCommand(f.ctx, model.String(command, "id"))
		if e == nil && (!model.Bool(d, "restored") || d["reservation_released_at"] == nil) {
			return errors.New("owned inverse did not release retained original reservation")
		}
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		var n int
		if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2 AND document->>'positive_savings_eligible'='false'", f.tenant, execution["id"]).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return errors.New("good owned recovery erased permanent execution failure")
		}
		d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(command, "id"))
		if e == nil && model.String(d, "status") != "BLOCKED" {
			return errors.New("restored owned execution revived forward health")
		}
		return e
	})
	for _, role := range []string{"finops_api", "finops_worker"} {
		for _, statement := range []string{"UPDATE fleet_cohort_failures SET document='{}'", "DELETE FROM fleet_cohort_failures"} {
			if e := f.run(role, func(tx *store.Tx) error { _, e := tx.Exec(f.ctx, statement); return e }); e == nil {
				t.Fatal("permanent failure history was mutable", role)
			}
		}
	}
}
