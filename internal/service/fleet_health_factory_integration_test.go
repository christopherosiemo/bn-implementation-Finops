package service

import (
	"errors"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func TestFleetPrivateFullWindowFactoriesUseRealAnchorsAndPermanentFailure(t *testing.T) {
	f := newFleetCohortProtocolFixture(t)
	discovery := f.membership(nil, f.blue, []string{})
	var baseline model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		baseline, e = f.api.freezeFleetCohortBaseline(f.ctx, tx, f.binding, model.String(discovery, "id"))
		return e
	})
	preparationParent := f.parent(baseline)
	preparation := f.child(preparationParent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	preparationCommand := f.apply(preparationParent, preparation, f.execution(preparationParent), "APPLIED")
	canaryParent := f.parent(baseline)
	canaryExecution := f.execution(canaryParent)
	prepared := f.child(canaryParent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	f.apply(canaryParent, prepared, canaryExecution, "NO_OP")
	canary := f.child(canaryParent, 1, 2, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	canaryCommand := f.apply(canaryParent, canary, canaryExecution, "APPLIED")
	var appliedAt time.Time
	f.must("finops_api", func(tx *store.Tx) error {
		owned, e := fleetHealthOne(f.ctx, tx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND id=$2", f.tenant, canaryCommand["owned_receipt_id"])
		if e == nil {
			e = fleetHealthDecode(owned["received_at"], &appliedAt)
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
			f.membership(&preparation, f.blue, []string{})
			f.membership(&canary, f.blue, f.green)
			last = minute
		}
		if now.After(end.Add(100 * time.Millisecond)) {
			break
		}
		sleep := time.Until(minute.Add(time.Minute).Add(100 * time.Millisecond))
		if sleep > 30*time.Second {
			sleep = 30 * time.Second
		}
		time.Sleep(sleep)
	}
	for _, command := range []model.Document{preparationCommand, canaryCommand} {
		var healthID string
		f.must("finops_api", func(tx *store.Tx) error {
			health, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(command, "id"))
			if e != nil {
				return e
			}
			if model.String(health, "status") != "HEALTHY" {
				return errors.New("actual full member window did not become healthy: " + model.String(health, "status") + " " + model.String(health, "reason_codes"))
			}
			healthID = model.String(health, "id")
			return nil
		})
		f.must("finops_worker", func(tx *store.Tx) error {
			_, _, e := tx.FleetReservationRelease(f.ctx, model.String(command, "id"), healthID)
			return e
		})
	}
	f.must("finops_worker", func(tx *store.Tx) error {
		d, e := tx.FleetCommand(f.ctx, model.String(canaryCommand, "id"))
		if e == nil && d["reservation_released_at"] == nil {
			return errors.New("accepted full physical health retained reservation")
		}
		return e
	})
	// A later lost historical authority is retained even if recovery later gets
	// fresh current sources. This is a protocol latch, not a Fleet financial
	// ledger implementation; V4 has no signed measurement contract or route.
	f.must("finops_api", func(tx *store.Tx) error {
		_, _, e := tx.TelemetryRevocationAppend(f.ctx, model.String(f.connections[f.blue[0]], "revision_id"), "protocol safety regression")
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(canaryCommand, "id"))
		if e == nil && model.String(d, "status") != "BLOCKED" {
			return errors.New("revoked frozen native source remained clear")
		}
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		var n int
		if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2", f.tenant, canaryExecution["id"]).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return errors.New("owned authority loss did not permanently latch")
		}
		_, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(canaryCommand, "id"))
		return e
	})
}
