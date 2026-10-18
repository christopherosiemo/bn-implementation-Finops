package service

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// This long, opt-in protocol test retains the real default1h/15min policy.
// It does not invoke a cloud API or claim native transport/customer pipeline/
// public signing/financial acceptance. Every SLI/callback receive clock is real.
func TestFleetFullProgramRealClockControlledDrain(t *testing.T) {
	if os.Getenv("TEST_FLEET_FULL_PROGRAM") != "true" {
		t.Skip("explicit ~3h default-policy private protocol acceptance")
	}
	runFleetProgramRealClock(t, false)
}

func TestFleetFullProgramRealClockTestPolicy(t *testing.T) {
	if os.Getenv("TEST_FLEET_TEST_POLICY") != "true" {
		t.Skip("explicit ~75min120s signed TEST_POLICY protocol acceptance; no default-duration credit")
	}
	runFleetProgramRealClock(t, true)
}

func runFleetProgramRealClock(t *testing.T, testPolicy bool) {
	f := newFleetCohortProtocolFixture(t, 20)
	discovery := f.membership(nil, f.blue, []string{})
	var baseline model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		baseline, e = f.api.freezeFleetCohortBaseline(f.ctx, tx, f.binding, model.String(discovery, "id"))
		return e
	})
	parent := f.parentPolicy(baseline, false, true, testPolicy)
	execution := f.execution(parent)
	sequence := uint64(0)
	old, candidates, traffic := 20, 0, 0
	apply := func(stageIndex int, nextOld, nextCandidates, nextTraffic int) {
		sequence++
		impact := absFleetHealth(nextOld-old) + absFleetHealth(nextCandidates-candidates)
		child := f.child(parent, stageIndex, sequence, fleet.Transition{OldBefore: old, OldAfter: nextOld, CandidateBefore: candidates, CandidateAfter: nextCandidates, TrafficBefore: traffic, TrafficAfter: nextTraffic, InFlight: impact})
		command := f.apply(parent, child, execution, "APPLIED")
		old, candidates, traffic = nextOld, nextCandidates, nextTraffic
		stage := fleetChildObservationStage(parent.Plan.Stages[stageIndex], child.Plan)
		t.Logf("private protocol %s child=%d owned_APPLIED old=%d green=%d traffic=%d signed_observation_seconds=%d at=%s", stage.Kind, sequence, old, candidates, traffic, stage.MinimumObservationSeconds, time.Now().UTC().Format(time.RFC3339))
		f.waitProgramHealth(child, command, stage, f.blue[:old], f.green[:candidates])
	}
	apply(0, 20, 0, 0)
	for stageIndex := 1; stageIndex < 5; stageIndex++ {
		stage := parent.Plan.Stages[stageIndex]
		for candidates < stage.TargetCandidateCount {
			apply(stageIndex, old, min(candidates+2, stage.TargetCandidateCount), traffic)
		}
		apply(stageIndex, old, candidates, stage.TargetTrafficPercent)
	}
	for old > 0 {
		apply(5, max(0, old-2), candidates, traffic)
	}
	f.must("finops_worker", func(tx *store.Tx) error {
		d, e := tx.FleetExecutionFinish(f.ctx, model.String(execution, "id"), "COMPLETED")
		if e == nil && model.String(d, "status") != "COMPLETED" {
			return errors.New("truthful full bounded protocol did not complete")
		}
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		var n int
		if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2", f.tenant, execution["id"]).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return errors.New("full protocol completed with permanent failure")
		}
		return nil
	})
	t.Logf("private bounded protocol complete: %d owned children, old0/green20/traffic100; TEST_POLICY=%t; no runtime/financial/cloud acceptance claimed", sequence, testPolicy)
}

func absFleetHealth(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (f *fleetCohortProtocolFixture) waitProgramHealth(child fleet.ChildEnvelope, command model.Document, stage fleet.Stage, oldIDs, greenIDs []string) {
	f.t.Helper()
	var appliedAt time.Time
	f.must("finops_api", func(tx *store.Tx) error {
		owned, e := fleetHealthOne(f.ctx, tx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND id=$2", f.tenant, command["owned_receipt_id"])
		if e == nil {
			e = fleetHealthDecode(owned["received_at"], &appliedAt)
		}
		return e
	})
	start := fleetCeilMinute(appliedAt)
	end := start.Add(time.Duration(max(120, stage.MinimumObservationSeconds)) * time.Second)
	ids := append(append([]string{}, oldIDs...), greenIDs...)
	last := time.Time{}
	for {
		now := time.Now().UTC()
		minute := now.Truncate(time.Minute)
		if !minute.Equal(last) {
			f.observeMembers(minute, ids)
			f.membership(&child, oldIDs, greenIDs)
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
	// The native double retains every minute actually sampled while waiting.
	// Missing earlier minutes are rejected rather than synthesized at the end.
	for _, id := range ids {
		f.native(id, start, end)
	}
	var healthID string
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(command, "id"))
		if e != nil {
			return e
		}
		if model.String(d, "status") != "HEALTHY" {
			return errors.New("full signed program observation failed: " + model.String(d, "status"))
		}
		healthID = model.String(d, "id")
		return nil
	})
	f.must("finops_worker", func(tx *store.Tx) error {
		_, _, e := tx.FleetReservationRelease(f.ctx, model.String(command, "id"), healthID)
		return e
	})
}
