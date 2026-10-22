package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
)

func TestFleetHistoryPersistenceUsesDomainObservationIdentity(t *testing.T) {
	a := time.Date(2026, 10, 1, 11, 0, 0, 3, time.FixedZone("native-offset", 3600))
	b := a.Add(-time.Hour)
	o := fleethistory.MembershipObservation{ID: "native-point", ObservedAt: a, ReceivedAt: a.Add(time.Second), Source: fleethistory.SourceRef{CapturedAt: a}, Members: []fleethistory.Member{{InstanceID: "i-fffffffffffffffff", LaunchTime: &b}, {InstanceID: "i-00000000000000000", Hardware: &fleethistory.SourceRef{CapturedAt: a}}}}
	raw, hash, e := fleetHistoryObservationBytes(o)
	if e != nil {
		t.Fatal(e)
	}
	if hash != fleethistory.ObservationHash(o) {
		t.Fatal("stored identity differs from canonical domain observation")
	}
	o.Members[0], o.Members[1] = o.Members[1], o.Members[0]
	o.ObservedAt = o.ObservedAt.UTC()
	again, next, e := fleetHistoryObservationBytes(o)
	if e != nil || !bytes.Equal(raw, again) || hash != next {
		t.Fatal("native member ordering or UTC offset changed observation identity", e)
	}
	o.Members[0].LaunchTemplateVersion++
	_, changed, _ := fleetHistoryObservationBytes(o)
	if changed == hash {
		t.Fatal("changed native member value retained old identity")
	}
}
func TestFleetHistoryInternalPageSentinelBound(t *testing.T) {
	for _, n := range []int{1, 100, 101} {
		if _, e := fleetHistoryPageLimit(n); e != nil {
			t.Fatal("public page plus one sentinel must be accepted", n)
		}
	}
	for _, n := range []int{-1, 0, 102, 50000} {
		if _, e := fleetHistoryPageLimit(n); e == nil {
			t.Fatal("unbounded page accepted", n)
		}
	}
}

func TestFleetHistoryAggregateBudgetFailsBeforePopulationGrowth(t *testing.T) {
	b := &fleetHistoryBudget{}
	if e := b.add(fleetHistoryByteLimit - 1); e != nil {
		t.Fatal(e)
	}
	if e := b.add(2); e != ErrFleetHistoryBounds {
		t.Fatal("aggregate population overflow accepted", e)
	}
	if b.used != fleetHistoryByteLimit-1 {
		t.Fatal("refused allocation changed budget")
	}
	if e := b.add(1); e != nil {
		t.Fatal("exact bound refused", e)
	}
	for _, n := range []int64{1, -1, 1 << 62} {
		if e := b.add(n); e != ErrFleetHistoryBounds {
			t.Fatal("unbounded or invalid allocation accepted", n)
		}
	}
}
