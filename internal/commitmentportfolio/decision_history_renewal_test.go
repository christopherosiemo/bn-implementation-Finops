package commitmentportfolio

import (
	"encoding/json"
	"testing"
	"time"
)

// Typed reader component only. SQL must separately authenticate current source,
// exact month heads and native inventory equality before issuing this clock.
func TestDecisionHistoryRenewalPreservesOriginalSourceClock(t *testing.T) {
	fixture := newHistoryDouble(1)
	span := Period{Start: fixture.Training.Start, End: time.Date(fixture.Training.Start.Year(), fixture.Training.Start.Month()+1, 1, 0, 0, 0, 0, time.UTC)}
	chunk := fixture.resolved(span)
	original := fixture.Base.ObservedAt
	actualNow := original.Add(2 * time.Hour)
	if decisionHistorySource(&DecisionHistoryPins{}, chunk, actualNow) {
		t.Fatal("legacy source freshness was extended without authenticated snapshot")
	}
	if err := decisionHistoryRestoreSnapshot(&chunk, original, actualNow); err != nil {
		t.Fatal("issued original snapshot clock refused")
	}
	if !decisionHistorySource(&DecisionHistoryPins{}, chunk, actualNow) {
		t.Fatal("unchanged original source snapshot was restamped instead of reconstructed")
	}
	scope := fixture.Base.Scope
	scope.HistoryPeriod = span
	scope.SHA256 = ""
	scope.SHA256 = Hash(scope)
	usage, err := PrepareDecisionUsage(chunk, scope, actualNow)
	if err != nil || usage.Status != "COMPLETE_OBSERVED_ELIGIBLE_WINDOW" {
		t.Fatal("original actual usage could not be reconstructed after independent source renewal", err)
	}
	raw, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("snapshot wire invalid")
	}
	for _, key := range []string{"snapshot_observed_at", "DecisionSnapshotObservedAt", "decision_snapshot_observed_at"} {
		if _, exists := wire[key]; exists {
			t.Fatal("private authenticated clock became client input")
		}
	}
	chunk.DecisionSnapshotObservedAt = time.Time{}
	if decisionHistorySource(&DecisionHistoryPins{}, chunk, actualNow) {
		t.Fatal("zero snapshot changed old freshness behavior")
	}
}

func TestDecisionHistoryRenewalRejectsInvalidSnapshotClock(t *testing.T) {
	actual := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for _, snapshot := range []time.Time{{}, actual.Add(6 * time.Second), actual.In(time.FixedZone("foreign", 3600))} {
		chunk := Resolved{}
		if decisionHistoryRestoreSnapshot(&chunk, snapshot, actual) == nil || !chunk.DecisionSnapshotObservedAt.IsZero() {
			t.Fatal("unqualified snapshot clock admitted")
		}
	}
	if decisionHistoryRestoreSnapshot(nil, actual, actual) == nil {
		t.Fatal("nil snapshot admitted")
	}
}
