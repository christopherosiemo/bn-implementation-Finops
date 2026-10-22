package commitmentportfolio

import "time"

// PrepareDecisionSnapshot reconstructs the original immutable039 mapper input.
// Only the selected issued analysis supplies this private anchor, after the
// owner-defined SQL resolver authenticates current HEALTHY source/config and
// exact current inventory/CUR renewal separately. An old snapshot is not made
// fresh, and native/history/offer checks must continue using actualNow.
//
// Ordinary039 callers have no anchor and retain Prepare's existing semantics.
// This function cannot authenticate a resolved document or a historical body.
func PrepareDecisionSnapshot(r Resolved, actualNow time.Time) (Input, error) {
	if r.DecisionSnapshotObservedAt.IsZero() {
		return Prepare(r, actualNow)
	}
	if actualNow.IsZero() || r.DecisionSnapshotObservedAt.After(actualNow) {
		return Input{}, ErrEvidence
	}
	return Prepare(r, r.DecisionSnapshotObservedAt)
}
