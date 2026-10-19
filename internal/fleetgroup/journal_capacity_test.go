package fleetgroup

import (
	"testing"
	"time"
)

func TestJournalLateAppliedRecoveryRemainsFactualAfterAllForwardExpiry(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.preparationRecovery()
	h.git()
	h.finalizeRecovery(h.recoveryBody())
	h.ready()
	h.intent()
	h.now = h.view.Authorization.Authorization.ExpiresAt.Add(time.Hour)
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.view, h.projection = v, p
	callback := h.applied()
	if len(h.projection.Stack) != 0 || len(h.projection.Consumed) != 1 {
		t.Fatal("late inverse outcome lost duty consumption")
	}
	h.mustAppend(JournalRecord{Kind: JournalApplied, Receipt: &callback})
	if len(h.projection.Stack) != 0 || len(h.projection.Consumed) != 1 {
		t.Fatal("late duplicate changed ownership")
	}
}

func TestJournalRecoveryOwnExpiryBlocksFreshReadyIntent(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.preparationRecovery()
	h.git()
	r := h.recoveryBody()
	r.ExpiresAt = h.now.Add(time.Minute)
	h.finalizeRecovery(r)
	h.now = h.now.Add(2 * time.Minute)
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.view, h.projection = v, p
	h.ready()
	c := h.projection.Pending.Command
	s := journalAtRevision(c.Before, c.Preparation.Revision)
	intent := h.receipt(JournalApplyIntent, s, s)
	if err = h.append(JournalRecord{Kind: JournalApplyIntent, Receipt: &intent}); err == nil || err.Error() != "JOURNAL_RECOVERY_LIFETIME_INVALID" {
		t.Fatalf("own expiry not checked: %v", err)
	}
}

func TestJournalFull26Forward25InverseFitsBoundedCompleteReplay(t *testing.T) {
	h := newJournalFixture(t)
	for sequence := uint64(1); sequence <= 26; sequence++ {
		h.forward(sequence)
	}
	if len(h.projection.Stack) != 25 {
		t.Fatal("full forward effect population")
	}
	for len(h.projection.Stack) > 0 {
		h.inverse()
	}
	if len(h.view.Records) != 306 || len(h.view.Records) > h.view.Authorization.Authorization.MaximumRecords || len(h.projection.Consumed) != 25 || h.projection.Current.Model != h.view.Authorization.Authorization.Base.Model || !h.projection.ForwardAborted {
		t.Fatal("full program journal was incomplete")
	}
	if _, err := VerifyJournal(h.view, h.keys, h.view.Head.Head.Ref, h.now); err != nil {
		t.Fatal(err)
	}
}
