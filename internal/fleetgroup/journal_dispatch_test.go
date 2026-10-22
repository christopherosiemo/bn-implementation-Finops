package fleetgroup

import (
	"testing"
	"time"
)

func (h *journalFixture) renewHead(at time.Time) {
	h.t.Helper()
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, at)
	if err != nil {
		h.t.Fatal(err)
	}
	h.now, h.view, h.projection = at, v, p
}

func TestJournalDispatchIntentCannotBeRenewedByCurrentHead(t *testing.T) {
	h := newJournalFixture(t)
	h.prepare(1)
	h.git()
	h.finalizeForward()
	h.ready()
	h.intent()
	c := h.projection.Pending.Command
	permit, err := AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now)
	if err != nil || permit.CommandSHA256 != Digest(c) || permit.OperationID != c.OperationID || permit.Fence != c.Fence || !permit.ValidUntil.After(h.now) || permit.ValidUntil.After(h.projection.Pending.ReadyUntil) {
		t.Fatal("fresh exact delivery refused", err)
	}
	if _, err = AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, sha("f"), h.now); err == nil {
		t.Fatal("stale command accepted")
	}
	wrong := h.view.Head.Head.Ref
	wrong.Version++
	if _, err = AuthorizeJournalApply(h.view, h.keys, wrong, Digest(c), h.now); err == nil {
		t.Fatal("caller head accepted")
	}
	h.renewHead(h.now.Add(31 * time.Second))
	if _, err = AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("renewed head revived intent")
	}
	// A delayed authenticated terminal fact is still required/recordable; expiry
	// never changes UNKNOWN to NOT_DISPATCHED or erases its owned obligation.
	h.issue(JournalUnknown, c.Before, c.Before)
	if _, err = AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("UNKNOWN redispatch accepted")
	}
	h.applied()
	if h.projection.Pending != nil {
		t.Fatal("late factual callback lost")
	}
}

func TestJournalDispatchRecoverySurvivesParentButNotOwnExpiry(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.renewHead(h.view.Authorization.Authorization.ExpiresAt.Add(time.Hour))
	h.preparationRecovery()
	h.git()
	r := h.recoveryBody()
	r.ExpiresAt = h.now.Add(15 * time.Second)
	h.finalizeRecovery(r)
	h.ready()
	h.intent()
	c := h.projection.Pending.Command
	permit, err := AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now)
	if err != nil || permit.ValidUntil.After(r.ExpiresAt) {
		t.Fatal("owned recovery borrowed parent lifetime or exceeded own", err)
	}
	h.renewHead(r.ExpiresAt)
	if _, err = AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil || err.Error() != "JOURNAL_RECOVERY_LIFETIME_INVALID" {
		t.Fatal("own expiry ignored at actual dispatch", err)
	}
	h.applied()
	if len(h.projection.Stack) != 0 {
		t.Fatal("late recovery fact could not consume duty")
	}
}

func TestJournalDispatchPermitCapsHeadAndEvidenceAge(t *testing.T) {
	h := newJournalFixture(t)
	h.renewHead(h.now.Add(5 * time.Minute))
	h.prepare(1)
	h.git()
	c := h.projection.Pending.Command
	child := gitChildFixture(h.view.Parent.Program, h.now, 1)
	child.Artifact.BeforeStateSHA256 = c.Before.StateSHA256
	child.Artifact.BeforeStateSerial = c.Before.StateSerial
	child.CreatedAt = h.now.Add(-4*time.Minute - 50*time.Second)
	for i := range child.Evidence {
		child.Evidence[i].ObservedAt = child.CreatedAt
	}
	signed, err := SignGitChild(child, h.view.Parent, h.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	c.Forward = &signed
	h.mustAppend(JournalRecord{Kind: JournalReserved, Command: &c})
	h.ready()
	h.intent()
	permit, err := AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now)
	if err != nil || permit.ValidUntil.After(child.CreatedAt.Add(5*time.Minute)) {
		t.Fatal("permit extended native proof age", err)
	}
	// The current ledger head may have a shorter lifetime than the intent.
	v := h.view
	v.Head.Head.ValidUntil = h.now.Add(time.Second)
	v.Head.Signature = journalSignature(journalHeadDomain, v.Head.Head, h.ledger)
	permit, err = AuthorizeJournalApply(v, h.keys, v.Head.Head.Ref, Digest(c), h.now)
	if err != nil || permit.ValidUntil != v.Head.Head.ValidUntil {
		t.Fatal("permit extended current head", err)
	}
}

func TestJournalGitRepairDispatchAgeAndLateFact(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.prepare(2)
	h.git()
	c := h.projection.Pending.Command
	h.issue(JournalNoApply, c.Before, journalAtRevision(c.Before, c.Preparation.Revision))
	source, _ := GitFixtureConfiguration(h.view.Parent.Program)
	desired, _ := GitFixtureDesired(h.view.Parent.Program, c.Before.Model)
	rev, _, _ := unitGitRevision(source, desired, c.Preparation.Revision.Commit, 40, "new repair")
	r := JournalGitRepair{JournalSchemaVersion, "repair-dispatch", c.ID, Digest(h.view.Authorization), Digest(h.view.Head), Digest(c.Preparation), Digest(*h.projection.Pending.NoApply), h.projection.Pending.NoApply.Receipt.After, rev, h.now, h.now.Add(10 * time.Minute), "repair-dispatch-nonce"}
	signed, err := SignJournalGitRepair(r, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.mustAppend(JournalRecord{Kind: JournalGitRepairIntent, GitRepair: &signed})
	if _, err = AuthorizeJournalGitRepair(h.view, h.keys, h.view.Head.Head.Ref, Digest(r), h.now); err != nil {
		t.Fatal(err)
	}
	if _, err = AuthorizeJournalGitRepair(h.view, h.keys, h.view.Head.Head.Ref, sha("f"), h.now); err == nil {
		t.Fatal("wrong repair body accepted")
	}
	if _, err = AuthorizeJournalApply(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("Git-only repair authorized Terraform")
	}
	h.renewHead(h.now.Add(31 * time.Second))
	if _, err = AuthorizeJournalGitRepair(h.view, h.keys, h.view.Head.Head.Ref, Digest(r), h.now); err == nil {
		t.Fatal("renewed head revived repair CAS intent")
	}
	h.issue(JournalGitRepaired, r.Before, journalAtRevision(c.Before, rev))
	if !h.projection.ForwardAborted || h.projection.Pending != nil {
		t.Fatal("late Git fact lost")
	}
}

func TestJournalEveryHistoricalCheckpointRemainsVerifiedInOneReplay(t *testing.T) {
	h := newJournalFixture(t)
	last := h.forward(1)
	// Exact receipt replay takes an early reducer continue, but its issued head
	// and the final independently resolved anchor must still be verified.
	h.mustAppend(JournalRecord{Kind: JournalApplied, Receipt: &last})
	p, err := VerifyJournalCheckpoints(h.view, h.checkpoints, h.keys, h.view.Head.Head.Ref, h.now)
	if err != nil || Digest(p) != Digest(h.projection) {
		t.Fatal("checkpoint replay differs", err)
	}
	for _, index := range []int{0, 1, len(h.checkpoints) - 1} {
		bad := append([]JournalHeadEnvelope{}, h.checkpoints...)
		bad[index].Head.ProjectionSHA256 = sha("f")
		bad[index].Signature = journalSignature(journalHeadDomain, bad[index].Head, h.ledger)
		if _, err = VerifyJournalCheckpoints(h.view, bad, h.keys, h.view.Head.Head.Ref, h.now); err == nil {
			t.Fatalf("re-signed false prefix %d accepted", index)
		}
	}
	bad := append([]JournalHeadEnvelope{}, h.checkpoints...)
	bad[1], bad[2] = bad[2], bad[1]
	if _, err = VerifyJournalCheckpoints(h.view, bad, h.keys, h.view.Head.Head.Ref, h.now); err == nil {
		t.Fatal("reordered checkpoints accepted")
	}
	if _, err = VerifyJournalCheckpoints(h.view, h.checkpoints[:len(h.checkpoints)-1], h.keys, h.view.Head.Head.Ref, h.now); err == nil {
		t.Fatal("omitted checkpoint accepted")
	}
	stale := h.view.Head.Head.Ref
	stale.Version--
	if _, err = VerifyJournalCheckpoints(h.view, h.checkpoints, h.keys, stale, h.now); err == nil {
		t.Fatal("historical checkpoints substituted current anchor")
	}
}

func TestJournalGitAdvanceNeedsCurrentUnexpiredPreparation(t *testing.T) {
	h := newJournalFixture(t)
	h.prepare(1)
	c := h.projection.Pending.Command
	permit, err := AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now)
	if err != nil || permit.ArtifactSHA256 != Digest(c.Preparation) || permit.CommandSHA256 != Digest(c) || !permit.ValidUntil.After(h.now) {
		t.Fatal("fresh preparation refused", err)
	}
	if _, err = AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, sha("f"), h.now); err == nil {
		t.Fatal("stale command accepted for CAS")
	}
	unknown := h.receipt(JournalUnknown, c.Before, c.Before)
	h.mustAppend(JournalRecord{Kind: JournalUnknown, Receipt: &unknown})
	if _, err = AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("UNKNOWN allowed new Git CAS")
	}
	// A fresh ledger seal cannot turn a historical reservation into new work.
	h.renewHead(h.view.Authorization.Authorization.ExpiresAt)
	if _, err = AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("expired UNKNOWN revived")
	}
	// Exercise plain PREPARING, not only UNKNOWN, across the forward deadline.
	h = newJournalFixture(t)
	deadline := GitForwardDeadline(h.view.Parent.Program)
	h.renewHead(deadline.Add(-2 * time.Second))
	h.prepare(1)
	c = h.projection.Pending.Command
	h.renewHead(deadline)
	if _, err = AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("expired forward CAS authorized by renewed head")
	}
	if h.projection.Pending.Phase != JournalPreparing || h.projection.Pending.GitAdvanced {
		t.Fatal("failed permit altered obligation")
	}
}

func TestJournalGitAdvanceOwnedRecoveryOutlivesParentWithFreshTop(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.renewHead(h.view.Authorization.Authorization.ExpiresAt.Add(time.Hour))
	h.preparationRecovery()
	c := h.projection.Pending.Command
	if _, err := AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err != nil {
		t.Fatal("owned recovery borrowed expired parent lifetime", err)
	}
	h.renewHead(c.CreatedAt.Add(5 * time.Minute))
	if _, err := AuthorizeJournalGitAdvance(h.view, h.keys, h.view.Head.Head.Ref, Digest(c), h.now); err == nil {
		t.Fatal("renewed head revived stale recovery preparation")
	}
}
