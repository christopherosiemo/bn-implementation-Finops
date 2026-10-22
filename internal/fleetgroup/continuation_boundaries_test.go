package fleetgroup

import (
	"testing"
	"time"
)

func TestContinuationImmutableDraftReviewUsesFreshUnchangedZeroHead(t *testing.T) {
	h := newContinuationFixture(t)
	a := h.chain.Authorization
	original := a.BootstrapHead
	renew := func(at time.Time) {
		t.Helper()
		v, p, err := SealJournalView(h.old.view.Parent, h.old.view.Authorization, nil, h.old.keys, h.old.ledger, at)
		if err != nil {
			t.Fatal(err)
		}
		h.old.view, h.old.projection, h.old.now = v, p, at
		h.memory.cursor = ContinuationOriginalCursor(a.ChainID, v)
	}
	approve := func(at time.Time) []ContinuationApproval {
		return []ContinuationApproval{{"actual-delayed-review", h.old.view.Parent.Program.Binding.Old.Target.TenantID, "independent-human-reviewer", ApproverRole, Digest(a), at}}
	}
	// Human approval uses its actual later timestamp. The immutable draft's
	// original issued head is retained; no timestamp or base is rewritten.
	at := a.CreatedAt.Add(15 * time.Minute)
	renew(at)
	if Digest(original) == Digest(h.old.view.Head) {
		t.Fatal("unit did not renew zero head")
	}
	signed, err := SignContinuationAuthorization(h.ctx, a, approve(at), h.old.view, h.old.keys, h.memory, h.old.signer, at)
	if err != nil || signed.Authorization.BootstrapHead != original || signed.Approvals[0].ApprovedAt != at {
		t.Fatal("actual delayed review not retained", err)
	}
	if err = VerifyContinuationAuthorization(signed, ContinuationOrigin{h.old.view.Parent, h.old.view.Authorization}, h.old.keys, at.Add(24*time.Hour)); err != nil {
		t.Fatal("historical approval incorrectly expires recovery", err)
	}
	// Exactly thirty minutes is supported; a nanosecond beyond is a new draft,
	// not an extension obtained by refreshing only the ledger observation.
	at = a.CreatedAt.Add(ContinuationDraftReviewWindow)
	renew(at)
	if _, err = SignContinuationAuthorization(h.ctx, a, approve(at), h.old.view, h.old.keys, h.memory, h.old.signer, at); err != nil {
		t.Fatal("review boundary rejected", err)
	}
	at = at.Add(time.Nanosecond)
	renew(at)
	if _, err = SignContinuationAuthorization(h.ctx, a, approve(at), h.old.view, h.old.keys, h.memory, h.old.signer, at); err == nil {
		t.Fatal("renewed head extended draft review window")
	}
	// Even a freshly issued but different logical zero projection cannot replace
	// the approved body. A changed base/ref is not a head-lifetime renewal.
	at = a.CreatedAt.Add(time.Minute)
	renew(at)
	for _, change := range []func(*JournalView){
		func(v *JournalView) { v.Head.Head.ProjectionSHA256 = sha("f") },
		func(v *JournalView) { v.Head.Head.Ref.Version++ },
		func(v *JournalView) { v.Authorization.Authorization.Base.StateSHA256 = sha("e") },
		func(v *JournalView) { v.Head.Signature = "forged-current-head" },
	} {
		bad := continuationClone(h.old.view)
		change(&bad)
		h.memory.cursor = ContinuationOriginalCursor(a.ChainID, bad)
		if _, err = SignContinuationAuthorization(h.ctx, a, approve(at), bad, h.old.keys, h.memory, h.old.signer, at); err == nil {
			t.Fatal("changed current base/ref/head authorized draft")
		}
	}
	h.memory.cursor = ContinuationOriginalCursor(a.ChainID, h.old.view)
	h.old.prepare(1)
	h.memory.cursor = ContinuationOriginalCursor(a.ChainID, h.old.view)
	if _, err = SignContinuationAuthorization(h.ctx, a, approve(h.old.now), h.old.view, h.old.keys, h.memory, h.old.signer, h.old.now); err == nil {
		t.Fatal("command after draft allowed retroactive approval")
	}
}

func TestContinuationDraftReviewNeverRenewsOriginalForwardFeasibility(t *testing.T) {
	h := newContinuationFixture(t)
	p := h.old.view.Parent.Program
	for _, at := range []time.Time{GitForwardDeadline(p).Add(-time.Minute), p.ExpiresAt.Add(time.Second)} {
		// This is a labelled unit clock. It models a NEW late draft, not backdated
		// source/evidence, and does not change original forward expiration.
		v, _, err := SealJournalView(h.old.view.Parent, h.old.view.Authorization, nil, h.old.keys, h.old.ledger, at)
		if err != nil {
			t.Fatal(err)
		}
		a := h.chain.Authorization
		a.CreatedAt = at
		a.BootstrapHead = v.Head
		approvals := []ContinuationApproval{{"late-review", p.Binding.Old.Target.TenantID, "independent-human-reviewer", ApproverRole, Digest(a), at}}
		h.memory.cursor = ContinuationOriginalCursor(a.ChainID, v)
		if _, err = SignContinuationAuthorization(h.ctx, a, approvals, v, h.old.keys, h.memory, h.old.signer, at); err == nil {
			t.Fatal("review renewed exhausted original forward window")
		}
	}
}

func TestContinuationOriginalRepairIntentRequiresPositiveFenceBeforeReplacement(t *testing.T) {
	h := newContinuationFixture(t)
	old := h.old
	old.forward(1)
	old.forward(2)
	old.prepare(3)
	old.git()
	c := old.projection.Pending.Command
	old.issue(JournalNoApply, c.Before, journalAtRevision(c.Before, c.Preparation.Revision))
	p := old.view.Parent.Program
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, c.Before.Model)
	revision, _, _ := unitGitRevision(source, desired, c.Preparation.Revision.Commit, 40, "old repair append")
	repair := JournalGitRepair{JournalSchemaVersion, "old-unresolved-repair", c.ID, Digest(old.view.Authorization), Digest(old.view.Head), Digest(c.Preparation), Digest(*old.projection.Pending.NoApply), old.projection.Pending.NoApply.Receipt.After, revision, old.now, old.now.Add(time.Minute), "old-repair-nonce"}
	envelope, err := SignJournalGitRepair(repair, old.view, old.keys, old.view.Head.Head.Ref, old.signer, old.now)
	if err != nil {
		t.Fatal(err)
	}
	old.mustAppend(JournalRecord{Kind: JournalGitRepairIntent, GitRepair: &envelope})
	h.open()
	if h.p.OriginalPending == nil || h.p.OriginalPending.GitRepair == nil || h.p.GitDuty != nil {
		t.Fatal("old ambiguous repair lost")
	}
	if _, err = h.append(ContinuationRecord{Kind: ContinuationPreparing, Command: &ContinuationCommand{}}); err == nil {
		t.Fatal("ambiguous old repair allowed a new effect")
	}
	r := ContinuationReceipt{SchemaVersion: ContinuationSchemaVersion, ID: "positive-old-repair-fence", IdempotencyKey: "positive-old-repair-fence-key", ChainSHA256: Digest(h.chain), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, Kind: ContinuationLegacyRepairFenced, CommandSHA256: Digest(c), FinalizationSHA256: Digest(repair), Before: h.p.Current, After: h.p.Current, ReceivedAt: h.now}
	bad := r
	bad.FinalizationSHA256 = sha("f")
	wrong, _ := SignContinuationReceipt(bad, old.pipeline)
	if _, err = h.append(ContinuationRecord{Kind: ContinuationLegacyRepairFenced, Receipt: &wrong}); err == nil {
		t.Fatal("different old repair fence accepted")
	}
	proof, _ := SignContinuationReceipt(r, old.pipeline)
	h.must(ContinuationRecord{Kind: ContinuationLegacyRepairFenced, Receipt: &proof})
	if h.p.OriginalPending != nil || h.p.GitDuty == nil || len(h.p.Stack) != 1 {
		t.Fatal("fenced repair released native obligation")
	}
	h.prepare(ContinuationRepair)
	h.finalize()
	h.ready()
	h.intent()
	c2 := h.p.Pending.Command
	h.renew(h.now.Add(2 * time.Minute))
	if _, err = AuthorizeContinuationDispatch(h.ctx, h.view, old.keys, h.memory, Digest(c2), ContinuationRepair, h.now); err == nil {
		t.Fatal("renewed head refreshed stale Git repair")
	}
	h.issue(ContinuationRepaired, c2.Before, journalAtRevision(c2.Before, c2.Revision))
	h.rotate()
	h.prepare(ContinuationInverse)
	h.git()
	h.finalize()
	h.ready()
	h.intent()
	h.applied()
	if len(h.p.Stack) != 0 || len(h.p.Consumed) != 1 {
		t.Fatal("old repair prevented subsequent owned inverse")
	}
}

func TestContinuationApprovalMustPrecedeOriginalCommandTimes(t *testing.T) {
	h := newContinuationFixture(t)
	old := h.old
	a := h.chain.Authorization
	a.CreatedAt = a.CreatedAt.Add(2 * time.Second)
	approvals := []ContinuationApproval{{"later-independent-approval", old.view.Parent.Program.Binding.Old.Target.TenantID, "independent-chain-approver", ApproverRole, Digest(a), a.CreatedAt}}
	signed, err := SignContinuationAuthorization(h.ctx, a, approvals, old.view, old.keys, h.memory, old.signer, a.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	// Old accepted journal timestamps are preserved, not rewritten to manufacture
	// approval ordering. The continuation refuses this backdated reservation.
	old.forward(1)
	h.memory.cursor = ContinuationOriginalCursor(a.ChainID, old.view)
	if _, err = OpenContinuationFromJournal(h.ctx, old.view, signed, old.keys, h.memory, old.ledger, "late-approval-checkpoint", old.now); err == nil || err.Error() != "CONTINUATION_APPROVAL_BEFORE_FIRST_COMMAND_REQUIRED" {
		t.Fatal("approval ordering was inferred", err)
	}
}

func TestContinuationRejectsMissingAuthorityWrongKeysAndNonOutcomeReplay(t *testing.T) {
	h := newContinuationFixture(t)
	old := h.old
	old.forward(1)
	old.forward(2)
	h.open()
	if _, err := VerifyContinuation(h.ctx, h.view, old.keys, nil, h.now); err == nil {
		t.Fatal("missing server repository certified currentness")
	}
	keys := old.keys
	keys.Ledger = keys.Pipeline
	if _, err := VerifyContinuation(h.ctx, h.view, keys, h.memory, h.now); err == nil {
		t.Fatal("mixed signer/pipeline/ledger identity accepted")
	}
	// READY was issued historically but is not a terminal fact that may create
	// a new original dispatch after continuation. Even its exact replay is not
	// blessed under the original-outcome wrapper.
	var ready *JournalReceiptEnvelope
	for _, event := range old.view.Records {
		if event.Kind == JournalReadyToApply {
			ready = event.Receipt
			break
		}
	}
	if ready == nil {
		t.Fatal("missing unit readiness fixture")
	}
	if _, err := h.append(ContinuationRecord{Kind: ContinuationLegacy, OriginalReceipt: ready}); err == nil {
		t.Fatal("readiness replay accepted as terminal original outcome")
	}
}
