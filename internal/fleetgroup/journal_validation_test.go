package fleetgroup

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func TestJournalCachedForwardChecksMatchFrozenFiveOne(t *testing.T) {
	p, now, _, _ := gitProgramFixture(t)
	pub, key := keyFixture()
	parent, err := SignGitProgram(p, gitApprovalsFixture(p, now), key, now)
	if err != nil {
		t.Fatal(err)
	}
	c := gitChildFixture(p, now, 2)
	signed, err := SignGitChild(c, parent, key, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-6 * time.Second), now, now.Add(4 * time.Minute), now.Add(6 * time.Minute), now.Add(10 * time.Minute), GitForwardDeadline(p), p.ExpiresAt.Add(time.Second)} {
		want := VerifyGitChild(signed, parent, pub, Expected{p.Binding, p.Realm}, at)
		got := verifyJournalForwardCached(signed, parent, pub, at)
		if (want == nil) != (got == nil) {
			t.Fatalf("time parity %s old=%v cached=%v", at, want, got)
		}
	}
	for name, mutate := range map[string]func(*GitChild){"schema": func(c *GitChild) { c.SchemaVersion = "5" }, "entry": func(c *GitChild) { c.Artifact.ManifestEntrySHA256 = sha("f") }, "nonce": func(c *GitChild) { c.Nonce = p.Nonce }, "stage": func(c *GitChild) { c.StageSHA256 = sha("f") }, "evidence": func(c *GitChild) {
		c.Evidence = append([]EvidenceRef{}, c.Evidence...)
		c.Evidence[0].ObservedAt = now.Add(-6 * time.Minute)
	}, "expiry": func(c *GitChild) { c.ExpiresAt = now }, "recovery": func(c *GitChild) { c.Mode = OwnedRecovery }} {
		t.Run(name, func(t *testing.T) {
			x := c
			mutate(&x)
			e := GitChildEnvelope{x, gitChildAlgorithm, journalSignature(gitChildDomain, x, key)}
			want := VerifyGitChild(e, parent, pub, Expected{p.Binding, p.Realm}, now)
			got := verifyJournalForwardCached(e, parent, pub, now)
			if (want == nil) != (got == nil) {
				t.Fatalf("old=%v cached=%v", want, got)
			}
		})
	}
}

func TestJournalDistinctKeysCrossTenantAndWrongIssuerFail(t *testing.T) {
	h := newJournalFixture(t)
	bad := h.keys
	bad.Pipeline = bad.Ledger
	if VerifyJournalAuthorization(h.view.Authorization, h.view.Parent, bad, h.now) == nil {
		t.Fatal("same pipeline/ledger key allowed")
	}
	bad = h.keys
	bad.Signer = bad.Pipeline
	if VerifyJournalAuthorization(h.view.Authorization, h.view.Parent, bad, h.now) == nil {
		t.Fatal("signer identity collapsed")
	}
	parent := h.view.Parent
	parent.Program.Binding.Old.Target.TenantID = "foreign"
	if VerifyJournalAuthorization(h.view.Authorization, parent, h.keys, h.now) == nil {
		t.Fatal("cross tenant source reused")
	}
	h.prepare(1)
	c := h.projection.Pending.Command
	r := h.receipt(JournalUnknown, c.Before, c.Before)
	r, _ = SignJournalReceipt(r.Receipt, h.signer)
	if h.append(JournalRecord{Kind: JournalUnknown, Receipt: &r}) == nil {
		t.Fatal("central signer impersonated pipeline")
	}
	v := h.view
	v.Head.Signature = journalSignature(journalHeadDomain, v.Head.Head, h.pipeline)
	if _, err := VerifyJournal(v, h.keys, h.view.Head.Head.Ref, h.now); err == nil {
		t.Fatal("pipeline impersonated current store")
	}
	var wrong ed25519.PublicKey = make([]byte, 32)
	bad = h.keys
	bad.Pipeline = wrong
	if _, err := VerifyJournal(h.view, bad, h.view.Head.Head.Ref, h.now); err == nil {
		t.Fatal("caller key registry override accepted")
	}
}

func TestJournalRecoveryUsesIndependentNativeSemanticValidator(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.forward(3)
	h.preparationRecovery()
	h.git()
	r := h.recoveryBody()
	p := h.view.Parent.Program
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, r.Artifact.After)
	_, _, raw, _ := unitCaptureForChild(t, gitModelView(p), Child{Artifact: Artifact{BeforeStateSerial: r.Artifact.BeforeStateSerial, Before: r.Artifact.Before, After: r.Artifact.After}}, source, h.now)
	before := journalNativeState(t, p, r.Artifact.Before, r.Artifact.BeforeStateSerial)
	capture := GitTerraformArtifactCapture{Context: p.ArtifactContext, Revision: r.Artifact.Revision, Configuration: source, DesiredVariables: desired, SavedPlan: unitFixtureContainer(t, source, before, nil), PlanJSON: raw.PlanJSON, BeforeState: before, GitCommitObject: h.commits[r.Artifact.Revision.Commit], GitTreeObject: h.trees[r.Artifact.Revision.Tree], Ref: p.Manifest.Ref, RefBefore: r.Artifact.PreviousRevision.Commit, RefAfter: r.Artifact.Revision.Commit, Invocation: gitInvocationFixture()}
	r.Artifact.SavedPlanSHA256 = BytesDigest(capture.SavedPlan)
	r.Artifact.PlanJSONSHA256 = BytesDigest(capture.PlanJSON)
	review, err := ValidateJournalTerraformArtifact(h.view, h.keys, h.view.Head.Head.Ref, r, capture, h.now)
	if err != nil {
		t.Fatal(err)
	}
	if review.Status != "FIXTURE_JOURNAL_RECOVERY_SEMANTICS_MATCHED" || review.ChildSHA256 != Digest(r) || review.CustomerNativeExecution || review.CustomerVerifiedSaving != nil {
		t.Fatal("wrong recovery review")
	}
	changed := capture
	plan, _ := fixtureObject(changed.PlanJSON, fixtureArtifactLimit)
	tfObject(tfObject(plan["variables"])["candidate_traffic_percent"])["value"] = json.Number("99")
	changed.PlanJSON, _ = json.Marshal(plan)
	bad := r
	bad.Artifact.PlanJSONSHA256 = BytesDigest(changed.PlanJSON)
	if _, err = ValidateJournalTerraformArtifact(h.view, h.keys, h.view.Head.Head.Ref, bad, changed, h.now); err == nil {
		t.Fatal("rehashed noninverse plan accepted")
	}
	changed = capture
	changed.Recovery = &GitTerraformRecoveryAuthority{}
	if _, err = ValidateJournalTerraformArtifact(h.view, h.keys, h.view.Head.Head.Ref, r, changed, h.now); err == nil {
		t.Fatal("old5.1 recovery adapter accepted")
	}
}

func TestJournalRecoveryRetainsBothHeadsAndRechecksDeliveryFreshness(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.preparationRecovery()
	h.git()
	r := h.recoveryBody()
	bad := r
	bad.SigningHeadSHA256 = bad.PreparationHeadSHA256
	if _, err := SignJournalRecovery(bad, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now); err == nil {
		t.Fatal("preparation head masqueraded as fresh signing head")
	}
	signed, err := SignJournalRecovery(r, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	c := h.projection.Pending.Command
	h.issue(JournalUnknown, c.Before, c.Before)
	c.Recovery = &signed
	if h.append(JournalRecord{Kind: JournalReserved, Command: &c}) == nil {
		t.Fatal("intervening journal change ignored at finalization")
	}
	r.SigningHeadSHA256 = Digest(h.view.Head)
	h.finalizeRecovery(r)
	h.now = h.now.Add(6 * time.Minute)
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.view, h.projection = v, p
	h.ready()
	s := journalAtRevision(c.Before, c.Preparation.Revision)
	intent := h.receipt(JournalApplyIntent, s, s)
	if h.append(JournalRecord{Kind: JournalApplyIntent, Receipt: &intent}) == nil {
		t.Fatal("fresh READY borrowed for stale recovery child/evidence")
	}
}
