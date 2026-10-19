package fleetgroup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// All keys/receipts below are explicit isolated unit issuers. Synthetic native
// containers are not actual CLI, database, fencing, health or identity proof.
type journalFixture struct {
	t                        *testing.T
	view                     JournalView
	projection               JournalProjection
	keys                     JournalKeys
	signer, pipeline, ledger ed25519.PrivateKey
	now                      time.Time
	commits, trees           map[string][]byte
	checkpoints              []JournalHeadEnvelope
}

func journalNativeState(t *testing.T, p GitProgram, m ModelState, serial uint64) []byte {
	t.Helper()
	source, _ := GitFixtureConfiguration(p)
	_, _, capture, _ := unitCaptureForChild(t, gitModelView(p), Child{Artifact: Artifact{BeforeStateSerial: serial, Before: m, After: m}}, source, p.CreatedAt)
	parsed, _ := fixtureObject(capture.BeforeState, fixtureArtifactLimit)
	resources := tfArray(parsed["resources"])
	sort.Slice(resources, func(i, j int) bool {
		return tfText(tfObject(resources[i])["name"]) < tfText(tfObject(resources[j])["name"])
	})
	raw, _ := json.Marshal(parsed)
	return raw
}
func newJournalFixture(t *testing.T) *journalFixture {
	t.Helper()
	p, now, commits, trees := gitProgramFixture(t)
	signerPub, signer := keyFixture()
	pipeline := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))
	ledger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{24}, 32))
	keys := JournalKeys{signerPub, pipeline.Public().(ed25519.PublicKey), ledger.Public().(ed25519.PublicKey)}
	parent, err := SignGitProgram(p, gitApprovalsFixture(p, now), signer, now)
	if err != nil {
		t.Fatal(err)
	}
	base := JournalState{p.Manifest.Base, p.ArtifactContext.StateLineage, p.ArtifactContext.InitialStateSerial, BytesDigest(journalNativeState(t, p, p.Manifest.Entries[0].Before, p.ArtifactContext.InitialStateSerial)), p.Manifest.Entries[0].Before}
	a := JournalAuthorization{JournalSchemaVersion, JournalKind, "journal-auth", "journal-a", Digest(parent), Digest(p), Digest(p.Binding), Digest(p.Realm), p.ArtifactContext.PipelineID, p.Manifest.Ref, JournalPolicy, base, BytesDigest(keys.Pipeline), BytesDigest(keys.Ledger), 32, 512, now, p.ExpiresAt, "journal-nonce"}
	approvals := []JournalApproval{{"journal-approval", p.Binding.Old.Target.TenantID, "independent-journal-approver", ApproverRole, Digest(a), now}}
	auth, err := SignJournalAuthorization(a, approvals, parent, keys, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	view, projection, err := SealJournalView(parent, auth, nil, keys, ledger, now)
	if err != nil {
		t.Fatal(err)
	}
	return &journalFixture{t: t, view: view, projection: projection, keys: keys, signer: signer, pipeline: pipeline, ledger: ledger, now: now, commits: commits, trees: trees, checkpoints: []JournalHeadEnvelope{view.Head}}
}
func (h *journalFixture) append(record JournalRecord) error {
	h.now = h.now.Add(time.Second)
	record.Sequence = uint64(len(h.view.Records) + 1)
	record.PreviousSHA256 = h.view.Head.Head.Ref.LastRecordSHA256
	record.RecordedAt = h.now
	records, _, err := AppendJournalRecord(h.view, h.keys, h.view.Head.Head.Ref, record, h.now)
	if err != nil {
		return err
	}
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, records, h.keys, h.ledger, h.now)
	if err == nil {
		h.view, h.projection = v, p
		h.checkpoints = append(h.checkpoints, v.Head)
	}
	return err
}
func (h *journalFixture) mustAppend(record JournalRecord) {
	h.t.Helper()
	if err := h.append(record); err != nil {
		h.t.Fatal(record.Kind, err)
	}
}
func (h *journalFixture) prepare(sequence uint64) {
	h.t.Helper()
	p := h.view.Parent.Program
	e := p.Manifest.Entries[sequence-1]
	c := JournalCommand{ID: fmt.Sprintf("command-%d", h.projection.LastFence+1), OperationID: fmt.Sprintf("operation-%d", h.projection.LastFence+1), IdempotencyKey: fmt.Sprintf("key-%d", h.projection.LastFence+1), Fence: h.projection.LastFence + 1, Head: h.view.Head, Before: h.projection.Current, Preparation: JournalPreparation{Mode: Forward, Sequence: sequence, ManifestEntrySHA256: Digest(e), Revision: e.Revision, Before: e.Before, After: e.After}, CreatedAt: h.now}
	h.mustAppend(JournalRecord{Kind: JournalPreparing, Command: &c})
}
func (h *journalFixture) receipt(kind string, before, after JournalState) JournalReceiptEnvelope {
	h.t.Helper()
	pending := h.projection.Pending
	if pending == nil {
		h.t.Fatal("receipt without command")
	}
	c := pending.Command
	r := JournalReceipt{SchemaVersion: JournalSchemaVersion, ID: fmt.Sprintf("receipt-%d", len(h.view.Records)+1), IdempotencyKey: fmt.Sprintf("receipt-key-%d", len(h.view.Records)+1), JournalID: h.view.Authorization.Authorization.JournalID, AuthorizationSHA256: Digest(h.view.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: h.view.Authorization.Authorization.PipelineID, Kind: kind, PreparationSHA256: Digest(c.Preparation), Before: before, After: after, ReceivedAt: h.now}
	if artifact, ok := commandArtifact(c); ok {
		r.ArtifactSHA256 = Digest(artifact)
		r.SavedPlanSHA256 = artifact.SavedPlanSHA256
	}
	if kind == JournalReadyToApply {
		r.ValidUntil = h.now.Add(30 * time.Second)
	}
	if kind == JournalGitRepaired {
		r.ArtifactSHA256 = Digest(pending.GitRepair.Repair)
		r.SavedPlanSHA256 = ""
	}
	env, err := SignJournalReceipt(r, h.pipeline)
	if err != nil {
		h.t.Fatal(err)
	}
	return env
}
func (h *journalFixture) issue(kind string, before, after JournalState) JournalReceiptEnvelope {
	e := h.receipt(kind, before, after)
	h.mustAppend(JournalRecord{Kind: kind, Receipt: &e})
	return e
}
func (h *journalFixture) git() {
	c := h.projection.Pending.Command
	h.issue(JournalGitAdvanced, c.Before, journalAtRevision(c.Before, c.Preparation.Revision))
}
func (h *journalFixture) finalizeForward() {
	h.t.Helper()
	pending := h.projection.Pending
	c := pending.Command
	p := h.view.Parent.Program
	child := gitChildFixture(p, h.now, c.Preparation.Sequence)
	child.Artifact.PreviousRevision = c.Before.Revision
	child.Artifact.BeforeStateSerial = c.Before.StateSerial
	child.Artifact.BeforeStateSHA256 = c.Before.StateSHA256
	signed, err := SignGitChild(child, h.view.Parent, h.signer, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	c.Forward = &signed
	h.mustAppend(JournalRecord{Kind: JournalReserved, Command: &c})
}
func (h *journalFixture) ready() {
	c := h.projection.Pending.Command
	s := journalAtRevision(c.Before, c.Preparation.Revision)
	h.issue(JournalReadyToApply, s, s)
}
func (h *journalFixture) intent() {
	c := h.projection.Pending.Command
	s := journalAtRevision(c.Before, c.Preparation.Revision)
	h.issue(JournalApplyIntent, s, s)
}
func (h *journalFixture) applied() JournalReceiptEnvelope {
	h.t.Helper()
	c := h.projection.Pending.Command
	a, _ := commandArtifact(c)
	after := JournalState{a.Revision, c.Before.StateLineage, c.Before.StateSerial, c.Before.StateSHA256, a.After}
	if a.Before != a.After {
		after.StateSerial++
		after.StateSHA256 = BytesDigest(journalNativeState(h.t, h.view.Parent.Program, a.After, after.StateSerial))
	}
	return h.issue(JournalApplied, c.Before, after)
}
func (h *journalFixture) forward(sequence uint64) JournalReceiptEnvelope {
	h.prepare(sequence)
	h.git()
	h.finalizeForward()
	h.ready()
	h.intent()
	return h.applied()
}
func (h *journalFixture) preparationRecovery() {
	h.t.Helper()
	p := h.view.Parent.Program
	top := h.projection.Stack[len(h.projection.Stack)-1]
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, top.Forward.Child.Artifact.Before)
	rev, commit, tree := unitGitRevision(source, desired, h.projection.Current.Revision.Commit, 40, fmt.Sprintf("NEW unit inverse-%d", h.projection.LastFence+1))
	h.commits[rev.Commit], h.trees[rev.Tree] = commit, tree
	c := JournalCommand{ID: fmt.Sprintf("inverse-command-%d", h.projection.LastFence+1), OperationID: fmt.Sprintf("inverse-operation-%d", h.projection.LastFence+1), IdempotencyKey: fmt.Sprintf("inverse-key-%d", h.projection.LastFence+1), Fence: h.projection.LastFence + 1, Head: h.view.Head, Before: h.projection.Current, Preparation: JournalPreparation{Mode: JournalRecoveryMode, EffectID: top.ID, Revision: rev, Before: top.Forward.Child.Artifact.After, After: top.Forward.Child.Artifact.Before}, CreatedAt: h.now}
	h.mustAppend(JournalRecord{Kind: JournalPreparing, Command: &c})
}
func (h *journalFixture) recoveryBody() JournalRecovery {
	h.t.Helper()
	c := h.projection.Pending.Command
	top := h.projection.Stack[len(h.projection.Stack)-1]
	p := h.view.Parent.Program
	r := JournalRecovery{SchemaVersion: JournalSchemaVersion, ID: "recovery-" + c.ID, CommandID: c.ID, JournalID: h.view.Authorization.Authorization.JournalID, AuthorizationSHA256: Digest(h.view.Authorization), ParentEnvelopeSHA256: Digest(h.view.Parent), PreparationHeadSHA256: Digest(c.Head), SigningHeadSHA256: Digest(h.view.Head), EffectID: top.ID, OriginalChildSHA256: Digest(top.Forward.Child), OriginalReceiptSHA256: Digest(top.Applied), Artifact: GitArtifact{Kind: BuiltinFixtureArtifact, Receipt: SnapshotRef{"journal-artifact-" + c.ID, sha("a")}, BaseContextSHA256: Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Preparation.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: sha("b"), PlanJSONSHA256: sha("c"), Before: c.Preparation.Before, After: c.Preparation.After}, MinimumObservationSeconds: 120, CreatedAt: h.now, ExpiresAt: h.now.Add(10 * time.Minute), Nonce: "nonce-" + c.ID}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
		r.Evidence = append(r.Evidence, EvidenceRef{kind, "journal-" + kind, sha("a"), Digest(p.Binding), Digest(p.Realm), h.now, h.now.Add(15 * time.Minute)})
	}
	return r
}
func (h *journalFixture) finalizeRecovery(r JournalRecovery) {
	h.t.Helper()
	c := h.projection.Pending.Command
	e, err := SignJournalRecovery(r, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	c.Recovery = &e
	h.mustAppend(JournalRecord{Kind: JournalReserved, Command: &c})
}
func (h *journalFixture) inverse() JournalReceiptEnvelope {
	h.preparationRecovery()
	h.git()
	h.finalizeRecovery(h.recoveryBody())
	h.ready()
	h.intent()
	return h.applied()
}

func TestJournalThreeEffectLIFOCommitsAndConsumedCallbackReplay(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.forward(3)
	last := h.forward(4)
	if len(h.projection.Stack) != 3 {
		t.Fatal("changed effect population")
	}
	terminal := h.projection.Current.Revision.Commit
	// Unit-only clock: forward authority has expired, but newly issued current
	// head/recovery evidence must still support the exact prior owned chain.
	h.now = h.view.Authorization.Authorization.ExpiresAt.Add(time.Hour)
	v0, p0, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.view, h.projection = v0, p0
	h.inverse()
	afterFirst := h.projection.Current.Revision.Commit
	h.inverse()
	h.inverse()
	if len(h.projection.Stack) != 0 || len(h.projection.Consumed) != 3 || !h.projection.ForwardAborted || h.projection.Current.Model != h.view.Authorization.Authorization.Base.Model || afterFirst == terminal || h.projection.Current.Revision.Commit == h.view.Authorization.Authorization.Base.Revision.Commit {
		t.Fatal("did not append exact inverses through authenticated current heads")
	}
	h.mustAppend(JournalRecord{Kind: JournalApplied, Receipt: &last})
	if len(h.projection.Stack) != 0 {
		t.Fatal("consumed receipt revived ownership")
	}
	bad := last
	bad.Receipt.After.StateSHA256 = sha("f")
	bad, _ = SignJournalReceipt(bad.Receipt, h.pipeline)
	if h.append(JournalRecord{Kind: JournalApplied, Receipt: &bad}) == nil {
		t.Fatal("conflicting signed callback accepted")
	}
	if h.append(JournalRecord{Kind: JournalReadyToApply, Receipt: &last}) == nil {
		t.Fatal("changed duplicate wrapper kind accepted")
	}
	var frames []byte
	for _, r := range h.view.Records {
		raw, err := EncodeJournalRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, raw...)
	}
	records, err := DecodeJournalRecords(frames)
	if err != nil {
		t.Fatal(err)
	}
	v, projection, err := SealJournalView(h.view.Parent, h.view.Authorization, records, h.keys, h.ledger, h.now)
	if err != nil || len(projection.Stack) != 0 {
		t.Fatal("reopen revived consumed duty", err)
	}
	if _, err = VerifyJournal(v, h.keys, v.Head.Head.Ref, h.now); err != nil {
		t.Fatal(err)
	}
}

func TestJournalUnknownNeedsPositiveFencedReceiptAndNeverBlindReapplies(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.prepare(2)
	h.git()
	h.finalizeForward()
	c := h.projection.Pending.Command
	s := journalAtRevision(c.Before, c.Preparation.Revision)
	intent := h.receipt(JournalApplyIntent, s, s)
	if h.append(JournalRecord{Kind: JournalApplyIntent, Receipt: &intent}) == nil {
		t.Fatal("absence of READY certified no-dispatch")
	}
	h.ready()
	h.intent()
	h.issue(JournalUnknown, c.Before, c.Before)
	if h.projection.Pending == nil || !h.projection.Pending.ApplyIntent {
		t.Fatal("unknown erased intent")
	}
	beforeRecords := len(h.view.Records)
	again := h.receipt(JournalApplyIntent, s, s)
	if h.append(JournalRecord{Kind: JournalApplyIntent, Receipt: &again}) == nil {
		t.Fatal("unknown apply redispatched")
	}
	if len(h.view.Records) != beforeRecords {
		t.Fatal("rejected append persisted")
	}
	wrongKey := h.keys
	wrongKey.Ledger = wrongKey.Pipeline
	if _, err := VerifyJournal(h.view, wrongKey, h.view.Head.Head.Ref, h.now); err == nil {
		t.Fatal("caller key confusion accepted")
	}
	receipt := h.applied()
	if h.projection.Pending != nil || len(h.projection.Stack) != 1 {
		t.Fatal("terminal APPLIED did not reconcile")
	}
	h.mustAppend(JournalRecord{Kind: JournalApplied, Receipt: &receipt})
	if len(h.projection.Stack) != 1 {
		t.Fatal("duplicate APPLIED doubled effect")
	}
}

func (h *journalFixture) gitOnlyRepair() JournalGitRepair {
	h.t.Helper()
	pending := h.projection.Pending
	c := pending.Command
	p := h.view.Parent.Program
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, c.Before.Model)
	rev, commit, tree := unitGitRevision(source, desired, c.Preparation.Revision.Commit, 40, "NEW Git-only desired repair, no CLI")
	h.commits[rev.Commit], h.trees[rev.Tree] = commit, tree
	r := JournalGitRepair{JournalSchemaVersion, "git-only-repair", c.ID, Digest(h.view.Authorization), Digest(h.view.Head), Digest(c.Preparation), Digest(*pending.NoApply), pending.NoApply.Receipt.After, rev, h.now, h.now.Add(10 * time.Minute), "git-repair-nonce"}
	envelope, err := SignJournalGitRepair(r, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	h.mustAppend(JournalRecord{Kind: JournalGitRepairIntent, GitRepair: &envelope})
	state := journalNativeState(h.t, p, c.Before.Model, c.Before.StateSerial)
	capture := JournalGitRepairCapture{p.ArtifactContext, source, desired, state, state, commit, tree, p.Manifest.Ref, r.Before.Revision.Commit, rev.Commit}
	if err = ValidateJournalGitRepairCapture(h.view, h.keys, h.view.Head.Head.Ref, r, capture, h.now); err != nil {
		h.t.Fatal(err)
	}
	altered := capture
	altered.AfterState = append(append([]byte{}, state...), ' ')
	if ValidateJournalGitRepairCapture(h.view, h.keys, h.view.Head.Head.Ref, r, altered, h.now) == nil {
		h.t.Fatal("Git-only repair changed native bytes")
	}
	h.issue(JournalGitRepaired, r.Before, journalAtRevision(c.Before, rev))
	return r
}

func TestJournalNoApplyGitDutyRepairThenPriorAppliedInverse(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.forward(2)
	h.prepare(3)
	h.git()
	c := h.projection.Pending.Command
	h.issue(JournalNoApply, c.Before, journalAtRevision(c.Before, c.Preparation.Revision))
	if h.projection.Pending == nil || h.projection.Pending.Phase != "GIT_REPAIR_REQUIRED" {
		t.Fatal("Git duty silently cleared")
	}
	ready := h.receipt(JournalReadyToApply, journalAtRevision(c.Before, c.Preparation.Revision), journalAtRevision(c.Before, c.Preparation.Revision))
	if h.append(JournalRecord{Kind: JournalReadyToApply, Receipt: &ready}) == nil {
		t.Fatal("terminal no-apply returned to READY")
	}
	h.gitOnlyRepair()
	if !h.projection.ForwardAborted || len(h.projection.Stack) != 1 || len(h.projection.GitRepairs) != 1 {
		t.Fatal("repair lost earlier duty/forward abort")
	}
	if h.append(JournalRecord{Kind: JournalPreparing, Command: &JournalCommand{}}) == nil {
		t.Fatal("empty/new forward accepted")
	}
	h.inverse()
	if len(h.projection.Stack) != 0 {
		t.Fatal("Git-only repair broke prior LIFO recovery")
	}
}

func TestJournalNoApplyBeforeGitConsumesOnlyUnissuedAndUnknownCannotRepair(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.prepare(2)
	c := h.projection.Pending.Command
	h.issue(JournalUnknown, c.Before, c.Before)
	r := JournalGitRepair{SchemaVersion: JournalSchemaVersion}
	if _, err := SignJournalGitRepair(r, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now); err == nil {
		t.Fatal("unknown certified no-apply")
	}
	h.issue(JournalNoApply, c.Before, c.Before)
	if h.projection.Pending != nil || h.projection.ForwardAborted {
		t.Fatal("unissued no-apply touched owned Git state")
	}
	h.forward(2)
}

func TestJournalRejectsCallerRootTornTailAndInsufficientProtocolCapacity(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	initial := h.view.Head.Head.Ref
	h.forward(2)
	if _, err := VerifyJournal(h.view, h.keys, initial, h.now); err == nil {
		t.Fatal("stale caller current head accepted")
	}
	for _, raw := range [][]byte{[]byte("{}"), []byte("{}\ntrailing"), []byte("\n"), []byte(" {}\n"), []byte("{\"sequence\":1,\"sequence\":1}\n")} {
		if _, err := DecodeJournalRecords(raw); err == nil {
			t.Fatalf("bad frame accepted %q", raw)
		}
	}
	a := h.view.Authorization.Authorization
	a.MaximumRecords = 128
	approval := []JournalApproval{{"review", h.view.Parent.Program.Binding.Old.Target.TenantID, "independent", ApproverRole, Digest(a), a.CreatedAt}}
	if _, err := SignJournalAuthorization(a, approval, h.view.Parent, h.keys, h.signer, a.CreatedAt); err == nil {
		t.Fatal("full protocol cannot fit journal")
	}
	if (2*len(h.view.Parent.Program.Manifest.Entries)-1)*6+64 > 512 {
		t.Fatal("default journal capacity insufficient")
	}
	raw, _ := EncodeJournalRecord(h.view.Records[0])
	if _, err := DecodeJournalRecords(raw[:len(raw)-1]); err == nil {
		t.Fatal("torn final frame truncated")
	}
	if !strings.Contains(JournalIntegrationBoundary, "NOT_RUNTIME_HEALTH") {
		t.Fatal("component claimed runtime health")
	}
}

func TestJournalForwardExpiryAndReplanMustRefreshReady(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.prepare(2)
	h.git()
	h.finalizeForward()
	h.ready()
	c := h.projection.Pending.Command
	child := c.Forward.Child
	child.Artifact.SavedPlanSHA256 = sha("f")
	signed, err := SignGitChild(child, h.view.Parent, h.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	c.Forward = &signed
	h.mustAppend(JournalRecord{Kind: JournalReserved, Command: &c})
	s := journalAtRevision(c.Before, c.Preparation.Revision)
	intent := h.receipt(JournalApplyIntent, s, s)
	if h.append(JournalRecord{Kind: JournalApplyIntent, Receipt: &intent}) == nil {
		t.Fatal("prior plan READY borrowed")
	}
	// A late factual terminal callback remains recordable; new forward intent
	// must not be dispatched after the immutable forward deadline.
	h.now = GitForwardDeadline(h.view.Parent.Program).Add(-2 * time.Second)
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.view, h.projection = v, p
	h.ready()
	h.now = h.now.Add(time.Second)
	intent = h.receipt(JournalApplyIntent, s, s)
	if h.append(JournalRecord{Kind: JournalApplyIntent, Receipt: &intent}) == nil {
		t.Fatal("new apply intent crossed deadline")
	}
}

func TestJournalHistoricalLateAppliedReceiptSurvivesForwardExpiry(t *testing.T) {
	h := newJournalFixture(t)
	h.forward(1)
	h.prepare(2)
	h.git()
	h.finalizeForward()
	h.ready()
	h.intent()
	h.now = GitForwardDeadline(h.view.Parent.Program).Add(time.Minute)
	v, p, err := SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.view, h.projection = v, p
	h.applied()
	if len(h.projection.Stack) != 1 || h.projection.Pending != nil {
		t.Fatal("late factual effect was dropped at expiry")
	}
}
