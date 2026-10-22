package fleetgroup

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// This is an explicitly trusted in-memory unit issuer/repository, not evidence
// of database fencing, actual native tools, identity or customer authority.
type continuationMemory struct {
	cursor    ContinuationCursor
	anchors   map[string]ContinuationIdentityAnchor
	snapshots map[string]map[string]ContinuationIdentity
}

func newContinuationMemory(cursor ContinuationCursor) *continuationMemory {
	return &continuationMemory{cursor: cursor, anchors: map[string]ContinuationIdentityAnchor{}, snapshots: map[string]map[string]ContinuationIdentity{}}
}
func (m *continuationMemory) Current(_ context.Context, chain string) (ContinuationCursor, error) {
	if chain != m.cursor.ChainID {
		return ContinuationCursor{}, invalid("UNIT_CHAIN_NOT_FOUND")
	}
	return m.cursor, nil
}
func (m *continuationMemory) LookupIdentity(_ context.Context, chain string, a ContinuationIdentityAnchor, k ContinuationIdentityKey) (ContinuationIdentity, bool, error) {
	if chain != m.cursor.ChainID || a.ChainID != chain || m.anchors[a.SHA256] != a {
		return ContinuationIdentity{}, false, invalid("UNIT_UNCOMMITTED_IDENTITY_ANCHOR")
	}
	e, ok := m.snapshots[a.SHA256][continuationIdentityCode(k)]
	return e, ok, nil
}
func copyContinuationEntries(in map[string]ContinuationIdentity) map[string]ContinuationIdentity {
	out := map[string]ContinuationIdentity{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (m *continuationMemory) commit(t *testing.T, r ContinuationTransition) error {
	t.Helper()
	if m.cursor != r.Expected {
		return invalid("UNIT_CURRENT_CAS_CONFLICT")
	}
	a := m.cursor.Identities
	entries := map[string]ContinuationIdentity{}
	if m.cursor.Kind == ContinuationOriginal {
		a = ContinuationIdentityBase(r.View.Authorization)
		m.anchors[a.SHA256] = a
		m.snapshots[a.SHA256] = map[string]ContinuationIdentity{}
	} else {
		entries = copyContinuationEntries(m.snapshots[a.SHA256])
	}
	for _, entry := range r.Identities {
		code := continuationIdentityCode(entry.Key)
		if _, ok := entries[code]; ok {
			return invalid("UNIT_DUPLICATE_IDENTITY_INSERT")
		}
		var err error
		a, err = ContinuationIdentityExtend(a, entry)
		if err != nil {
			return err
		}
		entries[code] = entry
		m.anchors[a.SHA256] = a
		m.snapshots[a.SHA256] = copyContinuationEntries(entries)
	}
	if a != r.Next.Identities {
		return invalid("UNIT_IDENTITY_CAS_DIFFERS")
	}
	m.cursor = r.Next
	return nil
}

type continuationFixture struct {
	t      *testing.T
	ctx    context.Context
	old    *journalFixture
	chain  ContinuationEnvelope
	memory *continuationMemory
	view   ContinuationView
	p      ContinuationProjection
	now    time.Time
}

func newContinuationFixture(t *testing.T) *continuationFixture {
	t.Helper()
	h := newJournalFixture(t)
	ctx := context.Background()
	m := newContinuationMemory(ContinuationOriginalCursor("chain-a", h.view))
	p := h.view.Parent.Program
	a := ContinuationAuthorization{SchemaVersion: ContinuationSchemaVersion, ID: "continuation-authorization", ChainID: "chain-a", Policy: ContinuationPolicy, ParentEnvelopeSHA256: Digest(h.view.Parent), JournalAuthorizationSHA256: Digest(h.view.Authorization), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), SignerKeySHA256: BytesDigest(h.keys.Signer), PipelineKeySHA256: BytesDigest(h.keys.Pipeline), LedgerKeySHA256: BytesDigest(h.keys.Ledger), BootstrapHead: h.view.Head, RecordLimit: 8, ByteLimit: 8 * JournalRecordByteLimit, CreatedAt: h.now, ForwardExpiresAt: h.view.Authorization.Authorization.ExpiresAt, Nonce: "chain-authorization-nonce"}
	approvals := []ContinuationApproval{{"continuation-approval", p.Binding.Old.Target.TenantID, "independent-continuation-approver", ApproverRole, Digest(a), h.now}}
	signed, err := SignContinuationAuthorization(ctx, a, approvals, h.view, h.keys, m, h.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	return &continuationFixture{t: t, ctx: ctx, old: h, chain: signed, memory: m, now: h.now}
}
func (h *continuationFixture) open() {
	h.t.Helper()
	h.now = h.old.now
	h.memory.cursor = ContinuationOriginalCursor(h.chain.Authorization.ChainID, h.old.view)
	r, err := OpenContinuationFromJournal(h.ctx, h.old.view, h.chain, h.old.keys, h.memory, h.old.ledger, "checkpoint-first", h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	h.install(r)
}
func (h *continuationFixture) install(r ContinuationTransition) {
	h.t.Helper()
	if err := h.memory.commit(h.t, r); err != nil {
		h.t.Fatal(err)
	}
	h.view, h.p = r.View, r.Projection
}
func (h *continuationFixture) append(r ContinuationRecord) (ContinuationTransition, error) {
	h.now = h.now.Add(time.Millisecond)
	r.Sequence = uint64(len(h.view.Records) + 1)
	r.PreviousSHA256 = h.view.Head.Head.LastRecordSHA256
	r.RecordedAt = h.now
	return AppendContinuationRecord(h.ctx, h.view, h.old.keys, h.memory, h.old.ledger, r, h.now)
}
func (h *continuationFixture) must(r ContinuationRecord) {
	h.t.Helper()
	out, err := h.append(r)
	if err != nil {
		h.t.Fatal(r.Kind, err)
	}
	h.install(out)
}
func (h *continuationFixture) rotate() {
	h.t.Helper()
	h.now = h.now.Add(time.Millisecond)
	r, err := RotateContinuation(h.ctx, h.view, h.old.keys, h.memory, h.old.ledger, fmt.Sprintf("checkpoint-%d", h.view.Head.Head.Segment+1), h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	h.install(r)
}
func (h *continuationFixture) renew(at time.Time) {
	h.t.Helper()
	r, err := RenewContinuationHead(h.ctx, h.view, h.old.keys, h.memory, h.old.ledger, at)
	if err != nil {
		h.t.Fatal(err)
	}
	h.now = at
	h.install(r)
}
func (h *continuationFixture) prepare(mode string) {
	h.t.Helper()
	p := h.view.Origin.Parent.Program
	after := h.p.Current.Model
	obligation := ""
	if mode == ContinuationInverse {
		top := h.p.Stack[len(h.p.Stack)-1]
		after = top.Forward.Child.Artifact.Before
		obligation = Digest(top)
	} else {
		obligation = Digest(*h.p.GitDuty)
	}
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, after)
	revision, _, _ := unitGitRevision(source, desired, h.p.Current.Revision.Commit, 40, fmt.Sprintf("NEW continuation inverse-%d", h.p.LastFence+1))
	c := ContinuationCommand{ID: fmt.Sprintf("continuation-command-%d", h.p.LastFence+1), OperationID: fmt.Sprintf("continuation-operation-%d", h.p.LastFence+1), IdempotencyKey: fmt.Sprintf("continuation-key-%d", h.p.LastFence+1), Nonce: fmt.Sprintf("continuation-command-nonce-%d", h.p.LastFence+1), Fence: h.p.LastFence + 1, Mode: mode, ObligationSHA256: obligation, Head: h.view.Head, Before: h.p.Current, Revision: revision, After: after, CreatedAt: h.now}
	h.must(ContinuationRecord{Kind: ContinuationPreparing, Command: &c})
}
func (h *continuationFixture) finalize() {
	h.t.Helper()
	c := h.p.Pending.Command
	p := h.view.Origin.Parent.Program
	f := ContinuationFinalization{SchemaVersion: ContinuationSchemaVersion, ID: fmt.Sprintf("continuation-artifact-%d", c.Fence), ChainSHA256: Digest(h.chain), CommandSHA256: Digest(c), SigningHeadSHA256: Digest(h.view.Head), CreatedAt: h.now, ExpiresAt: h.now.Add(time.Minute), Nonce: fmt.Sprintf("continuation-artifact-nonce-%d", c.Fence)}
	kinds := []string{"FIXTURE_CURRENT"}
	if c.Mode == ContinuationInverse {
		f.Artifact = GitArtifact{Kind: BuiltinFixtureArtifact, Receipt: SnapshotRef{fmt.Sprintf("continuation-artifact-receipt-%d", c.Fence), sha("a")}, BaseContextSHA256: Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: sha("b"), PlanJSONSHA256: sha("c"), Before: c.Before.Model, After: c.After}
		kinds = append(kinds, "FIXTURE_RECOVERY_SLO")
	}
	for _, kind := range kinds {
		f.Evidence = append(f.Evidence, EvidenceRef{kind, "unit-continuation-" + kind, sha("d"), Digest(p.Binding), Digest(p.Realm), h.now, h.now.Add(5 * time.Minute)})
	}
	signed, err := SignContinuationFinalization(h.ctx, f, h.view, h.old.keys, h.memory, h.old.signer, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	h.must(ContinuationRecord{Kind: ContinuationFinalized, Finalization: &signed})
}
func (h *continuationFixture) receipt(kind string, before, after JournalState) ContinuationReceiptEnvelope {
	h.t.Helper()
	c := h.p.Pending.Command
	r := ContinuationReceipt{SchemaVersion: ContinuationSchemaVersion, ID: fmt.Sprintf("continuation-receipt-%d-%d", h.view.Head.Head.Segment, len(h.view.Records)+1), IdempotencyKey: fmt.Sprintf("continuation-receipt-key-%d-%d", h.view.Head.Head.Segment, len(h.view.Records)+1), ChainSHA256: Digest(h.chain), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, Kind: kind, CommandSHA256: Digest(c), Before: before, After: after, ReceivedAt: h.now}
	if h.p.Pending.Finalized != nil {
		r.FinalizationSHA256 = Digest(h.p.Pending.Finalized.Finalization)
	}
	if kind == ContinuationReady {
		r.ValidUntil = h.now.Add(30 * time.Second)
	}
	e, err := SignContinuationReceipt(r, h.old.pipeline)
	if err != nil {
		h.t.Fatal(err)
	}
	return e
}
func (h *continuationFixture) issue(kind string, before, after JournalState) ContinuationReceiptEnvelope {
	e := h.receipt(kind, before, after)
	h.must(ContinuationRecord{Kind: kind, Receipt: &e})
	return e
}
func (h *continuationFixture) git() {
	c := h.p.Pending.Command
	if _, err := AuthorizeContinuationGitAdvance(h.ctx, h.view, h.old.keys, h.memory, Digest(c), h.now); err != nil {
		h.t.Fatal(err)
	}
	h.issue(ContinuationGitAdvanced, c.Before, journalAtRevision(c.Before, c.Revision))
}
func (h *continuationFixture) ready()  { h.issue(ContinuationReady, h.p.Current, h.p.Current) }
func (h *continuationFixture) intent() { h.issue(ContinuationIntent, h.p.Current, h.p.Current) }
func (h *continuationFixture) applied() ContinuationReceiptEnvelope {
	c := h.p.Pending.Command
	after := JournalState{c.Revision, c.Before.StateLineage, c.Before.StateSerial + 1, BytesDigest(journalNativeState(h.t, h.view.Origin.Parent.Program, c.After, c.Before.StateSerial+1)), c.After}
	return h.issue(ContinuationApplied, c.Before, after)
}
func oldContinuationTerminal(h *journalFixture) JournalReceiptEnvelope {
	c := h.projection.Pending.Command
	a, _ := commandArtifact(c)
	after := JournalState{a.Revision, c.Before.StateLineage, c.Before.StateSerial + 1, BytesDigest(journalNativeState(h.t, h.view.Parent.Program, a.After, c.Before.StateSerial+1)), a.After}
	return h.receipt(JournalApplied, c.Before, after)
}

func TestContinuationFullOriginalAndFullNewSegmentRetainUnknownConsumedAndLIFO(t *testing.T) {
	h := newContinuationFixture(t)
	old := h.old
	old.forward(1)
	old.forward(2)
	old.forward(3)
	consumed := old.forward(4)
	old.inverse()
	old.preparationRecovery()
	old.git()
	old.finalizeRecovery(old.recoveryBody())
	old.ready()
	old.intent()
	c := old.projection.Pending.Command
	unknown := old.issue(JournalUnknown, c.Before, c.Before)
	records := append([]JournalRecord{}, old.view.Records...)
	at := old.now
	for len(records) < old.view.Authorization.Authorization.MaximumRecords {
		at = at.Add(time.Millisecond)
		records = append(records, JournalRecord{Sequence: uint64(len(records) + 1), PreviousSHA256: Digest(records[len(records)-1]), Kind: JournalUnknown, Receipt: &unknown, RecordedAt: at})
	}
	old.now = old.view.Authorization.Authorization.ExpiresAt.Add(time.Hour)
	view, p, err := SealJournalView(old.view.Parent, old.view.Authorization, records, old.keys, old.ledger, old.now)
	if err != nil {
		t.Fatal(err)
	}
	old.view, old.projection = view, p
	if len(view.Records) != 512 {
		t.Fatal("unit did not exhaust original segment")
	}
	h.open()
	if h.p.OriginalPending == nil || h.p.OriginalPending.Phase != JournalUnknown || len(h.p.Stack) != 2 || len(h.p.Consumed) != 1 {
		t.Fatal("checkpoint lost original duties")
	}
	if _, err := VerifyContinuation(h.ctx, h.view, old.keys, h.memory, h.now); err != nil {
		t.Fatal(err)
	}
	terminal := oldContinuationTerminal(old)
	h.must(ContinuationRecord{Kind: ContinuationLegacy, OriginalReceipt: &terminal})
	if len(h.p.Stack) != 1 || len(h.p.Consumed) != 2 {
		t.Fatal("original terminal did not consume exactly top")
	}
	// Original consumed callbacks deduplicate before adding a record, including
	// across the original/continuation boundary after the current head advances.
	before := h.memory.cursor
	r, err := h.append(ContinuationRecord{Kind: ContinuationLegacy, OriginalReceipt: &consumed})
	if err != nil || !r.Replayed || r.Next != before {
		t.Fatal("original replay grew journal", err)
	}
	h.install(r)
	h.prepare(ContinuationInverse)
	h.git()
	h.finalize()
	h.ready()
	h.intent()
	h.issue(ContinuationUnknown, h.p.Current, h.p.Current)
	h.issue(ContinuationUnknown, h.p.Current, h.p.Current)
	if len(h.view.Records) != 8 {
		t.Fatal("unit did not exhaust new segment")
	}
	extra := h.receipt(ContinuationUnknown, h.p.Current, h.p.Current)
	if _, err = h.append(ContinuationRecord{Kind: ContinuationUnknown, Receipt: &extra}); err == nil {
		t.Fatal("segment bound ignored")
	}
	pending := Digest(*h.p.Pending)
	consumedHash := Digest(h.p.Consumed)
	oldRoot := h.p.Identities
	h.rotate()
	if len(h.view.Records) != 0 || Digest(*h.p.Pending) != pending || Digest(h.p.Consumed) != consumedHash || h.p.Identities.Count != oldRoot.Count+1 || h.p.Pending.Phase != ContinuationUnknown {
		t.Fatal("rotation changed/forgot duties")
	}
	if _, err = AuthorizeContinuationDispatch(h.ctx, h.view, old.keys, h.memory, Digest(h.p.Pending.Command), ContinuationInverse, h.now); err == nil {
		t.Fatal("UNKNOWN authorized reapply")
	}
	// Parent, original authorization and the recovery child's own lifetime may
	// expire; authenticated factual completion still consumes the retained duty.
	h.renew(h.now.Add(time.Hour))
	last := h.applied()
	if len(h.p.Stack) != 0 || len(h.p.Consumed) != 3 || h.p.Current.Model != old.view.Authorization.Authorization.Base.Model {
		t.Fatal("owned inverse not executable after continuation")
	}
	count := len(h.view.Records)
	again, err := h.append(ContinuationRecord{Kind: ContinuationApplied, Receipt: &last})
	if err != nil || !again.Replayed || len(again.View.Records) != count {
		t.Fatal("terminal replay added record", err)
	}
	h.install(again)
	bad := last
	bad.Receipt.After.StateSHA256 = sha("f")
	bad, _ = SignContinuationReceipt(bad.Receipt, old.pipeline)
	if _, err = h.append(ContinuationRecord{Kind: ContinuationApplied, Receipt: &bad}); err == nil {
		t.Fatal("conflicting signed callback accepted")
	}
	h.rotate()
	if len(h.p.Consumed) != 3 || len(h.p.Stack) != 0 {
		t.Fatal("consumption vanished on reopen/rotate")
	}
}

func TestContinuationCarriesGitRepairAndRetainedStackAcrossSegments(t *testing.T) {
	h := newContinuationFixture(t)
	old := h.old
	old.forward(1)
	old.forward(2)
	old.prepare(3)
	old.git()
	c := old.projection.Pending.Command
	old.issue(JournalNoApply, c.Before, journalAtRevision(c.Before, c.Preparation.Revision))
	h.open()
	if h.p.GitDuty == nil || h.p.OriginalPending != nil || len(h.p.Stack) != 1 {
		t.Fatal("known Git duty not derived")
	}
	h.prepare(ContinuationRepair)
	h.finalize()
	h.ready()
	h.intent()
	command := h.p.Pending.Command
	if _, err := AuthorizeContinuationDispatch(h.ctx, h.view, old.keys, h.memory, Digest(command), ContinuationInverse, h.now); err == nil {
		t.Fatal("Git-only repair authorized Terraform")
	}
	h.rotate()
	if h.p.GitDuty == nil || h.p.Pending == nil {
		t.Fatal("rotation forgot repair intent")
	}
	if _, err := AuthorizeContinuationDispatch(h.ctx, h.view, old.keys, h.memory, Digest(command), ContinuationRepair, h.now); err != nil {
		t.Fatal(err)
	}
	h.issue(ContinuationRepaired, command.Before, journalAtRevision(command.Before, command.Revision))
	if h.p.GitDuty != nil || h.p.Pending != nil || h.p.RepairCount != 1 || len(h.p.Stack) != 1 {
		t.Fatal("repair cleared native duty or lost prior stack")
	}
	h.prepare(ContinuationInverse)
	h.git()
	h.finalize()
	h.ready()
	h.intent()
	h.applied()
	if len(h.p.Stack) != 0 || len(h.p.Consumed) != 1 {
		t.Fatal("prior owned inverse unavailable after Git repair")
	}
}

func TestContinuationPrecommandApprovalCurrentCASRootsAndForwardRefusal(t *testing.T) {
	h := newContinuationFixture(t)
	old := h.old
	old.forward(1)
	old.forward(2)
	a := h.chain.Authorization
	aps := h.chain.Approvals
	if _, err := SignContinuationAuthorization(h.ctx, a, aps, old.view, old.keys, h.memory, old.signer, old.now); err == nil {
		t.Fatal("retroactive chain approval accepted")
	}
	h.memory.cursor = ContinuationOriginalCursor(a.ChainID, old.view)
	wrong := old.view
	wrong.Head.Head.ProjectionSHA256 = sha("f")
	wrong.Head.Signature = journalSignature(journalHeadDomain, wrong.Head.Head, old.ledger)
	if _, err := OpenContinuationFromJournal(h.ctx, wrong, h.chain, old.keys, h.memory, old.ledger, "bad-source", old.now); err == nil {
		t.Fatal("re-signed noncurrent original head accepted")
	}
	h.open()
	first, err := RotateContinuation(h.ctx, h.view, old.keys, h.memory, old.ledger, "rotation-a", h.now)
	if err != nil {
		t.Fatal(err)
	}
	fork, err := RotateContinuation(h.ctx, h.view, old.keys, h.memory, old.ledger, "rotation-b", h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.install(first)
	if h.memory.commit(t, fork) == nil {
		t.Fatal("stale fork CAS published identities/head")
	}
	if _, err = RotateContinuation(h.ctx, h.view, old.keys, h.memory, old.ledger, "rotation-a", h.now); err == nil {
		t.Fatal("checkpoint nonce reused")
	}
	changed := continuationClone(h.view)
	changed.Checkpoint.Checkpoint.PriorProjection.Consumed = append(changed.Checkpoint.Checkpoint.PriorProjection.Consumed, "forged-consumed")
	if _, err = VerifyContinuation(h.ctx, changed, old.keys, h.memory, h.now); err == nil {
		t.Fatal("carried consumed duties tampered")
	}
	top := h.p.Stack[len(h.p.Stack)-1]
	source, _ := GitFixtureConfiguration(h.view.Origin.Parent.Program)
	desired, _ := GitFixtureDesired(h.view.Origin.Parent.Program, top.Forward.Child.Artifact.Before)
	revision, _, _ := unitGitRevision(source, desired, h.p.Current.Revision.Commit, 40, "new but forward forbidden")
	c := ContinuationCommand{ID: "bad-forward", OperationID: "bad-operation", IdempotencyKey: "bad-key", Nonce: "bad-nonce", Fence: h.p.LastFence + 1, Mode: Forward, ObligationSHA256: Digest(top), Head: h.view.Head, Before: h.p.Current, Revision: revision, After: top.Forward.Child.Artifact.Before, CreatedAt: h.now}
	if _, err = h.append(ContinuationRecord{Kind: ContinuationPreparing, Command: &c}); err == nil {
		t.Fatal("continuation renewed forward authority")
	}
	h.prepare(ContinuationInverse)
	h.git()
	h.finalize()
	h.ready()
	h.intent()
	pending := h.p.Pending.Command
	h.renew(h.now.Add(31 * time.Second))
	if _, err = AuthorizeContinuationDispatch(h.ctx, h.view, old.keys, h.memory, Digest(pending), ContinuationInverse, h.now); err == nil {
		t.Fatal("head renewal revived old intent")
	}
	// A genuine NO_APPLY keeps Git-only repair required; it cannot silently free
	// the workload or consume the original stack after a failed inverse.
	h.issue(ContinuationNoApply, pending.Before, journalAtRevision(pending.Before, pending.Revision))
	if h.p.GitDuty == nil || len(h.p.Stack) != 1 {
		t.Fatal("no-apply erased Git/native obligations")
	}
}

func TestContinuationIdentityAuthorityIsChainAndCommittedRootScoped(t *testing.T) {
	h := newContinuationFixture(t)
	h.old.forward(1)
	h.old.forward(2)
	h.open()
	h.prepare(ContinuationInverse)
	current := h.memory.cursor
	forged := current.Identities
	forged.ChainID = "foreign-chain"
	if _, _, err := h.memory.LookupIdentity(h.ctx, current.ChainID, forged, ContinuationIdentityKey{"NONCE", "chain-authorization-nonce"}); err == nil {
		t.Fatal("cross-chain anchor accepted")
	}
	forged = current.Identities
	forged.SHA256 = sha("f")
	if _, _, err := h.memory.LookupIdentity(h.ctx, current.ChainID, forged, ContinuationIdentityKey{"NONCE", "missing"}); err == nil {
		t.Fatal("uncommitted anchor certified absence")
	}
	original := h.view
	h.memory.cursor.HeadSHA256 = sha("a")
	if _, err := VerifyContinuation(h.ctx, original, h.old.keys, h.memory, h.now); err == nil {
		t.Fatal("caller-owned current head accepted")
	}
	h.memory.cursor = current
	// Changing a nonce alone cannot borrow an already-reserved operation ID.
	c := h.p.Pending.Command
	c.ID = "different-command"
	c.Nonce = "different-nonce"
	c.Head = h.view.Head
	c.Fence++
	c.CreatedAt = h.now
	h.issue(ContinuationNoApply, h.p.Pending.Command.Before, h.p.Pending.Command.Before)
	c.Head = h.view.Head
	c.CreatedAt = h.now
	if _, err := h.append(ContinuationRecord{Kind: ContinuationPreparing, Command: &c}); err == nil {
		t.Fatal("operation identity reused across commands")
	}
}
