package fleetgroup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"time"
)

const (
	continuationAuthorizationDomain    = "finops/fleet-group/continuation/v1/isolated-fixture/authorization\x00"
	continuationCheckpointDomain       = "finops/fleet-group/continuation/v1/isolated-fixture/checkpoint\x00"
	continuationHeadDomain             = "finops/fleet-group/continuation/v1/isolated-fixture/head\x00"
	continuationFinalizationDomain     = "finops/fleet-group/continuation/v1/isolated-fixture/recovery-artifact\x00"
	continuationReceiptDomain          = "finops/fleet-group/continuation/v1/isolated-fixture/pipeline-receipt\x00"
	continuationAuthorizationAlgorithm = "Ed25519-FleetGroupContinuation-v1-authorization"
	continuationCheckpointAlgorithm    = "Ed25519-FleetGroupContinuation-v1-checkpoint"
	continuationHeadAlgorithm          = "Ed25519-FleetGroupContinuation-v1-head"
	continuationFinalizationAlgorithm  = "Ed25519-FleetGroupContinuation-v1-recovery-artifact"
	continuationReceiptAlgorithm       = "Ed25519-FleetGroupContinuation-v1-pipeline-receipt"
)
const continuationCheckpointLimit = 8 << 20

func continuationAuthorizationMessage(a ContinuationAuthorization, p []ContinuationApproval) any {
	return struct {
		Authorization ContinuationAuthorization
		Approvals     []ContinuationApproval
	}{a, p}
}
func ContinuationOriginalCursor(chainID string, v JournalView) ContinuationCursor {
	return ContinuationCursor{ChainID: chainID, Kind: ContinuationOriginal, RecordCount: len(v.Records), GlobalCount: uint64(len(v.Records)), HeadSHA256: Digest(v.Head), ProjectionSHA256: v.Head.Head.ProjectionSHA256, Identities: ContinuationIdentityAnchor{ChainID: chainID}}
}
func continuationCurrent(ctx context.Context, a ContinuationAuthority, chain string, want ContinuationCursor) error {
	if a == nil {
		return invalid("CONTINUATION_SERVER_AUTHORITY_REQUIRED")
	}
	actual, err := a.Current(ctx, chain)
	if err != nil {
		return err
	}
	if actual != want || actual.ChainID != chain {
		return invalid("CONTINUATION_SERVER_CURRENT_HEAD_REQUIRED")
	}
	return nil
}
func validateContinuationAuthorization(e ContinuationEnvelope, o ContinuationOrigin, keys JournalKeys, now time.Time) error {
	a := e.Authorization
	p := o.Parent.Program
	if !journalKeySet(keys) || e.Algorithm != continuationAuthorizationAlgorithm || !journalVerify(continuationAuthorizationDomain, continuationAuthorizationMessage(a, e.Approvals), e.Signature, keys.Signer) {
		return invalid("CONTINUATION_AUTHORIZATION_SIGNATURE_INVALID")
	}
	if err := validateJournalAuthorization(o.Authorization, o.Parent, keys, a.CreatedAt); err != nil {
		return err
	}
	if a.SchemaVersion != ContinuationSchemaVersion || !idPattern.MatchString(a.ID) || !idPattern.MatchString(a.ChainID) || a.Policy != ContinuationPolicy || a.ParentEnvelopeSHA256 != Digest(o.Parent) || a.JournalAuthorizationSHA256 != Digest(o.Authorization) || a.BindingSHA256 != Digest(p.Binding) || a.RealmSHA256 != Digest(p.Realm) || a.SignerKeySHA256 != BytesDigest(keys.Signer) || a.PipelineKeySHA256 != BytesDigest(keys.Pipeline) || a.LedgerKeySHA256 != BytesDigest(keys.Ledger) || a.RecordLimit < 8 || a.RecordLimit > 512 || a.ByteLimit < a.RecordLimit*JournalRecordByteLimit || a.ByteLimit > JournalByteLimit || !idPattern.MatchString(a.Nonce) || a.Nonce == p.Nonce || a.Nonce == o.Authorization.Authorization.Nonce {
		return invalid("CONTINUATION_AUTHORIZATION_BINDING_INVALID")
	}
	if !canonicalTime(now) || !canonicalTime(a.CreatedAt) || a.CreatedAt.Before(o.Authorization.Authorization.CreatedAt) || a.CreatedAt.After(now.Add(5*time.Second)) || a.ForwardExpiresAt != o.Authorization.Authorization.ExpiresAt || !a.ForwardExpiresAt.After(a.CreatedAt) {
		return invalid("CONTINUATION_AUTHORIZATION_LIFETIME_INVALID")
	}
	base := JournalProjection{Current: o.Authorization.Authorization.Base, Stack: []JournalEffect{}, Consumed: []string{}, GitRepairs: []string{}}
	if err := verifyJournalHead(a.BootstrapHead, o.Authorization, nil, base, keys, JournalExpectedHead(o.Authorization, nil), a.CreatedAt); err != nil {
		return invalid("CONTINUATION_PRECOMMAND_BOOTSTRAP_REQUIRED")
	}
	if len(e.Approvals) < 1 || len(e.Approvals) > 16 {
		return invalid("CONTINUATION_INDEPENDENT_APPROVAL_REQUIRED")
	}
	ids, actors := map[string]bool{}, map[string]bool{}
	for _, ap := range e.Approvals {
		if !idPattern.MatchString(ap.ID) || ids[ap.ID] || !idPattern.MatchString(ap.ActorID) || actors[ap.ActorID] || ap.ActorID == p.CreatorID || ap.TenantID != p.Binding.Old.Target.TenantID || ap.Role != ApproverRole || ap.AuthorizationSHA256 != Digest(a) || !canonicalTime(ap.ApprovedAt) || ap.ApprovedAt.Before(a.CreatedAt) || ap.ApprovedAt.After(a.CreatedAt.Add(ContinuationDraftReviewWindow)) || ap.ApprovedAt.After(now.Add(5*time.Second)) || !ap.ApprovedAt.Before(a.ForwardExpiresAt) {
			return invalid("CONTINUATION_APPROVAL_INVALID")
		}
		ids[ap.ID], actors[ap.ActorID] = true, true
	}
	return nil
}
func SignContinuationAuthorization(ctx context.Context, a ContinuationAuthorization, p []ContinuationApproval, v JournalView, keys JournalKeys, authority ContinuationAuthority, key ed25519.PrivateKey, now time.Time) (ContinuationEnvelope, error) {
	if len(key) != 64 || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Signer) {
		return ContinuationEnvelope{}, invalid("CONTINUATION_SIGNING_KEY_INVALID")
	}
	draft, current := a.BootstrapHead.Head, v.Head.Head
	if len(v.Records) != 0 || draft.JournalID != current.JournalID || draft.AuthorizationSHA256 != current.AuthorizationSHA256 || draft.Ref != current.Ref || draft.ProjectionSHA256 != current.ProjectionSHA256 || !a.ForwardExpiresAt.After(now) || now.Before(a.CreatedAt) || now.After(a.CreatedAt.Add(ContinuationDraftReviewWindow)) {
		return ContinuationEnvelope{}, invalid("CONTINUATION_APPROVAL_BEFORE_FIRST_COMMAND_REQUIRED")
	}
	if err := continuationCurrent(ctx, authority, a.ChainID, ContinuationOriginalCursor(a.ChainID, v)); err != nil {
		return ContinuationEnvelope{}, err
	}
	if _, err := VerifyJournal(v, keys, v.Head.Head.Ref, now); err != nil {
		return ContinuationEnvelope{}, err
	}
	// The old approved zero head is historical draft context. Only the fresh
	// server-resolved zero head above certifies absence of an intervening command.
	program := v.Parent.Program
	if err := VerifyGitProgram(v.Parent, keys.Signer, Expected{program.Binding, program.Realm}, now); err != nil {
		return ContinuationEnvelope{}, err
	}
	if now.Add(time.Duration(GitMinimumProgramDuration(program)) * time.Second).After(GitForwardDeadline(program)) {
		return ContinuationEnvelope{}, invalid("CONTINUATION_FORWARD_PROGRAM_WINDOW_UNAVAILABLE")
	}
	e := ContinuationEnvelope{a, p, continuationAuthorizationAlgorithm, journalSignature(continuationAuthorizationDomain, continuationAuthorizationMessage(a, p), key)}
	if err := validateContinuationAuthorization(e, ContinuationOrigin{v.Parent, v.Authorization}, keys, now); err != nil {
		return ContinuationEnvelope{}, err
	}
	return e, nil
}

// This verifies the immutable historical envelope. Attaching it to a repository
// additionally requires the ORIGINAL zero-record cursor CAS, as signing does.
func VerifyContinuationAuthorization(e ContinuationEnvelope, o ContinuationOrigin, keys JournalKeys, now time.Time) error {
	return validateContinuationAuthorization(e, o, keys, now)
}

func continuationRepairRoot(chain string) string {
	return Digest(struct{ Domain, Chain string }{"continuation-git-repairs-v1", chain})
}
func continuationFromOriginal(p JournalProjection, chain string) ContinuationProjection {
	p = continuationClone(p)
	out := ContinuationProjection{RecoveryOnly: true, Current: p.Current, Stack: p.Stack, Consumed: p.Consumed, OriginalPending: p.Pending, LastFence: p.LastFence, RepairRootSHA256: continuationRepairRoot(chain)}
	for _, id := range p.GitRepairs {
		out.RepairCount++
		out.RepairRootSHA256 = Digest(struct{ Previous, ID string }{out.RepairRootSHA256, id})
	}
	if out.OriginalPending != nil && out.OriginalPending.GitAdvanced {
		c := out.OriginalPending.Command
		out.Current = journalAtRevision(c.Before, c.Preparation.Revision)
	}
	if out.OriginalPending != nil && out.OriginalPending.NoApply != nil && out.OriginalPending.GitRepair == nil {
		q := out.OriginalPending
		c := q.Command
		out.GitDuty = &ContinuationGitDuty{c.ID, Digest(c), c.OperationID, c.Fence, c.Before, q.NoApply.Receipt.After, Digest(*q.NoApply)}
		out.Current = q.NoApply.Receipt.After
		out.OriginalPending = nil
	}
	return out
}
func continuationCheckpointNonce(c ContinuationCheckpoint) ContinuationIdentity {
	return ContinuationIdentity{ContinuationIdentityKey{"NONCE", c.Nonce}, Digest(struct {
		Chain   string
		Segment uint64
		Source  string
		Nonce   string
	}{c.ChainSHA256, c.Segment, c.SourceHeadSHA256, c.Nonce})}
}
func continuationSourceFresh(at, observed, until time.Time) bool {
	return canonicalTime(at) && canonicalTime(observed) && canonicalTime(until) && !observed.After(at.Add(5*time.Second)) && at.Sub(observed) <= 5*time.Minute && until.After(at) && until.Sub(observed) <= 5*time.Minute
}
func continuationSeed(e ContinuationEnvelope, c ContinuationCheckpointEnvelope, o ContinuationOrigin, keys JournalKeys) (ContinuationProjection, error) {
	b := c.Checkpoint
	var p ContinuationProjection
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > continuationCheckpointLimit {
		return p, invalid("CONTINUATION_CHECKPOINT_BOUNDS")
	}
	if c.Algorithm != continuationCheckpointAlgorithm || !journalVerify(continuationCheckpointDomain, b, c.Signature, keys.Ledger) || b.SchemaVersion != ContinuationSchemaVersion || b.ChainSHA256 != Digest(e) || b.Segment < 1 || !canonicalTime(b.CreatedAt) || !idPattern.MatchString(b.Nonce) {
		return p, invalid("CONTINUATION_CHECKPOINT_INVALID")
	}
	anchor := continuationIdentityRoot(e)
	if b.SourceKind == ContinuationOriginal {
		if b.Segment != 1 || b.OriginalHead == nil || b.OriginalProjection == nil || b.PriorHead != nil || b.PriorProjection != nil || b.GlobalCount != uint64(b.OriginalHead.Head.Ref.RecordCount) || b.SourceHeadSHA256 != Digest(*b.OriginalHead) || b.OriginalHead.Algorithm != journalHeadAlgorithm || !journalVerify(journalHeadDomain, b.OriginalHead.Head, b.OriginalHead.Signature, keys.Ledger) || b.OriginalHead.Head.JournalID != o.Authorization.Authorization.JournalID || b.OriginalHead.Head.AuthorizationSHA256 != Digest(o.Authorization) || b.OriginalHead.Head.ProjectionSHA256 != Digest(*b.OriginalProjection) || !continuationSourceFresh(b.CreatedAt, b.OriginalHead.Head.ObservedAt, b.OriginalHead.Head.ValidUntil) || len(b.ImportedIdentities) > 16384 {
			return p, invalid("CONTINUATION_ORIGINAL_CHECKPOINT_INVALID")
		}
		p = continuationFromOriginal(*b.OriginalProjection, e.Authorization.ChainID)
		seen := map[string]bool{}
		for _, entry := range b.ImportedIdentities {
			code := continuationIdentityCode(entry.Key)
			if seen[code] {
				return p, invalid("CONTINUATION_IMPORTED_IDENTITY_DUPLICATE")
			}
			seen[code] = true
			anchor, err = continuationIdentityAdd(anchor, entry)
			if err != nil {
				return p, err
			}
		}
	} else if b.SourceKind == ContinuationSegment {
		if b.OriginalHead != nil || b.OriginalProjection != nil || b.PriorHead == nil || b.PriorProjection == nil || len(b.ImportedIdentities) != 0 || b.Segment != b.PriorHead.Head.Segment+1 || b.SourceHeadSHA256 != Digest(*b.PriorHead) || b.GlobalCount != b.PriorHead.Head.GlobalCount || b.PriorHead.Algorithm != continuationHeadAlgorithm || !journalVerify(continuationHeadDomain, b.PriorHead.Head, b.PriorHead.Signature, keys.Ledger) || b.PriorHead.Head.ChainSHA256 != Digest(e) || b.PriorHead.Head.ProjectionSHA256 != Digest(*b.PriorProjection) || b.PriorHead.Head.Identities != b.PriorProjection.Identities || !continuationSourceFresh(b.CreatedAt, b.PriorHead.Head.ObservedAt, b.PriorHead.Head.ValidUntil) {
			return p, invalid("CONTINUATION_PRIOR_SEGMENT_INVALID")
		}
		p = continuationClone(*b.PriorProjection)
		anchor = p.Identities
	} else {
		return p, invalid("CONTINUATION_CHECKPOINT_SOURCE_INVALID")
	}
	if !p.RecoveryOnly || len(p.Stack) > o.Authorization.Authorization.MaximumEffects || len(p.Consumed) > o.Authorization.Authorization.MaximumEffects || !journalStateValid(p.Current, o.Parent.Program) || !hashPattern.MatchString(p.RepairRootSHA256) || anchor.ChainID != e.Authorization.ChainID {
		return p, invalid("CONTINUATION_PROJECTION_INVALID")
	}
	anchor, err = continuationIdentityAdd(anchor, continuationCheckpointNonce(b))
	if err != nil {
		return p, err
	}
	if anchor != b.Identities {
		return p, invalid("CONTINUATION_IDENTITY_ROOT_INVALID")
	}
	p.Identities = anchor
	return p, nil
}
func continuationCursor(v ContinuationView) ContinuationCursor {
	h := v.Head.Head
	return ContinuationCursor{v.Authorization.Authorization.ChainID, ContinuationSegment, h.Segment, h.RecordCount, h.GlobalCount, Digest(v.Head), h.CheckpointSHA256, h.ProjectionSHA256, h.Identities}
}
func continuationHead(v ContinuationView, p ContinuationProjection, key ed25519.PrivateKey, now time.Time) ContinuationHeadEnvelope {
	last := Digest(v.Checkpoint)
	if len(v.Records) > 0 {
		last = Digest(v.Records[len(v.Records)-1])
	}
	h := ContinuationHead{Digest(v.Authorization), v.Checkpoint.Checkpoint.Segment, Digest(v.Checkpoint), len(v.Records), v.Checkpoint.Checkpoint.GlobalCount + uint64(len(v.Records)), last, Digest(p), p.Identities, now, now.Add(5 * time.Minute)}
	signature := ""
	if len(key) == ed25519.PrivateKeySize {
		signature = journalSignature(continuationHeadDomain, h, key)
	}
	return ContinuationHeadEnvelope{h, continuationHeadAlgorithm, signature}
}
func verifyContinuationHead(v ContinuationView, p ContinuationProjection, keys JournalKeys, at time.Time) error {
	h := v.Head
	expected := continuationHead(v, p, nil, at).Head
	// No signature is synthesized for validation; compare the exact structural
	// binding separately from the issued observation lifetime.
	expected.ObservedAt = h.Head.ObservedAt
	expected.ValidUntil = h.Head.ValidUntil
	if h.Algorithm != continuationHeadAlgorithm || !journalVerify(continuationHeadDomain, h.Head, h.Signature, keys.Ledger) || h.Head != expected {
		return invalid("CONTINUATION_HEAD_INVALID")
	}
	if !continuationSourceFresh(at, h.Head.ObservedAt, h.Head.ValidUntil) {
		return invalid("CONTINUATION_HEAD_STALE")
	}
	return nil
}

func OpenContinuationFromJournal(ctx context.Context, v JournalView, e ContinuationEnvelope, keys JournalKeys, authority ContinuationAuthority, ledger ed25519.PrivateKey, nonce string, now time.Time) (ContinuationTransition, error) {
	var out ContinuationTransition
	if len(ledger) != 64 || !bytes.Equal(ledger.Public().(ed25519.PublicKey), keys.Ledger) {
		return out, invalid("CONTINUATION_LEDGER_KEY_INVALID")
	}
	o := ContinuationOrigin{v.Parent, v.Authorization}
	if err := validateContinuationAuthorization(e, o, keys, now); err != nil {
		return out, err
	}
	expected := ContinuationOriginalCursor(e.Authorization.ChainID, v)
	if err := continuationCurrent(ctx, authority, e.Authorization.ChainID, expected); err != nil {
		return out, err
	}
	p, err := VerifyJournal(v, keys, v.Head.Head.Ref, now)
	if err != nil {
		return out, err
	}
	for _, record := range v.Records {
		if record.Kind == JournalPreparing && record.Command != nil {
			if record.Command.CreatedAt.Before(e.Authorization.CreatedAt) {
				return out, invalid("CONTINUATION_APPROVAL_BEFORE_FIRST_COMMAND_REQUIRED")
			}
			for _, approval := range e.Approvals {
				if approval.ApprovedAt.After(record.Command.CreatedAt) {
					return out, invalid("CONTINUATION_APPROVAL_BEFORE_FIRST_COMMAND_REQUIRED")
				}
			}
			break
		}
	}
	entries, err := continuationOriginalIdentities(e, v)
	if err != nil {
		return out, err
	}
	c := ContinuationCheckpoint{SchemaVersion: ContinuationSchemaVersion, ChainSHA256: Digest(e), Segment: 1, GlobalCount: uint64(len(v.Records)), SourceKind: ContinuationOriginal, SourceHeadSHA256: Digest(v.Head), OriginalHead: &v.Head, OriginalProjection: &p, ImportedIdentities: entries, CreatedAt: now, Nonce: nonce}
	anchor := continuationIdentityRoot(e)
	for _, x := range entries {
		anchor, err = continuationIdentityAdd(anchor, x)
		if err != nil {
			return out, err
		}
	}
	for _, x := range entries {
		if x.Key == continuationCheckpointNonce(c).Key {
			return out, invalid("CONTINUATION_NONCE_REUSED")
		}
	}
	c.Identities, err = continuationIdentityAdd(anchor, continuationCheckpointNonce(c))
	if err != nil {
		return out, err
	}
	checkpoint := ContinuationCheckpointEnvelope{c, continuationCheckpointAlgorithm, journalSignature(continuationCheckpointDomain, c, ledger)}
	seed, err := continuationSeed(e, checkpoint, o, keys)
	if err != nil {
		return out, err
	}
	next := ContinuationView{Origin: o, Authorization: e, Checkpoint: checkpoint, Records: []ContinuationRecord{}}
	next.Head = continuationHead(next, seed, ledger, now)
	return ContinuationTransition{Expected: expected, Next: continuationCursor(next), View: next, Projection: seed, Identities: append(entries, continuationCheckpointNonce(c))}, nil
}
func RotateContinuation(ctx context.Context, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, ledger ed25519.PrivateKey, nonce string, now time.Time) (ContinuationTransition, error) {
	var out ContinuationTransition
	if len(ledger) != 64 || !bytes.Equal(ledger.Public().(ed25519.PublicKey), keys.Ledger) {
		return out, invalid("CONTINUATION_LEDGER_KEY_INVALID")
	}
	p, err := VerifyContinuation(ctx, v, keys, authority, now)
	if err != nil {
		return out, err
	}
	if v.Head.Head.Segment == math.MaxUint64 {
		return out, invalid("CONTINUATION_ORDINAL_EXHAUSTED_TAKEOVER_REQUIRED")
	}
	identities := newContinuationIdentities(ctx, authority, p.Identities)
	c := ContinuationCheckpoint{SchemaVersion: ContinuationSchemaVersion, ChainSHA256: Digest(v.Authorization), Segment: v.Head.Head.Segment + 1, GlobalCount: v.Head.Head.GlobalCount, SourceKind: ContinuationSegment, SourceHeadSHA256: Digest(v.Head), PriorHead: &v.Head, PriorProjection: &p, CreatedAt: now, Nonce: nonce}
	if _, err = identities.issue(continuationCheckpointNonce(c), false); err != nil {
		return out, err
	}
	c.Identities = identities.current
	checkpoint := ContinuationCheckpointEnvelope{c, continuationCheckpointAlgorithm, journalSignature(continuationCheckpointDomain, c, ledger)}
	seed, err := continuationSeed(v.Authorization, checkpoint, v.Origin, keys)
	if err != nil {
		return out, err
	}
	next := ContinuationView{Origin: v.Origin, Authorization: v.Authorization, Checkpoint: checkpoint, Records: []ContinuationRecord{}}
	next.Head = continuationHead(next, seed, ledger, now)
	return ContinuationTransition{Expected: continuationCursor(v), Next: continuationCursor(next), View: next, Projection: seed, Identities: identities.added}, nil
}
