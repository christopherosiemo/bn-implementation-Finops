package fleetgroup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"time"
)

func continuationOnePayload(r ContinuationRecord) bool {
	n := 0
	for _, ok := range []bool{r.Command != nil, r.Finalization != nil, r.Receipt != nil, r.OriginalReceipt != nil} {
		if ok {
			n++
		}
	}
	return n == 1
}
func continuationClaim(s *continuationIdentities, namespace, id, hash string) error {
	_, err := s.issue(ContinuationIdentity{ContinuationIdentityKey{namespace, id}, hash}, false)
	return err
}
func continuationValidateCommand(c ContinuationCommand, p ContinuationProjection, o ContinuationOrigin, at time.Time) error {
	if !idPattern.MatchString(c.ID) || !idPattern.MatchString(c.OperationID) || !idPattern.MatchString(c.IdempotencyKey) || !idPattern.MatchString(c.Nonce) || c.Fence <= p.LastFence || c.Before != p.Current || !canonicalTime(c.CreatedAt) || c.CreatedAt.After(at) || at.Sub(c.CreatedAt) > 5*time.Minute || !validGitRevision(c.Revision, o.Parent.Program.ArtifactContext.ConfigurationSHA256) || c.Revision.Commit == p.Current.Revision.Commit {
		return invalid("CONTINUATION_COMMAND_INVALID")
	}
	for _, entry := range o.Parent.Program.Manifest.Entries {
		if entry.Revision.Commit == c.Revision.Commit {
			return invalid("CONTINUATION_MUST_APPEND_NEW_COMMIT")
		}
	}
	if c.Mode == ContinuationInverse {
		if p.GitDuty != nil || len(p.Stack) == 0 {
			return invalid("CONTINUATION_TOP_EFFECT_REQUIRED")
		}
		top := p.Stack[len(p.Stack)-1]
		if c.ObligationSHA256 != Digest(top) || c.Before.Model != top.Forward.Child.Artifact.After || c.After != top.Forward.Child.Artifact.Before {
			return invalid("CONTINUATION_NOT_EXACT_INVERSE")
		}
	} else if c.Mode == ContinuationRepair {
		if p.GitDuty == nil || c.ObligationSHA256 != Digest(*p.GitDuty) || c.Before != p.GitDuty.Current || c.After != c.Before.Model {
			return invalid("CONTINUATION_GIT_DUTY_REQUIRED")
		}
	} else {
		return invalid("CONTINUATION_FORWARD_FORBIDDEN")
	}
	desired, err := GitFixtureDesired(o.Parent.Program, c.After)
	if err != nil {
		return err
	}
	if c.Revision.DesiredSHA256 != BytesDigest(desired) {
		return invalid("CONTINUATION_DESIRED_INVALID")
	}
	return nil
}
func continuationValidateFinalization(f ContinuationFinalization, v ContinuationView, p ContinuationProjection, head ContinuationHeadEnvelope, at time.Time, allowIntent bool) error {
	q := p.Pending
	if q == nil || q.ApplyIntent && !allowIntent {
		return invalid("CONTINUATION_PREPARED_COMMAND_REQUIRED")
	}
	c := q.Command
	if f.SchemaVersion != ContinuationSchemaVersion || !idPattern.MatchString(f.ID) || !idPattern.MatchString(f.Nonce) || f.ChainSHA256 != Digest(v.Authorization) || f.CommandSHA256 != Digest(c) || f.SigningHeadSHA256 != Digest(head) {
		return invalid("CONTINUATION_FINALIZATION_BINDING_INVALID")
	}
	if !canonicalTime(f.CreatedAt) || !canonicalTime(f.ExpiresAt) || f.CreatedAt.Before(c.CreatedAt) || f.CreatedAt.After(at.Add(5*time.Second)) || at.Sub(f.CreatedAt) > 5*time.Minute || !f.ExpiresAt.After(at) || f.ExpiresAt.Sub(f.CreatedAt) > 15*time.Minute {
		return invalid("CONTINUATION_FINALIZATION_STALE")
	}
	required := []string{"FIXTURE_CURRENT"}
	if c.Mode == ContinuationInverse {
		if len(p.Stack) == 0 || c.ObligationSHA256 != Digest(p.Stack[len(p.Stack)-1]) {
			return invalid("CONTINUATION_TOP_EFFECT_REQUIRED")
		}
		a := f.Artifact
		if err := gitArtifactBinding(a, v.Origin.Parent.Program); err != nil {
			return err
		}
		if a.ManifestEntrySHA256 != "" || a.PreviousRevision != c.Before.Revision || a.Revision != c.Revision || a.BeforeStateSerial != c.Before.StateSerial || a.BeforeStateSHA256 != c.Before.StateSHA256 || a.Before != c.Before.Model || a.After != c.After {
			return invalid("CONTINUATION_NOT_EXACT_INVERSE")
		}
		required = append(required, "FIXTURE_RECOVERY_SLO")
	} else if c.Mode == ContinuationRepair {
		if p.GitDuty == nil || c.ObligationSHA256 != Digest(*p.GitDuty) || f.Artifact != (GitArtifact{}) {
			return invalid("CONTINUATION_REPAIR_MUST_NOT_APPLY_TERRAFORM")
		}
	} else {
		return invalid("CONTINUATION_FORWARD_FORBIDDEN")
	}
	return evidence(f.Evidence, required, v.Origin.Parent.Program.Binding, v.Origin.Parent.Program.Realm, at, f.ExpiresAt, true)
}
func SignContinuationFinalization(ctx context.Context, f ContinuationFinalization, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, key ed25519.PrivateKey, now time.Time) (ContinuationFinalizationEnvelope, error) {
	if len(key) != 64 || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Signer) {
		return ContinuationFinalizationEnvelope{}, invalid("CONTINUATION_SIGNING_KEY_INVALID")
	}
	p, err := VerifyContinuation(ctx, v, keys, authority, now)
	if err != nil {
		return ContinuationFinalizationEnvelope{}, err
	}
	if err = continuationValidateFinalization(f, v, p, v.Head, now, false); err != nil {
		return ContinuationFinalizationEnvelope{}, err
	}
	return ContinuationFinalizationEnvelope{f, v.Head, continuationFinalizationAlgorithm, journalSignature(continuationFinalizationDomain, f, key)}, nil
}
func SignContinuationReceipt(r ContinuationReceipt, key ed25519.PrivateKey) (ContinuationReceiptEnvelope, error) {
	if len(key) != 64 {
		return ContinuationReceiptEnvelope{}, invalid("CONTINUATION_PIPELINE_KEY_INVALID")
	}
	return ContinuationReceiptEnvelope{r, continuationReceiptAlgorithm, journalSignature(continuationReceiptDomain, r, key)}, nil
}
func continuationRepairApplied(p *ContinuationProjection, id string) error {
	if p.RepairCount == math.MaxUint64 {
		return invalid("CONTINUATION_ORDINAL_EXHAUSTED_TAKEOVER_REQUIRED")
	}
	p.RepairCount++
	p.RepairRootSHA256 = Digest(struct{ Previous, ID string }{p.RepairRootSHA256, id})
	return nil
}
func continuationConsume(p *ContinuationProjection, effect string) error {
	if len(p.Stack) == 0 || p.Stack[len(p.Stack)-1].ID != effect {
		return invalid("CONTINUATION_TOP_EFFECT_REQUIRED")
	}
	for _, id := range p.Consumed {
		if id == effect {
			return invalid("CONTINUATION_EFFECT_ALREADY_CONSUMED")
		}
	}
	p.Consumed = append(p.Consumed, effect)
	p.Stack = p.Stack[:len(p.Stack)-1]
	return nil
}
func continuationClaimReceipt(ids *continuationIdentities, id, key, hash string) error {
	if err := continuationClaim(ids, "RECEIPT_ID", id, hash); err != nil {
		return err
	}
	return continuationClaim(ids, "RECEIPT_KEY", key, hash)
}

func continuationReduce(ctx context.Context, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, now time.Time) (ContinuationProjection, []ContinuationIdentity, error) {
	var zero ContinuationProjection
	if authority == nil {
		return zero, nil, invalid("CONTINUATION_SERVER_AUTHORITY_REQUIRED")
	}
	if err := validateContinuationAuthorization(v.Authorization, v.Origin, keys, now); err != nil {
		return zero, nil, err
	}
	p, err := continuationSeed(v.Authorization, v.Checkpoint, v.Origin, keys)
	if err != nil {
		return p, nil, err
	}
	if v.Checkpoint.Checkpoint.CreatedAt.After(now.Add(5 * time.Second)) {
		return p, nil, invalid("CONTINUATION_CHECKPOINT_FUTURE")
	}
	if len(v.Records) > v.Authorization.Authorization.RecordLimit {
		return p, nil, invalid("CONTINUATION_SEGMENT_FULL_ROTATE_REQUIRED")
	}
	if v.Checkpoint.Checkpoint.GlobalCount > math.MaxUint64-uint64(len(v.Records)) {
		return p, nil, invalid("CONTINUATION_ORDINAL_EXHAUSTED_TAKEOVER_REQUIRED")
	}
	ids := newContinuationIdentities(ctx, authority, p.Identities)
	previous, last := Digest(v.Checkpoint), v.Checkpoint.Checkpoint.CreatedAt
	size := 0
	for i, r := range v.Records {
		raw, err := json.Marshal(r)
		if err != nil || len(raw)+1 > JournalRecordByteLimit {
			return p, nil, invalid("CONTINUATION_RECORD_BOUNDS")
		}
		size += len(raw) + 1
		if size > v.Authorization.Authorization.ByteLimit {
			return p, nil, invalid("CONTINUATION_SEGMENT_FULL_ROTATE_REQUIRED")
		}
		if r.Sequence != uint64(i+1) || r.PreviousSHA256 != previous || !canonicalTime(r.RecordedAt) || r.RecordedAt.Before(last) || r.RecordedAt.After(now.Add(5*time.Second)) || !continuationOnePayload(r) {
			return p, nil, invalid("CONTINUATION_EVENT_CHAIN_INVALID")
		}
		previous, last = Digest(r), r.RecordedAt
		prefix := v
		prefix.Records = v.Records[:i]
		switch r.Kind {
		case ContinuationPreparing:
			if r.Command == nil || p.Pending != nil || p.OriginalPending != nil {
				return p, nil, invalid("CONTINUATION_UNRESOLVED_DUTY")
			}
			c := *r.Command
			prefix.Head = c.Head
			if err = verifyContinuationHead(prefix, p, keys, c.CreatedAt); err != nil {
				return p, nil, err
			}
			if err = continuationValidateCommand(c, p, v.Origin, r.RecordedAt); err != nil {
				return p, nil, err
			}
			h := Digest(c)
			for _, pair := range []ContinuationIdentityKey{{"COMMAND_ID", c.ID}, {"OPERATION_ID", c.OperationID}, {"COMMAND_KEY", c.IdempotencyKey}, {"NONCE", c.Nonce}} {
				if err = continuationClaim(ids, pair.Namespace, pair.ID, h); err != nil {
					return p, nil, err
				}
			}
			p.LastFence = c.Fence
			p.Pending = &ContinuationPending{Command: c, Phase: ContinuationPreparing}
		case ContinuationFinalized:
			if r.Finalization == nil || p.Pending == nil || p.Pending.Phase == ContinuationUnknown || p.Pending.ApplyIntent {
				return p, nil, invalid("CONTINUATION_PREPARED_COMMAND_REQUIRED")
			}
			f := *r.Finalization
			if f.Algorithm != continuationFinalizationAlgorithm || !journalVerify(continuationFinalizationDomain, f.Finalization, f.Signature, keys.Signer) {
				return p, nil, invalid("CONTINUATION_FINALIZATION_SIGNATURE_INVALID")
			}
			prefix.Head = f.Head
			if err = verifyContinuationHead(prefix, p, keys, r.RecordedAt); err != nil {
				return p, nil, err
			}
			if err = continuationValidateFinalization(f.Finalization, v, p, f.Head, r.RecordedAt, false); err != nil {
				return p, nil, err
			}
			for _, k := range []ContinuationIdentityKey{{"SIGNED_ID", f.Finalization.ID}, {"NONCE", f.Finalization.Nonce}} {
				if err = continuationClaim(ids, k.Namespace, k.ID, Digest(f.Finalization)); err != nil {
					return p, nil, err
				}
			}
			p.Pending.Finalized = &f
			p.Pending.ReadyUntil = time.Time{}
			p.Pending.Phase = ContinuationFinalized
		case ContinuationLegacy:
			if r.OriginalReceipt == nil {
				return p, nil, invalid("CONTINUATION_ORIGINAL_RECEIPT_REQUIRED")
			}
			if err = continuationOriginalOutcome(&p, *r.OriginalReceipt, v.Origin, keys, r.RecordedAt); err != nil {
				return p, nil, err
			}
			body := r.OriginalReceipt.Receipt
			if err = continuationClaimReceipt(ids, body.ID, body.IdempotencyKey, Digest(body)); err != nil {
				return p, nil, err
			}
		default:
			if r.Receipt == nil {
				return p, nil, invalid("CONTINUATION_RECEIPT_REQUIRED")
			}
			e := *r.Receipt
			body := e.Receipt
			if e.Algorithm != continuationReceiptAlgorithm || !journalVerify(continuationReceiptDomain, body, e.Signature, keys.Pipeline) || body.Kind != r.Kind {
				return p, nil, invalid("CONTINUATION_PIPELINE_SIGNATURE_INVALID")
			}
			if err = continuationReceiptOutcome(&p, body, v, r.RecordedAt); err != nil {
				return p, nil, err
			}
			if err = continuationClaimReceipt(ids, body.ID, body.IdempotencyKey, Digest(body)); err != nil {
				return p, nil, err
			}
		}
		p.Identities = ids.current
	}
	return p, ids.added, nil
}
func VerifyContinuation(ctx context.Context, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, now time.Time) (ContinuationProjection, error) {
	p, _, err := continuationReduce(ctx, v, keys, authority, now)
	if err != nil {
		return p, err
	}
	if err = verifyContinuationHead(v, p, keys, now); err != nil {
		return p, err
	}
	err = continuationCurrent(ctx, authority, v.Authorization.Authorization.ChainID, continuationCursor(v))
	return p, err
}
func continuationReplayRequest(ctx context.Context, r ContinuationRecord, p ContinuationProjection, v ContinuationView, keys JournalKeys, a ContinuationAuthority) (bool, error) {
	ids := newContinuationIdentities(ctx, a, p.Identities)
	var pairs []ContinuationIdentity
	if r.Receipt != nil {
		e := r.Receipt
		if e.Algorithm != continuationReceiptAlgorithm || e.Receipt.Kind != r.Kind || !journalVerify(continuationReceiptDomain, e.Receipt, e.Signature, keys.Pipeline) {
			return false, invalid("CONTINUATION_PIPELINE_SIGNATURE_INVALID")
		}
		h := Digest(e.Receipt)
		pairs = []ContinuationIdentity{{ContinuationIdentityKey{"RECEIPT_ID", e.Receipt.ID}, h}, {ContinuationIdentityKey{"RECEIPT_KEY", e.Receipt.IdempotencyKey}, h}}
	}
	if r.OriginalReceipt != nil {
		e := r.OriginalReceipt
		if r.Kind != ContinuationLegacy || e.Algorithm != journalReceiptAlgorithm || !journalVerify(journalReceiptDomain, e.Receipt, e.Signature, keys.Pipeline) {
			return false, invalid("CONTINUATION_ORIGINAL_RECEIPT_INVALID")
		}
		switch e.Receipt.Kind {
		case JournalUnknown, JournalGitAdvanced, JournalNoApply, JournalApplied, JournalGitRepaired:
		default:
			return false, invalid("CONTINUATION_ORIGINAL_NEW_DISPATCH_FORBIDDEN")
		}
		h := Digest(e.Receipt)
		pairs = []ContinuationIdentity{{ContinuationIdentityKey{"RECEIPT_ID", e.Receipt.ID}, h}, {ContinuationIdentityKey{"RECEIPT_KEY", e.Receipt.IdempotencyKey}, h}}
	}
	if r.Command != nil && r.Kind == ContinuationPreparing {
		pairs = []ContinuationIdentity{{ContinuationIdentityKey{"COMMAND_ID", r.Command.ID}, Digest(*r.Command)}}
	}
	if r.Finalization != nil && r.Kind == ContinuationFinalized {
		e := r.Finalization
		if e.Algorithm != continuationFinalizationAlgorithm || !journalVerify(continuationFinalizationDomain, e.Finalization, e.Signature, keys.Signer) {
			return false, invalid("CONTINUATION_FINALIZATION_SIGNATURE_INVALID")
		}
		pairs = []ContinuationIdentity{{ContinuationIdentityKey{"SIGNED_ID", e.Finalization.ID}, Digest(e.Finalization)}}
	}
	found := 0
	for _, entry := range pairs {
		old, ok, err := ids.find(entry.Key)
		if err != nil {
			return false, err
		}
		if ok {
			if old.SHA256 != entry.SHA256 {
				return false, invalid("CONTINUATION_IDENTITY_REPLAY_CONFLICT")
			}
			found++
		}
	}
	if found > 0 && found != len(pairs) {
		return false, invalid("CONTINUATION_IDENTITY_REPLAY_CONFLICT")
	}
	return found > 0, nil
}
func AppendContinuationRecord(ctx context.Context, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, ledger ed25519.PrivateKey, r ContinuationRecord, now time.Time) (ContinuationTransition, error) {
	var out ContinuationTransition
	if len(ledger) != 64 || !bytes.Equal(ledger.Public().(ed25519.PublicKey), keys.Ledger) {
		return out, invalid("CONTINUATION_LEDGER_KEY_INVALID")
	}
	p, err := VerifyContinuation(ctx, v, keys, authority, now)
	if err != nil {
		return out, err
	}
	expected := continuationCursor(v)
	if !continuationOnePayload(r) {
		return out, invalid("CONTINUATION_EVENT_CHAIN_INVALID")
	}
	replay, err := continuationReplayRequest(ctx, r, p, v, keys, authority)
	if err != nil {
		return out, err
	}
	if replay {
		return ContinuationTransition{Expected: expected, Next: expected, View: v, Projection: p, Replayed: true}, nil
	}
	_, oldEntries, err := continuationReduce(ctx, v, keys, authority, now)
	if err != nil {
		return out, err
	}
	candidate := continuationClone(v)
	candidate.Records = append(candidate.Records, r)
	next, entries, err := continuationReduce(ctx, candidate, keys, authority, now)
	if err != nil {
		return out, err
	}
	candidate.Head = continuationHead(candidate, next, ledger, now)
	return ContinuationTransition{Expected: expected, Next: continuationCursor(candidate), View: candidate, Projection: next, Identities: entries[len(oldEntries):]}, nil
}

// Renewal changes only the issued observation of the same committed head. It
// cannot refresh a command/evidence/READY lifetime or change a recovery duty.
func RenewContinuationHead(ctx context.Context, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, ledger ed25519.PrivateKey, now time.Time) (ContinuationTransition, error) {
	var out ContinuationTransition
	if len(ledger) != 64 || !bytes.Equal(ledger.Public().(ed25519.PublicKey), keys.Ledger) {
		return out, invalid("CONTINUATION_LEDGER_KEY_INVALID")
	}
	p, _, err := continuationReduce(ctx, v, keys, authority, now)
	if err != nil {
		return out, err
	}
	if v.Head.Head.ObservedAt.After(now.Add(5 * time.Second)) {
		return out, invalid("CONTINUATION_HEAD_STALE")
	}
	if err = verifyContinuationHead(v, p, keys, v.Head.Head.ObservedAt); err != nil {
		return out, err
	}
	expected := continuationCursor(v)
	if err = continuationCurrent(ctx, authority, v.Authorization.Authorization.ChainID, expected); err != nil {
		return out, err
	}
	v.Head = continuationHead(v, p, ledger, now)
	return ContinuationTransition{Expected: expected, Next: continuationCursor(v), View: v, Projection: p}, nil
}
