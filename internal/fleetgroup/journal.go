package fleetgroup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

const (
	journalAuthorizationDomain    = "finops/fleet-group/journal/v1/isolated-fixture/authorization\x00"
	journalReceiptDomain          = "finops/fleet-group/journal/v1/isolated-fixture/pipeline-receipt\x00"
	journalHeadDomain             = "finops/fleet-group/journal/v1/isolated-fixture/current-head\x00"
	journalRecoveryDomain         = "finops/fleet-group/journal/v1/isolated-fixture/owned-recovery\x00"
	journalGitRepairDomain        = "finops/fleet-group/journal/v1/isolated-fixture/git-only-repair\x00"
	journalAuthorizationAlgorithm = "Ed25519-FleetGroupJournal-v1-authorization"
	journalReceiptAlgorithm       = "Ed25519-FleetGroupJournal-v1-pipeline-receipt"
	journalHeadAlgorithm          = "Ed25519-FleetGroupJournal-v1-current-head"
	journalRecoveryAlgorithm      = "Ed25519-FleetGroupJournal-v1-owned-recovery"
	journalGitRepairAlgorithm     = "Ed25519-FleetGroupJournal-v1-git-only-repair"
)

func journalMessage(domain string, body any) []byte {
	raw, _ := json.Marshal(body)
	return append([]byte(domain), raw...)
}
func journalSignature(domain string, body any, key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, journalMessage(domain, body)))
}
func journalVerify(domain string, body any, signature string, key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	return e == nil && ed25519.Verify(key, journalMessage(domain, body), sig)
}
func journalKeySet(keys JournalKeys) bool {
	return len(keys.Signer) == 32 && len(keys.Pipeline) == 32 && len(keys.Ledger) == 32 && !bytes.Equal(keys.Signer, keys.Pipeline) && !bytes.Equal(keys.Signer, keys.Ledger) && !bytes.Equal(keys.Pipeline, keys.Ledger)
}
func journalAuthorizationMessage(a JournalAuthorization, approvals []JournalApproval) any {
	return struct {
		Authorization JournalAuthorization `json:"authorization"`
		Approvals     []JournalApproval    `json:"approvals"`
	}{a, approvals}
}

func validateJournalAuthorization(e JournalEnvelope, parent GitEnvelope, keys JournalKeys, now time.Time) error {
	a, p := e.Authorization, parent.Program
	if !journalKeySet(keys) || e.Algorithm != journalAuthorizationAlgorithm || !journalVerify(journalAuthorizationDomain, journalAuthorizationMessage(a, e.Approvals), e.Signature, keys.Signer) {
		return invalid("JOURNAL_AUTHORIZATION_SIGNATURE_INVALID")
	}
	if err := VerifyGitProgram(parent, keys.Signer, Expected{p.Binding, p.Realm}, a.CreatedAt); err != nil {
		return err
	}
	if a.SchemaVersion != JournalSchemaVersion || a.Kind != JournalKind || !idPattern.MatchString(a.ID) || !idPattern.MatchString(a.JournalID) || !idPattern.MatchString(a.Nonce) || a.Nonce == p.Nonce || a.ParentEnvelopeSHA256 != Digest(parent) || a.ParentSHA256 != Digest(p) || a.BindingSHA256 != Digest(p.Binding) || a.RealmSHA256 != Digest(p.Realm) || a.PipelineID != p.ArtifactContext.PipelineID || a.Ref != p.Manifest.Ref || a.Policy != JournalPolicy || a.PipelineKeySHA256 != BytesDigest(keys.Pipeline) || a.LedgerKeySHA256 != BytesDigest(keys.Ledger) {
		return invalid("JOURNAL_AUTHORIZATION_BINDING_INVALID")
	}
	if !canonicalTime(now) || !canonicalTime(a.CreatedAt) || !canonicalTime(a.ExpiresAt) || a.CreatedAt.Before(p.CreatedAt) || a.CreatedAt.After(now.Add(5*time.Second)) || !a.ExpiresAt.After(a.CreatedAt) || a.ExpiresAt.Sub(a.CreatedAt) > 24*time.Hour || a.ExpiresAt.Before(GitForwardDeadline(p)) || a.ExpiresAt.After(p.ExpiresAt) {
		return invalid("JOURNAL_AUTHORIZATION_LIFETIME_INVALID")
	}
	steps, _ := GitStageSpecifications(p)
	needed := len(steps) - 1
	if needed < 1 || a.MaximumEffects < needed || a.MaximumEffects > 32 || a.MaximumRecords < (2*len(steps)-1)*6+64 || a.MaximumRecords > 512 {
		return invalid("JOURNAL_POPULATION_UNSUPPORTED")
	}
	initial := p.Manifest.Entries[0].Before
	if a.Base.Revision != p.Manifest.Base || a.Base.StateLineage != p.ArtifactContext.StateLineage || a.Base.StateSerial != p.ArtifactContext.InitialStateSerial || !hashPattern.MatchString(a.Base.StateSHA256) || a.Base.Model != initial {
		return invalid("JOURNAL_BASE_STATE_INVALID")
	}
	if len(e.Approvals) < 1 || len(e.Approvals) > 16 {
		return invalid("JOURNAL_INDEPENDENT_APPROVAL_REQUIRED")
	}
	seen, actors := map[string]bool{}, map[string]bool{}
	for _, v := range e.Approvals {
		if !idPattern.MatchString(v.ID) || seen[v.ID] || !idPattern.MatchString(v.ActorID) || actors[v.ActorID] || v.ActorID == p.CreatorID || v.TenantID != p.Binding.Old.Target.TenantID || v.Role != ApproverRole || v.AuthorizationSHA256 != Digest(a) || !canonicalTime(v.ApprovedAt) || v.ApprovedAt.Before(a.CreatedAt) || v.ApprovedAt.After(now.Add(5*time.Second)) || !v.ApprovedAt.Before(a.ExpiresAt) {
			return invalid("JOURNAL_APPROVAL_INVALID")
		}
		seen[v.ID], actors[v.ActorID] = true, true
	}
	return nil
}

func SignJournalAuthorization(a JournalAuthorization, approvals []JournalApproval, parent GitEnvelope, keys JournalKeys, key ed25519.PrivateKey, now time.Time) (JournalEnvelope, error) {
	if len(key) != 64 || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Signer) {
		return JournalEnvelope{}, invalid("JOURNAL_SIGNING_KEY_INVALID")
	}
	if err := VerifyGitProgram(parent, keys.Signer, Expected{parent.Program.Binding, parent.Program.Realm}, now); err != nil {
		return JournalEnvelope{}, err
	}
	e := JournalEnvelope{a, approvals, journalAuthorizationAlgorithm, journalSignature(journalAuthorizationDomain, journalAuthorizationMessage(a, approvals), key)}
	if err := validateJournalAuthorization(e, parent, keys, now); err != nil {
		return JournalEnvelope{}, err
	}
	return e, nil
}
func VerifyJournalAuthorization(e JournalEnvelope, parent GitEnvelope, keys JournalKeys, now time.Time) error {
	return validateJournalAuthorization(e, parent, keys, now)
}
func SignJournalReceipt(r JournalReceipt, key ed25519.PrivateKey) (JournalReceiptEnvelope, error) {
	if len(key) != 64 {
		return JournalReceiptEnvelope{}, invalid("JOURNAL_PIPELINE_KEY_INVALID")
	}
	return JournalReceiptEnvelope{r, journalReceiptAlgorithm, journalSignature(journalReceiptDomain, r, key)}, nil
}

func JournalExpectedHead(e JournalEnvelope, records []JournalRecord) JournalHeadRef {
	last := Digest(e)
	if len(records) > 0 {
		last = Digest(records[len(records)-1])
	}
	return JournalHeadRef{uint64(len(records) + 1), len(records), last}
}
func verifyJournalHead(h JournalHeadEnvelope, e JournalEnvelope, records []JournalRecord, projection JournalProjection, keys JournalKeys, expected JournalHeadRef, at time.Time) error {
	if h.Algorithm != journalHeadAlgorithm || !journalVerify(journalHeadDomain, h.Head, h.Signature, keys.Ledger) {
		return invalid("JOURNAL_HEAD_SIGNATURE_INVALID")
	}
	if h.Head.JournalID != e.Authorization.JournalID || h.Head.AuthorizationSHA256 != Digest(e) || h.Head.Ref != expected || h.Head.Ref != JournalExpectedHead(e, records) || h.Head.ProjectionSHA256 != Digest(projection) {
		return invalid("JOURNAL_CURRENT_HEAD_REQUIRED")
	}
	if !canonicalTime(at) || !canonicalTime(h.Head.ObservedAt) || !canonicalTime(h.Head.ValidUntil) || h.Head.ObservedAt.After(at.Add(5*time.Second)) || at.Sub(h.Head.ObservedAt) > 5*time.Minute || !h.Head.ValidUntil.After(at) || h.Head.ValidUntil.Sub(h.Head.ObservedAt) > 5*time.Minute {
		return invalid("JOURNAL_HEAD_STALE")
	}
	return nil
}

// SealJournalView is a trusted issuer helper. Possession of the distinct ledger
// key and the real current journal is required; it is never an upload endpoint.
func SealJournalView(parent GitEnvelope, e JournalEnvelope, records []JournalRecord, keys JournalKeys, key ed25519.PrivateKey, now time.Time) (JournalView, JournalProjection, error) {
	if len(key) != 64 || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Ledger) {
		return JournalView{}, JournalProjection{}, invalid("JOURNAL_LEDGER_KEY_INVALID")
	}
	p, err := evaluateJournal(parent, e, records, keys, now)
	if err != nil {
		return JournalView{}, p, err
	}
	h := JournalHead{e.Authorization.JournalID, Digest(e), JournalExpectedHead(e, records), Digest(p), now, now.Add(5 * time.Minute)}
	return JournalView{parent, e, records, JournalHeadEnvelope{h, journalHeadAlgorithm, journalSignature(journalHeadDomain, h, key)}}, p, nil
}
func VerifyJournal(v JournalView, keys JournalKeys, expected JournalHeadRef, now time.Time) (JournalProjection, error) {
	p, err := evaluateJournal(v.Parent, v.Authorization, v.Records, keys, now)
	if err != nil {
		return p, err
	}
	err = verifyJournalHead(v.Head, v.Authorization, v.Records, p, keys, expected, now)
	return p, err
}

func commandArtifact(c JournalCommand) (GitArtifact, bool) {
	if c.Forward != nil && c.Recovery == nil {
		return c.Forward.Child.Artifact, true
	}
	if c.Recovery != nil && c.Forward == nil {
		return c.Recovery.Recovery.Artifact, true
	}
	return GitArtifact{}, false
}
func preparationMatches(q JournalPreparation, a GitArtifact) bool {
	return q.Revision == a.Revision && q.Before == a.Before && q.After == a.After
}
func journalStateValid(s JournalState, p GitProgram) bool {
	return validGitRevision(s.Revision, p.ArtifactContext.ConfigurationSHA256) && s.StateLineage == p.ArtifactContext.StateLineage && s.StateSerial >= p.ArtifactContext.InitialStateSerial && hashPattern.MatchString(s.StateSHA256) && model(s.Model, gitModelView(p))
}
func journalAtRevision(s JournalState, r GitRevision) JournalState { s.Revision = r; return s }
func preparationBase(c JournalCommand) JournalCommand              { c.Forward = nil; c.Recovery = nil; return c }

func validatePreparation(q JournalPreparation, p GitProgram, projection JournalProjection) error {
	if q.Before != projection.Current.Model || !validGitRevision(q.Revision, p.ArtifactContext.ConfigurationSHA256) {
		return invalid("JOURNAL_PREPARATION_BINDING_INVALID")
	}
	if q.Mode == Forward {
		if q.Sequence != projection.LastForwardSequence+1 || q.Sequence > uint64(len(p.Manifest.Entries)) || q.EffectID != "" {
			return invalid("JOURNAL_FORWARD_SEQUENCE_INVALID")
		}
		e := p.Manifest.Entries[q.Sequence-1]
		if q.ManifestEntrySHA256 != Digest(e) || q.Revision != e.Revision || q.Before != e.Before || q.After != e.After {
			return invalid("JOURNAL_FORWARD_SELECTION_INVALID")
		}
	} else if q.Mode == JournalRecoveryMode {
		if len(projection.Stack) == 0 || q.ManifestEntrySHA256 != "" || q.Sequence != 0 {
			return invalid("JOURNAL_RECOVERY_TOP_REQUIRED")
		}
		top := projection.Stack[len(projection.Stack)-1]
		if q.EffectID != top.ID || q.Before != top.Forward.Child.Artifact.After || q.After != top.Forward.Child.Artifact.Before || q.Revision.Commit == projection.Current.Revision.Commit {
			return invalid("JOURNAL_RECOVERY_TOP_REQUIRED")
		}
		want, _ := GitFixtureDesired(p, q.After)
		if q.Revision.DesiredSHA256 != BytesDigest(want) {
			return invalid("JOURNAL_RECOVERY_SELECTION_INVALID")
		}
	} else {
		return invalid("JOURNAL_PREPARATION_MODE_INVALID")
	}
	return nil
}

func validateJournalRecovery(r JournalRecovery, parent GitEnvelope, e JournalEnvelope, projection JournalProjection, head JournalHeadEnvelope, now time.Time) error {
	return validateJournalRecoveryState(r, parent, e, projection, head, now, false)
}

func validateJournalRecoveryState(r JournalRecovery, parent GitEnvelope, e JournalEnvelope, projection JournalProjection, head JournalHeadEnvelope, now time.Time, allowIntent bool) error {
	p := parent.Program
	if projection.Pending == nil || projection.Pending.Command.Preparation.Mode != JournalRecoveryMode || (projection.Pending.ApplyIntent && !allowIntent) || len(projection.Stack) == 0 {
		return invalid("JOURNAL_PREPARED_RECOVERY_REQUIRED")
	}
	c := projection.Pending.Command
	top := projection.Stack[len(projection.Stack)-1]
	if r.SchemaVersion != JournalSchemaVersion || !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.Nonce) || r.Nonce == p.Nonce || r.CommandID != c.ID || r.JournalID != e.Authorization.JournalID || r.AuthorizationSHA256 != Digest(e) || r.ParentEnvelopeSHA256 != Digest(parent) || r.PreparationHeadSHA256 != Digest(c.Head) || r.SigningHeadSHA256 != Digest(head) || r.EffectID != top.ID || r.OriginalChildSHA256 != Digest(top.Forward.Child) || r.OriginalReceiptSHA256 != Digest(top.Applied) {
		return invalid("JOURNAL_RECOVERY_BINDING_INVALID")
	}
	if !canonicalTime(r.CreatedAt) || !canonicalTime(r.ExpiresAt) || r.CreatedAt.Before(c.CreatedAt) || r.CreatedAt.After(now.Add(5*time.Second)) || now.Sub(r.CreatedAt) > 5*time.Minute || !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(r.CreatedAt) > 15*time.Minute || r.MinimumObservationSeconds < 120 || r.MinimumObservationSeconds > 3600 {
		return invalid("JOURNAL_RECOVERY_LIFETIME_INVALID")
	}
	if err := gitArtifactBinding(r.Artifact, p); err != nil {
		return err
	}
	a := r.Artifact
	if !preparationMatches(c.Preparation, a) || a.ManifestEntrySHA256 != "" || a.PreviousRevision != projection.Current.Revision || a.BeforeStateSerial != projection.Current.StateSerial || a.BeforeStateSHA256 != projection.Current.StateSHA256 || a.Before != top.Forward.Child.Artifact.After || a.After != top.Forward.Child.Artifact.Before {
		return invalid("JOURNAL_RECOVERY_NOT_EXACT_INVERSE")
	}
	for _, entry := range p.Manifest.Entries {
		if a.Revision.Commit == entry.Revision.Commit {
			return invalid("JOURNAL_RECOVERY_MUST_APPEND_NEW_COMMIT")
		}
	}
	return evidence(r.Evidence, []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"}, p.Binding, p.Realm, now, r.ExpiresAt, true)
}

func SignJournalRecovery(r JournalRecovery, v JournalView, keys JournalKeys, expected JournalHeadRef, key ed25519.PrivateKey, now time.Time) (JournalRecoveryEnvelope, error) {
	if len(key) != 64 || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Signer) {
		return JournalRecoveryEnvelope{}, invalid("JOURNAL_SIGNING_KEY_INVALID")
	}
	p, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return JournalRecoveryEnvelope{}, err
	}
	if err = validateJournalRecovery(r, v.Parent, v.Authorization, p, v.Head, now); err != nil {
		return JournalRecoveryEnvelope{}, err
	}
	return JournalRecoveryEnvelope{r, v.Head, journalRecoveryAlgorithm, journalSignature(journalRecoveryDomain, r, key)}, nil
}
func VerifyJournalRecovery(r JournalRecoveryEnvelope, v JournalView, keys JournalKeys, expected JournalHeadRef, now time.Time) error {
	p, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return err
	}
	if r.Algorithm != journalRecoveryAlgorithm || !journalVerify(journalRecoveryDomain, r.Recovery, r.Signature, keys.Signer) {
		return invalid("JOURNAL_RECOVERY_SIGNATURE_INVALID")
	}
	head := journalRecoverySigningHead(p, r.Recovery, v.Head)
	if Digest(r.Head) != Digest(head) {
		return invalid("JOURNAL_CURRENT_HEAD_REQUIRED")
	}
	return validateJournalRecovery(r.Recovery, v.Parent, v.Authorization, p, head, now)
}

func journalRecoverySigningHead(p JournalProjection, r JournalRecovery, current JournalHeadEnvelope) JournalHeadEnvelope {
	if p.Pending != nil && p.Pending.Command.Recovery != nil && Digest(p.Pending.Command.Recovery.Recovery) == Digest(r) {
		return p.Pending.Command.Recovery.Head
	}
	return current
}

func evaluateJournal(parent GitEnvelope, e JournalEnvelope, records []JournalRecord, keys JournalKeys, now time.Time) (JournalProjection, error) {
	return evaluateJournalCheckpoints(parent, e, records, keys, now, nil)
}

// VerifyJournalCheckpoints preserves every historical issued prefix check in a
// single replay. The final current anchor is independently compared with the
// server-resolved expected head. checkpoints[0] is the bootstrap head.
func VerifyJournalCheckpoints(v JournalView, checkpoints []JournalHeadEnvelope, keys JournalKeys, expected JournalHeadRef, now time.Time) (JournalProjection, error) {
	if len(checkpoints) != len(v.Records)+1 {
		return JournalProjection{}, invalid("JOURNAL_CHECKPOINT_POPULATION_INVALID")
	}
	p, err := evaluateJournalCheckpoints(v.Parent, v.Authorization, v.Records, keys, now, checkpoints)
	if err != nil {
		return p, err
	}
	err = verifyJournalHead(v.Head, v.Authorization, v.Records, p, keys, expected, now)
	return p, err
}

func evaluateJournalCheckpoints(parent GitEnvelope, e JournalEnvelope, records []JournalRecord, keys JournalKeys, now time.Time, checkpoints []JournalHeadEnvelope) (JournalProjection, error) {
	var projection JournalProjection
	if err := validateJournalAuthorization(e, parent, keys, now); err != nil {
		return projection, err
	}
	a, p := e.Authorization, parent.Program
	projection = JournalProjection{Current: a.Base, Stack: []JournalEffect{}, Consumed: []string{}, GitRepairs: []string{}}
	if len(records) > a.MaximumRecords {
		return projection, invalid("JOURNAL_RECORD_LIMIT")
	}
	previous, lastTime := Digest(e), a.CreatedAt
	commands, operations, idempotency := map[string]bool{}, map[string]bool{}, map[string]bool{}
	receiptIDs, receiptKeys := map[string]string{}, map[string]string{}
	encodedBytes := 0
	for i, record := range records {
		if checkpoints != nil {
			at := checkpoints[0].Head.ObservedAt
			if i > 0 {
				at = records[i-1].RecordedAt
			} else if at.After(record.RecordedAt.Add(5*time.Second)) || at.After(now.Add(5*time.Second)) {
				return projection, invalid("JOURNAL_CHECKPOINT_TIME_INVALID")
			}
			if err := verifyJournalHead(checkpoints[i], e, records[:i], projection, keys, JournalExpectedHead(e, records[:i]), at); err != nil {
				return projection, err
			}
		}
		frame, err := EncodeJournalRecord(record)
		if err != nil {
			return projection, err
		}
		encodedBytes += len(frame)
		if encodedBytes > JournalByteLimit {
			return projection, invalid("JOURNAL_FRAME_BOUNDS")
		}
		if record.Sequence != uint64(i+1) || record.PreviousSHA256 != previous || !canonicalTime(record.RecordedAt) || record.RecordedAt.Before(lastTime) || record.RecordedAt.After(now.Add(5*time.Second)) {
			return projection, invalid("JOURNAL_CHAIN_INVALID")
		}
		previous, lastTime = Digest(record), record.RecordedAt
		if record.Kind == JournalPreparing {
			if record.Command == nil || record.Receipt != nil || record.GitRepair != nil || projection.Pending != nil {
				return projection, invalid("JOURNAL_UNRESOLVED_COMMAND")
			}
			c := *record.Command
			if !idPattern.MatchString(c.ID) || !idPattern.MatchString(c.OperationID) || !idPattern.MatchString(c.IdempotencyKey) || commands[c.ID] || operations[c.OperationID] || idempotency[c.IdempotencyKey] || c.Fence <= projection.LastFence || c.Forward != nil || c.Recovery != nil || !canonicalTime(c.CreatedAt) || c.CreatedAt.Before(lastTime.Add(-5*time.Minute)) || c.CreatedAt.After(record.RecordedAt) || c.Before != projection.Current {
				return projection, invalid("JOURNAL_COMMAND_INVALID")
			}
			if err := verifyJournalHead(c.Head, e, records[:i], projection, keys, JournalExpectedHead(e, records[:i]), c.CreatedAt); err != nil {
				return projection, err
			}
			for _, approval := range e.Approvals {
				if approval.ApprovedAt.After(c.CreatedAt) {
					return projection, invalid("JOURNAL_APPROVAL_AFTER_COMMAND")
				}
			}
			if c.Preparation.Mode == Forward {
				if projection.ForwardAborted || !a.ExpiresAt.After(record.RecordedAt) {
					return projection, invalid("JOURNAL_FORWARD_EXPIRED_OR_ABORTED")
				}
				if err := journalForwardLifetime(p, record.RecordedAt); err != nil {
					return projection, err
				}
			}
			if err := validatePreparation(c.Preparation, p, projection); err != nil {
				return projection, err
			}
			commands[c.ID], operations[c.OperationID], idempotency[c.IdempotencyKey] = true, true, true
			projection.LastFence = c.Fence
			projection.Pending = &JournalPending{Command: c, Phase: JournalPreparing}
			continue
		}
		if record.Kind == JournalReserved {
			if record.Command == nil || record.Receipt != nil || record.GitRepair != nil || projection.Pending == nil {
				return projection, invalid("JOURNAL_PREPARING_REQUIRED")
			}
			c, pending := *record.Command, projection.Pending
			if pending.ApplyIntent || pending.NoApply != nil || Digest(preparationBase(c)) != Digest(preparationBase(pending.Command)) {
				return projection, invalid("JOURNAL_FINALIZATION_CHANGED_INTENT")
			}
			artifact, ok := commandArtifact(c)
			if !ok || !preparationMatches(c.Preparation, artifact) || artifact.PreviousRevision != projection.Current.Revision || artifact.BeforeStateSerial != projection.Current.StateSerial || artifact.BeforeStateSHA256 != projection.Current.StateSHA256 {
				return projection, invalid("JOURNAL_FINAL_ARTIFACT_BINDING_INVALID")
			}
			if c.Preparation.Mode == Forward {
				if c.Forward == nil || c.Forward.Child.Sequence != c.Preparation.Sequence {
					return projection, invalid("JOURNAL_FINAL_ARTIFACT_BINDING_INVALID")
				}
				if err := verifyJournalForwardCached(*c.Forward, parent, keys.Signer, record.RecordedAt); err != nil {
					return projection, err
				}
			} else {
				if c.Recovery == nil || c.Recovery.Algorithm != journalRecoveryAlgorithm || !journalVerify(journalRecoveryDomain, c.Recovery.Recovery, c.Recovery.Signature, keys.Signer) {
					return projection, invalid("JOURNAL_RECOVERY_SIGNATURE_INVALID")
				}
				if err := verifyJournalHead(c.Recovery.Head, e, records[:i], projection, keys, JournalExpectedHead(e, records[:i]), record.RecordedAt); err != nil {
					return projection, err
				}
				if err := validateJournalRecovery(c.Recovery.Recovery, parent, e, projection, c.Recovery.Head, record.RecordedAt); err != nil {
					return projection, err
				}
			}
			pending.Command = c
			pending.Phase = JournalReserved
			pending.ReadyUntil = time.Time{}
			continue
		}
		if record.Kind == JournalGitRepairIntent {
			if record.Command != nil || record.Receipt != nil || record.GitRepair == nil || projection.Pending == nil || projection.Pending.Phase != "GIT_REPAIR_REQUIRED" || projection.Pending.GitRepair != nil {
				return projection, invalid("JOURNAL_GIT_REPAIR_DUTY_REQUIRED")
			}
			repair := *record.GitRepair
			if err := verifyJournalHead(repair.Head, e, records[:i], projection, keys, JournalExpectedHead(e, records[:i]), repair.Repair.CreatedAt); err != nil {
				return projection, err
			}
			if repair.Algorithm != journalGitRepairAlgorithm || !journalVerify(journalGitRepairDomain, repair.Repair, repair.Signature, keys.Signer) {
				return projection, invalid("JOURNAL_GIT_REPAIR_SIGNATURE_INVALID")
			}
			if err := validateJournalGitRepair(repair.Repair, parent, e, projection, repair.Head, record.RecordedAt); err != nil {
				return projection, err
			}
			projection.Pending.GitRepair = &repair
			projection.Pending.Phase = JournalGitRepairIntent
			projection.Pending.RepairIntentAt = record.RecordedAt
			continue
		}
		if record.Command != nil || record.GitRepair != nil || record.Receipt == nil {
			return projection, invalid("JOURNAL_RECEIPT_REQUIRED")
		}
		envelope := *record.Receipt
		r := envelope.Receipt
		if envelope.Algorithm != journalReceiptAlgorithm || !journalVerify(journalReceiptDomain, r, envelope.Signature, keys.Pipeline) {
			return projection, invalid("JOURNAL_PIPELINE_SIGNATURE_INVALID")
		}
		if r.Kind != record.Kind {
			return projection, invalid("JOURNAL_CALLBACK_BINDING_INVALID")
		}
		h := Digest(r)
		if prior, seen := receiptIDs[r.ID]; seen {
			if prior != h || receiptKeys[r.IdempotencyKey] != h {
				return projection, invalid("JOURNAL_CALLBACK_CONFLICT")
			}
			continue
		}
		if prior, seen := receiptKeys[r.IdempotencyKey]; seen {
			if prior != h {
				return projection, invalid("JOURNAL_CALLBACK_CONFLICT")
			}
			continue
		}
		if projection.Pending == nil {
			return projection, invalid("JOURNAL_NO_CURRENT_COMMAND")
		}
		pending := projection.Pending
		c := pending.Command
		if r.SchemaVersion != JournalSchemaVersion || !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.IdempotencyKey) || r.JournalID != a.JournalID || r.AuthorizationSHA256 != Digest(e) || r.CommandID != c.ID || r.OperationID != c.OperationID || r.Fence != c.Fence || r.PipelineID != a.PipelineID || r.Kind != record.Kind || r.PreparationSHA256 != Digest(c.Preparation) || !canonicalTime(r.ReceivedAt) || r.ReceivedAt.Before(c.CreatedAt) || r.ReceivedAt.After(record.RecordedAt.Add(5*time.Second)) {
			return projection, invalid("JOURNAL_CALLBACK_BINDING_INVALID")
		}
		artifact, finalized := commandArtifact(c)
		if record.Kind == JournalGitRepaired {
			if pending.GitRepair == nil || r.ArtifactSHA256 != Digest(pending.GitRepair.Repair) || r.SavedPlanSHA256 != "" {
				return projection, invalid("JOURNAL_CALLBACK_ARTIFACT_INVALID")
			}
		} else if finalized {
			if r.ArtifactSHA256 != Digest(artifact) || r.SavedPlanSHA256 != artifact.SavedPlanSHA256 {
				return projection, invalid("JOURNAL_CALLBACK_ARTIFACT_INVALID")
			}
		} else if r.ArtifactSHA256 != "" || r.SavedPlanSHA256 != "" {
			return projection, invalid("JOURNAL_CALLBACK_ARTIFACT_INVALID")
		}
		if pending.NoApply != nil && record.Kind != JournalGitRepaired {
			return projection, invalid("JOURNAL_GIT_REPAIR_DUTY_REQUIRED")
		}
		receiptIDs[r.ID], receiptKeys[r.IdempotencyKey] = h, h
		gitState := journalAtRevision(c.Before, c.Preparation.Revision)
		switch record.Kind {
		case JournalGitAdvanced:
			if pending.ApplyIntent || r.Before != c.Before || r.After != gitState {
				return projection, invalid("JOURNAL_GIT_TRANSITION_INVALID")
			}
			pending.GitAdvanced = true
			pending.Phase = JournalGitAdvanced
		case JournalReadyToApply:
			if !pending.GitAdvanced || pending.ApplyIntent || !finalized || r.Before != gitState || r.After != gitState || !canonicalTime(r.ValidUntil) || !r.ValidUntil.After(record.RecordedAt) || r.ValidUntil.Sub(r.ReceivedAt) > 30*time.Second {
				return projection, invalid("JOURNAL_POSITIVE_NOT_DISPATCHED_REQUIRED")
			}
			pending.ReadyUntil = r.ValidUntil
			pending.Phase = JournalReadyToApply
		case JournalApplyIntent:
			if !pending.GitAdvanced || pending.ApplyIntent || !finalized || !pending.ReadyUntil.After(record.RecordedAt) || r.Before != gitState || r.After != gitState {
				return projection, invalid("JOURNAL_APPLY_INTENT_NOT_READY")
			}
			if c.Preparation.Mode == Forward {
				if !a.ExpiresAt.After(record.RecordedAt) || projection.ForwardAborted {
					return projection, invalid("JOURNAL_FORWARD_EXPIRED_OR_ABORTED")
				}
				if err := verifyJournalForwardCached(*c.Forward, parent, keys.Signer, record.RecordedAt); err != nil {
					return projection, err
				}
			} else if err := validateJournalRecovery(c.Recovery.Recovery, parent, e, projection, c.Recovery.Head, record.RecordedAt); err != nil {
				return projection, err
			}
			pending.ApplyIntent = true
			pending.Phase = JournalApplyIntent
			pending.IntentAt = record.RecordedAt
		case JournalUnknown:
			if r.Before != c.Before || r.After != c.Before {
				return projection, invalid("JOURNAL_UNKNOWN_MUST_NOT_INVENT_STATE")
			}
			pending.Phase = JournalUnknown
			pending.ReadyUntil = time.Time{}
		case JournalNoApply:
			if r.Before != c.Before || r.After.StateLineage != c.Before.StateLineage || r.After.StateSerial != c.Before.StateSerial || r.After.StateSHA256 != c.Before.StateSHA256 || r.After.Model != c.Before.Model {
				return projection, invalid("JOURNAL_NO_APPLY_STATE_CHANGED")
			}
			if pending.GitAdvanced {
				if r.After.Revision != gitState.Revision {
					return projection, invalid("JOURNAL_NO_APPLY_STATE_CHANGED")
				}
				pending.Phase = "GIT_REPAIR_REQUIRED"
				pending.ReadyUntil = time.Time{}
				pending.NoApply = &envelope
			} else {
				if r.After != c.Before {
					return projection, invalid("JOURNAL_NO_APPLY_STATE_CHANGED")
				}
				projection.Pending = nil
			}
		case JournalGitRepaired:
			if pending.GitRepair == nil || pending.NoApply == nil || pending.Phase != JournalGitRepairIntent {
				return projection, invalid("JOURNAL_GIT_REPAIR_DUTY_REQUIRED")
			}
			repair := pending.GitRepair.Repair
			if r.Before != repair.Before || r.After != journalAtRevision(c.Before, repair.Revision) {
				return projection, invalid("JOURNAL_GIT_REPAIR_CHANGED_NATIVE_STATE")
			}
			projection.Current = r.After
			projection.GitRepairs = append(projection.GitRepairs, repair.ID)
			projection.ForwardAborted = true
			projection.Pending = nil
		case JournalApplied:
			if !pending.ApplyIntent || !finalized || r.Before != c.Before || !journalStateValid(r.After, p) || r.After.Revision != artifact.Revision || r.After.Model != artifact.After {
				return projection, invalid("JOURNAL_APPLIED_NOT_EXACT_INTENT")
			}
			changed := artifact.Before != artifact.After
			if changed {
				if r.After.StateSerial <= c.Before.StateSerial {
					return projection, invalid("JOURNAL_APPLIED_STATE_NOT_ADVANCED")
				}
			} else if r.After.StateSerial != c.Before.StateSerial || r.After.StateSHA256 != c.Before.StateSHA256 {
				return projection, invalid("JOURNAL_NOOP_STATE_CHANGED")
			}
			if c.Preparation.Mode == Forward {
				projection.LastForwardSequence = c.Forward.Child.Sequence
				if changed {
					if len(projection.Stack) >= a.MaximumEffects {
						return projection, invalid("JOURNAL_EFFECT_LIMIT")
					}
					projection.Stack = append(projection.Stack, JournalEffect{c.ID, *c.Forward, envelope})
				}
			} else {
				if len(projection.Stack) == 0 || projection.Stack[len(projection.Stack)-1].ID != c.Preparation.EffectID {
					return projection, invalid("JOURNAL_RECOVERY_TOP_REQUIRED")
				}
				projection.Consumed = append(projection.Consumed, c.Preparation.EffectID)
				projection.Stack = projection.Stack[:len(projection.Stack)-1]
				projection.ForwardAborted = true
			}
			projection.Current = r.After
			projection.Pending = nil
		default:
			return projection, invalid("JOURNAL_RECEIPT_KIND_INVALID")
		}
	}
	if checkpoints != nil {
		at := checkpoints[0].Head.ObservedAt
		if len(records) > 0 {
			at = records[len(records)-1].RecordedAt
		}
		if at.After(now.Add(5 * time.Second)) {
			return projection, invalid("JOURNAL_CHECKPOINT_TIME_INVALID")
		}
		if err := verifyJournalHead(checkpoints[len(records)], e, records, projection, keys, JournalExpectedHead(e, records), at); err != nil {
			return projection, err
		}
	}
	return projection, nil
}

// AppendJournalRecord validates against the independently resolved current head.
// It does not persist, seal, consume database ownership or perform external I/O.
func AppendJournalRecord(v JournalView, keys JournalKeys, expected JournalHeadRef, next JournalRecord, now time.Time) ([]JournalRecord, JournalProjection, error) {
	if _, err := VerifyJournal(v, keys, expected, now); err != nil {
		return nil, JournalProjection{}, err
	}
	records := append(append([]JournalRecord{}, v.Records...), next)
	p, err := evaluateJournal(v.Parent, v.Authorization, records, keys, now)
	return records, p, err
}
