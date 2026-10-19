package fleetgroup

import "time"

// AuthorizeJournalGitAdvance gates the first actual Git CAS. A historical
// PREPARING record retains a duty, but cannot renew expired forward authority.
// The producer independently pins the actual before state/ref and positively
// verifies the same fenced operation NOT_DISPATCHED under its writer lock.
func AuthorizeJournalGitAdvance(v JournalView, keys JournalKeys, expected JournalHeadRef, currentCommandSHA256 string, now time.Time) (JournalDispatchPermit, error) {
	p, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return JournalDispatchPermit{}, err
	}
	q := p.Pending
	if q == nil || q.Phase != JournalPreparing || q.GitAdvanced || q.ApplyIntent || q.NoApply != nil || q.GitRepair != nil || q.Command.Forward != nil || q.Command.Recovery != nil || Digest(q.Command) != currentCommandSHA256 {
		return JournalDispatchPermit{}, invalid("JOURNAL_CURRENT_PREPARATION_REQUIRED")
	}
	c := q.Command
	if now.Before(c.CreatedAt) || !now.Before(c.CreatedAt.Add(5*time.Minute)) {
		return JournalDispatchPermit{}, invalid("JOURNAL_PREPARATION_EXPIRED")
	}
	if err = validatePreparation(c.Preparation, v.Parent.Program, p); err != nil {
		return JournalDispatchPermit{}, err
	}
	until := journalEarlier(v.Head.Head.ValidUntil, c.CreatedAt.Add(5*time.Minute))
	until = journalEarlier(until, now.Add(30*time.Second))
	if c.Preparation.Mode == Forward {
		if p.ForwardAborted || !v.Authorization.Authorization.ExpiresAt.After(now) {
			return JournalDispatchPermit{}, invalid("JOURNAL_FORWARD_EXPIRED_OR_ABORTED")
		}
		if err = journalForwardLifetime(v.Parent.Program, now); err != nil {
			return JournalDispatchPermit{}, err
		}
		entry := v.Parent.Program.Manifest.Entries[c.Preparation.Sequence-1]
		until = journalEarlier(until, v.Authorization.Authorization.ExpiresAt)
		until = journalEarlier(until, GitForwardDeadline(v.Parent.Program).Add(-time.Duration(entry.MinimumObservationSeconds)*time.Second))
	}
	if !until.After(now) {
		return JournalDispatchPermit{}, invalid("JOURNAL_DISPATCH_PERMISSION_EXPIRED")
	}
	return journalPermit(v, c, Digest(c.Preparation), until), nil
}

// AuthorizeJournalApply must run at the actual delivery boundary, after the
// producer has positively established the same fenced operation NOT_DISPATCHED.
// Persisted APPLY_INTENT retains a reconciliation duty; it is not indefinite
// permission to deliver. Late factual outcomes remain recordable independently.
func AuthorizeJournalApply(v JournalView, keys JournalKeys, expected JournalHeadRef, currentCommandSHA256 string, now time.Time) (JournalDispatchPermit, error) {
	p, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return JournalDispatchPermit{}, err
	}
	q := p.Pending
	if q == nil || q.Phase != JournalApplyIntent || !q.ApplyIntent || q.NoApply != nil || q.GitRepair != nil || Digest(q.Command) != currentCommandSHA256 {
		return JournalDispatchPermit{}, invalid("JOURNAL_CURRENT_APPLY_INTENT_REQUIRED")
	}
	if !journalDispatchTime(q.IntentAt, now) || !q.ReadyUntil.After(now) {
		return JournalDispatchPermit{}, invalid("JOURNAL_DISPATCH_PERMISSION_EXPIRED")
	}
	c := q.Command
	a, ok := commandArtifact(c)
	if !ok {
		return JournalDispatchPermit{}, invalid("JOURNAL_FINAL_ARTIFACT_BINDING_INVALID")
	}
	until := journalEarlier(q.ReadyUntil, v.Head.Head.ValidUntil)
	if c.Preparation.Mode == Forward {
		if p.ForwardAborted || !v.Authorization.Authorization.ExpiresAt.After(now) {
			return JournalDispatchPermit{}, invalid("JOURNAL_FORWARD_EXPIRED_OR_ABORTED")
		}
		if err = verifyJournalForwardCached(*c.Forward, v.Parent, keys.Signer, now); err != nil {
			return JournalDispatchPermit{}, err
		}
		until = journalEarlier(until, c.Forward.Child.ExpiresAt)
		until = journalEarlier(until, c.Forward.Child.CreatedAt.Add(5*time.Minute))
		until = journalEvidenceDeadline(until, c.Forward.Child.Evidence)
		until = journalEarlier(until, v.Authorization.Authorization.ExpiresAt)
		until = journalEarlier(until, GitForwardDeadline(v.Parent.Program).Add(-time.Duration(c.Forward.Child.MinimumObservationSeconds)*time.Second))
	} else {
		if c.Recovery == nil {
			return JournalDispatchPermit{}, invalid("JOURNAL_PREPARED_RECOVERY_REQUIRED")
		}
		if err = validateJournalRecoveryState(c.Recovery.Recovery, v.Parent, v.Authorization, p, c.Recovery.Head, now, true); err != nil {
			return JournalDispatchPermit{}, err
		}
		until = journalEarlier(until, c.Recovery.Recovery.ExpiresAt)
		until = journalEarlier(until, c.Recovery.Recovery.CreatedAt.Add(5*time.Minute))
		until = journalEvidenceDeadline(until, c.Recovery.Recovery.Evidence)
	}
	until = journalEarlier(until, q.IntentAt.Add(30*time.Second))
	if !until.After(now) {
		return JournalDispatchPermit{}, invalid("JOURNAL_DISPATCH_PERMISSION_EXPIRED")
	}
	return journalPermit(v, c, Digest(a), until), nil
}

// AuthorizeJournalGitRepair is the equivalent immediate pre-CAS gate for a
// signed Git-only repair. It never authorizes Terraform or renews a stale intent.
func AuthorizeJournalGitRepair(v JournalView, keys JournalKeys, expected JournalHeadRef, currentRepairSHA256 string, now time.Time) (JournalDispatchPermit, error) {
	p, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return JournalDispatchPermit{}, err
	}
	q := p.Pending
	if q == nil || q.Phase != JournalGitRepairIntent || q.GitRepair == nil || Digest(q.GitRepair.Repair) != currentRepairSHA256 {
		return JournalDispatchPermit{}, invalid("JOURNAL_CURRENT_GIT_REPAIR_INTENT_REQUIRED")
	}
	if !journalDispatchTime(q.RepairIntentAt, now) {
		return JournalDispatchPermit{}, invalid("JOURNAL_DISPATCH_PERMISSION_EXPIRED")
	}
	r := q.GitRepair
	if err = validateJournalGitRepair(r.Repair, v.Parent, v.Authorization, p, r.Head, now); err != nil {
		return JournalDispatchPermit{}, err
	}
	until := journalEarlier(r.Repair.ExpiresAt, q.RepairIntentAt.Add(30*time.Second))
	until = journalEarlier(until, r.Repair.CreatedAt.Add(5*time.Minute))
	until = journalEarlier(until, v.Head.Head.ValidUntil)
	if !until.After(now) {
		return JournalDispatchPermit{}, invalid("JOURNAL_DISPATCH_PERMISSION_EXPIRED")
	}
	return journalPermit(v, q.Command, Digest(r.Repair), until), nil
}

func journalDispatchTime(intent, now time.Time) bool {
	return canonicalTime(intent) && !now.Before(intent) && now.Before(intent.Add(30*time.Second))
}
func journalEarlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
func journalEvidenceDeadline(until time.Time, refs []EvidenceRef) time.Time {
	for _, ref := range refs {
		until = journalEarlier(until, ref.ObservedAt.Add(5*time.Minute))
		until = journalEarlier(until, ref.ValidUntil)
	}
	return until
}
func journalPermit(v JournalView, c JournalCommand, artifact string, until time.Time) JournalDispatchPermit {
	return JournalDispatchPermit{v.Authorization.Authorization.JournalID, c.ID, c.OperationID, c.Fence, Digest(c), artifact, v.Head.Head.Ref, until}
}
