package fleetgroup

import "time"

func continuationSameNative(a, b JournalState) bool {
	return a.StateLineage == b.StateLineage && a.StateSerial == b.StateSerial && a.StateSHA256 == b.StateSHA256 && a.Model == b.Model
}
func continuationValidReceipt(r ContinuationReceipt, v ContinuationView, at time.Time) bool {
	return r.SchemaVersion == ContinuationSchemaVersion && idPattern.MatchString(r.ID) && idPattern.MatchString(r.IdempotencyKey) && r.ChainSHA256 == Digest(v.Authorization) && canonicalTime(r.ReceivedAt) && !r.ReceivedAt.After(at.Add(5*time.Second))
}
func continuationOriginalOutcome(p *ContinuationProjection, e JournalReceiptEnvelope, o ContinuationOrigin, keys JournalKeys, at time.Time) error {
	q := p.OriginalPending
	if q == nil {
		return invalid("CONTINUATION_ORIGINAL_DUTY_REQUIRED")
	}
	c := q.Command
	r := e.Receipt
	if e.Algorithm != journalReceiptAlgorithm || !journalVerify(journalReceiptDomain, r, e.Signature, keys.Pipeline) || r.SchemaVersion != JournalSchemaVersion || !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.IdempotencyKey) || r.JournalID != o.Authorization.Authorization.JournalID || r.AuthorizationSHA256 != Digest(o.Authorization) || r.CommandID != c.ID || r.OperationID != c.OperationID || r.Fence != c.Fence || r.PipelineID != o.Authorization.Authorization.PipelineID || r.PreparationSHA256 != Digest(c.Preparation) || !canonicalTime(r.ReceivedAt) || r.ReceivedAt.Before(c.CreatedAt) || r.ReceivedAt.After(at.Add(5*time.Second)) {
		return invalid("CONTINUATION_ORIGINAL_RECEIPT_INVALID")
	}
	a, finalized := commandArtifact(c)
	if r.Kind == JournalGitRepaired {
		if q.GitRepair == nil || r.ArtifactSHA256 != Digest(q.GitRepair.Repair) || r.SavedPlanSHA256 != "" {
			return invalid("CONTINUATION_ORIGINAL_ARTIFACT_INVALID")
		}
	} else if finalized {
		if r.ArtifactSHA256 != Digest(a) || r.SavedPlanSHA256 != a.SavedPlanSHA256 {
			return invalid("CONTINUATION_ORIGINAL_ARTIFACT_INVALID")
		}
	} else if r.ArtifactSHA256 != "" || r.SavedPlanSHA256 != "" {
		return invalid("CONTINUATION_ORIGINAL_ARTIFACT_INVALID")
	}
	switch r.Kind {
	case JournalUnknown:
		if r.Before != c.Before || r.After != c.Before {
			return invalid("CONTINUATION_UNKNOWN_MUST_RETAIN_STATE")
		}
		q.Phase = JournalUnknown
		q.ReadyUntil = time.Time{}
	case JournalGitAdvanced:
		if q.ApplyIntent || q.NoApply != nil || r.Before != c.Before || r.After != journalAtRevision(c.Before, c.Preparation.Revision) {
			return invalid("CONTINUATION_ORIGINAL_GIT_INVALID")
		}
		q.GitAdvanced = true
		q.Phase = JournalGitAdvanced
		p.Current = r.After
	case JournalNoApply:
		if q.GitRepair != nil {
			return invalid("CONTINUATION_ORIGINAL_REPAIR_FENCE_REQUIRED")
		}
		if r.Before != c.Before || !continuationSameNative(r.After, c.Before) {
			return invalid("CONTINUATION_NO_APPLY_CHANGED_NATIVE_STATE")
		}
		if q.GitAdvanced {
			if r.After.Revision != c.Preparation.Revision {
				return invalid("CONTINUATION_NO_APPLY_CHANGED_NATIVE_STATE")
			}
			p.GitDuty = &ContinuationGitDuty{c.ID, Digest(c), c.OperationID, c.Fence, c.Before, r.After, Digest(e)}
		} else if r.After != c.Before {
			return invalid("CONTINUATION_NO_APPLY_CHANGED_NATIVE_STATE")
		}
		p.Current = r.After
		p.OriginalPending = nil
	case JournalApplied:
		if !q.ApplyIntent || !finalized || r.Before != c.Before || !journalStateValid(r.After, o.Parent.Program) || r.After.Revision != a.Revision || r.After.Model != a.After {
			return invalid("CONTINUATION_ORIGINAL_APPLIED_INVALID")
		}
		if a.Before != a.After {
			if r.After.StateSerial <= c.Before.StateSerial {
				return invalid("CONTINUATION_APPLIED_NOT_ADVANCED")
			}
		} else if !continuationSameNative(r.After, c.Before) {
			return invalid("CONTINUATION_NOOP_CHANGED_NATIVE_STATE")
		}
		if c.Preparation.Mode == Forward {
			if a.Before != a.After {
				if len(p.Stack) >= o.Authorization.Authorization.MaximumEffects {
					return invalid("CONTINUATION_EFFECT_LIMIT")
				}
				p.Stack = append(p.Stack, JournalEffect{c.ID, *c.Forward, e})
			}
		} else if c.Preparation.Mode == JournalRecoveryMode {
			if err := continuationConsume(p, c.Preparation.EffectID); err != nil {
				return err
			}
		} else {
			return invalid("CONTINUATION_ORIGINAL_APPLIED_INVALID")
		}
		p.Current = r.After
		p.OriginalPending = nil
	case JournalGitRepaired:
		if q.NoApply == nil || q.GitRepair == nil || q.Phase != JournalGitRepairIntent || r.Before != q.GitRepair.Repair.Before || r.After != journalAtRevision(c.Before, q.GitRepair.Repair.Revision) {
			return invalid("CONTINUATION_ORIGINAL_GIT_REPAIR_INVALID")
		}
		if err := continuationRepairApplied(p, q.GitRepair.Repair.ID); err != nil {
			return err
		}
		p.Current = r.After
		p.OriginalPending = nil
	default:
		return invalid("CONTINUATION_ORIGINAL_NEW_DISPATCH_FORBIDDEN")
	}
	return nil
}

func continuationReceiptOutcome(p *ContinuationProjection, r ContinuationReceipt, v ContinuationView, at time.Time) error {
	if !continuationValidReceipt(r, v, at) {
		return invalid("CONTINUATION_RECEIPT_BINDING_INVALID")
	}
	if r.Kind == ContinuationLegacyRepairFenced {
		q := p.OriginalPending
		if q == nil || q.GitRepair == nil || q.NoApply == nil || r.CommandID != q.Command.ID || r.OperationID != q.Command.OperationID || r.Fence != q.Command.Fence || r.CommandSHA256 != Digest(q.Command) || r.FinalizationSHA256 != Digest(q.GitRepair.Repair) || r.ReceivedAt.Before(q.GitRepair.Repair.CreatedAt) || r.Before != p.Current || r.After != p.Current {
			return invalid("CONTINUATION_ORIGINAL_REPAIR_FENCE_REQUIRED")
		}
		// Positive, fenced NOT_DISPATCHED evidence is issued by the commissioned
		// pipeline after checking actual ref/state. An absent callback cannot enter.
		c := q.Command
		p.GitDuty = &ContinuationGitDuty{c.ID, Digest(c), c.OperationID, c.Fence, c.Before, p.Current, Digest(*q.NoApply)}
		p.OriginalPending = nil
		return nil
	}
	q := p.Pending
	if q == nil {
		return invalid("CONTINUATION_PREPARED_COMMAND_REQUIRED")
	}
	c := q.Command
	if r.CommandID != c.ID || r.OperationID != c.OperationID || r.Fence != c.Fence || r.CommandSHA256 != Digest(c) || r.ReceivedAt.Before(c.CreatedAt) {
		return invalid("CONTINUATION_RECEIPT_BINDING_INVALID")
	}
	if q.Finalized != nil {
		if r.FinalizationSHA256 != Digest(q.Finalized.Finalization) {
			return invalid("CONTINUATION_RECEIPT_FINALIZATION_INVALID")
		}
	} else if r.FinalizationSHA256 != "" {
		return invalid("CONTINUATION_RECEIPT_FINALIZATION_INVALID")
	}
	switch r.Kind {
	case ContinuationGitAdvanced:
		if c.Mode != ContinuationInverse || q.GitAdvanced || q.ApplyIntent || q.Phase == ContinuationUnknown || r.Before != c.Before || r.After != journalAtRevision(c.Before, c.Revision) {
			return invalid("CONTINUATION_GIT_ADVANCE_INVALID")
		}
		p.Current = r.After
		q.GitAdvanced = true
		q.Phase = ContinuationGitAdvanced
	case ContinuationReady:
		if q.ApplyIntent || q.Phase == ContinuationUnknown || q.Finalized == nil || c.Mode == ContinuationInverse && !q.GitAdvanced || c.Mode == ContinuationRepair && q.GitAdvanced || r.Before != p.Current || r.After != p.Current || !canonicalTime(r.ValidUntil) || !r.ValidUntil.After(at) || r.ValidUntil.Sub(r.ReceivedAt) > 30*time.Second {
			return invalid("CONTINUATION_POSITIVE_NOT_DISPATCHED_REQUIRED")
		}
		q.ReadyUntil = r.ValidUntil
		q.Phase = ContinuationReady
	case ContinuationIntent:
		if q.ApplyIntent || q.Phase != ContinuationReady || q.Finalized == nil || !q.ReadyUntil.After(at) || r.Before != p.Current || r.After != p.Current {
			return invalid("CONTINUATION_INTENT_NOT_READY")
		}
		if err := continuationValidateFinalization(q.Finalized.Finalization, v, *p, q.Finalized.Head, at, false); err != nil {
			return err
		}
		q.ApplyIntent = true
		q.IntentAt = at
		q.Phase = ContinuationIntent
	case ContinuationUnknown:
		if r.Before != p.Current || r.After != p.Current {
			return invalid("CONTINUATION_UNKNOWN_MUST_RETAIN_STATE")
		}
		q.Phase = ContinuationUnknown
		q.ReadyUntil = time.Time{}
	case ContinuationNoApply:
		if r.Before != c.Before || !continuationSameNative(r.After, c.Before) {
			return invalid("CONTINUATION_NO_APPLY_CHANGED_NATIVE_STATE")
		}
		if q.GitAdvanced {
			if r.After.Revision != c.Revision {
				return invalid("CONTINUATION_NO_APPLY_CHANGED_NATIVE_STATE")
			}
			p.GitDuty = &ContinuationGitDuty{c.ID, Digest(c), c.OperationID, c.Fence, c.Before, r.After, Digest(r)}
		} else if r.After != c.Before {
			return invalid("CONTINUATION_NO_APPLY_CHANGED_NATIVE_STATE")
		}
		p.Current = r.After
		p.Pending = nil
	case ContinuationApplied:
		if c.Mode != ContinuationInverse || !q.ApplyIntent || q.Finalized == nil || r.Before != c.Before || r.After.Revision != c.Revision || r.After.Model != c.After || !journalStateValid(r.After, v.Origin.Parent.Program) || r.After.StateSerial <= c.Before.StateSerial {
			return invalid("CONTINUATION_APPLIED_NOT_EXACT_INTENT")
		}
		if len(p.Stack) == 0 || c.ObligationSHA256 != Digest(p.Stack[len(p.Stack)-1]) {
			return invalid("CONTINUATION_TOP_EFFECT_REQUIRED")
		}
		id := p.Stack[len(p.Stack)-1].ID
		if err := continuationConsume(p, id); err != nil {
			return err
		}
		p.Current = r.After
		p.Pending = nil
	case ContinuationRepaired:
		if c.Mode != ContinuationRepair || !q.ApplyIntent || q.Finalized == nil || p.GitDuty == nil || c.ObligationSHA256 != Digest(*p.GitDuty) || r.Before != c.Before || r.After != journalAtRevision(c.Before, c.Revision) {
			return invalid("CONTINUATION_GIT_REPAIR_CHANGED_NATIVE_STATE")
		}
		if err := continuationRepairApplied(p, c.ID); err != nil {
			return err
		}
		p.Current = r.After
		p.Pending = nil
		p.GitDuty = nil
	default:
		return invalid("CONTINUATION_FORWARD_FORBIDDEN")
	}
	return nil
}
