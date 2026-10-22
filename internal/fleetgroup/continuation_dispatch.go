package fleetgroup

import (
	"context"
	"time"
)

// These immediate local permits are not reusable capabilities. Actual current
// Git/native state and positive fenced NOT_DISPATCHED operation evidence remain
// producer checks under the same writer fence through CAS/CLI dispatch.
func AuthorizeContinuationGitAdvance(ctx context.Context, v ContinuationView, keys JournalKeys, a ContinuationAuthority, commandSHA string, now time.Time) (ContinuationPermit, error) {
	p, err := VerifyContinuation(ctx, v, keys, a, now)
	if err != nil {
		return ContinuationPermit{}, err
	}
	q := p.Pending
	if q == nil || q.Command.Mode != ContinuationInverse || q.Phase != ContinuationPreparing || q.GitAdvanced || q.ApplyIntent || Digest(q.Command) != commandSHA {
		return ContinuationPermit{}, invalid("CONTINUATION_CURRENT_PREPARATION_REQUIRED")
	}
	if now.Before(q.Command.CreatedAt) || !now.Before(q.Command.CreatedAt.Add(5*time.Minute)) {
		return ContinuationPermit{}, invalid("CONTINUATION_PREPARATION_STALE")
	}
	until := journalEarlier(v.Head.Head.ValidUntil, q.Command.CreatedAt.Add(5*time.Minute))
	until = journalEarlier(until, now.Add(30*time.Second))
	if !until.After(now) {
		return ContinuationPermit{}, invalid("CONTINUATION_DISPATCH_STALE")
	}
	return ContinuationPermit{continuationCursor(v), commandSHA, q.Command.OperationID, q.Command.Fence, q.Command.Mode, until}, nil
}
func AuthorizeContinuationDispatch(ctx context.Context, v ContinuationView, keys JournalKeys, a ContinuationAuthority, commandSHA, mode string, now time.Time) (ContinuationPermit, error) {
	p, err := VerifyContinuation(ctx, v, keys, a, now)
	if err != nil {
		return ContinuationPermit{}, err
	}
	q := p.Pending
	if q == nil || q.Phase != ContinuationIntent || !q.ApplyIntent || q.Finalized == nil || q.Command.Mode != mode || mode != ContinuationInverse && mode != ContinuationRepair || Digest(q.Command) != commandSHA || !q.ReadyUntil.After(now) || !journalDispatchTime(q.IntentAt, now) {
		return ContinuationPermit{}, invalid("CONTINUATION_CURRENT_DISPATCH_INTENT_REQUIRED")
	}
	if err = continuationValidateFinalization(q.Finalized.Finalization, v, p, q.Finalized.Head, now, true); err != nil {
		return ContinuationPermit{}, err
	}
	f := q.Finalized.Finalization
	until := journalEarlier(v.Head.Head.ValidUntil, q.ReadyUntil)
	until = journalEarlier(until, q.IntentAt.Add(30*time.Second))
	until = journalEarlier(until, f.ExpiresAt)
	until = journalEarlier(until, f.CreatedAt.Add(5*time.Minute))
	until = journalEvidenceDeadline(until, f.Evidence)
	if !until.After(now) {
		return ContinuationPermit{}, invalid("CONTINUATION_DISPATCH_STALE")
	}
	return ContinuationPermit{continuationCursor(v), commandSHA, q.Command.OperationID, q.Command.Fence, q.Command.Mode, until}, nil
}
