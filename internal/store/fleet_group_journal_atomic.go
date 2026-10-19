package store

import (
	"context"
	"crypto/ed25519"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

// A savepoint prevents a caller which handles a domain refusal from accidentally
// committing only an event, tombstone, reservation or outbox prefix. The caller
// still commits its outer transaction explicitly; no method commits network I/O.
func groupJournalAtomic[T any](ctx context.Context, t *Tx, fn func(*Tx) (T, error)) (T, error) {
	var zero T
	sub, err := t.Tx.Begin(ctx)
	if err != nil {
		return zero, err
	}
	defer func() { _ = sub.Rollback(ctx) }()
	value, err := fn(&Tx{Tx: sub, Tenant: t.Tenant})
	if err != nil {
		return zero, err
	}
	if err = sub.Commit(ctx); err != nil {
		return zero, err
	}
	return value, nil
}

type groupJournalAppendResult struct {
	cursor   g.ContinuationCursor
	replayed bool
}
type groupJournalClaimResult struct {
	delivery FleetGroupJournalDelivery
	permit   g.JournalDispatchPermit
	required bool
}

func (t *Tx) FleetGroupJournalBootstrap(ctx context.Context, b FleetGroupJournalBootstrap) (g.ContinuationCursor, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (g.ContinuationCursor, error) { return tx.groupJournalBootstrap(ctx, b) })
}
func (t *Tx) FleetGroupJournalAttachContinuation(ctx context.Context, chain string, e g.ContinuationEnvelope) error {
	_, err := groupJournalAtomic(ctx, t, func(tx *Tx) (bool, error) { return true, tx.groupJournalAttachContinuation(ctx, chain, e) })
	return err
}
func (t *Tx) FleetGroupJournalAppendOriginal(ctx context.Context, chain string, expected g.ContinuationCursor, r g.JournalRecord, head g.JournalHeadEnvelope) (g.ContinuationCursor, bool, error) {
	out, err := groupJournalAtomic(ctx, t, func(tx *Tx) (groupJournalAppendResult, error) {
		c, replayed, e := tx.groupJournalAppendOriginal(ctx, chain, expected, r, head)
		return groupJournalAppendResult{c, replayed}, e
	})
	return out.cursor, out.replayed, err
}
func (t *Tx) FleetGroupJournalOpenContinuation(ctx context.Context, chain string, key ed25519.PrivateKey, nonce string) (g.ContinuationCursor, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (g.ContinuationCursor, error) {
		return tx.groupJournalOpenContinuation(ctx, chain, key, nonce)
	})
}
func (t *Tx) FleetGroupJournalRotate(ctx context.Context, chain string, key ed25519.PrivateKey, nonce string) (g.ContinuationCursor, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (g.ContinuationCursor, error) { return tx.groupJournalRotate(ctx, chain, key, nonce) })
}
func (t *Tx) FleetGroupJournalAppendContinuation(ctx context.Context, chain string, expected g.ContinuationCursor, key ed25519.PrivateKey, r g.ContinuationRecord) (g.ContinuationCursor, bool, error) {
	out, err := groupJournalAtomic(ctx, t, func(tx *Tx) (groupJournalAppendResult, error) {
		c, replayed, e := tx.groupJournalAppendContinuation(ctx, chain, expected, key, r)
		return groupJournalAppendResult{c, replayed}, e
	})
	return out.cursor, out.replayed, err
}
func (t *Tx) FleetGroupJournalRenewContinuation(ctx context.Context, chain string, key ed25519.PrivateKey) (g.ContinuationCursor, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (g.ContinuationCursor, error) { return tx.groupJournalRenewContinuation(ctx, chain, key) })
}
func (t *Tx) FleetGroupJournalClaimOriginal(ctx context.Context, chain, id, attempt string) (FleetGroupJournalDelivery, g.JournalDispatchPermit, bool, error) {
	out, err := groupJournalAtomic(ctx, t, func(tx *Tx) (groupJournalClaimResult, error) {
		d, p, required, e := tx.groupJournalClaimOriginal(ctx, chain, id, attempt)
		return groupJournalClaimResult{d, p, required}, e
	})
	return out.delivery, out.permit, out.required, err
}
func (t *Tx) FleetGroupJournalReconcileAttempt(ctx context.Context, chain, id string) error {
	_, err := groupJournalAtomic(ctx, t, func(tx *Tx) (bool, error) { return true, tx.groupJournalReconcileAttempt(ctx, chain, id) })
	return err
}
