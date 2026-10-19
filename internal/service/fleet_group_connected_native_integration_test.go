package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Every mutation below loads the actual issued current row inside the private
// ledger transaction. No caller projection/hash chain is accepted as Current.
func (h *connectedJournal) refresh(t *testing.T, ctx context.Context) g.JournalProjection {
	t.Helper()
	var out g.JournalProjection
	if err := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalRenewOriginal(ctx, h.bootstrap.ChainID, h.ledgerKey)
		if e != nil {
			return e
		}
		h.view, _, e = tx.FleetGroupJournalOriginal(ctx, h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		out, e = g.VerifyJournal(h.view, h.bootstrap.Keys.Core(), h.view.Head.Head.Ref, time.Now().UTC())
		return e
	}); err != nil {
		t.Fatal("current issued journal projection", err)
	}
	return out
}

func (h *connectedJournal) appendNativeRecord(t *testing.T, ctx context.Context, build func(g.JournalView, g.JournalProjection) (g.JournalRecord, error)) g.JournalProjection {
	t.Helper()
	var out g.JournalProjection
	if err := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(ctx, h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		current, e := tx.FleetGroupJournalCursor(ctx, h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil {
			return e
		}
		r, e := build(v, p)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		r.Sequence = uint64(len(v.Records) + 1)
		r.PreviousSHA256 = v.Head.Head.Ref.LastRecordSHA256
		r.RecordedAt = now
		if r.Kind == g.JournalReadyToApply && (r.Receipt == nil || !r.Receipt.Receipt.ValidUntil.After(now)) {
			return errors.New("positive native readiness proof expired before publication")
		}
		records, _, e := g.AppendJournalRecord(v, keys.Core(), v.Head.Head.Ref, r, now)
		if e != nil {
			return e
		}
		next, p, e := g.SealJournalView(v.Parent, v.Authorization, records, keys.Core(), h.ledgerKey, now)
		if e != nil {
			return e
		}
		var replay bool
		h.cursor, replay, e = tx.FleetGroupJournalAppendOriginal(ctx, h.bootstrap.ChainID, current, r, next.Head)
		if e != nil {
			return e
		}
		if replay {
			return errors.New("new authority event replayed")
		}
		h.view, out = next, p
		return nil
	}); err != nil {
		t.Fatal("atomic native journal event", err)
	}
	return out
}

func (h *connectedJournal) preparingForward(t *testing.T, ctx context.Context, sequence uint64) g.JournalCommand {
	t.Helper()
	var command g.JournalCommand
	h.appendNativeRecord(t, ctx, func(v g.JournalView, p g.JournalProjection) (g.JournalRecord, error) {
		if sequence < 1 || sequence > uint64(len(v.Parent.Program.Manifest.Entries)) {
			return g.JournalRecord{}, errors.New("exact manifest sequence required")
		}
		e := v.Parent.Program.Manifest.Entries[sequence-1]
		command = g.JournalCommand{ID: model.ID(), OperationID: model.ID(), IdempotencyKey: model.ID(), Fence: p.LastFence + 1, Head: v.Head, Before: p.Current, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: sequence, ManifestEntrySHA256: g.Digest(e), Revision: e.Revision, Before: e.Before, After: e.After}, CreatedAt: time.Now().UTC()}
		return g.JournalRecord{Kind: g.JournalPreparing, Command: &command}, nil
	})
	return command
}

func (h *connectedJournal) preparingInverse(t *testing.T, ctx context.Context, native *groupfixtureproducer.NativeStage) g.JournalCommand {
	t.Helper()
	p := h.refresh(t, ctx)
	if len(p.Stack) == 0 || p.Pending != nil {
		t.Fatal("retained LIFO effect required")
	}
	top := p.Stack[len(p.Stack)-1]
	revision, err := native.RecoveryRevision(ctx, p.Current, top.Forward.Child.Artifact.Before)
	if err != nil {
		t.Fatal("actual append-only inverse Git objects", err)
	}
	var command g.JournalCommand
	h.appendNativeRecord(t, ctx, func(v g.JournalView, p g.JournalProjection) (g.JournalRecord, error) {
		if len(p.Stack) == 0 || p.Stack[len(p.Stack)-1].ID != top.ID {
			return g.JournalRecord{}, errors.New("current LIFO effect changed")
		}
		command = g.JournalCommand{ID: model.ID(), OperationID: model.ID(), IdempotencyKey: model.ID(), Fence: p.LastFence + 1, Head: v.Head, Before: p.Current, Preparation: g.JournalPreparation{Mode: g.JournalRecoveryMode, EffectID: top.ID, Revision: revision, Before: top.Forward.Child.Artifact.After, After: top.Forward.Child.Artifact.Before}, CreatedAt: time.Now().UTC()}
		return g.JournalRecord{Kind: g.JournalPreparing, Command: &command}, nil
	})
	return command
}

func (h *connectedJournal) receipt(t *testing.T, ctx context.Context, kind string, before, after g.JournalState, nativeProof ...groupfixtureproducer.NotDispatchedProof) g.JournalReceiptEnvelope {
	t.Helper()
	p := h.refresh(t, ctx)
	if p.Pending == nil {
		t.Fatal("receipt current operation required")
	}
	c := p.Pending.Command
	r := g.JournalReceipt{SchemaVersion: g.JournalSchemaVersion, ID: model.ID(), IdempotencyKey: model.ID(), JournalID: h.view.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(h.view.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: h.view.Authorization.Authorization.PipelineID, Kind: kind, PreparationSHA256: g.Digest(c.Preparation), Before: before, After: after, ReceivedAt: time.Now().UTC()}
	if c.Forward != nil {
		r.ArtifactSHA256 = g.Digest(c.Forward.Child.Artifact)
		r.SavedPlanSHA256 = c.Forward.Child.Artifact.SavedPlanSHA256
	}
	if c.Recovery != nil {
		r.ArtifactSHA256 = g.Digest(c.Recovery.Recovery.Artifact)
		r.SavedPlanSHA256 = c.Recovery.Recovery.Artifact.SavedPlanSHA256
	}
	if kind == g.JournalReadyToApply {
		if len(nativeProof) != 1 {
			t.Fatal("READY requires exact positive native operation proof")
		}
		proof := nativeProof[0]
		if proof.CommandSHA256 != g.Digest(c) || proof.OperationID != c.OperationID || proof.Fence != c.Fence || proof.ProgramSHA256 != g.Digest(h.view.Parent.Program) || proof.JournalID != h.view.Authorization.Authorization.JournalID || proof.Current != after || proof.ObservedAt.After(r.ReceivedAt) || !proof.ValidUntil.After(r.ReceivedAt) {
			t.Fatal("positive native operation proof expired or changed before signing")
		}
		r.ValidUntil = r.ReceivedAt.Add(30 * time.Second)
		for _, bound := range []time.Time{proof.ValidUntil, h.view.Head.Head.ValidUntil} {
			if bound.Before(r.ValidUntil) {
				r.ValidUntil = bound
			}
		}
	}
	envelope, err := g.SignJournalReceipt(r, h.pipelineKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	if err = h.pipeline.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		if kind == g.JournalReadyToApply && !r.ValidUntil.After(time.Now().UTC()) {
			return errors.New("positive native operation proof expired before inbox publication")
		}
		_, replay, e := tx.FleetGroupJournalInboxAppend(ctx, h.bootstrap.ChainID, g.ContinuationOriginal, store.FleetGroupPipelineIdentity{SourceID: "connected-machine", Issuer: "https://connected-machine.invalid", Subject: "connected-pipeline", Audience: "finops-group-pipeline"}, raw)
		if replay {
			return errors.New("new native pipeline fact replayed")
		}
		return e
	}); err != nil {
		t.Fatal("independent pipeline receipt inbox", err)
	}
	h.appendNativeRecord(t, ctx, func(g.JournalView, g.JournalProjection) (g.JournalRecord, error) {
		if kind == g.JournalReadyToApply && !r.ValidUntil.After(time.Now().UTC()) {
			return g.JournalRecord{}, errors.New("positive native operation proof expired after archival/inbox")
		}
		return g.JournalRecord{Kind: kind, Receipt: &envelope}, nil
	})
	return envelope
}

func (h *connectedJournal) claim(t *testing.T, ctx context.Context, command, action string) (store.FleetGroupJournalDelivery, g.JournalDispatchPermit, string) {
	t.Helper()
	h.refresh(t, ctx)
	var delivery store.FleetGroupJournalDelivery
	var permit g.JournalDispatchPermit
	attempt := model.ID()
	if err := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		var id string
		if e := tx.QueryRow(ctx, `SELECT id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND action=$4`, h.f.tenant, h.bootstrap.ChainID, command, action).Scan(&id); e != nil {
			return e
		}
		var claimed bool
		var e error
		delivery, permit, claimed, e = tx.FleetGroupJournalClaimOriginal(ctx, h.bootstrap.ChainID, id, attempt)
		if e != nil {
			return e
		}
		if !claimed {
			return errors.New("new operation was not claimable")
		}
		// PostgreSQL's actual stored timestamp is the dispatch lease boundary;
		// pgx timestamp encoding can discard sub-microsecond precision.
		var storedUntil time.Time
		if e = tx.QueryRow(ctx, `SELECT lease_until FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, h.f.tenant, h.bootstrap.ChainID, delivery.ID).Scan(&storedUntil); e != nil {
			return e
		}
		if storedUntil.Before(permit.ValidUntil) {
			permit.ValidUntil = storedUntil
		}
		return nil
	}); err != nil {
		t.Fatal("durable one-shot native dispatch claim", err)
	}
	if err := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		_, _, claimed, e := tx.FleetGroupJournalClaimOriginal(ctx, h.bootstrap.ChainID, delivery.ID, model.ID())
		if e != nil {
			return e
		}
		if claimed {
			return errors.New("one-shot delivery claimed twice")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return delivery, permit, attempt
}

func (h *connectedJournal) assertReconcileDeliveryRefused(t *testing.T, ctx context.Context, d store.FleetGroupJournalDelivery, permit g.JournalDispatchPermit, attempt string) {
	t.Helper()
	rollback := errors.New("owned negative probe rollback")
	err := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		if _, _, e := tx.FleetGroupJournalOriginal(ctx, h.bootstrap.ChainID); e != nil {
			return e
		}
		if e := tx.FleetGroupJournalReconcileAttempt(ctx, h.bootstrap.ChainID, d.ID); e != nil {
			return e
		}
		if e := h.deliveryFence(ctx, d, permit, attempt)(tx); e == nil {
			return errors.New("reconciled outbox accepted old dispatch permit")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("actual reconciled delivery guard regression", err)
	}
}

func (h *connectedJournal) deliveryFence(ctx context.Context, d store.FleetGroupJournalDelivery, permit g.JournalDispatchPermit, attempt string) func(*store.Tx) error {
	return func(tx *store.Tx) error {
		var state, storedAttempt, action, command, hash string
		var until time.Time
		if err := tx.QueryRow(ctx, `SELECT state,attempt_id,action,command_id,command_hash,lease_until FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 FOR UPDATE`, h.f.tenant, h.bootstrap.ChainID, d.ID).Scan(&state, &storedAttempt, &action, &command, &hash, &until); err != nil {
			return err
		}
		now := time.Now().UTC()
		if state != "ATTEMPTED" || storedAttempt != attempt || action != d.Action || command != d.CommandID || hash != d.CommandHash || hash != permit.CommandSHA256 || permit.CommandID != command || permit.JournalID != h.view.Authorization.Authorization.JournalID || !until.After(now) || !permit.ValidUntil.After(now) || permit.ValidUntil.After(until) {
			return errors.New("claimed native outbox delivery no longer current")
		}
		return nil
	}
}

// Claim commits BEFORE this function. Reacquiring source/head/workload locks
// immediately before actual I/O closes the post-commit revocation race; the
// native producer separately holds its filesystem fence and checks permit age.
func (h *connectedJournal) nativeFence(ctx context.Context, fn func(g.JournalView, g.JournalKeys) error, checks ...func(*store.Tx) error) error {
	return h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(ctx, h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil {
			return e
		}
		if p.Pending == nil {
			return errors.New("current native command required")
		}
		if p.Pending.Command.Preparation.Mode == g.Forward {
			var current bool
			if e = tx.QueryRow(ctx, "SELECT public.fleet_group_prepared_current($1,$2)", h.f.tenant, h.bootstrap.PreparedProgramID).Scan(&current); e != nil {
				return e
			}
			if !current {
				return errors.New("current source authority required before native forward I/O")
			}
		}
		for _, check := range checks {
			if e = check(tx); e != nil {
				return e
			}
		}
		return fn(v, keys.Core())
	})
}
