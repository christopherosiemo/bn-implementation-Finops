package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

func (h *groupJournalTest) originalEvent(t *testing.T, r g.JournalRecord) {
	t.Helper()
	if r.Receipt != nil {
		h.inbox(t, g.ContinuationOriginal, *r.Receipt)
	}
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(h.f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		at := time.Now().UTC()
		r.Sequence = uint64(len(v.Records) + 1)
		r.PreviousSHA256 = v.Head.Head.Ref.LastRecordSHA256
		r.RecordedAt = at
		records, _, e := g.AppendJournalRecord(v, keys.Core(), v.Head.Head.Ref, r, at)
		if e != nil {
			return e
		}
		v, _, e = g.SealJournalView(v.Parent, v.Authorization, records, keys.Core(), h.ledger, at)
		if e != nil {
			return e
		}
		h.cursor, _, e = tx.FleetGroupJournalAppendOriginal(h.f.ctx, h.b.ChainID, h.cursor, r, v.Head)
		return e
	})
}
func (h *groupJournalTest) protocolOriginalReceipt(t *testing.T, kind string) g.JournalReceiptEnvelope {
	t.Helper()
	var receipt g.JournalReceipt
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(h.f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil {
			return e
		}
		if p.Pending == nil {
			return errors.New("protocol receipt has no pending command")
		}
		c := p.Pending.Command
		at := time.Now().UTC()
		state := c.Before
		state.Revision = c.Preparation.Revision
		before, after := state, state
		if kind == g.JournalGitAdvanced {
			before = c.Before
		}
		if kind == g.JournalApplied {
			before = c.Before
			if c.Preparation.Before != c.Preparation.After {
				after.StateSerial++
				after.StateSHA256 = strings.Repeat("d", 64)
			}
			after.Model = c.Preparation.After
		}
		receipt = g.JournalReceipt{SchemaVersion: g.JournalSchemaVersion, ID: fmt.Sprintf("protocol-receipt-%d", h.cursor.GlobalCount+1), IdempotencyKey: fmt.Sprintf("protocol-receipt-key-%d", h.cursor.GlobalCount+1), JournalID: v.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(v.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: v.Authorization.Authorization.PipelineID, Kind: kind, PreparationSHA256: g.Digest(c.Preparation), Before: before, After: after, ReceivedAt: at}
		if c.Forward != nil {
			receipt.ArtifactSHA256 = g.Digest(c.Forward.Child.Artifact)
			receipt.SavedPlanSHA256 = c.Forward.Child.Artifact.SavedPlanSHA256
		}
		if kind == g.JournalReadyToApply {
			receipt.ValidUntil = at.Add(30 * time.Second)
		}
		return nil
	})
	signed, e := g.SignJournalReceipt(receipt, h.pipeline)
	if e != nil {
		t.Fatal(e)
	}
	return signed
}
func (h *groupJournalTest) protocolForward(t *testing.T, sequence uint64) g.JournalReceiptEnvelope {
	t.Helper()
	p := h.b.Parent.Program
	entry := p.Manifest.Entries[sequence-1]
	var command g.JournalCommand
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(h.f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		projection, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil {
			return e
		}
		command = g.JournalCommand{ID: fmt.Sprintf("owned-command-%d", sequence), OperationID: fmt.Sprintf("owned-operation-%d", sequence), IdempotencyKey: fmt.Sprintf("owned-key-%d", sequence), Fence: projection.LastFence + 1, Head: v.Head, Before: projection.Current, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: sequence, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}, CreatedAt: time.Now().UTC()}
		return nil
	})
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &command})
	git := h.protocolOriginalReceipt(t, g.JournalGitAdvanced)
	h.originalEvent(t, g.JournalRecord{Kind: git.Receipt.Kind, Receipt: &git})
	at := time.Now().UTC()
	child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: fmt.Sprintf("protocol-child-%d", sequence), ParentID: p.ID, ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Mode: g.Forward, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: sequence, Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: fmt.Sprintf("explicit-unit-artifact-%d", sequence), SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, ManifestEntrySHA256: g.Digest(entry), PreviousRevision: command.Before.Revision, Revision: entry.Revision, BeforeStateSerial: command.Before.StateSerial, BeforeStateSHA256: command.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: entry.Before, After: entry.After}, MinimumObservationSeconds: entry.MinimumObservationSeconds, CreatedAt: at, ExpiresAt: at.Add(10 * time.Minute), Nonce: fmt.Sprintf("protocol-child-nonce-%d", sequence)}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
		child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: fmt.Sprintf("explicit-unit-%s-%d", kind, sequence), SHA256: strings.Repeat("f", 64), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: at, ValidUntil: at.Add(15 * time.Minute)})
	}
	signed, e := g.SignGitChild(child, h.b.Parent, h.signer, at)
	if e != nil {
		t.Fatal(e)
	}
	command.Forward = &signed
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalReserved, Command: &command})
	var terminal g.JournalReceiptEnvelope
	for _, kind := range []string{g.JournalReadyToApply, g.JournalApplyIntent, g.JournalApplied} {
		terminal = h.protocolOriginalReceipt(t, kind)
		h.originalEvent(t, g.JournalRecord{Kind: kind, Receipt: &terminal})
	}
	return terminal
}

func (h *groupJournalTest) continuationEvent(t *testing.T, r g.ContinuationRecord) {
	t.Helper()
	if r.Receipt != nil {
		h.inbox(t, g.ContinuationSegment, *r.Receipt)
	}
	if r.OriginalReceipt != nil {
		h.inbox(t, g.ContinuationOriginal, *r.OriginalReceipt)
	}
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		v, _, e := tx.FleetGroupJournalContinuation(h.f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		r.Sequence = uint64(len(v.Records) + 1)
		r.PreviousSHA256 = v.Head.Head.LastRecordSHA256
		r.RecordedAt = time.Now().UTC()
		h.cursor, _, e = tx.FleetGroupJournalAppendContinuation(h.f.ctx, h.b.ChainID, h.cursor, h.ledger, r)
		return e
	})
}

func TestFleetGroupJournalIssuedEffectContinuesToOneShotOwnedInverseAndCannotRevive(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	h.protocolForward(t, 1)
	owned := h.protocolForward(t, 2)
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalOpenContinuation(f.ctx, h.b.ChainID, h.ledger, "owned-checkpoint")
		return e
	})
	var c g.ContinuationCommand
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalContinuation(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyContinuation(f.ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), time.Now().UTC())
		if e != nil {
			return e
		}
		if len(p.Stack) != 1 {
			return errors.New("real SQL-issued effect missing")
		}
		top := p.Stack[0]
		source, _ := g.GitFixtureConfiguration(h.b.Parent.Program)
		desired, _ := g.GitFixtureDesired(h.b.Parent.Program, top.Forward.Child.Artifact.Before)
		revision, _, _ := fixtureUnitGit(source, desired, p.Current.Revision.Commit, 100)
		c = g.ContinuationCommand{ID: "owned-inverse", OperationID: "owned-inverse-operation", IdempotencyKey: "owned-inverse-key", Nonce: "owned-inverse-nonce", Fence: p.LastFence + 1, Mode: g.ContinuationInverse, ObligationSHA256: g.Digest(top), Head: v.Head, Before: p.Current, Revision: revision, After: top.Forward.Child.Artifact.Before, CreatedAt: time.Now().UTC()}
		return nil
	})
	h.continuationEvent(t, g.ContinuationRecord{Kind: g.ContinuationPreparing, Command: &c})
	var gitOutbox string
	f.must("finops_group_ledger", func(tx *Tx) error {
		return tx.QueryRow(f.ctx, `SELECT id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND action='GIT_ADVANCE'`, f.tenant, h.b.ChainID, c.ID).Scan(&gitOutbox)
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		_, permit, required, e := tx.FleetGroupJournalClaimContinuation(f.ctx, h.b.ChainID, gitOutbox, "inverse-git-attempt")
		if e == nil && (!required || permit.CommandSHA256 != g.Digest(c)) {
			return errors.New("fresh owned Git claim failed")
		}
		return e
	})
	var final g.ContinuationFinalizationEnvelope
	issue := func(kind string) {
		t.Helper()
		var signed g.ContinuationReceiptEnvelope
		f.must("finops_group_ledger", func(tx *Tx) error {
			v, keys, e := tx.FleetGroupJournalContinuation(f.ctx, h.b.ChainID)
			if e != nil {
				return e
			}
			p, e := g.VerifyContinuation(f.ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), time.Now().UTC())
			if e != nil {
				return e
			}
			before, after := p.Current, p.Current
			if kind == g.ContinuationGitAdvanced {
				before = c.Before
				after.Revision = c.Revision
			}
			if kind == g.ContinuationApplied {
				before = c.Before
				after.Revision = c.Revision
				after.StateSerial = c.Before.StateSerial + 1
				after.StateSHA256 = strings.Repeat("e", 64)
				after.Model = c.After
			}
			at := time.Now().UTC()
			receipt := g.ContinuationReceipt{SchemaVersion: g.ContinuationSchemaVersion, ID: fmt.Sprintf("inverse-receipt-%d", h.cursor.GlobalCount+1), IdempotencyKey: fmt.Sprintf("inverse-receipt-key-%d", h.cursor.GlobalCount+1), ChainSHA256: g.Digest(v.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, Kind: kind, CommandSHA256: g.Digest(c), Before: before, After: after, ReceivedAt: at}
			if final.Signature != "" {
				receipt.FinalizationSHA256 = g.Digest(final.Finalization)
			}
			if kind == g.ContinuationReady {
				receipt.ValidUntil = at.Add(30 * time.Second)
			}
			signed, e = g.SignContinuationReceipt(receipt, h.pipeline)
			return e
		})
		h.continuationEvent(t, g.ContinuationRecord{Kind: kind, Receipt: &signed})
	}
	issue(g.ContinuationGitAdvanced)
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalContinuation(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		p := h.b.Parent.Program
		at := time.Now().UTC()
		body := g.ContinuationFinalization{SchemaVersion: g.ContinuationSchemaVersion, ID: "inverse-finalization", ChainSHA256: g.Digest(v.Authorization), CommandSHA256: g.Digest(c), SigningHeadSHA256: g.Digest(v.Head), Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "explicit-unit-inverse-artifact", SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: c.Before.Model, After: c.After}, CreatedAt: at, ExpiresAt: at.Add(10 * time.Minute), Nonce: "inverse-finalization-nonce"}
		for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
			body.Evidence = append(body.Evidence, g.EvidenceRef{Kind: kind, ID: "explicit-unit-" + kind, SHA256: strings.Repeat("f", 64), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: at, ValidUntil: at.Add(15 * time.Minute)})
		}
		final, e = g.SignContinuationFinalization(f.ctx, body, v, keys.Core(), tx.FleetGroupJournalAuthority(), h.signer, at)
		return e
	})
	h.continuationEvent(t, g.ContinuationRecord{Kind: g.ContinuationFinalized, Finalization: &final})
	issue(g.ContinuationReady)
	issue(g.ContinuationIntent)
	var applyOutbox string
	f.must("finops_group_ledger", func(tx *Tx) error {
		return tx.QueryRow(f.ctx, `SELECT id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND action='APPLY'`, f.tenant, h.b.ChainID, c.ID).Scan(&applyOutbox)
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		_, _, required, e := tx.FleetGroupJournalClaimContinuation(f.ctx, h.b.ChainID, applyOutbox, "inverse-apply-attempt")
		if e == nil && !required {
			return errors.New("first owned apply was not claimed")
		}
		return e
	})
	issue(g.ContinuationUnknown)
	groupJournalTestLogin(t, f, "finops_group_ledger") // A new authenticated process reads durable state only.
	f.must("finops_group_ledger", func(tx *Tx) error {
		_, _, required, e := tx.FleetGroupJournalClaimContinuation(f.ctx, h.b.ChainID, applyOutbox, "restart-attempt")
		if e == nil && required {
			return errors.New("uncertain owned apply redispatched after restart")
		}
		return e
	})
	issue(g.ContinuationApplied)
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalContinuation(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyContinuation(f.ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), time.Now().UTC())
		if e != nil {
			return e
		}
		if len(p.Stack) != 0 || len(p.Consumed) != 1 || p.Pending != nil {
			return errors.New("owned inverse did not consume exact effect")
		}
		before := h.cursor
		after, replayed, e := tx.FleetGroupJournalAppendContinuation(f.ctx, h.b.ChainID, before, h.ledger, g.ContinuationRecord{Kind: g.ContinuationLegacy, OriginalReceipt: &owned})
		if e == nil && (!replayed || after != before) {
			return errors.New("consumed original effect revived")
		}
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error { return tx.FleetGroupJournalRelease(f.ctx, h.b.ChainID, h.cursor) })
}
