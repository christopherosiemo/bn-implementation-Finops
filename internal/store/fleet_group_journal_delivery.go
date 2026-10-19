package store

import (
	"context"
	"encoding/json"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// An outbox entry is a durable invitation to perform a fresh private delivery
// check. Neither its queued timestamp nor its stored permit authorizes I/O.
// The producer still must compare actual Git/native state and positively fence
// NOT_DISPATCHED before an actual CAS or exact saved-plan apply.
type FleetGroupJournalDelivery struct {
	ID          string               `json:"id"`
	ChainID     string               `json:"chain_id"`
	CommandID   string               `json:"command_id"`
	Action      string               `json:"action"`
	Cursor      g.ContinuationCursor `json:"cursor"`
	CommandHash string               `json:"command_hash"`
	Command     json.RawMessage      `json:"command"`
}

func (t *Tx) groupJournalQueue(ctx context.Context, c g.ContinuationCursor, commandID, action string, command any) error {
	commandRaw, _, err := groupJournalBytes(command)
	if err != nil {
		return err
	}
	d := FleetGroupJournalDelivery{ID: model.ID(), ChainID: c.ChainID, CommandID: commandID, Action: action, Cursor: c, CommandHash: g.Digest(command), Command: commandRaw}
	raw, _, err := groupJournalBytes(d)
	if err != nil {
		return err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_outbox(tenant_id,chain_id,id,command_id,action,command_hash,head_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,convert_from($8::bytea,'UTF8')::jsonb,$8) ON CONFLICT(tenant_id,chain_id,command_id,action) DO NOTHING`, t.Tenant, c.ChainID, d.ID, commandID, action, d.CommandHash, c.HeadSHA256, raw)
	return err
}

func (t *Tx) groupJournalOriginalDelivery(ctx context.Context, v g.JournalView, keys g.JournalKeys, r g.JournalRecord, c g.ContinuationCursor) error {
	action := ""
	switch r.Kind {
	case g.JournalPreparing:
		action = "GIT_ADVANCE"
	case g.JournalApplyIntent:
		action = "APPLY"
	case g.JournalGitRepairIntent:
		action = "GIT_REPAIR"
	case g.JournalUnknown:
		action = "RECONCILE"
	}
	if action == "" {
		return nil
	}
	p, err := g.VerifyJournal(v, keys, v.Head.Head.Ref, time.Now().UTC())
	if err != nil {
		return err
	}
	if p.Pending == nil {
		return ErrGroupJournalInvalid
	}
	return t.groupJournalQueue(ctx, c, p.Pending.Command.ID, action, p.Pending.Command)
}

// Claim is one-shot, even across lease expiry and process restart. An expired
// attempt retains a reconciliation obligation; it never becomes deliverable
// again. The returned permit is freshly recomputed under the current cursor.
func (t *Tx) groupJournalClaimOriginal(ctx context.Context, chain, id, attempt string) (FleetGroupJournalDelivery, g.JournalDispatchPermit, bool, error) {
	var d FleetGroupJournalDelivery
	var permit g.JournalDispatchPermit
	c, err := t.FleetGroupJournalCursor(ctx, chain)
	if err != nil {
		return d, permit, false, err
	}
	var raw []byte
	var state string
	err = t.QueryRow(ctx, `SELECT raw_document,state FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 FOR UPDATE`, t.Tenant, chain, id).Scan(&raw, &state)
	if err != nil {
		return d, permit, false, err
	}
	if err = groupJournalDecode(raw, &d); err != nil {
		return d, permit, false, err
	}
	if state != "PENDING" {
		return d, permit, false, nil
	}
	if !groupJournalValidID(attempt) || c.ChainID != d.ChainID || c.Kind != g.ContinuationOriginal {
		return d, permit, false, ErrGroupJournalConflict
	}
	v, keys, err := t.FleetGroupJournalOriginal(ctx, chain)
	if err != nil {
		return d, permit, false, err
	}
	d.Cursor = c
	now := time.Now().UTC()
	p, err := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, now)
	if err != nil {
		return d, permit, false, err
	}
	if p.Pending != nil && p.Pending.Command.Preparation.Mode == g.Forward && (d.Action == "GIT_ADVANCE" || d.Action == "APPLY") {
		b, e := t.groupJournalRoot(ctx, chain)
		if e != nil {
			return d, permit, false, e
		}
		if e = t.groupJournalForwardCurrent(ctx, b); e != nil {
			return d, permit, false, e
		}
	}
	switch d.Action {
	case "GIT_ADVANCE":
		permit, err = g.AuthorizeJournalGitAdvance(v, keys.Core(), v.Head.Head.Ref, d.CommandHash, now)
	case "APPLY":
		permit, err = g.AuthorizeJournalApply(v, keys.Core(), v.Head.Head.Ref, d.CommandHash, now)
	case "GIT_REPAIR":
		p, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, now)
		if e != nil {
			return d, permit, false, e
		}
		if p.Pending == nil || p.Pending.GitRepair == nil {
			return d, permit, false, ErrGroupJournalInvalid
		}
		permit, err = g.AuthorizeJournalGitRepair(v, keys.Core(), v.Head.Head.Ref, g.Digest(p.Pending.GitRepair.Repair), now)
	default:
		return d, permit, false, ErrGroupJournalInvalid
	}
	if err != nil {
		return d, permit, false, err
	}
	r, err := t.Exec(ctx, `UPDATE public.fleet_group_journal_outbox SET state='ATTEMPTED',attempt_id=$4,attempted_at=clock_timestamp(),lease_until=$5 WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 AND state='PENDING'`, t.Tenant, chain, id, attempt, permit.ValidUntil)
	return d, permit, err == nil && r.RowsAffected() == 1, err
}

func (t *Tx) groupJournalReconcileAttempt(ctx context.Context, chain, id string) error {
	if _, err := t.FleetGroupJournalCursor(ctx, chain); err != nil {
		return err
	}
	_, err := t.Exec(ctx, `UPDATE public.fleet_group_journal_outbox SET state='RECONCILE' WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 AND state='ATTEMPTED'`, t.Tenant, chain, id)
	return err
}

func (t *Tx) FleetGroupJournalClaimContinuation(ctx context.Context, chain, id, attempt string) (FleetGroupJournalDelivery, g.ContinuationPermit, bool, error) {
	type result struct {
		delivery FleetGroupJournalDelivery
		permit   g.ContinuationPermit
		required bool
	}
	out, err := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		var r result
		c, e := tx.FleetGroupJournalCursor(ctx, chain)
		if e != nil {
			return r, e
		}
		var raw []byte
		var state string
		e = tx.QueryRow(ctx, `SELECT raw_document,state FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 FOR UPDATE`, tx.Tenant, chain, id).Scan(&raw, &state)
		if e != nil {
			return r, e
		}
		if e = groupJournalDecode(raw, &r.delivery); e != nil {
			return r, e
		}
		if state != "PENDING" {
			return r, nil
		}
		if c.Kind != g.ContinuationSegment || !groupJournalValidID(attempt) || r.delivery.ChainID != chain {
			return r, ErrGroupJournalConflict
		}
		v, keys, e := tx.FleetGroupJournalContinuation(ctx, chain)
		if e != nil {
			return r, e
		}
		now := time.Now().UTC()
		p, e := g.VerifyContinuation(ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), now)
		if e != nil {
			return r, e
		}
		if p.Pending == nil {
			return r, ErrGroupJournalInvalid
		}
		switch r.delivery.Action {
		case "GIT_ADVANCE":
			r.permit, e = g.AuthorizeContinuationGitAdvance(ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), r.delivery.CommandHash, now)
		case "APPLY", "GIT_REPAIR":
			r.permit, e = g.AuthorizeContinuationDispatch(ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), r.delivery.CommandHash, p.Pending.Command.Mode, now)
		default:
			return r, ErrGroupJournalInvalid
		}
		if e != nil {
			return r, e
		}
		changed, e := tx.Exec(ctx, `UPDATE public.fleet_group_journal_outbox SET state='ATTEMPTED',attempt_id=$4,attempted_at=clock_timestamp(),lease_until=$5 WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 AND state='PENDING'`, tx.Tenant, chain, id, attempt, r.permit.ValidUntil)
		r.required = e == nil && changed.RowsAffected() == 1
		r.delivery.Cursor = c
		return r, e
	})
	return out.delivery, out.permit, out.required, err
}

// A terminal callback can close transport bookkeeping only after it is an
// authenticated, reduced authority record. It never releases the reservation.
func (t *Tx) groupJournalFinishDelivery(ctx context.Context, chain, command, kind string) error {
	state := "COMPLETE"
	switch kind {
	case g.JournalUnknown:
		state = "RECONCILE"
	case g.JournalApplied, g.JournalNoApply, g.JournalGitRepaired:
	default:
		return nil
	}
	if state == "RECONCILE" {
		_, e := t.Exec(ctx, `UPDATE public.fleet_group_journal_outbox SET state='RECONCILE' WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND state='ATTEMPTED'`, t.Tenant, chain, command)
		return e
	}
	_, e := t.Exec(ctx, `UPDATE public.fleet_group_journal_outbox SET state='COMPLETE' WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND state IN('ATTEMPTED','RECONCILE')`, t.Tenant, chain, command)
	return e
}

func (t *Tx) FleetGroupJournalOutbox(ctx context.Context, chain, id string) (FleetGroupJournalDelivery, string, error) {
	var d FleetGroupJournalDelivery
	var state string
	var raw []byte
	if _, e := t.FleetGroupJournalCursor(ctx, chain); e != nil {
		return d, state, e
	}
	e := t.QueryRow(ctx, `SELECT raw_document,state FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, t.Tenant, chain, id).Scan(&raw, &state)
	if e == nil {
		e = groupJournalDecode(raw, &d)
	}
	return d, state, e
}

// Release records a fully resolved private obligation. It is not approval for
// any forward action, and an old empty head cannot release a newer duty.
func (t *Tx) FleetGroupJournalRelease(ctx context.Context, chain string, expected g.ContinuationCursor) error {
	_, err := groupJournalAtomic(ctx, t, func(tx *Tx) (bool, error) {
		c, e := tx.FleetGroupJournalCursor(ctx, chain)
		if e != nil {
			return false, e
		}
		if c != expected {
			return false, ErrGroupJournalConflict
		}
		if c.Kind == g.ContinuationOriginal {
			v, keys, e := tx.FleetGroupJournalOriginal(ctx, chain)
			if e != nil {
				return false, e
			}
			p, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, time.Now().UTC())
			if e != nil {
				return false, e
			}
			if !p.ForwardAborted || p.Pending != nil || len(p.Stack) != 0 {
				return false, ErrGroupJournalInvalid
			}
		} else {
			v, keys, e := tx.FleetGroupJournalContinuation(ctx, chain)
			if e != nil {
				return false, e
			}
			p, e := g.VerifyContinuation(ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), time.Now().UTC())
			if e != nil {
				return false, e
			}
			if !p.RecoveryOnly || p.Pending != nil || p.OriginalPending != nil || p.GitDuty != nil || len(p.Stack) != 0 {
				return false, ErrGroupJournalInvalid
			}
		}
		r, e := tx.Exec(ctx, `UPDATE public.fleet_group_journal_reservations SET released_at=clock_timestamp(),release_head_hash=$3 WHERE tenant_id=$1 AND chain_id=$2 AND released_at IS NULL`, tx.Tenant, chain, c.HeadSHA256)
		if e == nil && r.RowsAffected() != 1 {
			return false, ErrGroupJournalConflict
		}
		return true, e
	})
	return err
}
