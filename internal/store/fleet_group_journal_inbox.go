package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/jackc/pgx/v5"
)

// Supplied by a dedicated machine-OIDC handler after token verification, never
// decoded from callback JSON. PostgreSQL repeats commissioned identity matching.
type FleetGroupPipelineIdentity struct{ SourceID, Issuer, Subject, Audience string }
type FleetGroupPipelineInbox struct {
	ID             string          `json:"id"`
	IdempotencyKey string          `json:"idempotency_key"`
	CommandID      string          `json:"command_id"`
	Kind           string          `json:"kind"`
	BodyHash       string          `json:"body_hash"`
	Body           json.RawMessage `json:"body"`
	ReceivedAt     time.Time       `json:"received_at"`
}

func (t *Tx) groupJournalRequireInbox(ctx context.Context, chain, kind, id string, envelope any) error {
	raw, _, err := groupJournalBytes(envelope)
	if err != nil {
		return err
	}
	var stored []byte
	var actualKind string
	if err = t.QueryRow(ctx, `SELECT raw_body,kind FROM public.fleet_group_pipeline_inbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, t.Tenant, chain, id).Scan(&stored, &actualKind); err != nil {
		return err
	}
	if actualKind != kind || !bytes.Equal(stored, raw) {
		return ErrGroupJournalConflict
	}
	return nil
}

// This writes only a quarantined inbox. It cannot append authority events,
// change current heads, dispatch an outbox or release an ownership obligation.
// The dedicated ledger must verify its pinned pipeline signature and reducer.
func (t *Tx) FleetGroupJournalInboxAppend(ctx context.Context, chain, kind string, identity FleetGroupPipelineIdentity, raw []byte) (FleetGroupPipelineInbox, bool, error) {
	type result struct {
		row    FleetGroupPipelineInbox
		replay bool
	}
	out, err := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		d := FleetGroupPipelineInbox{Kind: kind, Body: raw, BodyHash: g.BytesDigest(raw)}
		if len(raw) == 0 || len(raw) > g.JournalRecordByteLimit || !groupJournalValidID(chain) {
			return result{}, ErrGroupJournalInvalid
		}
		switch kind {
		case g.ContinuationOriginal:
			var e g.JournalReceiptEnvelope
			if groupJournalDecode(raw, &e) != nil {
				return result{}, ErrGroupJournalInvalid
			}
			d.ID, d.IdempotencyKey, d.CommandID = e.Receipt.ID, e.Receipt.IdempotencyKey, e.Receipt.CommandID
		case g.ContinuationSegment:
			var e g.ContinuationReceiptEnvelope
			if groupJournalDecode(raw, &e) != nil {
				return result{}, ErrGroupJournalInvalid
			}
			d.ID, d.IdempotencyKey, d.CommandID = e.Receipt.ID, e.Receipt.IdempotencyKey, e.Receipt.CommandID
		default:
			return result{}, ErrGroupJournalInvalid
		}
		if !groupJournalValidID(d.ID) || !groupJournalValidID(d.IdempotencyKey) || !groupJournalValidID(d.CommandID) {
			return result{}, ErrGroupJournalInvalid
		}
		var allowed bool
		if e := tx.QueryRow(ctx, `SELECT public.fleet_group_pipeline_binding($1,$2,$3,$4,$5,$6,$7)`, tx.Tenant, chain, identity.SourceID, identity.Issuer, identity.Subject, identity.Audience, d.CommandID).Scan(&allowed); e != nil {
			return result{}, e
		}
		if !allowed {
			return result{}, ErrGroupJournalInvalid
		}
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tx.Tenant+":group-pipeline-inbox:"+chain); e != nil {
			return result{}, e
		}
		var priorRaw []byte
		var priorKind, priorSource, priorIssuer, priorSubject, priorAudience string
		e := tx.QueryRow(ctx, `SELECT raw_body,kind,source_id,issuer,subject,audience,received_at FROM public.fleet_group_pipeline_inbox WHERE tenant_id=$1 AND chain_id=$2 AND (id=$3 OR receipt_key=$4)`, tx.Tenant, chain, d.ID, d.IdempotencyKey).Scan(&priorRaw, &priorKind, &priorSource, &priorIssuer, &priorSubject, &priorAudience, &d.ReceivedAt)
		if e == nil {
			if !bytes.Equal(priorRaw, raw) || priorKind != kind || priorSource != identity.SourceID || priorIssuer != identity.Issuer || priorSubject != identity.Subject || priorAudience != identity.Audience {
				return result{}, ErrGroupJournalConflict
			}
			return result{d, true}, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return result{}, e
		}
		e = tx.QueryRow(ctx, `INSERT INTO public.fleet_group_pipeline_inbox(tenant_id,chain_id,id,receipt_key,command_id,source_id,issuer,subject,audience,kind,body_hash,document,raw_body) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,convert_from($12::bytea,'UTF8')::jsonb,$12) RETURNING received_at`, tx.Tenant, chain, d.ID, d.IdempotencyKey, d.CommandID, identity.SourceID, identity.Issuer, identity.Subject, identity.Audience, kind, d.BodyHash, raw).Scan(&d.ReceivedAt)
		return result{d, false}, e
	})
	return out.row, out.replay, err
}
