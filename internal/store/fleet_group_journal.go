package store

// This is a private issuer repository, not a public upload contract. Its SQL
// role is deliberately different from API, workflow, signer and pipeline roles.
// PostgreSQL checks storage closure/CAS; the Go reducer verifies signatures and
// transition semantics. A JSONB projection or a database writer label alone is
// never accepted as cryptographic ownership evidence.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrGroupJournalConflict = errors.New("GROUP_JOURNAL_CURRENT_CURSOR_CONFLICT")
var ErrGroupJournalInvalid = errors.New("GROUP_JOURNAL_ISSUED_EVIDENCE_INVALID")

var groupJournalID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

type FleetGroupJournalKeys struct {
	Signer   ed25519.PublicKey `json:"signer"`
	Pipeline ed25519.PublicKey `json:"pipeline"`
	Ledger   ed25519.PublicKey `json:"ledger"`
}

func (k FleetGroupJournalKeys) Core() g.JournalKeys {
	return g.JournalKeys{Signer: k.Signer, Pipeline: k.Pipeline, Ledger: k.Ledger}
}

type FleetGroupJournalBootstrap struct {
	ChainID           string                `json:"chain_id"`
	KeyBindingID      string                `json:"key_binding_id"`
	PreparedProgramID string                `json:"prepared_program_id"`
	ApprovalID        string                `json:"approval_id"`
	Parent            g.GitEnvelope         `json:"parent"`
	Authorization     g.JournalEnvelope     `json:"authorization"`
	Head              g.JournalHeadEnvelope `json:"bootstrap_head"`
	Keys              FleetGroupJournalKeys `json:"keys"`
}

func (b FleetGroupJournalBootstrap) View() g.JournalView {
	return g.JournalView{Parent: b.Parent, Authorization: b.Authorization, Records: []g.JournalRecord{}, Head: b.Head}
}

func groupJournalBytes(v any) ([]byte, string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	return raw, g.BytesDigest(raw), nil
}
func groupJournalDecode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrGroupJournalInvalid
	}
	want, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, want) {
		return ErrGroupJournalInvalid
	}
	return nil
}
func groupJournalValidID(s string) bool { return groupJournalID.MatchString(s) }

func (t *Tx) groupJournalLock(ctx context.Context, chain string) error {
	if !groupJournalValidID(chain) {
		return ErrGroupJournalInvalid
	}
	var workload string
	if err := t.QueryRow(ctx, `SELECT workload_id FROM public.fleet_group_journal_roots WHERE tenant_id=$1 AND chain_id=$2`, t.Tenant, chain).Scan(&workload); err != nil {
		return err
	}
	_, err := t.Exec(ctx, `SELECT public.fleet_group_journal_lock($1,$2)`, t.Tenant, workload)
	return err
}
func (t *Tx) groupJournalRoot(ctx context.Context, chain string) (FleetGroupJournalBootstrap, error) {
	var b FleetGroupJournalBootstrap
	var raw []byte
	err := t.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_journal_roots WHERE tenant_id=$1 AND chain_id=$2`, t.Tenant, chain).Scan(&raw)
	if err == nil {
		err = groupJournalDecode(raw, &b)
	}
	return b, err
}

// Bootstrap establishes only the actual zero-record original cursor. Attaching
// an independently approved continuation envelope is a separate pre-command CAS.
// The caller is the dedicated ledger process, with server-configured public keys.
func (t *Tx) groupJournalBootstrap(ctx context.Context, b FleetGroupJournalBootstrap) (g.ContinuationCursor, error) {
	var empty g.ContinuationCursor
	if !groupJournalValidID(b.ChainID) || !groupJournalValidID(b.KeyBindingID) || !groupJournalValidID(b.PreparedProgramID) || !groupJournalValidID(b.ApprovalID) || b.Parent.Program.Binding.Old.Target.TenantID != t.Tenant || b.Parent.Program.Realm.Kind != g.IsolatedFixture {
		return empty, ErrGroupJournalInvalid
	}
	trusted, err := t.groupJournalCommissionedKeys(ctx, b)
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(trusted.Signer, b.Keys.Signer) || !bytes.Equal(trusted.Pipeline, b.Keys.Pipeline) || !bytes.Equal(trusted.Ledger, b.Keys.Ledger) {
		return empty, ErrGroupJournalInvalid
	}
	now := time.Now().UTC()
	view := b.View()
	p, err := g.VerifyJournal(view, trusted.Core(), view.Head.Head.Ref, now)
	if err != nil {
		return empty, err
	}
	var programRaw, reviewRaw []byte
	var programHash, actor string
	err = t.QueryRow(ctx, `SELECT p.program_raw,p.program_hash,a.actor_id,p.journal_review_raw FROM public.fleet_fixture_prepared_programs p JOIN public.fleet_fixture_approvals a ON a.tenant_id=p.tenant_id AND a.prepared_program_id=p.id WHERE p.tenant_id=$1 AND p.id=$2 AND a.id=$3 AND a.program_hash=p.program_hash AND a.manifest_hash=p.manifest_hash AND a.journal_review_hash=p.journal_review_hash`, t.Tenant, b.PreparedProgramID, b.ApprovalID).Scan(&programRaw, &programHash, &actor, &reviewRaw)
	if err != nil {
		return empty, err
	}
	if g.BytesDigest(programRaw) != programHash || programHash != g.Digest(b.Parent.Program) {
		return empty, ErrGroupJournalInvalid
	}
	var approvedProgram g.GitProgram
	if groupJournalDecode(programRaw, &approvedProgram) != nil || g.Digest(approvedProgram) != g.Digest(b.Parent.Program) {
		return empty, ErrGroupJournalInvalid
	}
	var review fleetfixture.JournalReview
	if groupJournalDecode(reviewRaw, &review) != nil {
		return empty, ErrGroupJournalInvalid
	}
	a := b.Authorization.Authorization
	if a.Base != review.Base || a.PipelineID != review.PipelineID || a.Ref != review.Ref || a.PipelineKeySHA256 != review.PipelineKeySHA256 || a.LedgerKeySHA256 != review.LedgerKeySHA256 || uint64(a.MaximumEffects) != review.MaxEffects || uint64(a.MaximumRecords) != review.MaxRecords || a.ExpiresAt != review.ExpiresAt {
		return empty, ErrGroupJournalInvalid
	}
	parentApproval, err := t.FleetGroupJournalParentApproval(ctx, b.PreparedProgramID, b.ApprovalID)
	if err != nil {
		return empty, err
	}
	if len(b.Parent.Approvals) != 1 || b.Parent.Approvals[0] != parentApproval {
		return empty, ErrGroupJournalInvalid
	}
	approval, err := t.groupJournalAuthorityApproval(ctx, b, "JOURNAL", b.Authorization.Authorization)
	if err != nil {
		return empty, err
	}
	if len(b.Authorization.Approvals) != 1 || !groupJournalApprovalSame(b.Authorization.Approvals[0], approval) {
		return empty, ErrGroupJournalInvalid
	}
	workload := b.Parent.Program.Binding.Old.Target.WorkloadID
	if _, err = t.Exec(ctx, `SELECT public.fleet_group_journal_lock($1,$2)`, t.Tenant, workload); err != nil {
		return empty, err
	}
	if err = t.groupJournalForwardCurrent(ctx, b); err != nil {
		return empty, err
	}
	if prior, e := t.FleetGroupJournalCursor(ctx, b.ChainID); e == nil {
		old, er := t.groupJournalRoot(ctx, b.ChainID)
		if er == nil && g.Digest(old) == g.Digest(b) {
			return prior, nil
		}
		return empty, ErrGroupJournalConflict
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return empty, e
	}
	raw, hash, err := groupJournalBytes(b)
	if err != nil {
		return empty, err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_roots(tenant_id,chain_id,workload_id,prepared_program_id,approval_id,key_binding_id,parent_hash,authorization_hash,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,convert_from($10::bytea,'UTF8')::jsonb,$10)`, t.Tenant, b.ChainID, workload, b.PreparedProgramID, b.ApprovalID, b.KeyBindingID, g.Digest(b.Parent), g.Digest(b.Authorization), hash, raw)
	if err != nil {
		return empty, err
	}
	segment := model.Document{"kind": g.ContinuationOriginal, "bootstrap_head": b.Head}
	sraw, _, err := groupJournalBytes(segment)
	if err != nil {
		return empty, err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_segments(tenant_id,chain_id,segment,kind,checkpoint_hash,document,raw_document) VALUES($1,$2,0,'ORIGINAL_JOURNAL','',convert_from($3::bytea,'UTF8')::jsonb,$3)`, t.Tenant, b.ChainID, sraw)
	if err != nil {
		return empty, err
	}
	cursor := g.ContinuationOriginalCursor(b.ChainID, view)
	if err = t.groupJournalHeadInsert(ctx, cursor, b.Head, p); err != nil {
		return empty, err
	}
	craw, _, err := groupJournalBytes(cursor)
	if err != nil {
		return empty, err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_current(tenant_id,chain_id,version,head_hash,document,raw_document) VALUES($1,$2,1,$3,convert_from($4::bytea,'UTF8')::jsonb,$4)`, t.Tenant, b.ChainID, cursor.HeadSHA256, craw)
	return cursor, err
}

func (t *Tx) FleetGroupJournalCursor(ctx context.Context, chain string) (g.ContinuationCursor, error) {
	var c g.ContinuationCursor
	if err := t.groupJournalLock(ctx, chain); err != nil {
		return c, err
	}
	var raw []byte
	err := t.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_journal_current WHERE tenant_id=$1 AND chain_id=$2 FOR UPDATE`, t.Tenant, chain).Scan(&raw)
	if err == nil {
		err = groupJournalDecode(raw, &c)
	}
	if err == nil && c.ChainID != chain {
		err = ErrGroupJournalInvalid
	}
	return c, err
}

func (t *Tx) groupJournalAttachContinuation(ctx context.Context, chain string, e g.ContinuationEnvelope) error {
	c, err := t.FleetGroupJournalCursor(ctx, chain)
	if err != nil {
		return err
	}
	b, err := t.groupJournalRoot(ctx, chain)
	if err != nil {
		return err
	}
	draft, bootstrap := e.Authorization.BootstrapHead.Head, b.Head.Head
	if c.Kind != g.ContinuationOriginal || c.RecordCount != 0 || c.Segment != 0 || e.Authorization.ChainID != chain || draft.JournalID != bootstrap.JournalID || draft.AuthorizationSHA256 != bootstrap.AuthorizationSHA256 || draft.Ref != bootstrap.Ref || draft.ProjectionSHA256 != bootstrap.ProjectionSHA256 {
		return ErrGroupJournalConflict
	}
	if _, _, err = t.FleetGroupJournalOriginal(ctx, chain); err != nil {
		return err
	}
	if err = g.VerifyContinuationAuthorization(e, g.ContinuationOrigin{Parent: b.Parent, Authorization: b.Authorization}, b.Keys.Core(), time.Now().UTC()); err != nil {
		return err
	}
	approval, err := t.groupJournalAuthorityApproval(ctx, b, "CONTINUATION", e.Authorization)
	if err != nil {
		return err
	}
	if len(e.Approvals) != 1 || !groupJournalApprovalSame(e.Approvals[0], approval) {
		return ErrGroupJournalInvalid
	}
	raw, h, err := groupJournalBytes(e)
	if err != nil {
		return err
	}
	var prior string
	err = t.QueryRow(ctx, `SELECT content_hash FROM public.fleet_group_journal_chain_authorizations WHERE tenant_id=$1 AND chain_id=$2`, t.Tenant, chain).Scan(&prior)
	if err == nil {
		if prior == h {
			return nil
		}
		return ErrGroupJournalConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_chain_authorizations(tenant_id,chain_id,content_hash,document,raw_document) VALUES($1,$2,$3,convert_from($4::bytea,'UTF8')::jsonb,$4)`, t.Tenant, chain, h, raw)
	return err
}

func (t *Tx) groupJournalHeadInsert(ctx context.Context, c g.ContinuationCursor, head, projection any) error {
	hraw, hash, err := groupJournalBytes(head)
	if err != nil {
		return err
	}
	praw, _, err := groupJournalBytes(projection)
	if err != nil {
		return err
	}
	craw, _, err := groupJournalBytes(c)
	if err != nil {
		return err
	}
	if hash != c.HeadSHA256 {
		return ErrGroupJournalInvalid
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_heads(tenant_id,chain_id,content_hash,segment,record_count,document,raw_document,projection,raw_projection,cursor_document,raw_cursor) VALUES($1,$2,$3,$4,$5,convert_from($6::bytea,'UTF8')::jsonb,$6,convert_from($7::bytea,'UTF8')::jsonb,$7,convert_from($8::bytea,'UTF8')::jsonb,$8) ON CONFLICT(tenant_id,chain_id,content_hash) DO NOTHING`, t.Tenant, c.ChainID, hash, fmt.Sprint(c.Segment), c.RecordCount, hraw, praw, craw)
	return err
}
func (t *Tx) groupJournalCAS(ctx context.Context, expected, next g.ContinuationCursor) error {
	if expected.ChainID != next.ChainID {
		return ErrGroupJournalInvalid
	}
	raw, _, err := groupJournalBytes(next)
	if err != nil {
		return err
	}
	before, _, err := groupJournalBytes(expected)
	if err != nil {
		return err
	}
	r, err := t.Exec(ctx, `UPDATE public.fleet_group_journal_current SET version=version+1,head_hash=$3,document=convert_from($4::bytea,'UTF8')::jsonb,raw_document=$4 WHERE tenant_id=$1 AND chain_id=$2 AND raw_document=$5`, t.Tenant, expected.ChainID, next.HeadSHA256, raw, before)
	if err == nil && r.RowsAffected() != 1 {
		return ErrGroupJournalConflict
	}
	return err
}

func (t *Tx) FleetGroupJournalOriginal(ctx context.Context, chain string) (g.JournalView, FleetGroupJournalKeys, error) {
	return t.groupJournalOriginal(ctx, chain, false)
}
func (t *Tx) groupJournalOriginal(ctx context.Context, chain string, allowStale bool) (g.JournalView, FleetGroupJournalKeys, error) {
	var v g.JournalView
	c, err := t.FleetGroupJournalCursor(ctx, chain)
	if err != nil {
		return v, FleetGroupJournalKeys{}, err
	}
	b, err := t.groupJournalRoot(ctx, chain)
	if err != nil {
		return v, b.Keys, err
	}
	if c.Kind != g.ContinuationOriginal {
		return v, b.Keys, ErrGroupJournalConflict
	}
	v = b.View()
	checkpoints := []g.JournalHeadEnvelope{b.Head}
	rows, err := t.Query(ctx, `SELECT raw_document,raw_head FROM public.fleet_group_journal_records WHERE tenant_id=$1 AND chain_id=$2 AND segment=0 ORDER BY sequence`, t.Tenant, chain)
	if err != nil {
		return v, b.Keys, err
	}
	for rows.Next() {
		var raw, head []byte
		var r g.JournalRecord
		var h g.JournalHeadEnvelope
		if err = rows.Scan(&raw, &head); err != nil {
			break
		}
		if err = groupJournalDecode(raw, &r); err != nil {
			break
		}
		if err = groupJournalDecode(head, &h); err != nil {
			break
		}
		v.Records = append(v.Records, r)
		checkpoints = append(checkpoints, h)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return v, b.Keys, err
	}
	var raw []byte
	if err = t.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_journal_heads WHERE tenant_id=$1 AND chain_id=$2 AND content_hash=$3`, t.Tenant, chain, c.HeadSHA256).Scan(&raw); err != nil {
		return v, b.Keys, err
	}
	if err = groupJournalDecode(raw, &v.Head); err != nil {
		return v, b.Keys, err
	}
	at := time.Now().UTC()
	if allowStale {
		at = v.Head.Head.ObservedAt
	}
	_, err = g.VerifyJournalCheckpoints(v, checkpoints, b.Keys.Core(), v.Head.Head.Ref, at)
	return v, b.Keys, err
}

func (t *Tx) FleetGroupJournalRenewOriginal(ctx context.Context, chain string, key ed25519.PrivateKey) (g.ContinuationCursor, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (g.ContinuationCursor, error) {
		c, err := tx.FleetGroupJournalCursor(ctx, chain)
		if err != nil {
			return c, err
		}
		v, keys, err := tx.groupJournalOriginal(ctx, chain, true)
		if err != nil {
			return c, err
		}
		v, p, err := g.SealJournalView(v.Parent, v.Authorization, v.Records, keys.Core(), key, time.Now().UTC())
		if err != nil {
			return c, err
		}
		next := g.ContinuationOriginalCursor(chain, v)
		if err = tx.groupJournalHeadInsert(ctx, next, v.Head, p); err != nil {
			return c, err
		}
		if err = tx.groupJournalCAS(ctx, c, next); err != nil {
			return c, err
		}
		return next, nil
	})
}

// Duplicate receipt bodies are compared with an already authenticated stored
// envelope, including its signature, before any new authority event is appended.
// This works at a full segment and cannot spend capacity on transport retries.
func groupJournalReceiptReplay(v g.JournalView, r g.JournalRecord) (bool, error) {
	if r.Receipt == nil {
		return false, nil
	}
	for _, old := range v.Records {
		if old.Receipt != nil && (old.Receipt.Receipt.ID == r.Receipt.Receipt.ID || old.Receipt.Receipt.IdempotencyKey == r.Receipt.Receipt.IdempotencyKey) {
			if old.Kind != r.Kind || g.Digest(*old.Receipt) != g.Digest(*r.Receipt) {
				return false, ErrGroupJournalConflict
			}
			return true, nil
		}
	}
	return false, nil
}

func (t *Tx) groupJournalAppendOriginal(ctx context.Context, chain string, expected g.ContinuationCursor, r g.JournalRecord, head g.JournalHeadEnvelope) (g.ContinuationCursor, bool, error) {
	c, err := t.FleetGroupJournalCursor(ctx, chain)
	if err != nil {
		return c, false, err
	}
	v, keys, err := t.FleetGroupJournalOriginal(ctx, chain)
	if err != nil {
		return c, false, err
	}
	if r.Receipt != nil {
		if err = t.groupJournalRequireInbox(ctx, chain, g.ContinuationOriginal, r.Receipt.Receipt.ID, *r.Receipt); err != nil {
			return c, false, err
		}
	}
	if replay, e := groupJournalReceiptReplay(v, r); e != nil || replay {
		return c, replay, e
	}
	if c != expected {
		return c, false, ErrGroupJournalConflict
	}
	var attached bool
	if err = t.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.fleet_group_journal_chain_authorizations WHERE tenant_id=$1 AND chain_id=$2)`, t.Tenant, chain).Scan(&attached); err != nil {
		return c, false, err
	}
	if !attached {
		return c, false, ErrGroupJournalInvalid
	}
	if r.Command != nil && (r.Kind == g.JournalPreparing || r.Kind == g.JournalReserved) && r.Command.Preparation.Mode == g.Forward {
		b, e := t.groupJournalRoot(ctx, chain)
		if e != nil {
			return c, false, e
		}
		if e = t.groupJournalForwardCurrent(ctx, b); e != nil {
			return c, false, e
		}
	}
	now := time.Now().UTC()
	records, p, err := g.AppendJournalRecord(v, keys.Core(), v.Head.Head.Ref, r, now)
	if err != nil {
		return c, false, err
	}
	v.Records, v.Head = records, head
	if _, err = g.VerifyJournal(v, keys.Core(), head.Head.Ref, now); err != nil {
		return c, false, err
	}
	next := g.ContinuationOriginalCursor(chain, v)
	if err = t.groupJournalRecordInsert(ctx, c, r.Kind, r, head); err != nil {
		return c, false, err
	}
	if err = t.groupJournalHeadInsert(ctx, next, head, p); err != nil {
		return c, false, err
	}
	if err = t.groupJournalOperation(ctx, chain, r); err != nil {
		return c, false, err
	}
	if err = t.groupJournalCAS(ctx, c, next); err != nil {
		return c, false, err
	}
	if err = t.groupJournalOriginalDelivery(ctx, v, keys.Core(), r, next); err != nil {
		return c, false, err
	}
	if r.Receipt != nil {
		if err = t.groupJournalFinishDelivery(ctx, chain, r.Receipt.Receipt.CommandID, r.Receipt.Receipt.Kind); err != nil {
			return c, false, err
		}
	}
	return next, false, nil
}

func (t *Tx) groupJournalRecordInsert(ctx context.Context, c g.ContinuationCursor, kind string, record, head any) error {
	raw, h, err := groupJournalBytes(record)
	if err != nil {
		return err
	}
	hraw, hh, err := groupJournalBytes(head)
	if err != nil {
		return err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_records(tenant_id,chain_id,segment,sequence,kind,content_hash,document,raw_document,head_hash,head,raw_head) VALUES($1,$2,$3,$4,$5,$6,convert_from($7::bytea,'UTF8')::jsonb,$7,$8,convert_from($9::bytea,'UTF8')::jsonb,$9)`, t.Tenant, c.ChainID, fmt.Sprint(c.Segment), c.RecordCount+1, kind, h, raw, hh, hraw)
	return err
}
func (t *Tx) groupJournalOperation(ctx context.Context, chain string, r g.JournalRecord) error {
	if r.Kind != g.JournalPreparing || r.Command == nil {
		return nil
	}
	c := r.Command
	raw, hash, err := groupJournalBytes(c)
	if err != nil {
		return err
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_operations(tenant_id,chain_id,command_id,operation_id,fence,command_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,convert_from($7::bytea,'UTF8')::jsonb,$7)`, t.Tenant, chain, c.ID, c.OperationID, fmt.Sprint(c.Fence), hash, raw)
	if err != nil {
		return err
	}
	return t.groupJournalReserve(ctx, chain, c.Preparation.Mode == g.Forward, hash)
}
func (t *Tx) groupJournalReserve(ctx context.Context, chain string, forward bool, hash string) error {
	b, err := t.groupJournalRoot(ctx, chain)
	if err != nil {
		return err
	}
	workload := b.Parent.Program.Binding.Old.Target.WorkloadID
	var exists, released bool
	err = t.QueryRow(ctx, `SELECT true,released_at IS NOT NULL FROM public.fleet_group_journal_reservations WHERE tenant_id=$1 AND chain_id=$2`, t.Tenant, chain).Scan(&exists, &released)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if exists && released {
		return ErrGroupJournalConflict
	}
	if exists && forward {
		var allowed bool
		if err = t.QueryRow(ctx, `SELECT public.fleet_group_admission($1,$2,'GROUP',$3)`, t.Tenant, workload, chain).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return ErrGroupWorkloadBusy
		}
	}
	if exists {
		return nil
	}
	_, err = t.Exec(ctx, `INSERT INTO public.fleet_group_journal_reservations(tenant_id,chain_id,workload_id,obligation_hash) VALUES($1,$2,$3,$4)`, t.Tenant, chain, workload, hash)
	return err
}
