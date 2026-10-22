package store

import (
	"context"
	"encoding/json"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type FleetGroupAuthorityDraft struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	BodyHash  string          `json:"body_hash"`
	Body      json.RawMessage `json:"body"`
	CreatedAt time.Time       `json:"created_at"`
}
type FleetGroupAuthorityApproval struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	ActorID             string    `json:"actor_id"`
	Role                string    `json:"role"`
	AuthorizationSHA256 string    `json:"authorization_sha256"`
	ApprovedAt          time.Time `json:"approved_at"`
}

func (t *Tx) FleetGroupJournalParentApproval(ctx context.Context, prepared, approval string) (g.Approval, error) {
	var a g.Approval
	var raw []byte
	err := t.QueryRow(ctx, `SELECT a.id,a.tenant_id,a.actor_id,a.document->>'role',a.program_hash,a.created_at,p.program_raw FROM public.fleet_fixture_approvals a JOIN public.fleet_fixture_prepared_programs p ON p.tenant_id=a.tenant_id AND p.id=a.prepared_program_id WHERE a.tenant_id=$1 AND p.id=$2 AND a.id=$3 AND a.manifest_hash=p.manifest_hash AND a.journal_review_hash=p.journal_review_hash`, t.Tenant, prepared, approval).Scan(&a.ID, &a.TenantID, &a.ActorID, &a.Role, &a.ProgramSHA256, &a.ApprovedAt, &raw)
	if err != nil {
		return a, err
	}
	var p g.GitProgram
	if err = groupJournalDecode(raw, &p); err != nil {
		return a, err
	}
	a.RealmSHA256 = g.Digest(p.Realm)
	a.ApprovedAt = a.ApprovedAt.UTC()
	return a, nil
}
func (t *Tx) FleetGroupJournalDraftAuthorization(ctx context.Context, b FleetGroupJournalBootstrap, kind string, body any) (FleetGroupAuthorityDraft, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (FleetGroupAuthorityDraft, error) {
		d := FleetGroupAuthorityDraft{ID: model.ID(), Kind: kind}
		switch body.(type) {
		case g.JournalAuthorization:
			if kind != "JOURNAL" {
				return d, ErrGroupJournalInvalid
			}
		case g.ContinuationAuthorization:
			if kind != "CONTINUATION" {
				return d, ErrGroupJournalInvalid
			}
		default:
			return d, ErrGroupJournalInvalid
		}
		raw, hash, err := groupJournalBytes(body)
		if err != nil {
			return d, err
		}
		d.Body, d.BodyHash = raw, hash
		err = tx.QueryRow(ctx, `INSERT INTO public.fleet_group_journal_authority_drafts(tenant_id,id,chain_id,kind,prepared_program_id,key_binding_id,parent_hash,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,convert_from($9::bytea,'UTF8')::jsonb,$9) RETURNING created_at`, tx.Tenant, d.ID, b.ChainID, kind, b.PreparedProgramID, b.KeyBindingID, g.Digest(b.Parent), hash, raw).Scan(&d.CreatedAt)
		return d, err
	})
}
func (t *Tx) FleetGroupJournalAuthorityDraft(ctx context.Context, id string) (FleetGroupAuthorityDraft, error) {
	var d FleetGroupAuthorityDraft
	err := t.QueryRow(ctx, `SELECT id,kind,content_hash,raw_document,created_at FROM public.fleet_group_journal_authority_drafts WHERE tenant_id=$1 AND id=$2`, t.Tenant, id).Scan(&d.ID, &d.Kind, &d.BodyHash, &d.Body, &d.CreatedAt)
	return d, err
}

// actor comes from the API's authenticated independent approver, never a
// pipeline callback. Review is over the exact immutable body hash.
func (t *Tx) FleetGroupJournalApproveAuthority(ctx context.Context, draft, bodyHash, actor string) (FleetGroupAuthorityApproval, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (FleetGroupAuthorityApproval, error) {
		a := FleetGroupAuthorityApproval{ID: model.ID(), TenantID: tx.Tenant, ActorID: actor, Role: g.ApproverRole, AuthorizationSHA256: bodyHash}
		err := tx.QueryRow(ctx, `INSERT INTO public.fleet_group_journal_authority_approvals(tenant_id,id,draft_id,actor_id,body_hash) VALUES($1,$2,$3,$4,$5) RETURNING created_at`, tx.Tenant, a.ID, draft, actor, bodyHash).Scan(&a.ApprovedAt)
		a.ApprovedAt = a.ApprovedAt.UTC()
		return a, err
	})
}
func (t *Tx) groupJournalAuthorityApproval(ctx context.Context, b FleetGroupJournalBootstrap, kind string, body any) (FleetGroupAuthorityApproval, error) {
	var a FleetGroupAuthorityApproval
	err := t.QueryRow(ctx, `SELECT a.id,a.tenant_id,a.actor_id,a.role,a.body_hash,a.created_at FROM public.fleet_group_journal_authority_drafts d JOIN public.fleet_group_journal_authority_approvals a ON a.tenant_id=d.tenant_id AND a.draft_id=d.id WHERE d.tenant_id=$1 AND d.chain_id=$2 AND d.prepared_program_id=$3 AND d.key_binding_id=$4 AND d.parent_hash=$5 AND d.kind=$6 AND d.content_hash=$7 AND a.body_hash=d.content_hash`, t.Tenant, b.ChainID, b.PreparedProgramID, b.KeyBindingID, g.Digest(b.Parent), kind, g.Digest(body)).Scan(&a.ID, &a.TenantID, &a.ActorID, &a.Role, &a.AuthorizationSHA256, &a.ApprovedAt)
	a.ApprovedAt = a.ApprovedAt.UTC()
	return a, err
}
func groupJournalApprovalSame(actual any, expected FleetGroupAuthorityApproval) bool {
	raw, _, err := groupJournalBytes(actual)
	if err != nil {
		return false
	}
	var a FleetGroupAuthorityApproval
	if groupJournalDecode(raw, &a) != nil {
		return false
	}
	return a == expected
}
