package store

import (
	"context"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Public review deliberately exposes the immutable authorization body, never
// signing keys, object locations, Terraform state or a caller-written draft.
const fleetGroupAuthorityProjection = `SELECT jsonb_build_object(
 'id',d.id,'kind',d.kind,'authorization_sha256',d.content_hash,'authorization',d.document,
 'authorization_canonical_json',convert_from(d.raw_document,'UTF8'),
 'created_at',d.created_at,'chain_id',d.chain_id,'prepared_program_id',d.prepared_program_id,
 'proposal_id',p.id,'workload_id',p.workload_id,'creator_id',p.document->>'creator_id',
 'version',1+CASE WHEN a.id IS NULL THEN 0 ELSE 1 END,
 'status',CASE WHEN a.id IS NULL THEN 'AWAITING_APPROVAL' ELSE 'APPROVED' END,
 'customer_execution_authorized',false,
 'approval',CASE WHEN a.id IS NULL THEN NULL ELSE jsonb_build_object(
   'id',a.id,'actor_id',a.actor_id,'role',a.role,
   'authorization_sha256',a.body_hash,'approved_at',a.created_at) END)
 FROM public.fleet_group_journal_authority_drafts d
 JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=d.tenant_id AND g.id=d.prepared_program_id
 JOIN public.fleet_fixture_proposals p ON p.tenant_id=g.tenant_id AND p.id=g.proposal_id
 LEFT JOIN public.fleet_group_journal_authority_approvals a ON a.tenant_id=d.tenant_id AND a.draft_id=d.id`

func (t *Tx) FleetGroupAuthorityReview(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, fleetGroupAuthorityProjection+` WHERE d.tenant_id=$1 AND d.id=$2`, t.Tenant, id)
}

func (t *Tx) FleetGroupAuthorityReviewPage(ctx context.Context, proposal, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrGroupJournalInvalid
	}
	return t.sourceRows(ctx, fleetGroupAuthorityProjection+` WHERE d.tenant_id=$1 AND p.id=$2
 AND ($3='' OR (d.created_at,d.id)<(SELECT x.created_at,x.id FROM public.fleet_group_journal_authority_drafts x JOIN public.fleet_fixture_prepared_programs y ON y.tenant_id=x.tenant_id AND y.id=x.prepared_program_id WHERE x.tenant_id=$1 AND y.proposal_id=$2 AND x.id=$3))
 ORDER BY d.created_at DESC,d.id DESC LIMIT $4`, t.Tenant, proposal, after, limit)
}

// Inspection is separate from execution availability. The API can show actual
// private journal duties without gaining access to native artifacts or writes.
func (t *Tx) FleetFixtureRunPage(ctx context.Context, proposal, after string, limit int) ([]model.Document, bool, error) {
	if limit < 1 || limit > 101 {
		return nil, false, ErrGroupJournalInvalid
	}
	var installed bool
	if err := t.QueryRow(ctx, "SELECT to_regprocedure('public.fleet_group_fixture_runs(text,text,text,integer)') IS NOT NULL").Scan(&installed); err != nil {
		return nil, false, err
	}
	if !installed {
		return []model.Document{}, false, nil
	}
	rows, err := t.sourceRows(ctx, "SELECT * FROM public.fleet_group_fixture_runs($1,$2,$3,$4)", t.Tenant, proposal, after, limit)
	for _, row := range rows {
		row["status"] = "ACTIVE"
		reasons := []string{"ISOLATED_FIXTURE", "CUSTOMER_EXECUTION_DISABLED", "NO_FINANCIAL_VERIFICATION_AUTHORITY"}
		phase := model.String(row, "pending_phase")
		aborted, _ := row["forward_aborted"].(bool)
		recovery, _ := row["recovery_only"].(bool)
		released, _ := row["obligation_released"].(bool)
		if released {
			row["status"] = "RECOVERED"
			reasons = append(reasons, "OWNED_NATIVE_EFFECTS_RESOLVED")
		} else if phase == "UNKNOWN" {
			row["status"] = "RECONCILING"
			reasons = append(reasons, "AUTHENTICATED_TERMINAL_OUTCOME_REQUIRED")
		} else if aborted || recovery {
			row["status"] = "RECOVERY_REQUIRED"
			reasons = append(reasons, "FORWARD_PROGRESS_PERMANENTLY_ABORTED")
		}
		row["reason_codes"] = reasons
	}
	return rows, true, err
}
