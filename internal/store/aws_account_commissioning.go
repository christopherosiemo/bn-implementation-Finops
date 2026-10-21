package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const accountPreflightProjection = `jsonb_build_object('id',id,'version',1,'cloud_account_id',cloud_account_id,'cloud_account_version',cloud_account_version,'account_id',account_id,'region',region,'read_role_binding_id',read_role_binding_id,'status',status,'created_by',created_by,'created_at',created_at,'report_id',report_id,'reason_code',reason_code)`

func (t *Tx) AWSAccountPreflightGet(ctx context.Context, account, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT `+accountPreflightProjection+` FROM aws_account_preflights WHERE tenant_id=$1 AND cloud_account_id=$2 AND id=$3`, t.Tenant, account, id)
}
func (t *Tx) AWSAccountPreflightPage(ctx context.Context, account, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, `SELECT `+accountPreflightProjection+` FROM aws_account_preflights WHERE tenant_id=$1 AND cloud_account_id=$2 AND id>$3 ORDER BY id LIMIT $4`, t.Tenant, account, after, limit)
}
func (t *Tx) AWSAccountPreflightCreate(ctx context.Context, account model.Document, actor string) (model.Document, error) {
	if actor == "" {
		return nil, errors.New("AWS_ACCOUNT_ACTOR_REQUIRED")
	}
	id := model.ID()
	d, e := t.sourceOne(ctx, `INSERT INTO aws_account_preflights(tenant_id,id,cloud_account_id,cloud_account_version,account_id,region,read_role_binding_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+accountPreflightProjection, t.Tenant, id, account["id"], account["version"], account["account_id"], account["region"], account["read_role_binding_id"], actor)
	if e == nil {
		e = t.Event(ctx, "cloud_account.preflight.requested", model.Document{"id": id, "cloud_account_id": account["id"]})
	}
	return d, e
}

// Claim is a short durable lease. Provider calls and archival never hold this
// transaction open. A crashed ingester's lease can be reclaimed safely.
func (t *Tx) AWSAccountPreflightClaim(ctx context.Context, token string, now time.Time) (model.Document, error) {
	return t.sourceOne(ctx, `WITH candidate AS (SELECT id FROM aws_account_preflights WHERE tenant_id=$1 AND (status='QUEUED' OR status='RUNNING' AND lease_until<$3) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE aws_account_preflights p SET status='RUNNING',lease_token=$2,lease_until=$3+interval '3 minutes' FROM candidate c WHERE p.tenant_id=$1 AND p.id=c.id RETURNING `+prefixedAccountPreflightProjection(), t.Tenant, token, now)
}
func prefixedAccountPreflightProjection() string {
	return `jsonb_build_object('id',p.id,'version',1,'cloud_account_id',p.cloud_account_id,'cloud_account_version',p.cloud_account_version,'account_id',p.account_id,'region',p.region,'read_role_binding_id',p.read_role_binding_id,'status',p.status,'created_by',p.created_by,'created_at',p.created_at,'report_id',p.report_id,'reason_code',p.reason_code)`
}
func (t *Tx) AWSAccountPreflightFail(ctx context.Context, id, token, reason string) error {
	r, e := t.Exec(ctx, `UPDATE aws_account_preflights SET status='FAILED',reason_code=$4,lease_token=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND status='RUNNING'`, t.Tenant, id, token, reason)
	if e == nil && r.RowsAffected() != 1 {
		return ErrConflict
	}
	if e != nil {
		return e
	}
	if e = t.Audit(ctx, "ingestion-worker", "cloud_account.preflight.failed", id, model.Document{"reason_code": reason, "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "cloud_account.preflight.failed", model.Document{"id": id, "reason_code": reason})
}
func (t *Tx) AWSAccountPreflightComplete(ctx context.Context, id, token string, report model.Document) error {
	var valid bool
	if e := t.QueryRow(ctx, `SELECT lease_token=$3 AND lease_until>clock_timestamp() AND status='RUNNING' FROM aws_account_preflights WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, t.Tenant, id, token).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return ErrConflict
	}
	raw, e := json.Marshal(report)
	if e != nil {
		return e
	}
	if _, e = t.Exec(ctx, `INSERT INTO aws_account_commissioning_reports(tenant_id,id,preflight_id,document) VALUES($1,$2,$3,$4)`, t.Tenant, report["id"], id, raw); e != nil {
		return e
	}
	if _, e = t.Exec(ctx, `UPDATE aws_account_preflights SET status='COMPLETED',report_id=$4,lease_token=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2 AND lease_token=$3`, t.Tenant, id, token, report["id"]); e != nil {
		return e
	}
	if e = t.Audit(ctx, "ingestion-worker", "cloud_account.preflight.completed", id, model.Document{"report_id": report["id"], "summary_state": report["summary_state"], "content_hash": report["content_hash"], "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "cloud_account.preflight.completed", model.Document{"id": id, "report_id": report["id"], "summary_state": report["summary_state"]})
}
func (t *Tx) AWSAccountCommissioningReport(ctx context.Context, account, preflight string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT r.document FROM aws_account_commissioning_reports r JOIN aws_account_preflights p ON p.tenant_id=r.tenant_id AND p.id=r.preflight_id WHERE r.tenant_id=$1 AND p.cloud_account_id=$2 AND p.id=$3`, t.Tenant, account, preflight)
}
