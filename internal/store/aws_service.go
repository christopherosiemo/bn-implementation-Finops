package store

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// AWSServiceEvidenceAppend stores a bounded authority reference, not the native
// response or an object/task-per-observation transactional projection.
func (t *Tx) AWSServiceEvidenceAppend(ctx context.Context, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, `INSERT INTO aws_service_evidence_snapshots(tenant_id,id,resource_id,source_id,registration_version,generation_id,family,account_id,region,config_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(tenant_id,source_id,registration_version,generation_id,resource_id,content_hash) DO NOTHING RETURNING document`, t.Tenant, d["id"], d["resource_id"], d["source_id"], d["registration_version"], d["generation_id"], d["family"], d["account_id"], d["region"], d["config_hash"], d["content_hash"], raw)
}
func (t *Tx) AWSServiceEvidenceLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('id',id,'created_at',created_at,'writer_role',writer_role) FROM aws_service_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, t.Tenant, resource)
}
func (t *Tx) AWSServiceEvidenceGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('id',id,'created_at',created_at,'writer_role',writer_role) FROM aws_service_evidence_snapshots WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}
