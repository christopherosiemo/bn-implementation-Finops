package store

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Checkpoint health comes only from the ingestion identity. Registration control
// and configuration stay authoritative even if a status checkpoint is malformed.
const sourceProjection = `(s.document-ARRAY['status','reason_code','last_sync_at','last_sync_version','config_hash','latest_revision_id','latest_receipt_id','ingestion_job_id','commitment_receipt_id','manifest_count','backfill_pending'])||COALESCE((SELECT jsonb_object_agg(key,value) FROM jsonb_each(c.document) WHERE key IN ('status','reason_code','last_sync_at','last_sync_version','config_hash','latest_revision_id','latest_receipt_id','ingestion_job_id','commitment_receipt_id','manifest_count','backfill_pending')),'{}'::jsonb)||CASE WHEN NOT COALESCE((s.document->>'enabled')::boolean,false) OR COALESCE((s.document->>'revoked')::boolean,false) THEN '{"status":"REVOKED"}'::jsonb ELSE '{}'::jsonb END`

func (t *Tx) SourceCreate(ctx context.Context, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	id := model.String(d, "id")
	if id == "" {
		id = model.ID()
	}
	d["id"], d["tenant_id"], d["version"] = id, t.Tenant, int64(1)
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, "INSERT INTO source_registrations(tenant_id,id,kind,document) VALUES($1,$2,$3,$4)", t.Tenant, id, d["kind"], b)
	return d, e
}
func (t *Tx) SourceGet(ctx context.Context, id string) (model.Document, error) {
	var b []byte
	var version int64
	e := t.QueryRow(ctx, `SELECT `+sourceProjection+`,s.version FROM source_registrations s LEFT JOIN source_checkpoints c ON c.tenant_id=s.tenant_id AND c.source_id=s.id AND c.checkpoint_key='status' WHERE s.tenant_id=$1 AND s.id=$2`, t.Tenant, id).Scan(&b, &version)
	if e != nil {
		return nil, e
	}
	d := model.Document{}
	e = json.Unmarshal(b, &d)
	d["version"] = version
	return d, e
}
func (t *Tx) SourceList(ctx context.Context) ([]model.Document, error) {
	return t.sourceRows(ctx, `SELECT (`+sourceProjection+`)||jsonb_build_object('version',s.version) FROM source_registrations s LEFT JOIN source_checkpoints c ON c.tenant_id=s.tenant_id AND c.source_id=s.id AND c.checkpoint_key='status' WHERE s.tenant_id=$1 ORDER BY s.created_at,s.id`, t.Tenant)
}
func (t *Tx) SourceUpdate(ctx context.Context, id string, version int64, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	d["id"], d["tenant_id"], d["version"] = id, t.Tenant, version+1
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	r, e := t.Exec(ctx, "UPDATE source_registrations SET document=$4,kind=$5,version=version+1,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND version=$3", t.Tenant, id, version, b, d["kind"])
	if e == nil && r.RowsAffected() != 1 {
		return nil, ErrConflict
	}
	return d, e
}
func (t *Tx) SourceRevisionGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_revisions WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) SourceRevisionList(ctx context.Context, source string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_revisions WHERE tenant_id=$1 AND source_id=$2 ORDER BY created_at,id", t.Tenant, source)
}
func (t *Tx) SourceRevisionCreate(ctx context.Context, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	d["tenant_id"] = t.Tenant
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, "INSERT INTO source_revisions(tenant_id,id,source_id,revision_hash,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,source_id,revision_hash) DO NOTHING", t.Tenant, d["id"], d["source_id"], d["revision_hash"], b)
	return d, e
}
func (t *Tx) SourceReceiptGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_receipts WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) SourceReceiptList(ctx context.Context, kind, source string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_receipts WHERE tenant_id=$1 AND ($2='' OR kind=$2) AND ($3='' OR source_id=$3) ORDER BY created_at,id", t.Tenant, kind, source)
}
func (t *Tx) SourceReceiptCreate(ctx context.Context, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	d["tenant_id"] = t.Tenant
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var revision any
	if s := model.String(d, "revision_id"); s != "" {
		revision = s
	}
	_, e = t.Exec(ctx, "INSERT INTO source_receipts(tenant_id,id,source_id,revision_id,kind,document) VALUES($1,$2,$3,$4,$5,$6)", t.Tenant, d["id"], d["source_id"], revision, d["kind"], b)
	return d, e
}
func (t *Tx) SourceCheckpointGet(ctx context.Context, source, key string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM source_checkpoints WHERE tenant_id=$1 AND source_id=$2 AND checkpoint_key=$3", t.Tenant, source, key)
}
func (t *Tx) SourceCheckpointSet(ctx context.Context, source, key string, d model.Document) error {
	b, e := json.Marshal(d)
	if e != nil {
		return e
	}
	_, e = t.Exec(ctx, "INSERT INTO source_checkpoints(tenant_id,source_id,checkpoint_key,document) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,source_id,checkpoint_key) DO UPDATE SET document=excluded.document,updated_at=now()", t.Tenant, source, key, b)
	return e
}
func (t *Tx) sourceOne(ctx context.Context, q string, args ...any) (model.Document, error) {
	var b []byte
	e := t.QueryRow(ctx, q, args...).Scan(&b)
	if e != nil {
		return nil, e
	}
	d := model.Document{}
	e = json.Unmarshal(b, &d)
	return d, e
}
func (t *Tx) sourceRows(ctx context.Context, q string, args ...any) ([]model.Document, error) {
	rows, e := t.Query(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		d := model.Document{}
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
