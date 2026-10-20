package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) DatabaseEvidenceLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM database_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1", t.Tenant, resource)
}
func (t *Tx) DatabaseEvidenceGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM database_evidence_snapshots WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) DatabaseEvidenceAppend(ctx context.Context, d model.Document) (model.Document, error) {
	id := model.String(d, "id")
	if id == "" {
		id = model.ID()
	}
	d = model.Clone(d)
	d["id"] = id
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO database_evidence_snapshots(tenant_id,id,resource_id,account_id,region,config_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING document", t.Tenant, id, d["resource_id"], d["account_id"], d["region"], d["config_hash"], d["content_hash"], raw)
}
func (t *Tx) DatabaseAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM database_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) DatabaseAssessmentPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM database_assessments WHERE tenant_id=$1 AND id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) DatabaseAssessmentCreate(ctx context.Context, resource, actor string) (model.Document, error) {
	if actor == "" {
		return nil, errors.New("DATABASE_ACTOR_REQUIRED")
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, e
	}
	r, e := t.Get(ctx, "resources", resource)
	if e != nil {
		return nil, e
	}
	if model.String(r, "resource_type") != "RDS_INSTANCE" && model.String(r, "resource_type") != "RDS_CLUSTER" {
		return nil, errors.New("DATABASE_RESOURCE_REQUIRED")
	}
	snapshot, e := t.DatabaseEvidenceLatest(ctx, resource)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	profile, e := t.WorkloadSafetyLatest(ctx, model.String(r, "workload_id"))
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	var snapshotID, profileID any
	if snapshot != nil {
		snapshotID = snapshot["id"]
	}
	if profile != nil {
		profileID = profile["id"]
	}
	id := model.ID()
	raw, _ := json.Marshal(model.Document{"assessment": nil})
	out, e := t.sourceOne(ctx, "INSERT INTO database_assessments(tenant_id,id,resource_id,workload_id,snapshot_id,resource_version,safety_profile_id,document,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING document", t.Tenant, id, resource, r["workload_id"], snapshotID, r["version"], profileID, raw, actor)
	if e == nil {
		e = t.Event(ctx, "database.assessment.requested", model.Document{"id": id, "resource_id": resource})
	}
	return out, e
}
