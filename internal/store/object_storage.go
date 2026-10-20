package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) ObjectStorageEvidenceCreate(ctx context.Context, resourceID, sourceID string, canonical, archive model.Document) (model.Document, error) {
	d := model.Document{"schema_version": "1", "id": model.ID(), "resource_id": resourceID, "source_id": sourceID, "account_id": canonical["account_id"], "region": canonical["region"], "config_hash": canonical["config_hash"], "content_hash": archive["body_sha256"], "archive": archive, "observed_at": canonical["observed_at"], "source_version": canonical["source_version"], "source_registration_version": canonical["source_registration_version"]}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var source any
	if sourceID != "" {
		source = sourceID
	}
	return t.sourceOne(ctx, "INSERT INTO object_storage_evidence_snapshots(tenant_id,id,resource_id,source_id,account_id,region,config_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING document", t.Tenant, d["id"], resourceID, source, d["account_id"], d["region"], d["config_hash"], d["content_hash"], raw)
}
func (t *Tx) ObjectStorageEvidenceLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM object_storage_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 ORDER BY (source_id IS NOT NULL) DESC,created_at DESC,id DESC LIMIT 1", t.Tenant, resource)
}
func (t *Tx) ObjectStorageEvidenceGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM object_storage_evidence_snapshots WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) ObjectStorageDatasetGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM object_storage_datasets WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, id)
}
func (t *Tx) ObjectStorageDatasetVersion(ctx context.Context, id string, version int64) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM object_storage_datasets WHERE tenant_id=$1 AND id=$2 AND version=$3", t.Tenant, id, version)
}
func (t *Tx) ObjectStorageDatasetPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM (SELECT DISTINCT ON(id) id,resource_id,document FROM object_storage_datasets WHERE tenant_id=$1 ORDER BY id,version DESC) d WHERE id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) ObjectStorageDatasetAppend(ctx context.Context, d model.Document, actor string) (model.Document, error) {
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO object_storage_datasets(tenant_id,id,version,resource_id,document,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], d["version"], d["resource_id"], raw, actor)
}
func (t *Tx) ObjectStorageAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM object_storage_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) ObjectStorageAssessmentPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM object_storage_assessments WHERE tenant_id=$1 AND id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) ObjectStorageAssessmentCreate(ctx context.Context, resource, dataset, actor string) (model.Document, error) {
	if actor == "" {
		return nil, errors.New("OBJECT_STORAGE_ACTOR_REQUIRED")
	}
	r, e := t.Get(ctx, "resources", resource)
	if e != nil {
		return nil, e
	}
	if model.String(r, "resource_type") != "S3_BUCKET" {
		return nil, errors.New("S3_BUCKET_REQUIRED")
	}
	var datasetID, datasetVersion, snapshotID any
	if dataset != "" {
		d, e := t.ObjectStorageDatasetGet(ctx, dataset)
		if e != nil {
			return nil, e
		}
		if model.String(d, "resource_id") != resource {
			return nil, errors.New("DATASET_RESOURCE_MISMATCH")
		}
		datasetID, datasetVersion = d["id"], d["version"]
	}
	snapshot, e := t.ObjectStorageEvidenceLatest(ctx, resource)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	if snapshot != nil {
		snapshotID = snapshot["id"]
	}
	id := model.ID()
	raw, _ := json.Marshal(model.Document{"assessment": nil})
	out, e := t.sourceOne(ctx, "INSERT INTO object_storage_assessments(tenant_id,id,resource_id,workload_id,snapshot_id,dataset_id,dataset_version,resource_version,document,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING document", t.Tenant, id, resource, r["workload_id"], snapshotID, datasetID, datasetVersion, r["version"], raw, actor)
	if e == nil {
		e = t.Event(ctx, "object_storage.assessment.requested", model.Document{"id": id, "resource_id": resource})
	}
	return out, e
}
