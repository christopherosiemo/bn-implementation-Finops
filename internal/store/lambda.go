package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) LambdaEvidenceCreate(ctx context.Context, resourceID, sourceID string, canonical, archive model.Document) (model.Document, error) {
	d := model.Document{"schema_version": "1", "id": model.ID(), "resource_id": resourceID, "qualifier": canonical["qualifier"], "serving_target": canonical["serving_target"], "source_id": sourceID, "account_id": canonical["account_id"], "region": canonical["region"], "config_hash": canonical["config_hash"], "content_hash": archive["body_sha256"], "archive": archive, "observed_at": canonical["observed_at"], "source_version": canonical["source_version"], "source_registration_version": canonical["source_registration_version"], "source_refs": canonical["source_refs"]}
	resource, e := t.Get(ctx, "resources", resourceID)
	if e != nil {
		return nil, e
	}
	if accountID := model.String(resource, "cloud_account_id"); accountID != "" {
		account, e := t.Get(ctx, "cloud_accounts", accountID)
		if e != nil {
			return nil, e
		}
		d["cloud_account_id"], d["cloud_account_authority_hash"] = accountID, LambdaCloudAccountAuthorityHash(account)
	}
	return t.LambdaEvidenceAppend(ctx, d)
}
func (t *Tx) LambdaEvidenceAppend(ctx context.Context, d model.Document) (model.Document, error) {
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var source any
	if model.String(d, "source_id") != "" {
		source = d["source_id"]
	}
	return t.sourceOne(ctx, "INSERT INTO lambda_evidence_snapshots(tenant_id,id,resource_id,qualifier,source_id,account_id,region,config_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING document", t.Tenant, d["id"], d["resource_id"], d["qualifier"], source, d["account_id"], d["region"], d["config_hash"], d["content_hash"], raw)
}

func (t *Tx) LambdaEvidenceLatest(ctx context.Context, resource, qualifier string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM lambda_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 AND qualifier=$3 ORDER BY (source_id IS NOT NULL) DESC,created_at DESC,id DESC LIMIT 1", t.Tenant, resource, qualifier)
}
func (t *Tx) LambdaEvidenceGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM lambda_evidence_snapshots WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) LambdaEvidenceLatestForConfig(ctx context.Context, resource, qualifier, hash string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM lambda_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 AND qualifier=$3 AND config_hash=$4 ORDER BY (source_id IS NOT NULL) DESC,created_at DESC,id DESC LIMIT 1", t.Tenant, resource, qualifier, hash)
}
func (t *Tx) LambdaPolicyGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM lambda_policies WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, id)
}
func (t *Tx) LambdaPolicyVersion(ctx context.Context, id string, version int64) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM lambda_policies WHERE tenant_id=$1 AND id=$2 AND version=$3", t.Tenant, id, version)
}
func (t *Tx) LambdaPolicyPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM (SELECT DISTINCT ON(id) id,resource_id,document FROM lambda_policies WHERE tenant_id=$1 ORDER BY id,version DESC) d WHERE id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) LambdaPolicyAppend(ctx context.Context, d model.Document, actor string) (model.Document, error) {
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO lambda_policies(tenant_id,id,version,resource_id,document,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], d["version"], d["resource_id"], raw, actor)
}
func (t *Tx) LambdaAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM lambda_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) LambdaAssessmentPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM lambda_assessments WHERE tenant_id=$1 AND id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) LambdaAssessmentCreate(ctx context.Context, resource, qualifier, policy, actor string) (model.Document, error) {
	if actor == "" {
		return nil, errors.New("LAMBDA_ACTOR_REQUIRED")
	}
	r, e := t.Get(ctx, "resources", resource)
	if e != nil {
		return nil, e
	}
	if !lambdaAssessmentResourceType(model.String(r, "resource_type")) {
		return nil, errors.New("LAMBDA_RESOURCE_REQUIRED")
	}
	var policyID, policyVersion, snapshotID any
	if policy != "" {
		d, e := t.LambdaPolicyGet(ctx, policy)
		if e != nil {
			return nil, e
		}
		if model.String(d, "resource_id") != resource {
			return nil, errors.New("DATASET_RESOURCE_MISMATCH")
		}
		policyID, policyVersion = d["id"], d["version"]
	}
	snapshot, e := t.LambdaEvidenceLatest(ctx, resource, qualifier)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	if snapshot != nil {
		snapshotID = snapshot["id"]
	}
	id := model.ID()
	raw, _ := json.Marshal(model.Document{"assessment": nil})
	out, e := t.sourceOne(ctx, "INSERT INTO lambda_assessments(tenant_id,id,resource_id,qualifier,workload_id,snapshot_id,policy_id,policy_version,resource_version,document,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING document", t.Tenant, id, resource, qualifier, r["workload_id"], snapshotID, policyID, policyVersion, r["version"], raw, actor)
	if e == nil {
		e = t.Event(ctx, "lambda.assessment.requested", model.Document{"id": id, "resource_id": resource})
	}
	return out, e
}

func lambdaAssessmentResourceType(kind string) bool { return kind == "LAMBDA_FUNCTION" }

func LambdaCloudAccountAuthorityHash(d model.Document) string {
	return evidence.Hash(model.Document{"id": d["id"], "provider": d["provider"], "account_id": d["account_id"], "region": d["region"], "status": d["status"], "enabled": d["enabled"], "revoked": d["revoked"]})
}
