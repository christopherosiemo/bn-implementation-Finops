package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) NetworkEvidenceCreate(ctx context.Context, resourceID, sourceID string, canonical, archive model.Document) (model.Document, error) {
	d := model.Document{"schema_version": "1", "id": model.ID(), "resource_id": resourceID, "source_id": sourceID, "account_id": canonical["account_id"], "region": canonical["region"], "config_hash": canonical["config_hash"], "content_hash": archive["body_sha256"], "archive": archive, "observed_at": canonical["observed_at"], "source_version": canonical["source_version"], "source_registration_version": canonical["source_registration_version"]}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var source any
	if sourceID != "" {
		source = sourceID
	}
	return t.sourceOne(ctx, "INSERT INTO network_evidence_snapshots(tenant_id,id,resource_id,source_id,account_id,region,config_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING document", t.Tenant, d["id"], resourceID, source, d["account_id"], d["region"], d["config_hash"], d["content_hash"], raw)
}
func (t *Tx) NetworkEvidenceLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM network_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 ORDER BY (source_id IS NOT NULL) DESC,created_at DESC,id DESC LIMIT 1", t.Tenant, resource)
}
func (t *Tx) NetworkEvidenceGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM network_evidence_snapshots WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) NetworkEvidenceLatestForConfig(ctx context.Context, resource, hash string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('id',id,'created_at',created_at) FROM network_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 AND config_hash=$3 ORDER BY (source_id IS NOT NULL) DESC,created_at DESC,id DESC LIMIT 1", t.Tenant, resource, hash)
}
func (t *Tx) NetworkPolicyGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM network_policies WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, id)
}
func (t *Tx) NetworkPolicyVersion(ctx context.Context, id string, version int64) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM network_policies WHERE tenant_id=$1 AND id=$2 AND version=$3", t.Tenant, id, version)
}
func (t *Tx) NetworkPolicyPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM (SELECT DISTINCT ON(id) id,resource_id,document FROM network_policies WHERE tenant_id=$1 ORDER BY id,version DESC) d WHERE id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) NetworkPolicyAppend(ctx context.Context, d model.Document, actor string) (model.Document, error) {
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO network_policies(tenant_id,id,version,resource_id,document,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], d["version"], d["resource_id"], raw, actor)
}
func (t *Tx) NetworkAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM network_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) NetworkAssessmentPage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM network_assessments WHERE tenant_id=$1 AND id>$2 AND ($3='' OR resource_id=$3) ORDER BY id LIMIT $4", t.Tenant, after, resource, limit)
}
func (t *Tx) NetworkAssessmentCreate(ctx context.Context, resource, policy, actor string) (model.Document, error) {
	if actor == "" {
		return nil, errors.New("NETWORK_ACTOR_REQUIRED")
	}
	r, e := t.Get(ctx, "resources", resource)
	if e != nil {
		return nil, e
	}
	if !networkAssessmentResourceType(model.String(r, "resource_type")) {
		return nil, errors.New("NETWORK_RESOURCE_REQUIRED")
	}
	var policyID, policyVersion, snapshotID any
	if policy != "" {
		d, e := t.NetworkPolicyGet(ctx, policy)
		if e != nil {
			return nil, e
		}
		if model.String(d, "resource_id") != resource {
			return nil, errors.New("DATASET_RESOURCE_MISMATCH")
		}
		policyID, policyVersion = d["id"], d["version"]
	}
	snapshot, e := t.NetworkEvidenceLatest(ctx, resource)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	if snapshot != nil {
		snapshotID = snapshot["id"]
	}
	id := model.ID()
	raw, _ := json.Marshal(model.Document{"assessment": nil})
	out, e := t.sourceOne(ctx, "INSERT INTO network_assessments(tenant_id,id,resource_id,workload_id,snapshot_id,policy_id,policy_version,resource_version,document,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING document", t.Tenant, id, resource, r["workload_id"], snapshotID, policyID, policyVersion, r["version"], raw, actor)
	if e == nil {
		e = t.Event(ctx, "network.assessment.requested", model.Document{"id": id, "resource_id": resource})
	}
	return out, e
}

func networkAssessmentResourceType(kind string) bool {
	switch kind {
	case "AVAILABILITY_ZONE", "SECURITY_GROUP", "VPC_ENDPOINT_SERVICE", "FLOW_LOG", "AWS_SERVICE_PREFIX_LIST", "NAT_GATEWAY", "ELASTIC_IP", "PUBLIC_IPV4", "VPC", "SUBNET", "ROUTE_TABLE", "VPC_ENDPOINT", "NETWORK_INTERFACE", "INTERNET_GATEWAY", "EGRESS_ONLY_INTERNET_GATEWAY", "VPC_PEERING", "TRANSIT_GATEWAY_ATTACHMENT", "LOAD_BALANCER":
		return true
	}
	return false
}
