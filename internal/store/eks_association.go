package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/eksassociation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (t *Tx) EKSNativeSource(ctx context.Context, r eksassociation.Registration) (awsservice.Registration, error) {
	sources, e := t.SourceList(ctx)
	if e != nil {
		return awsservice.Registration{}, e
	}
	found := []awsservice.Registration{}
	for _, d := range sources {
		if d["kind"] != awsservice.NativeKind || !model.Bool(d, "enabled") || model.Bool(d, "revoked") {
			continue
		}
		v, e := awsservice.ParseRegistration(d)
		if e == nil && v.AccountID == r.AccountID && v.Region == r.Region && v.ReadRoleBindingID == r.ReadRoleBindingID && awsservice.Contains(v.ServiceFamilies, "EKS") && (v.ScopeMode == "ACCOUNT" || awsservice.Contains(v.RootResourceARNs, r.ClusterARN)) {
			found = append(found, v)
		}
	}
	if len(found) != 1 {
		return awsservice.Registration{}, errors.New("EKS_REGISTERED_NATIVE_SOURCE_REQUIRED_OR_AMBIGUOUS")
	}
	return found[0], nil
}
func (t *Tx) EKSAssociationCreate(ctx context.Context, d model.Document) (model.Document, error) {
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO eks_kubernetes_associations(tenant_id,id,resource_id,source_id,source_version,native_source_id,native_source_version,config_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,source_id,source_version,resource_id,content_hash) DO NOTHING`, t.Tenant, d["id"], d["resource_id"], d["source_id"], d["source_version"], d["native_source_id"], d["native_source_version"], d["config_hash"], d["content_hash"], b)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, `SELECT document FROM eks_kubernetes_associations WHERE tenant_id=$1 AND source_id=$2 AND source_version=$3 AND resource_id=$4 AND content_hash=$5`, t.Tenant, d["source_id"], d["source_version"], d["resource_id"], d["content_hash"])
}
func (t *Tx) EKSAssociationLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('created_at',created_at) FROM eks_kubernetes_associations WHERE tenant_id=$1 AND resource_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, t.Tenant, resource)
}
