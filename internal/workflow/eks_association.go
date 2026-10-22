package workflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/eksassociation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"os"
	"strings"
	"time"
)

func SyncEKSAssociation(ctx context.Context, a *Activities, storage *native.Storage, r eksassociation.Registration, reader *provider.AWS, secretBindings string) error {
	var nativeReg awsservice.Registration
	if e := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error { var e error; nativeReg, e = tx.EKSNativeSource(ctx, r); return e }); e != nil {
		return e
	}
	var cluster model.Document
	collectionReasons := []string{}
	freshNative := map[string]bool{}
	cursor := ""
	generation := model.ID()
	for page := 0; page < 32; page++ {
		c, e := reader.ServiceInventory(ctx, nativeReg, "EKS", cursor)
		if e != nil {
			return e
		}
		collectionReasons = append(collectionReasons, c.Reasons...)
		published, e := PublishAWSServiceCollection(ctx, a.Store, storage, nativeReg, generation, c)
		if e != nil {
			return e
		}
		for _, resource := range published {
			freshNative[model.String(resource, "id")] = true
			if resource["provider_resource_id"] == r.ClusterARN && resource["resource_type"] == "EKS_CLUSTER" {
				cluster = resource
			}
		}
		if cluster != nil {
			break
		}
		cursor = c.NextCursor
		if cursor == "" {
			return errors.New("EKS_CLUSTER_NOT_OBSERVED_AT_READ")
		}
	}
	if cluster == nil {
		return errors.New("EKS_CLUSTER_COLLECTION_INCOMPLETE")
	}
	cfg := eksassociation.Document(cluster["aws_service_configuration"])
	for _, field := range eksassociation.Document(cfg["collection_status"]) {
		if eksassociation.Document(field)["status"] == "DENIED" && model.String(cfg, "endpoint") == "" {
			return errors.New("EKS_NATIVE_CLUSTER_READ_DENIED")
		}
	}
	kube, expectedUID, e := source.EKSIdentityReader(ctx, secretBindings, r, cfg)
	if e != nil {
		return e
	}
	identity, e := kube.CollectIdentity(ctx, expectedUID, r.WorkloadBindings)
	if e != nil {
		return e
	}
	identity.Problems = append(identity.Problems, collectionReasons...)
	var resources []model.Document
	e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		rows, e := tx.Query(ctx, `SELECT document||jsonb_build_object('id',id,'version',version) FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'account_id'=$2 AND document->>'region'=$3 AND (document->>'resource_type'='EC2' OR document->>'service_family'='EKS') ORDER BY id LIMIT 10001`, r.TenantID, r.AccountID, r.Region)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			resource := eksassociation.Document(json.RawMessage(raw))
			if resource["resource_type"] == "EC2" || freshNative[model.String(resource, "id")] {
				resources = append(resources, resource)
			}
		}
		if len(resources) > 10000 {
			return errors.New("EKS_ASSOCIATION_RESOURCE_BOUND")
		}
		return rows.Err()
	})
	if e != nil {
		return e
	}
	names := []string{}
	seen := map[string]bool{}
	for _, resource := range resources {
		c := eksassociation.Document(resource["aws_service_configuration"])
		if resource["resource_type"] == "EKS_NODE_GROUP" && model.String(c, "clusterName") == model.String(cfg, "name") {
			for _, name := range model.Strings(c, "native_auto_scaling_group_names") {
				if !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	ids := []string{}
	seen = map[string]bool{}
	for _, node := range identity.Nodes {
		parts := strings.Split(node.ProviderID, "/")
		id := parts[len(parts)-1]
		if strings.HasPrefix(id, "i-") && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	memberships, membershipRaw, membershipError := reader.EKSMembership(ctx, awsservice.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}, names, ids)
	if membershipError != nil {
		identity.Problems = append(identity.Problems, "EKS_NATIVE_MEMBERSHIP_UNAVAILABLE")
		if q, ok := membershipError.(*provider.QueryRejection); ok && (q.StatusCode == 403 || strings.Contains(q.Code, "AccessDenied")) {
			identity.Problems = append(identity.Problems, "EKS_NATIVE_MEMBERSHIP_DENIED")
		}
		memberships = nil
	}
	result := eksassociation.Associate(r, identity, resources, memberships)
	result["resource_id"], result["source_id"], result["source_version"] = cluster["id"], r.ID, r.Version
	result["account_id"], result["region"] = r.AccountID, r.Region
	result["native_source_id"], result["native_source_version"], result["config_hash"] = nativeReg.ID, nativeReg.Version, awsservice.ConfigurationHash(cluster)
	result["observed_at"] = identity.CollectedAt
	clusterProof := eksassociation.Document(result["cluster"])
	pem, _ := base64.StdEncoding.DecodeString(model.String(eksassociation.Document(cfg["certificateAuthority"]), "data"))
	clusterProof["endpoint_sha256"], clusterProof["ca_sha256"] = source.BytesHash([]byte(kube.URL)), source.BytesHash(pem)
	result["cluster"] = clusterProof
	hashes := model.Document{}
	for _, resource := range resources {
		configuration := eksassociation.Document(resource["aws_service_configuration"])
		if resource["provider_resource_id"] == r.ClusterARN || configuration["clusterName"] == cfg["name"] {
			hashes[model.String(resource, "id")] = awsservice.ConfigurationHash(resource)
		}
	}
	result["native_configuration_hashes"] = hashes
	refs := []model.Document{}
	if len(membershipRaw) > 0 {
		ref, e := awsServiceArchive(ctx, storage, r.TenantID, "wire", membershipRaw)
		if e != nil {
			return e
		}
		refs = append(refs, ref)
	}
	identityRaw, _ := json.Marshal(identity)
	identityRef, e := awsServiceArchive(ctx, storage, r.TenantID, "wire", identityRaw)
	if e != nil {
		return e
	}
	refs = append(refs, identityRef)
	if e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		snapshot, e := tx.AWSServiceEvidenceLatest(ctx, model.String(cluster, "id"))
		if e != nil {
			return e
		}
		refs = append(refs, eksassociation.Document(snapshot["archive"]))
		return nil
	}); e != nil {
		return e
	}
	result["source_refs"] = refs
	raw, _ := json.Marshal(result)
	ref, e := awsServiceArchive(ctx, storage, r.TenantID, "canonical", raw)
	if e != nil {
		return e
	}
	result["id"], result["archive"], result["content_hash"] = model.ID(), ref, source.BytesHash(raw)
	return a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		parsed, e := eksassociation.Parse(current)
		if e != nil || !parsed.Enabled || model.Bool(current, "revoked") || eksassociation.Hash(parsed) != eksassociation.Hash(r) {
			return errors.New("EKS_ASSOCIATION_SOURCE_CHANGED")
		}
		if e = awsServiceRegistrationCurrent(ctx, tx, nativeReg); e != nil {
			return e
		}
		latest, e := tx.Get(ctx, "resources", model.String(cluster, "id"))
		if e != nil {
			return e
		}
		if awsservice.ConfigurationHash(latest) != result["config_hash"] {
			return errors.New("EKS_ASSOCIATION_NATIVE_CONFIGURATION_CHANGED")
		}
		if _, e = tx.EKSAssociationCreate(ctx, result); e != nil {
			return e
		}
		status := "HEALTHY"
		if result["status"] != "ASSOCIATED" {
			status = "PARTIAL"
		}
		if e = tx.SourceCheckpointSet(ctx, r.ID, "status", model.Document{"status": status, "reason_code": "EKS_ASSOCIATION_POINT_EVIDENCE_PERSISTED", "last_sync_version": r.Version, "last_sync_at": model.Now(), "config_hash": eksassociation.Hash(r)}); e != nil {
			return e
		}
		return tx.Audit(ctx, "eks-association-ingester", "eks.association.published", model.String(result, "id"), model.Document{"resource_id": cluster["id"], "status": result["status"], "execution_authorized": false})
	})
}

func eksAssociationTick(ctx context.Context, a *Activities, tenant string) error {
	if a.Config.Fixture {
		return nil
	}
	var sources []model.Document
	if e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; sources, e = tx.SourceList(ctx); return e }); e != nil {
		return e
	}
	var storage *native.Storage
	requested := false
	for _, d := range sources {
		if d["kind"] == eksassociation.Kind && model.Bool(d, "enabled") && !model.Bool(d, "revoked") && model.Bool(d, "sync_requested") {
			requested = true
		}
	}
	if !requested {
		return nil
	}
	encoded := os.Getenv("AWS_SERVICE_READ_BINDINGS_JSON")
	if encoded == "" {
		encoded = os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON")
	}
	factory, e := source.AWSServiceFactory(encoded)
	if e != nil {
		return e
	}
	var first error
	for _, d := range sources {
		if d["kind"] != eksassociation.Kind || !model.Bool(d, "enabled") || model.Bool(d, "revoked") || !model.Bool(d, "sync_requested") {
			continue
		}
		r, e := eksassociation.Parse(d)
		if e != nil {
			continue
		}
		at, _ := time.Parse(time.RFC3339Nano, model.String(d, "last_sync_at"))
		if model.Number(d, "last_sync_version") == r.Version && !at.IsZero() && time.Since(at) < 10*time.Minute {
			continue
		}
		if storage == nil {
			storage, e = native.StorageFromEnvironment(ctx, false)
			if e != nil {
				return e
			}
		}
		var nr awsservice.Registration
		e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; nr, e = tx.EKSNativeSource(ctx, r); return e })
		if e == nil {
			var reader *provider.AWS
			reader, e = factory(ctx, nr)
			if e == nil {
				readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				e = SyncEKSAssociation(readCtx, a, storage, r, reader, os.Getenv("EKS_KUBERNETES_READ_BINDINGS_JSON"))
				cancel()
			}
		}
		if e != nil {
			code := "EKS_ASSOCIATION_EVIDENCE_UNAVAILABLE"
			if strings.Contains(e.Error(), "STATUS_403") {
				code = "EKS_KUBERNETES_READ_DENIED"
			} else if strings.Contains(e.Error(), "STATUS_404") {
				code = "EKS_KUBERNETES_OBJECT_ABSENT_AT_READ"
			} else {
				var rejected *provider.QueryRejection
				if strings.Contains(e.Error(), "DENIED") || errors.As(e, &rejected) && (rejected.StatusCode == 403 || strings.Contains(rejected.Code, "AccessDenied")) {
					code = "EKS_NATIVE_READ_DENIED"
				}
			}
			_ = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
				return tx.SourceCheckpointSet(ctx, r.ID, "status", model.Document{"status": "BLOCKED", "reason_code": code, "last_sync_version": r.Version, "last_sync_at": model.Now()})
			})
			if first == nil {
				first = e
			}
		}
	}
	return first
}
