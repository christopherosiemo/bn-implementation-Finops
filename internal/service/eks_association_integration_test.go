package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/eksassociation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"testing"
)

// Component acceptance only: synthetic archive references do not claim native
// cluster, object storage or browser acceptance.
func TestEKSPersistedAssociationAPIIsolationCurrentnessAndImmutableRLS(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	token := f.token(f.tenant, "eks-operator", "PLATFORM_ADMIN")
	arn := "arn:aws:eks:eu-west-1:111122223333:cluster/pilot"
	approved, _ := json.Marshal(map[string]source.EKSApprovedBinding{"kube-reader": {TenantID: f.tenant, AccountID: "111122223333", Region: "eu-west-1", ClusterARN: arn}})
	t.Setenv("EKS_KUBERNETES_APPROVED_BINDINGS_JSON", string(approved))
	code, native, _ := f.request("source-connections", `"0"`, "eks-native-source", token, model.Document{"kind": awsservice.NativeKind, "account_id": "111122223333", "region": "eu-west-1", "read_role_binding_id": "aws-reader", "service_families": []string{"EKS"}, "scope_mode": "RESOURCE", "root_resource_arns": []string{arn}})
	if code != 201 {
		t.Fatalf("native registration %d %#v", code, native)
	}
	body := model.Document{"kind": eksassociation.Kind, "name": "Component identity source", "account_id": "111122223333", "region": "eu-west-1", "cluster_arn": arn, "read_role_binding_id": "aws-reader", "kubernetes_read_binding_id": "kube-reader", "workload_bindings": []model.Document{}}
	code, registration, _ := f.request("source-connections", `"0"`, "eks-identity-source", token, body)
	if code != 201 {
		t.Fatalf("identity registration %d %#v", code, registration)
	}
	bad := model.Clone(body)
	bad["token"] = "forbidden"
	if c, _, _ := f.request("source-connections", `"0"`, "eks-no-secrets", token, bad); c != 422 {
		t.Fatalf("public credential accepted %d", c)
	}
	var resource model.Document
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		resource, e = tx.Create(ctx, "resources", model.Document{"provider": "AWS", "resource_type": "EKS_CLUSTER", "service_family": "EKS", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": arn, "aws_service_configuration": model.Document{"arn": arn, "name": "pilot"}})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	id := model.String(resource, "id")
	h := awsservice.Hash(model.Document{"synthetic": "identity component"})
	doc := model.Document{"id": model.ID(), "schema_version": "1", "resource_id": id, "source_id": registration["id"], "source_version": 1, "native_source_id": native["id"], "native_source_version": 1, "config_hash": awsservice.ConfigurationHash(resource), "content_hash": h, "status": "ASSOCIATED", "reason_codes": []string{}, "nodes": []model.Document{}, "workloads": []model.Document{}, "observed_at": model.Now(), "execution_authorized": false, "verified_saving": nil, "cost_attribution": "RELATIONSHIP_ONLY_NO_ADDITIONAL_COST", "archive": model.Document{"key": "tenant/" + f.tenant + "/native/synthetic/canonical/" + h, "version_id": "synthetic-reference", "body_sha256": h}}
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.EKSAssociationCreate(ctx, doc); return e }); e != nil {
		t.Fatal(e)
	}
	if c, d := fleetNativeHTTPGet(t, f, "resources/"+id+"/eks-association", token); c != 200 || d["current"] != true || d["execution_authorized"] != false {
		t.Fatalf("normal read %d %#v", c, d)
	}
	if c, _ := fleetNativeHTTPGet(t, f, "resources/"+id+"/eks-association", f.token("foreign-"+f.tenant, "other", "FINOPS_ADMIN")); c != 404 {
		t.Fatalf("foreign identity disclosed %d", c)
	}
	for _, role := range []string{"api", "worker", "signer", "executor"} {
		if e := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.EKSAssociationCreate(ctx, doc); return e }); e == nil {
			t.Fatalf("%s published identity", role)
		}
	}
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE eks_kubernetes_associations SET document='{}' WHERE tenant_id=$1 AND resource_id=$2", f.tenant, id)
		return e
	}); e == nil {
		t.Fatal("immutable association modified")
	}
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, model.String(registration, "id"), "status", model.Document{"status": "BLOCKED", "reason_code": "EKS_KUBERNETES_READ_DENIED"})
	}); e != nil {
		t.Fatal(e)
	}
	if c, d := fleetNativeHTTPGet(t, f, "resources/"+id+"/eks-association", token); c != 200 || d["current"] != false {
		t.Fatalf("failed current read hidden %d %#v", c, d)
	}
	if code, _, _ := f.request("source-connections/"+model.String(registration, "id")+"/revoke", `"1"`, "eks-revoke", token, model.Document{}); code != 202 {
		t.Fatalf("revoke %d", code)
	}
	if c, d := fleetNativeHTTPGet(t, f, "resources/"+id+"/eks-association", token); c != 200 || d["current"] != false {
		t.Fatalf("revocation hidden %d %#v", c, d)
	}
}
