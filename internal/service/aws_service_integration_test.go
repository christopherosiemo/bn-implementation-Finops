package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"testing"
)

// Persistence/API component acceptance. These archive references are explicitly
// synthetic; provider transport and actual archive acceptance run separately.
func TestAWSServiceInventoryPersistedAPIIsolationAndRevocation(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	token := f.token(f.tenant, "inventory-owner", "PLATFORM_ADMIN")
	body := model.Document{"kind": awsservice.NativeKind, "name": "Synthetic read-only service source", "account_id": "111122223333", "region": "eu-west-1", "read_role_binding_id": "approved-service-reader", "service_families": awsservice.Families, "scope_mode": "ACCOUNT", "root_resource_arns": []string{}}
	code, registration, _ := f.request("source-connections", `"0"`, "aws-service-register", token, body)
	if code != 201 {
		t.Fatalf("registration %d %#v", code, registration)
	}
	sourceID := model.String(registration, "id")
	if code, _, _ := f.request("source-connections", `"0"`, "aws-service-authority", token, model.Document{"kind": awsservice.NativeKind, "complete": true}); code != 422 {
		t.Fatalf("caller completeness accepted %d", code)
	}
	bad := model.Clone(body)
	bad["root_resource_arns"] = []string{"arn:aws:ecs:eu-west-1:999900001111:cluster/foreign"}
	bad["scope_mode"] = "RESOURCE"
	if code, _, _ := f.request("source-connections", `"0"`, "aws-service-foreign-scope", token, bad); code != 422 {
		t.Fatalf("foreign ARN accepted %d", code)
	}
	resources := []model.Document{}
	for index, spec := range []struct{ family, kind, arn, placement string }{
		{"ECS", "ECS_SERVICE", "arn:aws:ecs:eu-west-1:111122223333:service/test/ec2", "EC2"},
		{"ECS", "ECS_SERVICE", "arn:aws:ecs:eu-west-1:111122223333:service/test/fargate", "FARGATE"},
		{"EKS", "EKS_CLUSTER", "arn:aws:eks:eu-west-1:111122223333:cluster/test", ""},
		{"ELASTICACHE", "ELASTICACHE_REPLICATION_GROUP", "arn:aws:elasticache:eu-west-1:111122223333:replicationgroup:test", ""},
		{"DYNAMODB", "DYNAMODB_TABLE", "arn:aws:dynamodb:eu-west-1:111122223333:table/test", ""},
		{"ELB", "LOAD_BALANCER", "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/test/0123456789abcdef", ""},
	} {
		var resource model.Document
		if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			var e error
			resource, e = tx.Create(ctx, "resources", model.Document{"provider": "AWS", "resource_type": spec.kind, "provider_resource_id": spec.arn, "account_id": "111122223333", "region": "eu-west-1", "name": "Synthetic service inventory", "service_family": spec.family, "aws_service_configuration": model.Document{"placement": spec.placement, "observed_configuration": "synthetic"}, "workload_id": "replay-workload", "owner": "preserved-owner", "configuration_authority": "TERRAFORM", "cost_status": "UNAVAILABLE", "estimated_monthly_cost": nil, "spend_coverage": "OBSERVATION_ONLY"})
			return e
		}); e != nil {
			t.Fatal(e)
		}
		resources = append(resources, resource)
		h := awsservice.Hash(model.Document{"synthetic_snapshot": index})
		doc := model.Document{"schema_version": "1", "kind": "AWS_SERVICE_NATIVE_SNAPSHOT_V1", "resource_id": resource["id"], "source_id": sourceID, "registration_version": 1, "generation_id": "synthetic-component-generation", "family": spec.family, "account_id": "111122223333", "region": "eu-west-1", "config_hash": awsservice.ConfigurationHash(resource), "content_hash": h, "archive": model.Document{"bucket": "component-reference", "key": "tenant/" + f.tenant + "/native/synthetic/canonical/" + h, "version_id": "synthetic-component-reference", "body_sha256": h}, "observed_at": model.Now(), "collection_complete": false, "collection_reason_codes": []string{"SYNTHETIC_COMPONENT_NOT_PROVIDER_ACCEPTANCE"}, "execution_authorized": false, "verified_saving": nil}
		if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.AWSServiceEvidenceAppend(ctx, doc); return e }); e != nil {
			t.Fatal(e)
		}
		status, detail := fleetNativeHTTPGet(t, f, "resources/"+model.String(resource, "id")+"/aws-service-evidence", token)
		if status != 200 || detail["current"] != true || storageObject(detail["snapshot"])["family"] != spec.family {
			t.Fatalf("evidence detail %d %#v", status, detail)
		}
		status, page := fleetNativeHTTPGet(t, f, "resources?service_family="+spec.family+"&workload_id=replay-workload&limit=1", token)
		if status != 200 || len(storageRows(page["items"])) != 1 {
			t.Fatalf("normal inventory %d %#v", status, page)
		}
		observed := storageRows(page["items"])[0]
		if observed["cost_status"] != "UNAVAILABLE" || observed["estimated_monthly_cost"] != nil {
			t.Fatal("unknown native cost became zero")
		}
		foreign := f.token("foreign-"+f.tenant, "foreign", "FINOPS_ADMIN")
		if status, _ := fleetNativeHTTPGet(t, f, "resources/"+model.String(resource, "id")+"/aws-service-evidence", foreign); status != 404 {
			t.Fatalf("foreign evidence disclosed %d", status)
		}
	}
	rid := model.String(resources[0], "id")
	for _, role := range []string{"api", "signer", "executor", "worker"} {
		if e := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "UPDATE aws_service_evidence_snapshots SET document='{}' WHERE tenant_id=$1 AND resource_id=$2", tx.Tenant, rid)
			return e
		}); e == nil {
			t.Fatalf("%s changed immutable source", role)
		}
	}
	if e := f.roles["api"].Do(ctx, "foreign-"+f.tenant, func(tx *store.Tx) error { _, e := tx.AWSServiceEvidenceLatest(ctx, rid); return e }); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatalf("tenant RLS leaked: %v", e)
	}
	if code, _, _ := f.request("source-connections/"+sourceID+"/revoke", `"1"`, "aws-service-revoke", token, model.Document{}); code != 202 {
		t.Fatalf("revoke %d", code)
	}
	status, detail := fleetNativeHTTPGet(t, f, "resources/"+rid+"/aws-service-evidence", token)
	if status != 200 || detail["current"] != false {
		t.Fatalf("revocation not visible %d %#v", status, detail)
	}
	if len(model.Strings(detail, "reason_codes")) == 0 {
		t.Fatal("revocation blocker absent")
	}
}
