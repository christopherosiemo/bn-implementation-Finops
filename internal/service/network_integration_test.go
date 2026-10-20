package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"strings"
	"testing"
)

func TestNetworkIDsOnlyPolicyRevisionsIsolationAndBlockedPublication(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "network-assessor", "finops_network_analyst")
	var r model.Document
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		r, e = tx.Create(ctx, "resources", model.Document{"name": "Synthetic network policy", "provider": "AWS", "resource_type": "NAT_GATEWAY", "provider_resource_id": "nat-0123456789abcdef0", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "replay-workload", "network_configuration": model.Document{"availability_mode": "zonal", "vpc_id": "vpc-native"}, "configuration_authority": "UNKNOWN"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	rid := model.String(r, "id")
	token := f.token(f.tenant, "network-reviewer", "PLATFORM_ADMIN")
	body := model.Document{"name": "Unknown safety remains visible", "resource_id": rid, "policy": model.Document{"criticality": "NON_PRODUCTION", "security_reviewed": nil}}
	code, policy, _ := f.request("network-policies", `"0"`, "network-policy", token, body)
	if code != 201 {
		t.Fatalf("policy %d %#v", code, policy)
	}
	pid := model.String(policy, "id")
	code, replay, _ := f.request("network-policies", `"0"`, "network-policy", token, body)
	if code != 201 || replay["id"] != pid {
		t.Fatal("idempotent policy replay changed")
	}
	if code, _, _ := f.request("network-policies", `"0"`, "network-money", token, model.Document{"resource_id": rid, "name": "invalid", "policy": model.Document{"monthly_saving": "100"}}); code != 422 {
		t.Fatalf("policy accepted economics: %d", code)
	}
	if code, _, _ := f.request("network-assessments", `"0"`, "network-caller-cost", token, model.Document{"resource_id": rid, "observations": model.Document{"complete": true}}); code != 422 {
		t.Fatalf("authoritative body accepted: %d", code)
	}
	code, queued, _ := f.request("network-assessments", `"0"`, "network-blocked", token, model.Document{"resource_id": rid, "policy_id": pid})
	if code != 202 {
		t.Fatalf("queue %d %#v", code, queued)
	}
	a := &API{Store: analyst, Config: Config{Fixture: true}}
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		return networkAssessmentOne(ctx, a, tx, func(context.Context, string, model.Document) ([]byte, error) {
			return nil, errors.New("unexpected archive read")
		})
	}); e != nil {
		t.Fatal(e)
	}
	id := model.String(queued, "id")
	status, record := fleetNativeHTTPGet(t, f, "network-assessments/"+id, token)
	if status != 200 || record["status"] != "BLOCKED" {
		t.Fatalf("blocked record %d %#v", status, record)
	}
	result := storageObject(record["assessment"])
	if result["verified_saving"] != nil || result["execution_authorized"] != false || result["pre_execution_ready"] != false {
		t.Fatal("read-only advice violated")
	}
	status, pub := fleetNativeHTTPGet(t, f, "recommendations/network-"+id, token)
	if status != 200 || pub["model_kind"] != "NETWORK_ASSESSMENT_V1" || pub["execution_authorized"] != false {
		t.Fatalf("publication %d %#v", status, pub)
	}
	foreign := f.token("foreign-"+f.tenant, "foreign", "FINOPS_ADMIN")
	if code, _ := fleetNativeHTTPGet(t, f, "network-assessments/"+id, foreign); code != 404 {
		t.Fatal("foreign assessment disclosed")
	}
	if code, _ := fleetNativeHTTPGet(t, f, "network-policies/"+pid, foreign); code != 404 {
		t.Fatal("foreign policy disclosed")
	}
	for _, path := range []string{"network-assessments?resource_id=" + rid + "&limit=1", "network-policies?resource_id=" + rid + "&limit=1", "resources?resource_type=NAT_GATEWAY&limit=1", "recommendations?model_kind=NETWORK_ASSESSMENT_V1&resource_id=" + rid + "&limit=1"} {
		if code, _ := fleetNativeHTTPGet(t, f, path, token); code != 200 {
			t.Fatalf("ordinary list %s: %d", path, code)
		}
	}
	if _, e := BuildPlan(ctx, nil, "network-"+id, "", true); e == nil {
		t.Fatal("network advice became executable")
	}
	// Immutability holds below the API; no correction overwrites history.
	for _, role := range []string{"api", "ingester", "signer", "executor", "worker"} {
		e := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "UPDATE network_policies SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, pid)
			return e
		})
		if e == nil {
			t.Fatalf("%s changed immutable policy", role)
		}
	}
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE network_assessments SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, id)
		return e
	}); e == nil {
		t.Fatal("terminal result overwritten")
	}
	revision := model.Document{"name": "Reviewed still unknown", "policy": model.Document{"criticality": "NON_PRODUCTION", "security_reviewed": false}}
	code, next, _ := f.request("network-policies/"+pid+"/revisions", `"1"`, "network-revision", token, revision)
	if code != 201 || model.Number(next, "version") != 2 {
		t.Fatalf("revision %d %#v", code, next)
	}
	if code, _, _ := f.request("network-policies/"+pid+"/revisions", `"1"`, "network-stale", token, revision); code != 409 && code != 412 {
		t.Fatalf("stale revision allowed %d", code)
	}
	// No source registration can submit provenance or prices.
	if code, _, _ := f.request("source-connections", "", "network-source-cost", token, model.Document{"kind": "AWS_VPC_FLOW_LOGS", "trusted": true}); code != 422 {
		t.Fatalf("source authority submitted %d", code)
	}
	raw, _ := json.Marshal(record)
	if strings.Contains(string(raw), "SIGNING_PRIVATE_KEY") {
		t.Fatal("secret disclosed")
	}
}

func TestNetworkNativeChargeCategoriesAndNoExecute(t *testing.T) {
	cases := map[string]string{"EUN1-NatGateway-Hours": "NAT_HOURLY", "EUN1-NatGateway-Bytes": "NAT_PROCESSING", "EUN1-PublicIPv4:InUseAddress": "PUBLIC_IPV4", "EUN1-VpcEndpoint-Hours": "ENDPOINT_HOURLY", "EUN1-VpcEndpoint-Bytes": "ENDPOINT_PROCESSING", "EUN1-DataTransfer-Regional-Bytes": "CROSS_AZ_TRANSFER", "EUN1-EUW2-AWS-Out-Bytes": "CROSS_REGION_TRANSFER", "EUN1-DataTransfer-Out-Bytes": "INTERNET_EGRESS", "EUN1-TransitGateway-Hours": "TRANSIT_GATEWAY", "BoxUsage:c7i.large": ""}
	for usage, want := range cases {
		if got := networkChargeKind(model.Document{"product_servicecode": "AmazonEC2", "line_item_usage_type": usage}); got != want {
			t.Errorf("%s=%s want %s", usage, got, want)
		}
	}
	if networkChargeKind(model.Document{"product_servicecode": "AmazonS3", "line_item_usage_type": "DataTransfer-Out-Bytes"}) != "" {
		t.Fatal("S3 charge reclassified into network family")
	}
}
