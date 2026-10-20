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

func TestLambdaIDsOnlyPolicyRevisionsIsolationAndBlockedPublication(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "lambda-assessor", "finops_lambda_analyst")
	var r model.Document
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		r, e = tx.Create(ctx, "resources", model.Document{"name": "Synthetic lambda policy", "provider": "AWS", "resource_type": "LAMBDA_FUNCTION", "provider_resource_id": "arn:aws:lambda:eu-west-1:111122223333:function:synthetic-fixture", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "replay-workload", "lambda_configuration": model.Document{"memory_size_mb": 1024, "architecture": "x86_64", "model": "DEFAULT_EVENT"}, "configuration_authority": "UNKNOWN"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	rid := model.String(r, "id")
	token := f.token(f.tenant, "lambda-reviewer", "PLATFORM_ADMIN")
	body := model.Document{"name": "Unknown safety remains visible", "resource_id": rid, "policy": model.Document{"criticality": "NON_PRODUCTION", "requires_warm_capacity": nil}}
	code, policy, _ := f.request("lambda-policies", `"0"`, "lambda-policy", token, body)
	if code != 201 {
		t.Fatalf("policy %d %#v", code, policy)
	}
	pid := model.String(policy, "id")
	code, replay, _ := f.request("lambda-policies", `"0"`, "lambda-policy", token, body)
	if code != 201 || replay["id"] != pid {
		t.Fatal("idempotent policy replay changed")
	}
	if code, _, _ := f.request("lambda-policies", `"0"`, "lambda-money", token, model.Document{"resource_id": rid, "name": "invalid", "policy": model.Document{"monthly_saving": "100"}}); code != 422 {
		t.Fatalf("policy accepted economics: %d", code)
	}
	if code, _, _ := f.request("lambda-assessments", `"0"`, "lambda-caller-cost", token, model.Document{"resource_id": rid, "observations": model.Document{"complete": true}}); code != 422 {
		t.Fatalf("authoritative body accepted: %d", code)
	}
	code, queued, _ := f.request("lambda-assessments", `"0"`, "lambda-blocked", token, model.Document{"resource_id": rid, "qualifier": "$LATEST", "policy_id": pid})
	if code != 202 {
		t.Fatalf("queue %d %#v", code, queued)
	}
	a := &API{Store: analyst, Config: Config{Fixture: true}}
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		return lambdaAssessmentOne(ctx, a, tx, func(context.Context, string, model.Document) ([]byte, error) {
			return nil, errors.New("unexpected archive read")
		})
	}); e != nil {
		t.Fatal(e)
	}
	id := model.String(queued, "id")
	status, record := fleetNativeHTTPGet(t, f, "lambda-assessments/"+id, token)
	if status != 200 || record["status"] != "BLOCKED" {
		t.Fatalf("blocked record %d %#v", status, record)
	}
	result := storageObject(record["assessment"])
	if result["verified_saving"] != nil || result["execution_authorized"] != false || result["pre_execution_ready"] != false {
		t.Fatal("read-only advice violated")
	}
	status, pub := fleetNativeHTTPGet(t, f, "recommendations/lambda-"+id, token)
	if status != 200 || pub["model_kind"] != "LAMBDA_ASSESSMENT_V1" || pub["execution_authorized"] != false {
		t.Fatalf("publication %d %#v", status, pub)
	}
	foreign := f.token("foreign-"+f.tenant, "foreign", "FINOPS_ADMIN")
	if code, _ := fleetNativeHTTPGet(t, f, "lambda-assessments/"+id, foreign); code != 404 {
		t.Fatal("foreign assessment disclosed")
	}
	if code, _ := fleetNativeHTTPGet(t, f, "lambda-policies/"+pid, foreign); code != 404 {
		t.Fatal("foreign policy disclosed")
	}
	for _, path := range []string{"lambda-assessments?resource_id=" + rid + "&limit=1", "lambda-policies?resource_id=" + rid + "&limit=1", "resources?resource_type=LAMBDA_FUNCTION&limit=1", "recommendations?model_kind=LAMBDA_ASSESSMENT_V1&resource_id=" + rid + "&limit=1"} {
		if code, _ := fleetNativeHTTPGet(t, f, path, token); code != 200 {
			t.Fatalf("ordinary list %s: %d", path, code)
		}
	}
	if _, e := BuildPlan(ctx, nil, "lambda-"+id, "", true); e == nil {
		t.Fatal("lambda advice became executable")
	}
	// Immutability holds below the API; no correction overwrites history.
	for _, role := range []string{"api", "ingester", "signer", "executor", "worker"} {
		e := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "UPDATE lambda_policies SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, pid)
			return e
		})
		if e == nil {
			t.Fatalf("%s changed immutable policy", role)
		}
	}
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE lambda_assessments SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, id)
		return e
	}); e == nil {
		t.Fatal("terminal result overwritten")
	}
	revision := model.Document{"name": "Reviewed still unknown", "policy": model.Document{"criticality": "NON_PRODUCTION", "requires_warm_capacity": false}}
	code, next, _ := f.request("lambda-policies/"+pid+"/revisions", `"1"`, "lambda-revision", token, revision)
	if code != 201 || model.Number(next, "version") != 2 {
		t.Fatalf("revision %d %#v", code, next)
	}
	if code, _, _ := f.request("lambda-policies/"+pid+"/revisions", `"1"`, "lambda-stale", token, revision); code != 409 && code != 412 {
		t.Fatalf("stale revision allowed %d", code)
	}
	// No source registration can submit provenance or prices.
	if code, _, _ := f.request("source-connections", "", "lambda-source-cost", token, model.Document{"kind": "AWS_LAMBDA_NATIVE_V1", "trusted": true}); code != 422 {
		t.Fatalf("source authority submitted %d", code)
	}
	raw, _ := json.Marshal(record)
	if strings.Contains(string(raw), "SIGNING_PRIVATE_KEY") {
		t.Fatal("secret disclosed")
	}
}
