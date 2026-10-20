package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
	"time"
)

func TestLambdaProjectionUnknownConcurrencyAndExactImmutableReceipts(t *testing.T) {
	r, c, _, _, _, end := lambdaFinancialFixture()
	config := storageObject(c["configuration"])
	config["account_concurrency"] = model.Document{"AccountLimit": model.Document{"ConcurrentExecutions": 1000, "UnreservedConcurrentExecutions": 800}}
	c["configuration"] = config
	policy := model.Document{"id": "policy", "version": 1, "policy": model.Document{"owner": "owner", "configuration_authority": "TERRAFORM", "available_concurrency": "9999"}}
	point := model.Document{"memory_size_mb": "1536", "source_ref": model.Document{"kind": "AWS_LAMBDA_PERFORMANCE_CURVE_V1", "id": "source", "version": 1, "sha256": evidence.Hash("body")}}
	input, reasons := lambdaProjectInput(r, c, policy, storageBinding("tenant-test", r), model.Document{}, nil, model.Document{"receipts": []model.Document{point}}, end.Add(time.Hour))
	if len(reasons) > 0 {
		t.Fatal(reasons)
	}
	conf := storageObject(input["configuration"])
	if conf["account_available_concurrency"] != "800.000000000000" || conf["provisioned_concurrency"] == nil || model.Number(conf, "provisioned_concurrency") != 0 {
		t.Fatal(conf)
	}
	points := storageRows(storageObject(input["performance"])["receipts"])
	if model.String(storageObject(points[0]["source_ref"]), "version") != "1" || model.Number(points[0], "memory_size_mb") != 1536 {
		t.Fatal(points)
	}
	config["account_concurrency"] = nil
	config["reserved_concurrency"] = nil
	config["provisioned_concurrency"] = nil
	c["configuration"] = config
	input, _ = lambdaProjectInput(r, c, policy, storageBinding("tenant-test", r), model.Document{}, nil, model.Document{}, end.Add(time.Hour))
	conf = storageObject(input["configuration"])
	if conf["account_available_concurrency"] != nil || conf["reserved_concurrency"] != nil || conf["provisioned_concurrency"] != nil {
		t.Fatal("unknown became quota/zero", conf)
	}
}
func TestLambdaProjectionRejectsChangedBindingAndDoesNotAcceptPolicyEconomics(t *testing.T) {
	for _, change := range []string{"account", "region", "configuration", "owner", "authority"} {
		r, c, _, _, _, end := lambdaFinancialFixture()
		p := model.Document{"policy": model.Document{"owner": "owner", "configuration_authority": "TERRAFORM"}}
		switch change {
		case "account":
			c["account_id"] = "222233334444"
		case "region":
			c["region"] = "us-east-1"
		case "configuration":
			c["config_hash"] = evidence.Hash("different")
		case "owner":
			r["owner"] = nil
		case "authority":
			r["configuration_authority"] = "UNKNOWN"
		}
		_, reasons := lambdaProjectInput(r, c, p, storageBinding("tenant-test", r), model.Document{}, nil, model.Document{}, end.Add(time.Hour))
		if len(reasons) == 0 {
			t.Fatal(change)
		}
	}
}
func TestLambdaResponseAndRevocationCannotRetainPositiveAuthorityOrClaims(t *testing.T) {
	binding := model.Document{"resource_id": "lambda"}
	input := model.Document{"binding": binding, "resource_id": "lambda", "config_hash": evidence.Hash("config")}
	result := lambdaBlocked(binding, nil)
	result["config_hash"] = input["config_hash"]
	if e := validateLambdaResult(result, input); e != nil {
		t.Fatal(e)
	}
	result["execution_authorized"] = true
	if validateLambdaResult(result, input) == nil {
		t.Fatal("execution authority accepted")
	}
	result["execution_authorized"] = false
	result["candidates"] = []model.Document{{"id": "candidate", "status": "RECOMMENDED", "read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil, "economics": model.Document{"estimated_window_saving": "120.00", "estimated_monthly_saving": "730.00", "estimated_annual_saving": nil}}}
	result["status"] = "RECOMMENDED"
	result["decision_families"] = []model.Document{{"family": "MEMORY", "status": "RECOMMENDED", "decision": "REDUCE_MEMORY"}}
	if e := validateLambdaResult(result, input); e != nil {
		t.Fatal(e)
	}
	lambdaBlockForEvidence(result, []string{"LAMBDA_SOURCE_REVOKED"})
	if result["status"] != "BLOCKED" {
		t.Fatal(result)
	}
	candidate := storageRows(result["candidates"])[0]
	if candidate["status"] != "BLOCKED" || storageObject(candidate["economics"])["estimated_window_saving"] != nil {
		t.Fatal(candidate)
	}
}
