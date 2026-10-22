package service

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestAWSServiceResultCannotManufactureAuthorityOrMoney(t *testing.T) {
	binding := model.Document{"tenant_id": "tenant-a", "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "resource_id": "resource-a", "provider_resource_id": "arn:aws:dynamodb:eu-west-1:111122223333:table/a", "workload_id": "workload-a"}
	input := model.Document{"binding": binding, "family": "DYNAMODB", "billing": model.Document{"currency": "GBP", "complete": false, "scope_complete": false, "marginal_pricing_known": false, "commitment_scope_known": false}}
	base := awsServiceBlocked(binding, "DYNAMODB", []string{"NATIVE_INPUT_REQUIRED"})
	if e := validateAWSServiceResult(base, input); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(model.Document){
		func(r model.Document) { r["execution_authorized"] = true }, func(r model.Document) { r["verified_saving"] = "1" }, func(r model.Document) { r["family"] = "ECS" }, func(r model.Document) { r["resource_id"] = "foreign" }, func(r model.Document) {
			r["economics"] = model.Document{"currency": "GBP", "candidate_window_cost": "1", "estimated_window_saving": "2"}
		}, func(r model.Document) { r["economics"] = model.Document{"currency": "GBP", "current_window_cost": 1.5} },
	} {
		candidate := model.Clone(base)
		change(candidate)
		if e := validateAWSServiceResult(candidate, input); e == nil {
			t.Fatal("tampered result accepted")
		}
	}
	if _, e := BuildPlan(context.Background(), nil, "aws-service-advice", "", true); e == nil {
		t.Fatal("read-only review reached generic execution plan lookup")
	}
}
