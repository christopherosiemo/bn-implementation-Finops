package awsservice

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestAWSServiceRegistrationScopeAndKinds(t *testing.T) {
	d := model.Document{"id": "registered", "tenant_id": "tenant-a", "kind": NativeKind, "account_id": "111122223333", "region": "eu-west-1", "read_role_binding_id": "approved", "version": 1, "enabled": true, "service_families": []string{"ECS", "EKS", "ELASTICACHE", "DYNAMODB", "ELB"}, "scope_mode": "ACCOUNT"}
	if _, e := ParseRegistration(d); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"kind", "account_id", "region", "read_role_binding_id", "scope_mode"} {
		t.Run(key, func(t *testing.T) {
			x := model.Clone(d)
			x[key] = "invalid"
			if key == "read_role_binding_id" {
				x[key] = ""
			}
			if _, e := ParseRegistration(x); e == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
	x := model.Clone(d)
	x["scope_mode"] = "RESOURCE"
	x["root_resource_arns"] = []string{"arn:aws:ecs:eu-west-1:999900001111:cluster/foreign"}
	if _, e := ParseRegistration(x); e == nil {
		t.Fatal("foreign account accepted")
	}
	x["root_resource_arns"] = []string{"arn:aws:ecs:eu-west-1:111122223333:cluster/approved"}
	if _, e := ParseRegistration(x); e != nil {
		t.Fatal(e)
	}
	x["service_families"] = []string{"DYNAMODB"}
	if _, e := ParseRegistration(x); e == nil {
		t.Fatal("unselected resource family accepted")
	}
}
