package source

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"testing"
)

func TestLambdaPrivateReadBindingRejectsTenantAccountRegionAndExecutionFallback(t *testing.T) {
	binding := map[string]AWSReadBinding{"approved": {TenantID: "tenant-lambda", AccountID: "111122223333", PayerAccountID: "111122223333", Region: "eu-west-1", RoleARN: "arn:aws:iam::111122223333:role/registered-lambda-read", ExternalID: "unique-external-id-at-least-thirty-two-characters"}}
	raw, _ := json.Marshal(binding)
	factory, e := LambdaAWSFactory(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	base := lambdacost.Registration{ID: "native", TenantID: "tenant-lambda", Kind: lambdacost.NativeKind, AccountID: "111122223333", Region: "eu-west-1", FunctionARN: "arn:aws:lambda:eu-west-1:111122223333:function:processor", Qualifier: "live", ReadRoleBindingID: "approved", Version: 1, Enabled: true}
	for name, change := range map[string]func(*lambdacost.Registration){"tenant": func(r *lambdacost.Registration) { r.TenantID = "foreign" }, "account": func(r *lambdacost.Registration) { r.AccountID = "999999999999" }, "region": func(r *lambdacost.Registration) { r.Region = "us-east-1" }, "unregistered-execution-role": func(r *lambdacost.Registration) { r.ReadRoleBindingID = "arn:aws:iam::111122223333:role/executor" }} {
		t.Run(name, func(t *testing.T) {
			r := base
			change(&r)
			if _, e := factory(context.Background(), r); e == nil {
				t.Fatal("unregistered identity accepted")
			}
		})
	}
	if _, e = LambdaAWSFactory(`{"reader":{"unknown":"not-config"}}`); e == nil {
		t.Fatal("unknown private binding accepted")
	}
}
