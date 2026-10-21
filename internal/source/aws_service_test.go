package source

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"testing"
)

func TestAWSServiceReadBindingRejectsTenantAccountRegionConfusion(t *testing.T) {
	encoded := `{"approved":{"tenant_id":"tenant-a","account_id":"111122223333","region":"eu-west-1","role_arn":"arn:aws:iam::111122223333:role/read-only","external_id":"01234567890123456789012345678901"}}`
	factory, e := AWSServiceFactory(encoded)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range []awsservice.Registration{
		{ID: "source-a", TenantID: "tenant-b", AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "approved", Version: 1, Enabled: true, ServiceFamilies: []string{"ECS"}, ScopeMode: "ACCOUNT"},
		{ID: "source-a", TenantID: "tenant-a", AccountID: "999900001111", Region: "eu-west-1", ReadRoleBindingID: "approved", Version: 1, Enabled: true, ServiceFamilies: []string{"ECS"}, ScopeMode: "ACCOUNT"},
		{ID: "source-a", TenantID: "tenant-a", AccountID: "111122223333", Region: "eu-west-2", ReadRoleBindingID: "approved", Version: 1, Enabled: true, ServiceFamilies: []string{"ECS"}, ScopeMode: "ACCOUNT"},
	} {
		if _, e := factory(context.Background(), r); e == nil {
			t.Fatal("unregistered role scope accepted")
		}
	}
	if _, e := AWSServiceFactory(encoded + ` {}`); e == nil {
		t.Fatal("trailing binding payload accepted")
	}
}
