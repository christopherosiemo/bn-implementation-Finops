package source

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
)

func TestS3PrivateBindingsRejectScopeAndCollectorConfusion(t *testing.T) {
	for _, name := range []string{"tenant", "account", "region", "role-account", "external-id", "collector", "definition-version"} {
		t.Run(name, func(t *testing.T) {
			binding := model.Document{"tenant_id": "tenant-s3", "account_id": "111122223333", "region": "eu-west-1", "role_arn": "arn:aws:iam::111122223333:role/read", "external_id": strings.Repeat("synthetic", 5), "approved_writer_principal_arn": "arn:aws:iam::111122223333:role/collector", "metric_definition_id": "get-requests-v1", "metric_definition_version": "1"}
			switch name {
			case "tenant":
				binding["tenant_id"] = "other-tenant"
			case "account":
				binding["account_id"] = "999900001111"
			case "region":
				binding["region"] = "us-east-1"
			case "role-account":
				binding["role_arn"] = "arn:aws:iam::999900001111:role/read"
			case "external-id":
				binding["external_id"] = "short"
			case "collector":
				binding["approved_writer_principal_arn"] = binding["role_arn"]
			case "definition-version":
				delete(binding, "metric_definition_version")
			}
			encoded, _ := json.Marshal(model.Document{"read": binding})
			factory, e := ObjectStorageAWSFactory(string(encoded))
			if e != nil {
				t.Fatal(e)
			}
			_, e = factory(context.Background(), objectstorage.Registration{TenantID: "tenant-s3", AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "read", ReportType: "APP_ACCESS"})
			if e == nil {
				t.Fatal("confused private binding accepted")
			}
		})
	}
}
