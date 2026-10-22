package source

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

func TestNetworkReadBindingRejectsPublicScopeCredentialConfusion(t *testing.T) {
	r := network.Registration{ID: "source-network", TenantID: "tenant-network", Kind: network.FlowKind, AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "read", FlowLogID: "fl-11111111", ResourceIDs: []string{"vpc-11111111"}, ReportBucket: "network-reports", ReportOwner: "111122223333", ReportRegion: "eu-west-1", Prefix: "AWSLogs/111122223333/vpcflowlogs/eu-west-1/", Fields: strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status region"), TrafficType: "ALL", MaxAggregationSeconds: 60, Version: 1}
	for _, scenario := range []string{"tenant", "account", "region", "missing binding", "bad role", "short externalID"} {
		t.Run(scenario, func(t *testing.T) {
			binding := model.Document{"tenant_id": "tenant-network", "payer_account_id": "111122223333", "account_id": "111122223333", "region": "eu-west-1", "role_arn": "arn:aws:iam::111122223333:role/ingestion", "external_id": strings.Repeat("synthetic", 5)}
			reg := r
			switch scenario {
			case "tenant":
				reg.TenantID = "other"
			case "account":
				reg.AccountID = "444455556666"
			case "region":
				reg.Region = "us-east-1"
			case "missing binding":
				reg.ReadRoleBindingID = "other"
			case "bad role":
				binding["role_arn"] = "arn:aws:iam::444455556666:role/read"
			case "short externalID":
				binding["external_id"] = "short"
			}
			raw, _ := json.Marshal(model.Document{"read": binding})
			factory, e := NetworkAWSFactory(string(raw))
			if e == nil {
				_, e = factory(context.Background(), reg)
			}
			if e == nil {
				t.Fatal("binding confusion accepted")
			}
		})
	}
}
