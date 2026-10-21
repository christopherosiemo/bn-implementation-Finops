package source

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAWSAccountBindingsSeparateMetadataAndPrivateScope(t *testing.T) {
	metadata := map[string]AWSAccountApprovedBinding{"ireland-read": {TenantID: "tenant-a", AccountID: "111122223333", Regions: []string{"eu-west-1"}, RoleARN: "arn:aws:iam::111122223333:role/ReadOnly", ScopeMode: "ACCOUNT", ExternalIDConfigured: true}}
	raw, _ := json.Marshal(metadata)
	rows, e := AWSAccountApprovedBindings(string(raw), "tenant-a")
	if e != nil || len(rows) != 1 || rows[0].TenantID != "" || rows[0].ID != "ireland-read" {
		t.Fatal("approved metadata", e)
	}
	if rows, e = AWSAccountApprovedBindings(string(raw), "tenant-b"); e != nil || len(rows) != 0 {
		t.Fatal("cross-tenant metadata disclosed")
	}
	if _, e = AWSAccountApprovedBindings(strings.Replace(string(raw), `"scope_mode":"ACCOUNT"`, `"external_id":"secret","scope_mode":"ACCOUNT"`, 1), "tenant-a"); e == nil {
		t.Fatal("secret accepted in public metadata")
	}
	private := map[string]AWSReadBinding{"ireland-read": {TenantID: "tenant-a", PayerAccountID: "111122223333", AccountID: "111122223333", Region: "eu-west-1", RoleARN: "arn:aws:iam::111122223333:role/ReadOnly", ExternalID: strings.Repeat("x", 32)}}
	secret, _ := json.Marshal(private)
	if _, e = ResolveApprovedAWSAccountReadBinding(string(secret), string(raw), "ireland-read", "tenant-a", "111122223333", "eu-west-1"); e != nil {
		t.Fatal("matching safe/private binding refused", e)
	}
	for _, changed := range []string{"{}", strings.Replace(string(raw), "role/ReadOnly", "role/OtherReadRole", 1), strings.Replace(string(raw), `"external_id_configured":true`, `"external_id_configured":false`, 1)} {
		if _, e = ResolveApprovedAWSAccountReadBinding(string(secret), changed, "ireland-read", "tenant-a", "111122223333", "eu-west-1"); e == nil {
			t.Fatal("revoked or changed approved binding still authorized")
		}
	}
	if _, e = ResolveAWSAccountReadBinding(string(secret), "ireland-read", "tenant-a", "111122223333", "eu-west-1"); e != nil {
		t.Fatal(e)
	}
	for _, scope := range [][4]string{{"missing", "tenant-a", "111122223333", "eu-west-1"}, {"ireland-read", "tenant-b", "111122223333", "eu-west-1"}, {"ireland-read", "tenant-a", "999988887777", "eu-west-1"}, {"ireland-read", "tenant-a", "111122223333", "us-east-1"}} {
		if _, e = ResolveAWSAccountReadBinding(string(secret), scope[0], scope[1], scope[2], scope[3]); e == nil {
			t.Fatal("binding scope confusion accepted")
		}
	}
}
