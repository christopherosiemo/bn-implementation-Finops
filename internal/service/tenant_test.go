package service

import "testing"

func TestLiveCredentialsCannotCrossTenantBoundary(t *testing.T) {
	t.Setenv("AWS_TENANT_ID", "")
	if ValidateAWSTenant("tenant-a") == nil {
		t.Fatal("unconfigured live tenant was allowed")
	}
	t.Setenv("AWS_TENANT_ID", "tenant-a")
	if e := ValidateAWSTenant("tenant-a"); e != nil {
		t.Fatal(e)
	}
	for _, tenant := range []string{"tenant-b", "", "tenant-a ", "Tenant-a"} {
		if ValidateAWSTenant(tenant) == nil {
			t.Fatalf("identity lent to %q", tenant)
		}
	}
}
