package workflow

import (
	"context"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
)

func TestFleetHistoryRuntimeRequiresExplicitTenantBoundTargets(t *testing.T) {
	valid := `[{"tenant_id":"tenant-a","registration_id":"history-a"}]`
	if targets, err := fleetHistoryTargets(valid, "tenant-a", false); err != nil || len(targets) != 1 {
		t.Fatal("commissioned registration rejected", err)
	}
	for _, raw := range []string{"", "[]", "null", valid + " {}", strings.Replace(valid, "tenant-a", "tenant-b", 1), strings.Replace(valid, "history-a", "../other", 1), strings.Replace(valid, `"registration_id"`, `"trusted":true,"registration_id"`, 1), `[{"tenant_id":"tenant-a","registration_id":"history-a"},{"tenant_id":"tenant-a","registration_id":"history-a"}]`} {
		if _, err := fleetHistoryTargets(raw, "tenant-a", false); err == nil {
			t.Fatal("uncommissioned or credential-bearing target accepted")
		}
	}
	if _, err := fleetHistoryTargets(valid, "tenant-a", true); err == nil || err.Error() != "HISTORY_NATIVE_READ_DISABLED_IN_FIXTURE_MODE" {
		t.Fatal("fixture mode reached live AWS transport")
	}
	if _, err := fleetHistoryTargets(valid, "", false); err == nil {
		t.Fatal("native reader lacks explicit commissioned tenant")
	}
}

func TestFleetHistoryRuntimeRejectsStaticIdentityAndNonIrishStorageBeforeNetwork(t *testing.T) {
	t.Setenv("AWS_TENANT_ID", "tenant-a")
	t.Setenv("AWS_FLEET_HISTORY_REGISTRATIONS_JSON", `[{"tenant_id":"tenant-a","registration_id":"history-a"}]`)
	for _, key := range []string{"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		t.Setenv(key, "")
	}
	if err := RunFleetHistoryReader(context.Background(), service.Config{}, nil); err == nil || err.Error() != "HISTORY_RENEWABLE_WORKLOAD_IDENTITY_REQUIRED" {
		t.Fatal("reader reached network without renewable identity")
	}
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::111122223333:role/read-only-fixture")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/unopened-fixture-token")
	for _, key := range []string{"OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		t.Setenv(key, "fixture-static-material")
		if err := RunFleetHistoryReader(context.Background(), service.Config{}, nil); err == nil || err.Error() != "HISTORY_RENEWABLE_WORKLOAD_IDENTITY_REQUIRED" {
			t.Fatal("static credentials bypassed renewable reader identity")
		}
		t.Setenv(key, "")
	}
	for _, endpoint := range []string{"http://s3.eu-west-1.amazonaws.com", "https://s3.us-east-1.amazonaws.com", "https://s3.eu-west-1.amazonaws.com.evil.invalid", "https://user@s3.eu-west-1.amazonaws.com"} {
		t.Setenv("OBJECT_ENDPOINT", endpoint)
		if err := RunFleetHistoryReader(context.Background(), service.Config{}, nil); err == nil || err.Error() != "HISTORY_IRELAND_STORAGE_ENDPOINT_REQUIRED" {
			t.Fatal("foreign or unverified object storage reached network")
		}
	}
}
