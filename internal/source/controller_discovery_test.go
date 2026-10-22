package source

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestControllerDiscoveryPrivateBindingsDefaultOffAndBounded(t *testing.T) {
	if bindings, err := ControllerDiscoveryBindings(""); err != nil || len(bindings) != 0 {
		t.Fatal("optional capture did not default off")
	}
	target := ControllerDiscoveryTarget{SourceID: "source-native", Binding: ControllerDiscoveryBinding{TenantID: "tenant-one", WorkloadID: "workload-one", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1"}, ResourceIDs: []string{"resource-one", "resource-two"}}
	for _, name := range []string{"valid", "duplicate_resource", "empty_roster", "foreign_provider", "wrong_region", "bad_account", "unknown_field"} {
		t.Run(name, func(t *testing.T) {
			value := target
			value.ResourceIDs = append([]string{}, target.ResourceIDs...)
			switch name {
			case "duplicate_resource":
				value.ResourceIDs[1] = value.ResourceIDs[0]
			case "empty_roster":
				value.ResourceIDs = nil
			case "foreign_provider":
				value.Binding.Provider = "GCP"
			case "wrong_region":
				value.Binding.Region = "us-east-1"
			case "bad_account":
				value.Binding.AccountID = "bad"
			}
			body, _ := json.Marshal(map[string]ControllerDiscoveryTarget{"binding-one": value})
			if name == "unknown_field" {
				body = []byte(`{"binding-one":{"complete":true}}`)
			}
			_, err := ControllerDiscoveryBindings(string(body))
			if (err == nil) != (name == "valid") {
				t.Fatal("private source binding validation differs", name)
			}
		})
	}
}

func TestControllerDiscoveryNoConfiguredAuthorityDoesNotDispatch(t *testing.T) {
	var pipeline *ControllerDiscoveryPipeline
	if value, err := pipeline.Capture(context.Background(), "tenant-one", "binding-one"); err == nil || value != nil {
		t.Fatal("missing private dependencies acquired source authority")
	}
}

func TestControllerDiscoveryPersistencePreservesBigintRosterPins(t *testing.T) {
	// Above float64's exact integer range and at the PostgreSQL bigint maximum.
	// These are persisted roster/source versions, not a floating point metric.
	for _, version := range []json.Number{"9007199254740993", "9223372036854775807"} {
		t.Run(string(version), func(t *testing.T) {
			roster := []model.Document{{"id": "resource-one", "version": version, "provider_resource_id": "i-0123456789abcdef0"}}
			input := model.Document{"id": "receipt-one", "source_id": "source-one", "registration_version": version, "roster_snapshot": roster, "roster_sha256": Hash(roster)}
			raw, err := controllerDiscoveryEncode(input, "tenant-one")
			if err != nil {
				t.Fatal(err)
			}
			stored, err := controllerDiscoveryDecode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if stored["registration_version"] != version || Hash(stored["roster_snapshot"]) != input["roster_sha256"] || model.String(stored, "tenant_id") != "tenant-one" {
				t.Fatal("persisted integer version changed immutable roster/source pins")
			}
			if _, exists := input["tenant_id"]; exists {
				t.Fatal("persistence mutated caller evidence")
			}
		})
	}
	for _, raw := range []string{"null", "[]", "{} {}", "{} trailing"} {
		if _, err := controllerDiscoveryDecode([]byte(raw)); err == nil {
			t.Fatal("malformed stored document accepted")
		}
	}
}
