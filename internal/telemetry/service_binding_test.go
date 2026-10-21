package telemetry

import "testing"

func TestHistoricalServiceConnectionAcceptsOnlyExactStableNativeARN(t *testing.T) {
	c := Connection{SchemaVersion: "1", ID: "registered", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "approved", Enabled: true, Binding: Binding{TenantID: "tenant", ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "arn:aws:ecs:eu-west-1:111122223333:service/orders/2-web", AccountID: "111122223333", Region: "eu-west-1"}, Definitions: []Definition{{ID: "config", Version: "1", Metric: "ECSServiceConfiguration", Name: "service_configuration", Unit: "Count", Type: "GAUGE", CadenceSeconds: 300, MaxGapSeconds: 300}}}
	if err := ValidateConnection(c); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"arn:aws:ecs:eu-west-1:444455556666:service/orders/web", "arn:aws:ecs:us-east-1:111122223333:service/orders/web", "arn:aws:ecs:eu-west-1:111122223333:task/orders/id", "arn:aws:ecs:eu-west-1:111122223333:service/web", "arn:aws:ecs:eu-west-1:111122223333:service/orders/*"} {
		wrong := c
		wrong.Binding.ProviderResourceID = id
		if ValidateConnection(wrong) == nil {
			t.Fatal("confused or ephemeral service binding accepted", id)
		}
	}
	c.Kind, c.Issuer, c.Subject = "OTLP", "https://machine.example", "collector"
	if ValidateConnection(c) == nil {
		t.Fatal("historical reader widened current OTLP contract")
	}
}
