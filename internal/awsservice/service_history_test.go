package awsservice

import (
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func serviceHistoryFixture() (telemetry.Connection, telemetry.Batch, time.Time, time.Time, model.Document, model.Document) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	c := telemetry.Connection{SchemaVersion: "1", ID: "service-history", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "registered-service", Enabled: true, Binding: telemetry.Binding{TenantID: "tenant", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "arn:aws:ecs:eu-west-1:111122223333:service/orders/web", ResourceID: "resource", WorkloadID: "workload"}}
	definition := "arn:aws:ecs:eu-west-1:111122223333:task-definition/orders:7"
	config := model.Document{"clusterArn": "arn:aws:ecs:eu-west-1:111122223333:cluster/orders", "serviceName": "web", "taskDefinition": definition, "desiredCount": 2, "runningCount": 2, "launchType": "FARGATE", "deployments": []model.Document{{"id": "ecs-svc/7", "taskDefinition": definition, "rolloutState": "COMPLETED"}}, "task_definition": model.Document{"cpu": "1024", "memory": "2048", "runtimePlatform": model.Document{"cpuArchitecture": "X86_64"}}}
	labels := map[string]string{"cluster_arn": model.String(config, "clusterArn"), "service_arn": c.Binding.ProviderResourceID, "task_definition_arn": definition, "cpu_units": "1024", "memory_mib": "2048", "desired_count": "2", "running_count": "2", "launch_type": "FARGATE", "capacity_provider": "FARGATE", "architecture": "X86_64", "deployment_id": "ecs-svc/7"}
	b := telemetry.Batch{SchemaVersion: "1", ConnectionID: c.ID, Binding: c.Binding, SourceKind: c.Kind, RawSHA256: strings.Repeat("b", 64), Start: start, End: end}
	for _, metric := range []string{"ECSServiceConfiguration", "AcceptedWork", "CompletedWork", "RejectedWork", "Backlog", "InFlightWork"} {
		kind := "GAUGE"
		if Contains([]string{"AcceptedWork", "CompletedWork", "RejectedWork"}, metric) {
			kind = "SUM"
		}
		d := telemetry.Definition{ID: metric, Version: "1", Metric: metric, Name: metric, Unit: "Count", Type: kind, Monotonic: kind == "SUM", CadenceSeconds: 300, MaxGapSeconds: 300, EpochMetric: "process_start_time_seconds"}
		c.Definitions = append(c.Definitions, d)
		for at := start; !at.After(end); at = at.Add(5 * time.Minute) {
			s := telemetry.Sample{DefinitionID: metric, StreamID: metric, Metric: metric, Unit: "Count", Time: at, Value: "0", Type: kind, Attributes: labels, Statistic: "SAMPLED_VALUE", RawSHA256: b.RawSHA256}
			if kind == "SUM" {
				s.Statistic, s.Temporality, s.Epoch = "MONOTONIC_COUNTER", "CUMULATIVE", "native-process-epoch"
			} else if metric == "ECSServiceConfiguration" {
				s.Value = "1"
			}
			b.Samples = append(b.Samples, s)
		}
	}
	b.ConfigHash = telemetry.ConfigHash(c)
	return c, b, start, end, config, model.Document{"kind": "AWS_SERVICE_HISTORICAL_DEMAND_RECEIPT", "id": "receipt", "version": "1", "sha256": strings.Repeat("a", 64)}
}

func TestServiceHistoricalDemandPreservesObservedZeroAndSampledEpoch(t *testing.T) {
	c, b, start, end, config, ref := serviceHistoryFixture()
	h, activity, err := ServiceHistoryFromBatch(c, b, start, end, config, ref)
	if err != nil || len(model.Strings(h, "reason_codes")) != 0 || len(Rows(h["epochs"])) != 1 || len(activity) != 5*288 || h["semantics"] != "SAMPLED_CONFIGURATION_NOT_CONTINUOUS_CHANGE_LOG" {
		t.Fatal("complete sampled epoch and genuine zero should be retained", err, h["reason_codes"], len(activity))
	}
	for _, row := range activity {
		if row["value"] != "0.000000000000" || row["metric"] == "Backlog" && row["statistic"] != "SAMPLED_VALUE" {
			t.Fatal("gauge semantics or explicit zero lost")
		}
	}
}

func TestServiceHistoricalDemandRejectsGapResetAndConfigurationChange(t *testing.T) {
	for _, scenario := range []string{"gap", "counter reset", "changed epoch", "wrong tenant", "overlap"} {
		t.Run(scenario, func(t *testing.T) {
			c, b, start, end, config, ref := serviceHistoryFixture()
			switch scenario {
			case "gap":
				b.Samples = b.Samples[1:]
			case "counter reset":
				for n := range b.Samples {
					if b.Samples[n].Metric == "CompletedWork" && b.Samples[n].Time.Equal(start.Add(5*time.Minute)) {
						b.Samples[n].Epoch = "replacement-process"
					}
				}
			case "changed epoch":
				for n := range b.Samples {
					if b.Samples[n].Metric == "ECSServiceConfiguration" && b.Samples[n].Time.Equal(start) {
						attrs := map[string]string{}
						for k, v := range b.Samples[n].Attributes {
							attrs[k] = v
						}
						attrs["task_definition_arn"] += "8"
						b.Samples[n].Attributes = attrs
					}
				}
			case "wrong tenant":
				b.Binding.TenantID = "other"
			case "overlap":
				b.Samples = append(b.Samples, b.Samples[0])
			}
			h, _, err := ServiceHistoryFromBatch(c, b, start, end, config, ref)
			if err == nil && len(model.Strings(h, "reason_codes")) == 0 {
				t.Fatal("unsafe or incomplete historical demand accepted")
			}
		})
	}
}
