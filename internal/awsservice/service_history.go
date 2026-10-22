package awsservice

import (
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

const ServiceHistoryVersion = "ECS_SERVICE_HISTORY_V1"

// ServiceHistoryFromBatch selects a previously archived native historical
// reader batch. It never writes guarded activity receipts. Configuration is
// evidenced at the actual sample cadence, not asserted to be a continuous AWS
// change log. Only a complete compatible sampled epoch may support this bounded
// rightsizing path; replacement tasks need no invented historical membership.
func ServiceHistoryFromBatch(c telemetry.Connection, b telemetry.Batch, start, end time.Time, current model.Document, sourceRef model.Document) (model.Document, []model.Document, error) {
	if telemetry.ValidateConnection(c) != nil || c.Kind != "PROMETHEUS" || !c.Enabled || b.Binding != c.Binding || b.ConnectionID != c.ID || b.ConfigHash != telemetry.ConfigHash(c) || b.SourceKind != c.Kind || len(b.Samples) > telemetry.MaxSamples || !end.After(start) || end.Sub(start) > 90*24*time.Hour || start.UTC().Truncate(24*time.Hour) != start || end.UTC().Truncate(24*time.Hour) != end || len(model.String(sourceRef, "sha256")) != 64 || model.String(sourceRef, "id") == "" || len(b.Rejections) != 0 || len(b.Warnings) != 0 {
		return nil, nil, ErrEvidence
	}
	const cadence = 300 * time.Second
	history := model.Document{"schema_version": ServiceHistoryVersion, "binding": telemetry.Document(c.Binding), "source_refs": []model.Document{sourceRef}, "epochs": []model.Document{}, "reason_codes": []string{}, "semantics": "SAMPLED_CONFIGURATION_NOT_CONTINUOUS_CHANGE_LOG", "cadence_seconds": 300}
	reasons := map[string]bool{}
	definitions := map[string]telemetry.Definition{}
	for _, d := range c.Definitions {
		definitions[d.ID] = d
	}
	byMetric := map[string]map[time.Time]telemetry.Sample{}
	for _, s := range b.Samples {
		if s.Time.Before(start) || s.Time.After(end) {
			continue
		}
		d, ok := definitions[s.DefinitionID]
		if !ok || d.Metric != s.Metric || d.CadenceSeconds != 300 || d.MaxGapSeconds != 300 || s.Time.Sub(start)%cadence != 0 || len(s.ReasonCodes) != 0 || s.RawSHA256 != b.RawSHA256 {
			return nil, nil, ErrEvidence
		}
		if s.Metric != "ECSServiceConfiguration" && !Contains([]string{"AcceptedWork", "CompletedWork", "RejectedWork", "Backlog", "InFlightWork"}, s.Metric) {
			continue
		}
		if byMetric[s.Metric] == nil {
			byMetric[s.Metric] = map[time.Time]telemetry.Sample{}
		}
		if _, exists := byMetric[s.Metric][s.Time]; exists {
			return nil, nil, ErrEvidence
		}
		byMetric[s.Metric][s.Time] = s
	}
	configKeys := []string{"cluster_arn", "service_arn", "task_definition_arn", "cpu_units", "memory_mib", "desired_count", "running_count", "launch_type", "capacity_provider", "architecture", "deployment_id"}
	definition := Document(current["task_definition"])
	runtime := Document(definition["runtimePlatform"])
	expected := map[string]string{"cluster_arn": model.String(current, "clusterArn"), "service_arn": c.Binding.ProviderResourceID, "task_definition_arn": model.String(current, "taskDefinition"), "cpu_units": model.String(definition, "cpu"), "memory_mib": model.String(definition, "memory"), "desired_count": strconv.FormatInt(model.Number(current, "desiredCount"), 10), "running_count": strconv.FormatInt(model.Number(current, "runningCount"), 10), "launch_type": model.String(current, "launchType"), "architecture": model.String(runtime, "cpuArchitecture")}
	epochs := []model.Document{}
	lastHash := ""
	for at := start; at.Before(end); at = at.Add(cadence) {
		s, ok := byMetric["ECSServiceConfiguration"][at]
		if !ok {
			reasons["INSUFFICIENT_HISTORICAL_DEMAND"] = true
			lastHash = ""
			continue
		}
		if s.Type != "GAUGE" || s.Statistic != "SAMPLED_VALUE" || s.Unit != "Count" || s.Value != "1" {
			return nil, nil, ErrEvidence
		}
		config := model.Document{}
		for _, key := range configKeys {
			value := s.Attributes[key]
			if value == "" || len(value) > 2048 {
				return nil, nil, ErrEvidence
			}
			config[key] = value
			if want, known := expected[key]; known && (want == "" || value != want) {
				reasons["CONFIGURATION_EPOCH_CHANGED"] = true
			}
		}
		if current["launchType"] == "FARGATE" && config["capacity_provider"] != "FARGATE" {
			reasons["CONFIGURATION_EPOCH_CHANGED"] = true
		}
		// Match the native deployment ID independently when AWS supplied it.
		deployments := Rows(current["deployments"])
		if len(deployments) != 1 || model.String(deployments[0], "id") == "" || config["deployment_id"] != deployments[0]["id"] {
			reasons["CONFIGURATION_EPOCH_CHANGED"] = true
		}
		hash := Hash(config)
		if hash == lastHash && len(epochs) > 0 {
			epochs[len(epochs)-1]["end"] = at.Add(cadence).Format(time.RFC3339Nano)
		} else {
			epoch := Document(config)
			for _, key := range []string{"desired_count", "running_count"} {
				n, err := strconv.ParseInt(model.String(config, key), 10, 64)
				if err != nil || n < 0 {
					return nil, nil, ErrEvidence
				}
				epoch[key] = n
			}
			epoch["id"], epoch["configuration_hash"] = "ecs-service-epoch-"+Hash(model.Document{"configuration": config, "start": at}), hash
			epoch["start"], epoch["end"] = at.Format(time.RFC3339Nano), at.Add(cadence).Format(time.RFC3339Nano)
			epoch["source_ref"], epoch["observation_semantics"] = sourceRef, "SAMPLED_CONFIGURATION_NOT_CONTINUOUS_CHANGE_LOG"
			epochs = append(epochs, epoch)
			if len(epochs) > 256 {
				return nil, nil, ErrEvidence
			}
		}
		lastHash = hash
	}
	if len(epochs) != 1 {
		reasons["CONFIGURATION_EPOCH_CHANGED"] = true
	}
	activity := []model.Document{}
	for _, metric := range []string{"AcceptedWork", "CompletedWork", "RejectedWork", "Backlog", "InFlightWork"} {
		for at := start; at.Before(end); at = at.Add(cadence) {
			s, ok := byMetric[metric][at]
			if !ok || s.Unit != "Count" {
				reasons["INSUFFICIENT_HISTORICAL_DEMAND"] = true
				continue
			}
			value, valid := new(big.Rat).SetString(s.Value)
			if !valid || value.Sign() < 0 {
				return nil, nil, ErrEvidence
			}
			statistic, semantics := "SAMPLED_VALUE", "OBSERVED_INSTANT_GAUGE_NOT_PERIOD_MAXIMUM"
			if Contains([]string{"AcceptedWork", "CompletedWork", "RejectedWork"}, metric) {
				next, found := byMetric[metric][at.Add(cadence)]
				if !found || s.Type != "SUM" || next.Type != "SUM" || s.Statistic != "MONOTONIC_COUNTER" || next.Statistic != "MONOTONIC_COUNTER" || s.Temporality != "CUMULATIVE" || next.Temporality != "CUMULATIVE" || s.Epoch == "" || next.Epoch != s.Epoch || next.StreamID != s.StreamID || next.Unit != s.Unit {
					reasons["INSUFFICIENT_HISTORICAL_DEMAND"] = true
					continue
				}
				n, valid := new(big.Rat).SetString(next.Value)
				if !valid || !value.IsInt() || !n.IsInt() || n.Cmp(value) < 0 {
					reasons["INSUFFICIENT_HISTORICAL_DEMAND"] = true
					continue
				}
				value = new(big.Rat).Sub(n, value)
				statistic, semantics = "Sum", "OBSERVED_CUMULATIVE_ENDPOINT_DIFFERENCE_NOT_EXTRAPOLATED"
			} else if s.Type != "GAUGE" || s.Statistic != "SAMPLED_VALUE" {
				return nil, nil, ErrEvidence
			}
			activity = append(activity, model.Document{"metric": metric, "statistic": statistic, "unit": s.Unit, "value": value.FloatString(12), "native_value": s.Value, "source_time": at.Format(time.RFC3339Nano), "period_seconds": 300, "sample_count": "1", "provider_resource_id": c.Binding.ProviderResourceID, "dimensions": s.Attributes, "source_resolution": semantics, "counter_epoch": s.Epoch, "source_ref": sourceRef})
		}
	}
	keys := []string{}
	for key := range reasons {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	history["epochs"], history["reason_codes"] = epochs, keys
	history["population_hash"] = Hash(model.Document{"epochs": epochs, "activity": activity})
	return history, activity, nil
}
