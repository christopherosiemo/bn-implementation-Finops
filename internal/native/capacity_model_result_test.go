package native

import (
	"encoding/json"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func proxyResultFixture(version string) (CapacityModelRequest, CapacityModelResult) {
	metric := CapacityModelMetric{Name: "demand", Unit: "work_unit/second", Statistic: "OBSERVED_INTERVAL_RATE"}
	if version == CapacityProxyModelVersion {
		metric.Unit, metric.SemanticRole, metric.SourceMetric, metric.SourceUnit = "requests/second", CapacityRequestProxyRole, "request_count", "requests"
	}
	input := CapacityModelRequest{ModelVersion: version, Metrics: []CapacityModelMetric{metric}, Candidates: []CapacityModelCatalog{}, ForecastHorizons: []string{"7_day"}}
	summary := model.Document{"name": metric.Name, "unit": metric.Unit, "statistic": metric.Statistic}
	forecast := model.Document{}
	if version == CapacityProxyModelVersion {
		for k, v := range map[string]string{"semantic_role": metric.SemanticRole, "source_metric": metric.SourceMetric, "source_unit": metric.SourceUnit} {
			summary[k], forecast[k] = v, v
		}
		forecast["unit"] = metric.Unit
	}
	return input, CapacityModelResult{SchemaVersion: "4", ModelVersion: version, Status: "BLOCKED", History: model.Document{}, Metrics: []model.Document{summary}, Forecasts: []model.Document{{"horizon": "7_day", "metrics": model.Document{"demand": forecast}}}, Candidates: []CapacityModelCandidate{}, EvidenceRefs: []CapacityModelRef{{}}, ModelAssumptions: []string{}, ReasonCodes: []string{}}
}

func encodedCapacityResult(t *testing.T, result CapacityModelResult) []byte {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	result.AssessmentHash, err = CapacityModelBodyHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCapacityResultBindsProxyVersionAndNativeUnits(t *testing.T) {
	for _, version := range []string{"capacity-weekday-block-v1", CapacityProxyModelVersion} {
		input, result := proxyResultFixture(version)
		if _, err := DecodeCapacityModelResult(encodedCapacityResult(t, result), input); err != nil {
			t.Fatal("valid matching version rejected", version, err)
		}
	}
	legacy, old := proxyResultFixture("capacity-weekday-block-v1")
	legacy.ModelVersion = ""
	if _, err := DecodeCapacityModelResult(encodedCapacityResult(t, old), legacy); err != nil {
		t.Fatal("original unversioned request is no longer readable", err)
	}
	for name, mutate := range map[string]func(*CapacityModelResult){
		"downgrade":            func(r *CapacityModelResult) { r.ModelVersion = "capacity-weekday-block-v1" },
		"missing semantics":    func(r *CapacityModelResult) { delete(r.Metrics[0], "semantic_role") },
		"business work":        func(r *CapacityModelResult) { r.Metrics[0]["semantic_role"] = "COMPLETED_WORK" },
		"wrong native unit":    func(r *CapacityModelResult) { r.Metrics[0]["source_unit"] = "count" },
		"generic work units":   func(r *CapacityModelResult) { r.Metrics[0]["unit"] = "work_unit/second" },
		"missing forecast":     func(r *CapacityModelResult) { r.Forecasts = []model.Document{} },
		"unrequested forecast": func(r *CapacityModelResult) { r.Forecasts[0]["horizon"] = "annual" },
		"forecast promoted": func(r *CapacityModelResult) {
			metrics := telemetry.Document(r.Forecasts[0]["metrics"])
			metric := telemetry.Document(metrics["demand"])
			metric["semantic_role"] = "COMPLETED_WORK"
			metrics["demand"], r.Forecasts[0]["metrics"] = metric, metrics
		},
		"forecast units changed": func(r *CapacityModelResult) {
			metrics := telemetry.Document(r.Forecasts[0]["metrics"])
			metric := telemetry.Document(metrics["demand"])
			metric["unit"] = "count/second"
			metrics["demand"], r.Forecasts[0]["metrics"] = metric, metrics
		},
	} {
		t.Run(name, func(t *testing.T) {
			input, result := proxyResultFixture(CapacityProxyModelVersion)
			mutate(&result)
			if _, err := DecodeCapacityModelResult(encodedCapacityResult(t, result), input); err == nil {
				t.Fatal("rehashed semantic mismatch accepted")
			}
		})
	}
	input, result := proxyResultFixture("capacity-weekday-block-v1")
	result.ModelVersion = CapacityProxyModelVersion
	if _, err := DecodeCapacityModelResult(encodedCapacityResult(t, result), input); err == nil {
		t.Fatal("legacy result was silently upgraded")
	}
}
