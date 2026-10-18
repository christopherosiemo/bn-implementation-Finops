package native

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

func capacityModelFixture(t *testing.T) (CapacityPopulation, workload.Profile, model.Document) {
	t.Helper()
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	binding := telemetry.Binding{TenantID: "capacity-native-test", WorkloadID: "workload", ResourceID: "resource", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}
	profile := workload.Profile{SchemaVersion: "1", ID: "profile", WorkloadID: binding.WorkloadID, Version: 1, Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	raw, err := os.ReadFile("../provider/testdata/hardware_capture.bin")
	if err != nil {
		t.Fatal(err)
	}
	e, err := provider.ParseHardwareEvidence(raw, binding.AccountID, binding.Region, binding.ProviderResourceID, []string{"m6i.large"}, now)
	if err != nil {
		t.Fatal(err)
	}
	hardware := model.Document{"id": "hardware-receipt", "kind": "AWS_EC2_HARDWARE", "writer_role": "finops_ingester", "registration_version": 1, "native": telemetry.Document(e), "candidate_types": []string{"m6i.large"}}
	p := CapacityPopulation{SchemaVersion: "1", Binding: binding, ConnectionID: "connection", ConnectionVersion: 1, ConfigHash: strings.Repeat("c", 64), SafetyProfileID: profile.ID, SafetyProfileVersion: profile.Version, SafetyProfileHash: workload.Hash(profile), AsOf: now, Start: start, End: end, HistoryDays: 14, Timezone: "UTC", Environment: "NON_PRODUCTION", Definitions: []telemetry.Definition{}, Segments: []telemetry.Segment{}, ReceiptIDs: []string{"telemetry-receipt"}, SourceRefs: []CapacityReceiptRef{{ReceiptID: "telemetry-receipt", BatchID: "batch", ConfigHash: strings.Repeat("c", 64), RawSHA256: strings.Repeat("a", 64), CanonicalHash: strings.Repeat("b", 64)}}, ReasonCodes: []string{}, Evaluation: telemetry.Evaluation{SchemaVersion: "1", Status: "READY", ReasonCodes: []string{}, Metrics: []telemetry.MetricResult{}}}
	values := map[string]string{"cpu_utilization": "0.2", "memory_utilization": "0.2", "cpu_capacity": "2", "memory_capacity": "17179869184", "network_in": "36000", "network_out": "36000", "disk_read_operations": "36000", "disk_write_operations": "36000", "disk_read_bytes": "36000", "disk_write_bytes": "36000", "request_count": "18000"}
	for metric, value := range values {
		kind, unit, statistic := "SUM", "bytes", "MONOTONIC_COUNTER"
		if metric == "cpu_utilization" || metric == "memory_utilization" {
			kind, unit, statistic = "GAUGE", "ratio", "OBSERVED_SAMPLE_DISTRIBUTION"
		}
		if metric == "cpu_capacity" {
			kind, unit, statistic = "GAUGE", "vCPU", "OBSERVED_SAMPLE_DISTRIBUTION"
		}
		if metric == "memory_capacity" {
			kind, unit, statistic = "GAUGE", "bytes", "OBSERVED_SAMPLE_DISTRIBUTION"
		}
		if metric == "disk_read_operations" || metric == "disk_write_operations" || metric == "request_count" {
			unit = "count"
		}
		p.Definitions = append(p.Definitions, telemetry.Definition{ID: metric, Version: "1", Metric: metric, Name: metric, Type: kind, Unit: unit, Monotonic: kind == "SUM", CadenceSeconds: 3600, MaxGapSeconds: 7200, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}})
		for at := start; at.Before(end); at = at.Add(time.Hour) {
			p.Segments = append(p.Segments, telemetry.Segment{ID: metric + at.Format(time.RFC3339), DefinitionID: metric, StreamID: metric, Metric: metric, Type: kind, Unit: unit, Statistic: statistic, Start: at, End: at.Add(time.Hour), Status: "OBSERVED", Value: value, RawHashes: []string{strings.Repeat("a", 64)}})
		}
	}
	p.PopulationHash = CapacityPopulationHash(p)
	return p, profile, hardware
}
func mappingMetric(input *CapacityModelRequest, name string) CapacityModelMetric {
	for _, metric := range input.Metrics {
		if metric.Name == name {
			return metric
		}
	}
	return CapacityModelMetric{}
}

func TestCapacityNativeMapperUsesConfiguredPhysicalDenominatorsAndActualIntervals(t *testing.T) {
	p, profile, hardware := capacityModelFixture(t)
	m, err := BuildCapacityModelInput(p, profile, hardware)
	if err != nil || m.Request == nil {
		t.Fatal("complete native fixture not mapped", err, m.ReasonCodes, m.CandidateReasons)
	}
	if *m.Current.Capacity.CPU != "2.000000000000" || *m.Current.Capacity.Memory != "17179869184.000000000000" || *m.Current.Capacity.Network != "97625000.000000000000" || *m.Current.Capacity.StorageIOPS != "3000.000000000000" || *m.Current.Capacity.StorageThroughput != "81250000.000000000000" {
		t.Fatal("configured CPU, binary memory, sustained network or bottleneck EBS units changed", m.Current.Capacity)
	}
	if m.Request.Current.Pricing != nil || m.Request.Candidates[0].Pricing != nil || m.Request.Candidates[0].CommitmentCompatible != nil || m.Request.Candidates[0].Count != 1 {
		t.Fatal("unknown money/commitment became trusted catalogue")
	}
	cpu := mappingMetric(m.Request, "cpu")
	memory := mappingMetric(m.Request, "memory")
	network := mappingMetric(m.Request, "network")
	if cpu.Statistic != "RAW_SAMPLE" || *cpu.Points[0].Value != "0.400000000000" || *memory.Points[0].Value != "3435973836.800000000000" || network.Statistic != "OBSERVED_INTERVAL_RATE" || *network.Points[0].Value != "20.000000000000" {
		t.Fatal("gauge/rate population semantics changed")
	}
	if m.Request.Policy["cpu_p95_max_ppm"] != 700000 || m.Request.Policy["cpu_p99_rollback_ppm"] != 850000 || m.Request.Policy["cpu_free_ppm"] != 300000 || m.Request.Policy["reserve_above_forecast_ppm"] != 300000 {
		t.Fatal("hard planning, rollback and explicit headroom gates were conflated")
	}
}

func TestCapacityNativeMapperKeepsUnknownAndUnsupportedEvidenceBlocked(t *testing.T) {
	for name, mutate := range map[string]func(*CapacityPopulation, model.Document){
		"classification conflict": func(p *CapacityPopulation, _ model.Document) {
			p.Environment = "PRODUCTION"
			p.ReasonCodes = []string{"CAPACITY_ENVIRONMENT_CLASSIFICATION_CONFLICT"}
		},
		"source partial rejection": func(p *CapacityPopulation, _ model.Document) {
			p.ReasonCodes = []string{"TELEMETRY_SOURCE_PARTIAL_REJECTIONS"}
		},
		"blocked history": func(p *CapacityPopulation, _ model.Document) {
			p.Evaluation.Status = "BLOCKED"
			p.Evaluation.ReasonCodes = []string{"MEMORY_OBSERVATIONS_REQUIRED"}
		},
		"peak is not baseline": func(_ *CapacityPopulation, h model.Document) {
			raw, _ := json.Marshal(h["native"])
			var e provider.HardwareEvidence
			_ = json.Unmarshal(raw, &e)
			e.Types[1].NetworkCards[0].Baseline = ""
			h["native"] = telemetry.Document(e)
		},
		"configured CPU missing": func(_ *CapacityPopulation, h model.Document) {
			raw, _ := json.Marshal(h["native"])
			var e provider.HardwareEvidence
			_ = json.Unmarshal(raw, &e)
			e.Instance.CPU.Cores = nil
			h["native"] = telemetry.Document(e)
		},
		"historical denominator changed": func(p *CapacityPopulation, _ model.Document) {
			for i := range p.Segments {
				if p.Segments[i].Metric == "cpu_capacity" {
					p.Segments[i].Value = "4"
					break
				}
			}
		},
		"memory denominator absent": func(p *CapacityPopulation, _ model.Document) {
			for i, d := range p.Definitions {
				if d.Metric == "memory_capacity" {
					p.Definitions = append(p.Definitions[:i], p.Definitions[i+1:]...)
					break
				}
			}
		},
		"unknown source hash": func(p *CapacityPopulation, _ model.Document) {
			p.Segments[0].RawHashes = []string{strings.Repeat("f", 64)}
		},
		"maximum not sampled quantiles": func(p *CapacityPopulation, _ model.Document) {
			for i := range p.Segments {
				if p.Segments[i].Metric == "cpu_utilization" {
					p.Segments[i].Statistic = "INTERVAL_MAXIMUM"
					break
				}
			}
		},
		"multiple unbound streams": func(p *CapacityPopulation, _ model.Document) {
			for i := range p.Segments {
				if p.Segments[i].Metric == "cpu_utilization" {
					p.Segments[i].StreamID = "other-stream"
					break
				}
			}
		},
		"missing tenancy": func(_ *CapacityPopulation, h model.Document) {
			raw, _ := json.Marshal(h["native"])
			var e provider.HardwareEvidence
			_ = json.Unmarshal(raw, &e)
			e.Instance.Placement.Tenancy = ""
			h["native"] = telemetry.Document(e)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, profile, h := capacityModelFixture(t)
			mutate(&p, h)
			p.PopulationHash = CapacityPopulationHash(p)
			m, err := BuildCapacityModelInput(p, profile, h)
			if err != nil || m.Request != nil || len(m.ReasonCodes) == 0 {
				t.Fatal("unknown evidence became model authority", err, m.ReasonCodes)
			}
		})
	}
}

func TestCapacityNativeMapperDoesNotFillUnalignedCounterDirectionsWithZero(t *testing.T) {
	p, profile, h := capacityModelFixture(t)
	for i := range p.Segments {
		if p.Segments[i].Metric == "network_out" {
			p.Segments[i].Start = p.Segments[i].Start.Add(time.Second)
			break
		}
	}
	p.PopulationHash = CapacityPopulationHash(p)
	m, err := BuildCapacityModelInput(p, profile, h)
	if err != nil || m.Request == nil {
		t.Fatal(err, m.ReasonCodes)
	}
	stream := mappingMetric(m.Request, "network")
	unknown := 0
	for _, point := range stream.Points {
		if point.Value == nil {
			unknown++
		}
	}
	if unknown != 2 {
		t.Fatal("unmatched native intervals were fabricated as zero", unknown)
	}
}
