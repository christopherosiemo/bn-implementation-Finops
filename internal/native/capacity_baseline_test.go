package native

import (
	"encoding/json"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func TestCapacityCurrentBaselineUsesObservedOptionsAndDoesNotBecomeCandidate(t *testing.T) {
	p, profile, hardware := capacityModelFixture(t)
	var evidence provider.HardwareEvidence
	raw, _ := json.Marshal(hardware["native"])
	if json.Unmarshal(raw, &evidence) != nil {
		t.Fatal("native fixture invalid")
	}
	hardware["candidate_types"] = []string{evidence.Instance.Type}
	ordinary, err := BuildCapacityModelInput(p, profile, hardware)
	if err != nil || ordinary.Request != nil {
		t.Fatal("ordinary candidate mapper accepted unchanged type", err)
	}
	baseline, err := BuildCurrentCapacityModelInput(p, profile, hardware)
	if err != nil || baseline.Request == nil || len(baseline.Request.Candidates) != 1 {
		t.Fatal("observed current baseline unavailable", err, baseline.ReasonCodes)
	}
	if telemetry.Hash(baseline.Request.Current) != telemetry.Hash(baseline.Request.Candidates[0]) || *baseline.Request.Candidates[0].Capacity.CPU != "2.000000000000" {
		t.Fatal("baseline replaced observed CPU options with type defaults")
	}
	if baseline.Request.Current.Pricing != nil || baseline.Request.Candidates[0].CommitmentCompatible != nil {
		t.Fatal("baseline manufactured financial evidence")
	}
	hardware["candidate_types"] = []string{"different.type"}
	unavailable, err := BuildCurrentCapacityModelInput(p, profile, hardware)
	if err != nil || unavailable.Request != nil {
		t.Fatal("baseline accepted a hypothetical replacement", err)
	}
}

func TestCapacityCurrentBaselineCannotInferMissingMemoryFromCPU(t *testing.T) {
	p, profile, hardware := capacityModelFixture(t)
	var evidence provider.HardwareEvidence
	raw, _ := json.Marshal(hardware["native"])
	if json.Unmarshal(raw, &evidence) != nil {
		t.Fatal("native fixture invalid")
	}
	hardware["candidate_types"] = []string{evidence.Instance.Type}
	for i := range p.Segments {
		if p.Segments[i].Metric == "memory_utilization" {
			p.Segments[i].Status = "UNKNOWN"
			p.Segments[i].Value = ""
		}
	}
	p.PopulationHash = CapacityPopulationHash(p)
	baseline, err := BuildCurrentCapacityModelInput(p, profile, hardware)
	if err != nil || baseline.Request == nil {
		t.Fatal("unknown memory intervals were not preserved for the model", err)
	}
	memory := mappingMetric(baseline.Request, "memory")
	if len(memory.Points) == 0 {
		t.Fatal("missing memory intervals disappeared")
	}
	for _, point := range memory.Points {
		if point.Value != nil {
			t.Fatal("unknown memory was inferred from CPU")
		}
	}
	for i, definition := range p.Definitions {
		if definition.Metric == "memory_utilization" {
			p.Definitions = append(p.Definitions[:i], p.Definitions[i+1:]...)
			break
		}
	}
	p.PopulationHash = CapacityPopulationHash(p)
	missing, err := BuildCurrentCapacityModelInput(p, profile, hardware)
	if err != nil || missing.Request != nil || len(missing.ReasonCodes) == 0 {
		t.Fatal("missing memory definition became a baseline", err)
	}
}
