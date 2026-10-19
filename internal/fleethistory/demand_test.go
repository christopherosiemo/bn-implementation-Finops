package fleethistory

import (
	"testing"
	"time"
)

func cumulativeInput() Input {
	in := testInput()
	in.Definition.Temporality = "CUMULATIVE"
	in.Definition.SourceSystem = "NATIVE_TELEMETRY_CONNECTION"
	in.Definition.SourceRegistrationVersion = ptr(int64(1))
	in.Definition.ValueField = "NATIVE_MONOTONIC_COUNT"
	in.Sources[1].SourceSystem = in.Definition.SourceSystem
	in.Sources[1].SourceRegistrationVersion = in.Definition.SourceRegistrationVersion
	in.Demand = nil
	for i, value := range []string{"100", "150", "200"} {
		at := in.Start.Add(time.Duration(i) * time.Minute)
		in.Demand = append(in.Demand, DemandSample{SchemaVersion: SchemaVersion, ID: "counter-" + at.Format("150405"), DefinitionID: in.Definition.ID, DefinitionVersion: in.Definition.Version, DefinitionHash: DefinitionHash(in.Definition), MetricDefinitionID: in.Definition.MetricDefinitionID, MetricDefinitionVersion: in.Definition.MetricDefinitionVersion, Start: in.Start.Add(-24 * time.Hour), Time: at, Epoch: ptr(in.Start.Add(-24 * time.Hour)), ReceivedAt: at.Add(2 * time.Second), Value: ptr(value), Source: testRef(in, "INDEPENDENT_COMPLETED_WORK", in.Definition.SourceID, in.Registration.Binding.WorkloadID, at)})
	}
	return in
}
func TestDemandObservedZeroMissingAndLargeCountsStayDistinct(t *testing.T) {
	in := testInput()
	for i := range in.Demand {
		in.Demand[i].Value = ptr("0")
	}
	out := analyze(t, in).Demand
	if out.Status != "OBSERVED" || out.WindowUnits == nil || *out.WindowUnits != "0" {
		t.Fatalf("observed zero lost: %+v", out)
	}
	in.Demand[0].Value = nil
	out = analyze(t, in).Demand
	if out.Status != "UNKNOWN" || out.WindowUnits != nil || len(out.Gaps) == 0 {
		t.Fatal("missing became zero")
	}
	in = testInput()
	in.Demand[0].Value = ptr("18446744073709551615")
	in.Demand[1].Value = ptr("1")
	out = analyze(t, in).Demand
	if out.WindowUnits == nil || *out.WindowUnits != "18446744073709551616" {
		t.Fatal("native count overflowed/rounded")
	}
	for _, value := range []string{"NaN", "1.5", "-1", "1e3", "00"} {
		in = testInput()
		in.Demand[0].Value = ptr(value)
		out = analyze(t, in).Demand
		if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_INTEGER_COUNT_INVALID") {
			t.Fatalf("invalid native count accepted %s", value)
		}
	}
}
func TestCumulativeCountsUseRealEpochAndNativeBounds(t *testing.T) {
	in := cumulativeInput()
	out := analyze(t, in).Demand
	if out.WindowUnits == nil || *out.WindowUnits != "100" || len(out.Segments) != 2 {
		t.Fatalf("native cumulative delta wrong %+v", out)
	}
	in.Demand[1].Value = ptr("50")
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_COUNTER_RESET_UNKNOWN") {
		t.Fatal("counter reset assumed zero")
	}
	in = cumulativeInput()
	in.Demand[1].Epoch = ptr(in.Start.Add(30 * time.Second))
	in.Demand[1].Start = *in.Demand[1].Epoch
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_COUNTER_EPOCH_CHANGED") {
		t.Fatal("epoch transition bridged")
	}
	in = cumulativeInput()
	in.Demand[1].Value = nil
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || out.ObservedUnits != nil {
		t.Fatal("missing middle observation bridged")
	}
	in = cumulativeInput()
	in.Start = in.Start.Add(30 * time.Second)
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_WINDOW_BOUNDARY_NOT_OBSERVED") {
		t.Fatal("native counter interval prorated")
	}
}
func TestDemandConflictsCorrectionsAndOverlapCannotDoubleCount(t *testing.T) {
	in := testInput()
	duplicate := clone(in.Demand[0])
	duplicate.ID = "duplicate"
	duplicate.Source.ReceiptID = "another-raw-receipt"
	in.Demand = append(in.Demand, duplicate)
	if got := analyze(t, in).Demand; got.WindowUnits == nil || *got.WindowUnits != "20" {
		t.Fatal("identical native point duplicated")
	}
	in.Demand[len(in.Demand)-1].Value = ptr("11")
	out := analyze(t, in).Demand
	if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_NATIVE_POINT_CONFLICT") {
		t.Fatal("native conflicting point combined")
	}
	in = testInput()
	correction := clone(in.Demand[0])
	correction.ID = "correction"
	correction.CorrectsID = in.Demand[0].ID
	correction.ReceivedAt = correction.ReceivedAt.Add(time.Second)
	correction.Source.CapturedAt = correction.ReceivedAt
	correction.Source.ReceiptID = "corrected"
	correction.Value = ptr("5")
	in.Demand = append(in.Demand, correction)
	out = analyze(t, in).Demand
	if out.WindowUnits == nil || *out.WindowUnits != "15" {
		t.Fatalf("superseded demand counted %+v", out)
	}
	in = testInput()
	in.Demand[1].Start = in.Demand[1].Start.Add(-30 * time.Second)
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_INTERVAL_OVERLAP") {
		t.Fatal("overlapping totals added")
	}
	in = testInput()
	in.Demand = in.Demand[1:]
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || len(out.Gaps) == 0 {
		t.Fatal("missing first interval hidden")
	}
}
func TestRawThroughputAndUnsupportedPartitionsDoNotBecomeBusinessWork(t *testing.T) {
	for name, change := range map[string]func(*DemandDefinition){"throughput-proxy": func(d *DemandDefinition) { d.Metric = "request_count"; d.Meaning = "REQUEST_THROUGHPUT_PROXY" }, "no-meaning-contract": func(d *DemandDefinition) { d.SemanticContractHash = "" }, "replica-local": func(d *DemandDefinition) { d.Origin = "PER_INSTANCE" }, "partition-sum": func(d *DemandDefinition) { d.Aggregation = "SUM" }, "gauge": func(d *DemandDefinition) { d.Temporality = "GAUGE" }} {
		t.Run(name, func(t *testing.T) {
			in := testInput()
			change(&in.Definition)
			out := analyze(t, in).Demand
			if out.Status != "UNKNOWN" || out.WindowUnits != nil {
				t.Fatal("unsupported demand acquired meaning")
			}
		})
	}
	in := testInput()
	in.Demand[0].Partition = "replica-a"
	out := analyze(t, in).Demand
	if out.WindowUnits != nil || !has(out.ReasonCodes, "DEMAND_PARTITIONS_UNSUPPORTED") {
		t.Fatal("partitioned count accepted")
	}
	in = testInput()
	in.Sources[1].Status = "REVOKED"
	out = analyze(t, in).Demand
	if out.WindowUnits != nil || out.ObservedUnits != nil {
		t.Fatal("revoked source supplied counts")
	}
}
