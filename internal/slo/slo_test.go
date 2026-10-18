package slo

import (
	"encoding/json"
	"testing"
	"time"
)

func objective() Objective {
	return Objective{SchemaVersion: "1", ID: "objective", Version: 1, WorkloadID: "workload", Limits: Limits{MaxErrorRatePPM: 10_000, MinAvailabilityPPM: 990_000, MaxP95LatencyMS: 180, MaxP99LatencyMS: 250, MinLatencySamples: 10}, EvaluationMinutes: 2, Availability: Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []Window{}}, Regression: Regression{Enabled: false, MaxPercent: 15}}
}
func input() Input {
	now := time.Date(2026, 10, 19, 20, 2, 20, 0, time.UTC)
	o := objective()
	s := Source{SchemaVersion: "1", ID: "source", TenantID: "tenant", ObjectiveID: o.ID, WorkloadID: o.WorkloadID, ResourceID: "resource", ProviderResourceID: "i-test", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.invalid", Subject: "collector", Enabled: true}
	rs := []Receipt{}
	for n := 0; n < 2; n++ {
		end := now.Truncate(time.Minute).Add(time.Duration(n-1) * time.Minute)
		i := Interval{SchemaVersion: "1", SourceID: s.ID, ObjectiveID: o.ID, WorkloadID: s.WorkloadID, ResourceID: s.ResourceID, Sequence: int64(n + 1), IntervalStart: end.Add(-time.Minute), IntervalEnd: end, RequestCount: 100, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: Histogram{Unit: "milliseconds", SampleCount: 100, Buckets: []Bucket{{ptr(99), 0}, {ptr(100), 100}, {ptr(180), 0}, {ptr(250), 0}, {nil, 0}}}}
		rs = append(rs, Receipt{Interval: i, ID: string(rune('a' + n)), TenantID: s.TenantID, Subject: s.Subject, ReceivedAt: end.Add(time.Second), WriterRole: "finops_activity", Binding: s.Binding()})
	}
	return Input{Now: now, Objective: o, Source: s, Receipts: rs}
}
func reason(e Evaluation, r string) bool {
	for _, s := range e.ReasonCodes {
		if s == r {
			return true
		}
	}
	return false
}
func TestIndependentHardLimitsAndFrozenRegression(t *testing.T) {
	in := input()
	in.Objective.Regression.Enabled = true
	in.CaptureBaseline = true
	base := Evaluate(in)
	if base.Status != "CLEAR" {
		t.Fatal(base.ReasonCodes)
	}
	base.ID = "frozen"
	in.Baseline = &base
	in.CaptureBaseline = false
	if e := Evaluate(in); e.Status != "CLEAR" {
		t.Fatal(e.ReasonCodes)
	}
	// A hard limit remains binding even when the frozen regression permits it.
	in.Objective.Limits.MaxP95LatencyMS = 90
	in.Baseline = nil
	in.CaptureBaseline = true
	if e := Evaluate(in); !reason(e, "SLO_P95_HARD_BREACH") {
		t.Fatal("hard limit was replaced by regression", e)
	}
	in = input()
	in.Objective.Regression.Enabled = true
	in.CaptureBaseline = true
	base = Evaluate(in)
	in.CaptureBaseline = false
	in.Baseline = &base
	for n := range in.Receipts {
		in.Receipts[n].Latency.Buckets[1].Count = 0
		in.Receipts[n].Latency.Buckets[2].Count = 100
	}
	if e := Evaluate(in); !reason(e, "SLO_LATENCY_REGRESSION") {
		t.Fatal("absolute-pass regression did not block", e)
	}
	base.SourceHash = "invented"
	if e := Evaluate(in); !reason(e, "SLO_REGRESSION_BASELINE_REQUIRED") {
		t.Fatal("mismatched frozen baseline accepted")
	}
}
func TestHistogramCountsAreAggregatedWithoutAveragingPercentiles(t *testing.T) {
	in := input()
	in.Receipts[0].RequestCount = 1000
	in.Receipts[0].Latency.SampleCount = 1000
	in.Receipts[0].Latency.Buckets[1].Count = 1000
	in.Receipts[1].Latency.Buckets[1].Count = 0
	in.Receipts[1].Latency.Buckets[3].Count = 100
	e := Evaluate(in)
	if e.P95LatencyMS == nil || *e.P95LatencyMS != 250 || !reason(e, "SLO_P95_HARD_BREACH") {
		t.Fatal("histogram quantile was averaged", e)
	}
	in = input()
	in.Receipts[0].Latency.Buckets[1].Count = 0
	in.Receipts[0].Latency.Buckets[4].Count = 100
	if e = Evaluate(in); !reason(e, "SLO_LATENCY_UNBOUNDED") || e.P95LatencyMS != nil {
		t.Fatal("overflow fabricated bounded latency")
	}
}
func TestCoverageFreshnessBindingAndMeaningfulSamplesFailClosed(t *testing.T) {
	for name, mutate := range map[string]func(*Input){"gap": func(i *Input) { i.Receipts = i.Receipts[1:] }, "duplicate": func(i *Input) { i.Receipts[1] = i.Receipts[0] }, "sequence": func(i *Input) { i.Receipts[1].Sequence = 10 }, "stale": func(i *Input) { i.Now = i.Now.Add(5 * time.Minute) }, "tenant": func(i *Input) { i.Receipts[0].Binding.TenantID = "other" }, "source": func(i *Input) { i.Source.Enabled = false }, "future": func(i *Input) { i.Receipts[1].ReceivedAt = i.Now.Add(time.Minute) }, "samples": func(i *Input) { i.Objective.Limits.MinLatencySamples = 10000 }, "bucket_layout": func(i *Input) { i.Receipts[1].Latency.Buckets[0].UpperBoundMS = ptr(98) }} {
		t.Run(name, func(t *testing.T) {
			in := input()
			mutate(&in)
			if e := Evaluate(in); e.Status != "BLOCKED" {
				t.Fatal("missing or mismatched evidence cleared", e)
			}
		})
	}
}
func TestAvailabilityCalendarSingletonAndNoDemandSemantics(t *testing.T) {
	in := input()
	if len(StopAllowed(in.Objective, in.Now, in.Now.Add(time.Hour))) == 0 {
		t.Fatal("24x7 singleton allowed to stop")
	}
	in.Objective.Availability = Availability{Mode: "WINDOWS", Timezone: "Europe/London", Windows: []Window{{Days: []int{1, 2, 3, 4, 5}, StartTime: "09:00", EndTime: "17:00"}}}
	if rs := StopAllowed(in.Objective, in.Now, in.Now.Add(time.Hour)); len(rs) != 0 {
		t.Fatal(rs)
	}
	if len(StopAllowed(in.Objective, time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC), time.Date(2026, 10, 20, 8, 1, 0, 0, time.UTC))) == 0 {
		t.Fatal("restore buffer overlapped declared window")
	}
	for n := range in.Receipts {
		in.Receipts[n].RequestCount = 0
		in.Receipts[n].Latency.SampleCount = 0
		in.Receipts[n].Latency.Buckets[1].Count = 0
		in.Receipts[n].AvailabilityGoodSeconds = 0
	}
	e := Evaluate(in)
	if e.Status != "CLEAR" || e.LatencyStatus != "NO_DEMAND" || e.P95LatencyMS != nil || e.AvailabilityPPM != nil || e.AvailabilityTotalSeconds != 0 {
		t.Fatal("closed no-demand fabricated measured zero/availability", e)
	}
	in.Objective.Regression.Enabled = true
	in.CaptureBaseline = true
	if e = Evaluate(in); !reason(e, "SLO_REGRESSION_BASELINE_UNMEASURABLE") {
		t.Fatal("no-demand captured a latency baseline")
	}
	// The autumn DST repeated hour is tested on real UTC instants in the calendar.
	o := objective()
	o.Availability = Availability{Mode: "WINDOWS", Timezone: "Europe/London", Windows: []Window{{Days: []int{0}, StartTime: "01:00", EndTime: "02:00"}}}
	for _, hour := range []int{0, 1} {
		start := time.Date(2026, 10, 25, hour, 15, 0, 0, time.UTC)
		if len(StopAllowed(o, start, start.Add(time.Minute))) == 0 {
			t.Fatal("repeated local hour lost availability")
		}
	}
}
func TestStrictVersionedIntegerHistogramDecoder(t *testing.T) {
	in := input().Receipts[0].Interval
	raw, _ := json.Marshal(in)
	if _, e := DecodeInterval(raw); e != nil {
		t.Fatal(e)
	}
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	for _, key := range []string{"request_count", "error_count", "availability_good_seconds", "availability_total_seconds", "latency"} {
		copy := map[string]any{}
		for k, v := range d {
			copy[k] = v
		}
		delete(copy, key)
		b, _ := json.Marshal(copy)
		if _, e := DecodeInterval(b); e == nil {
			t.Fatalf("missing %s became zero", key)
		}
	}
	for name, mutate := range map[string]func(*Interval){"negative": func(i *Interval) { i.ErrorCount = -1 }, "missing_latency": func(i *Interval) { i.Latency.SampleCount = 99 }, "average_percentile": func(i *Interval) { i.Latency.Unit = "p95" }, "missing_overflow": func(i *Interval) { i.Latency.Buckets = i.Latency.Buckets[:4] }, "negative_bucket": func(i *Interval) { i.Latency.Buckets[0].Count = -1 }} {
		t.Run(name, func(t *testing.T) {
			copy := in
			copy.Latency.Buckets = append([]Bucket{}, in.Latency.Buckets...)
			mutate(&copy)
			if ValidateInterval(copy) == nil {
				t.Fatal("invalid histogram accepted")
			}
		})
	}
}
