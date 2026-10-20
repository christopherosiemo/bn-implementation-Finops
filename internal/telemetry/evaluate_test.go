package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func nativeSample(d Definition, at time.Time, value string) Sample {
	return Sample{DefinitionID: d.ID, StreamID: "one-stream", Metric: d.Metric, Type: d.Type, Unit: d.Unit, Time: at, Value: value, Temporality: "INSTANT", Statistic: "SAMPLED_VALUE", RawSHA256: strings.Repeat("a", 64), ReasonCodes: []string{}}
}
func hasReason(reasons []string, reason string) bool {
	for _, s := range reasons {
		if s == reason {
			return true
		}
	}
	return false
}
func TestSegmentsNeverInventResetCountsAndPreserveActualIntervals(t *testing.T) {
	d := Definition{ID: "requests", Version: "1", Metric: "request_count", Type: "SUM", Unit: "count", CadenceSeconds: 15, MaxGapSeconds: 30}
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	points := []Sample{}
	for i, v := range []string{"100", "130", "1", "7", "10"} {
		s := nativeSample(d, at.Add(time.Duration(i)*15*time.Second), v)
		s.Temporality = "CUMULATIVE"
		s.Epoch = "old"
		if i >= 2 {
			s.Epoch = "new"
		}
		points = append(points, s)
	}
	segments := Segments(points, []Definition{d})
	if len(segments) != 5 || segments[1].Value != "30" || segments[2].Status != "RESET" || segments[2].Value != "" || segments[3].Value != "6" {
		t.Fatalf("counter reset fabricated values: %+v", segments)
	}
	points[4].Time = at.Add(100 * time.Second)
	segments = Segments(points, []Definition{d})
	if segments[4].Status != "UNKNOWN" || !hasReason(segments[4].ReasonCodes, "TELEMETRY_OBSERVATION_GAP") {
		t.Fatal("gap extrapolated")
	}
}
func TestHistogramPopulationDeltasAndBoundsNotAveragePercentiles(t *testing.T) {
	d := Definition{ID: "latency", Version: "1", Metric: "latency", Type: "HISTOGRAM", Unit: "milliseconds", CadenceSeconds: 15, MaxGapSeconds: 30}
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	a := nativeSample(d, at, "")
	a.Temporality = "CUMULATIVE"
	a.Epoch = "epoch"
	a.Histogram = &Histogram{Count: 100, Bounds: []string{"100", "1000"}, BucketCounts: []uint64{100, 0, 0}}
	b := a
	b.Time = at.Add(15 * time.Second)
	b.Histogram = &Histogram{Count: 200, Bounds: []string{"100", "1000"}, BucketCounts: []uint64{100, 100, 0}}
	segments := Segments([]Sample{a, b}, []Definition{d})
	if segments[1].Histogram.Count != 100 || segments[1].Histogram.BucketCounts[0] != 0 || segments[1].Histogram.BucketCounts[1] != 100 {
		t.Fatal("time/boundary differencing wrong")
	}
	h := &Histogram{Count: 1000, Bounds: []string{"100", "1000"}, BucketCounts: []uint64{949, 50, 1}}
	if got := histogramQuantile(h, 950); got == nil || *got != "1000" {
		t.Fatalf("p95 wrong: %v", got)
	}
	if histogramQuantile(h, 1000) != nil {
		t.Fatal("overflow bucket treated as finite max")
	}
	empty := &Histogram{Count: 0, Bounds: []string{"100"}, BucketCounts: []uint64{0, 0}}
	if histogramQuantile(empty, 950) != nil {
		t.Fatal("zero demand treated as zero latency")
	}
}
func TestWindowUsesActualJitteredTimesAndRequiresCadence(t *testing.T) {
	d := testConnection("OTLP").Definitions[0]
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	points := []Sample{}
	for i := 0; i <= 9; i++ {
		at := start.Add(time.Duration(i) * 15 * time.Second)
		if i%3 == 1 {
			at = at.Add(100 * time.Millisecond)
		}
		points = append(points, nativeSample(d, at, "0.25"))
	}
	end := points[len(points)-1].Time
	e := EvaluateWindow(WindowInput{Now: end.Add(time.Second), Definitions: []Definition{d}, Segments: Segments(points, []Definition{d}), Minutes: 2, RequiredMetrics: []string{"cpu_utilization"}})
	if e.Status != "READY" || e.Metrics[0].Maximum == nil || *e.Metrics[0].Maximum != "0.25" || e.Metrics[0].P99 != nil {
		t.Fatalf("jitter rejected or tail invented: %+v", e)
	}
	if e.Start.Equal(end.Add(-2 * time.Minute)) {
		t.Fatal("window was silently interpolated to requested start")
	}
	missing := append([]Sample{}, points[:3]...)
	missing = append(missing, points[4:]...)
	e = EvaluateWindow(WindowInput{Now: end.Add(time.Second), Definitions: []Definition{d}, Segments: Segments(missing, []Definition{d}), Minutes: 2})
	if e.Status != "BLOCKED" {
		t.Fatal("missing scrape converted to complete window")
	}
}
func TestHistoryUsesCalendarDSTAndNoUnknownZeros(t *testing.T) {
	d := testConnection("OTLP").Definitions[0]
	d.CadenceSeconds = 300
	d.MaxGapSeconds = 600
	loc, _ := time.LoadLocation("Europe/London")
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, loc)
	end := time.Date(2026, 4, 5, 0, 0, 0, 0, loc).UTC()
	start := end.In(loc).AddDate(0, 0, -14).UTC()
	if end.Sub(start) != 335*time.Hour {
		t.Fatal("test did not cross spring DST")
	}
	points := []Sample{}
	for at := start.Add(-5 * time.Minute); at.Before(end); at = at.Add(5 * time.Minute) {
		points = append(points, nativeSample(d, at, "0"))
	}
	e := EvaluateHistory(HistoryInput{Now: now, Definitions: []Definition{d}, Samples: points, Days: 14, Timezone: "Europe/London"})
	if e.Status != "READY" || e.Metrics[0].ExpectedSamples != 4020 || e.Metrics[0].CoveragePPM != 1000000 || e.Metrics[0].P95 == nil || *e.Metrics[0].P95 != "0" {
		t.Fatalf("DST/observed zero lost: %+v", e)
	}
	points = append(points[:100], points[101:]...)
	e = EvaluateHistory(HistoryInput{Now: now, Definitions: []Definition{d}, Samples: points, Days: 14, Timezone: "Europe/London"})
	if e.Status != "BLOCKED" || e.Metrics[0].CoveragePPM >= 1000000 {
		t.Fatal("missing value invented as zero")
	}
	empty := EvaluateHistory(HistoryInput{Now: now, Definitions: []Definition{d}, Days: 14, Timezone: "Europe/London"})
	if empty.Status != "BLOCKED" || empty.Metrics[0].Maximum != nil {
		t.Fatal("empty source became observed zero")
	}
}
func TestCounterRatesAreDurationWeightedAndCountWireExact(t *testing.T) {
	d := Definition{ID: "network", Version: "1", Metric: "network_in", Type: "SUM", Unit: "bytes", CadenceSeconds: 15, MaxGapSeconds: 30}
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	segments := []Segment{{ID: "a", DefinitionID: d.ID, StreamID: "s", Metric: d.Metric, Type: d.Type, Unit: d.Unit, Start: start, End: start.Add(30 * time.Second), Status: "OBSERVED", Value: "300"}, {ID: "b", DefinitionID: d.ID, StreamID: "s", Metric: d.Metric, Type: d.Type, Unit: d.Unit, Start: start.Add(30 * time.Second), End: start.Add(45 * time.Second), Status: "OBSERVED", Value: "1500"}}
	r := summarize(d, segments, start, start.Add(45*time.Second), false)
	if r.P50 == nil || *r.P50 != "10" || r.Total == nil || *r.Total != "1800" || r.Unit != "bytes/second" {
		t.Fatalf("rate weighted per interval count: %+v", r)
	}
	for _, s := range []string{`{"count":9007199254740993,"bounds":["1"],"bucket_counts":["9007199254740993","0"]}`, `{"count":"1","bounds":["1"],"bucket_counts":[null,"1"]}`} {
		var h Histogram
		if json.Unmarshal([]byte(s), &h) == nil {
			t.Fatal("lossy or null histogram count accepted")
		}
	}
}
func TestCounterTotalRequiresAnAcceptedObservationAndPreservesExplicitZero(t *testing.T) {
	d := Definition{ID: "requests", Version: "1", Metric: "request_count", Type: "SUM", Unit: "count", CadenceSeconds: 15, MaxGapSeconds: 30}
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	segment := Segment{ID: "one", DefinitionID: d.ID, StreamID: "stream", Metric: d.Metric, Type: d.Type, Unit: d.Unit, Start: start, End: start.Add(15 * time.Second), Status: "OBSERVED", Value: "0"}
	for _, tc := range []struct {
		name   string
		status string
		value  string
	}{
		{"missing", "", ""},
		{"reset", "RESET", ""},
		{"unknown", "UNKNOWN", ""},
		{"invalid", "OBSERVED", "invalid"},
		{"negative", "OBSERVED", "-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := segment
			s.Status, s.Value = tc.status, tc.value
			segments := []Segment{s}
			if tc.name == "missing" {
				segments = nil
			}
			r := summarize(d, segments, start, segment.End, true)
			if r.Status != "BLOCKED" || r.Total != nil || r.Maximum != nil || r.P50 != nil {
				t.Fatalf("unobserved counter became a number: %+v", r)
			}
		})
	}
	r := summarize(d, []Segment{segment}, start, segment.End, true)
	if r.Status != "READY" || r.Total == nil || *r.Total != "0" || r.Maximum == nil || *r.Maximum != "0" || r.ObservedSamples != 1 {
		t.Fatalf("explicit observed zero was lost: %+v", r)
	}
}
func TestHistoryNativeCountsUseIntervalEndNotGaugeTimestampConvention(t *testing.T) {
	d := Definition{ID: "requests", Version: "1", Metric: "request_count", Type: "SUM", Unit: "count", CadenceSeconds: 300, MaxGapSeconds: 600}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	points := []Sample{}
	for at := start; !at.After(end); at = at.Add(5 * time.Minute) {
		s := nativeSample(d, at, "1")
		s.StartTime = at.Add(-5 * time.Minute)
		s.Temporality = "DELTA"
		if at.Equal(start) {
			s.Value = "999"
		}
		if at.Equal(end) {
			s.Value = "7"
		}
		points = append(points, s)
	}
	e := EvaluateHistory(HistoryInput{Now: now, Definitions: []Definition{d}, Samples: points, Days: 14, Timezone: "UTC"})
	if e.Status != "READY" || e.Metrics[0].Total == nil || *e.Metrics[0].Total != "4038" || e.Metrics[0].UnknownDurationNS != 0 {
		t.Fatalf("native interval boundary population wrong %+v", e)
	}
}
