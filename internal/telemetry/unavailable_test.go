package telemetry

import (
	"testing"
	"time"
)

func TestMissingNativeObservationsKeepBoundsAndNullMeasurements(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	d := Definition{ID: "requests", Version: "1", Metric: "request_count", Name: "requests_total", Unit: "requests", Type: "SUM", Monotonic: true, CadenceSeconds: 15, MaxGapSeconds: 30}
	for name, e := range map[string]Evaluation{"history": EvaluateHistory(HistoryInput{Now: now, Definitions: []Definition{d}, Days: 14, Timezone: "Europe/London"}), "window": EvaluateWindow(WindowInput{Now: now, Definitions: []Definition{d}, Minutes: 5})} {
		if e.Status != "BLOCKED" || len(e.Metrics) != 1 {
			t.Fatalf("%s: %+v", name, e)
		}
		m := e.Metrics[0]
		if m.Start.IsZero() || !m.End.After(m.Start) || m.ExpectedSamples < 1 || m.UnknownDurationNS <= 0 || m.ObservedSamples != 0 || m.CoveragePPM != 0 || m.Total != nil || m.P95 != nil || m.Maximum != nil || m.Unit != "requests/second" || m.Statistic != "OBSERVED_INTERVAL_RATE_DISTRIBUTION" {
			t.Fatalf("%s unavailable falsely measured or unbound: %+v", name, m)
		}
	}
}
