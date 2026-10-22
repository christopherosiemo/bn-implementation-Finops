package telemetry

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func testConnection(kind string) Connection {
	return Connection{SchemaVersion: "1", ID: "native-source", Version: 1, Kind: kind, ReadBindingID: "approved-binding", Issuer: "https://collector.example", Subject: "collector:one", Enabled: true, Binding: Binding{TenantID: "tenant-a", ResourceID: "resource-a", WorkloadID: "workload-a", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "123456789012", Region: "eu-west-1"}, Definitions: []Definition{{ID: "def-cpu", Version: "1", Metric: "cpu_utilization", Name: "cpu_utilization", Type: "GAUGE", Unit: "ratio", CadenceSeconds: 15, MaxGapSeconds: 30, Attributes: map[string]string{"service": "checkout"}, ResourceAttributes: map[string]string{}}}}
}
func kv(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}
func pointTime(t time.Time) uint64 { return uint64(t.UnixNano()) }
func wire(t *testing.T, c Connection, metrics ...*metricspb.Metric) []byte {
	t.Helper()
	attrs := []*commonpb.KeyValue{kv("cloud.provider", "aws"), kv("cloud.account.id", c.Binding.AccountID), kv("cloud.region", c.Binding.Region), kv("host.id", c.Binding.ProviderResourceID)}
	req := &collectorpb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{Resource: &resourcepb.Resource{Attributes: attrs}, ScopeMetrics: []*metricspb.ScopeMetrics{{Scope: &commonpb.InstrumentationScope{Name: "native-test", Version: "1"}, Metrics: metrics}}}}}
	b, e := proto.Marshal(req)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func gauge(at time.Time, v float64) *metricspb.Metric {
	return &metricspb.Metric{Name: "cpu_utilization", Unit: "ratio", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{TimeUnixNano: pointTime(at), Attributes: []*commonpb.KeyValue{kv("service", "checkout")}, Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: v}}}}}}
}

func TestOTLPPreservesCurrentPointsOldEpochAndUint64(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	c := testConnection("OTLP")
	c.Definitions = []Definition{{ID: "latency", Version: "1", Metric: "latency", Name: "request_latency", Type: "HISTOGRAM", Unit: "milliseconds", CadenceSeconds: 15, MaxGapSeconds: 30}}
	count := uint64(9007199254740993)
	epoch := now.AddDate(0, 0, -7)
	m := &metricspb.Metric{Name: "request_latency", Unit: "milliseconds", Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, DataPoints: []*metricspb.HistogramDataPoint{{StartTimeUnixNano: pointTime(epoch), TimeUnixNano: pointTime(now.Add(-5 * time.Second)), Count: count, ExplicitBounds: []float64{100, 200}, BucketCounts: []uint64{count - 1, 1, 0}}}}}}
	raw := wire(t, c, m)
	b, e := DecodeOTLP(raw, c, now)
	if e != nil || len(b.Samples) != 1 || len(b.Rejections) != 0 {
		t.Fatalf("decode: %v %+v", e, b.Rejections)
	}
	s := b.Samples[0]
	if !s.StartTime.Equal(epoch) || s.Histogram.Count != count || !b.Start.Equal(s.Time) || b.RawSHA256 != BytesHash(raw) {
		t.Fatalf("native values not retained: %+v", s)
	}
	d := Document(b)
	encoded, _ := json.Marshal(d)
	if !strings.Contains(string(encoded), `"count":"9007199254740993"`) {
		t.Fatalf("uint64 lost across Document: %s", encoded)
	}
	var round Batch
	if e = json.Unmarshal(encoded, &round); e != nil || round.Samples[0].Histogram.Count != count {
		t.Fatalf("roundtrip: %v", e)
	}
	later, e := DecodeOTLP(raw, c, now.Add(time.Second))
	if e != nil || CanonicalHash(later) != CanonicalHash(b) || later.Samples[0].ID != s.ID {
		t.Fatal("transport receipt time changed canonical identity")
	}
}
func TestOTLPPartialRejectionsAreVisibleAndNoLatencyFabricated(t *testing.T) {
	now := time.Now().UTC()
	c := testConnection("OTLP")
	bad := gauge(now.Add(-3*time.Minute), 0.2)
	good := gauge(now.Add(-time.Second), 0.3)
	exp := &metricspb.Metric{Name: "latency", Unit: "milliseconds", Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{DataPoints: []*metricspb.ExponentialHistogramDataPoint{{TimeUnixNano: pointTime(now)}}}}}
	c.Definitions = append(c.Definitions, Definition{ID: "lat", Version: "1", Metric: "latency", Name: "latency", Unit: "milliseconds", Type: "HISTOGRAM", CadenceSeconds: 15, MaxGapSeconds: 30})
	b, e := DecodeOTLP(wire(t, c, bad, good, exp), c, now)
	if e != nil || len(b.Samples) != 1 || len(b.Rejections) != 2 {
		t.Fatalf("partial: %v %+v", e, b)
	}
	var response collectorpb.ExportMetricsServiceResponse
	if e = proto.Unmarshal(OTLPResponse(b), &response); e != nil || response.GetPartialSuccess().GetRejectedDataPoints() != 2 {
		t.Fatalf("partial protocol: %s %v", response.String(), e)
	}
	if b.Rejections[0].ReasonCode != "TELEMETRY_CURRENT_RECEIVE_WINDOW_REQUIRED" || b.Rejections[1].ReasonCode != "TELEMETRY_EXPONENTIAL_HISTOGRAM_UNSUPPORTED" {
		t.Fatalf("wrong reason %+v", b.Rejections)
	}
}
func TestOTLPBindingUnitsFlagsAndNonfiniteFailClosed(t *testing.T) {
	now := time.Now().UTC()
	c := testConnection("OTLP")
	cases := []struct {
		name   string
		mutate func(*metricspb.Metric)
	}{
		{"unit", func(m *metricspb.Metric) { m.Unit = "percent" }},
		{"nan", func(m *metricspb.Metric) {
			m.GetGauge().DataPoints[0].Value = &metricspb.NumberDataPoint_AsDouble{AsDouble: math.NaN()}
		}},
		{"flags", func(m *metricspb.Metric) { m.GetGauge().DataPoints[0].Flags = 1 }},
		{"labels", func(m *metricspb.Metric) {
			m.GetGauge().DataPoints[0].Attributes = []*commonpb.KeyValue{kv("service", "other")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := gauge(now, 0.2)
			tc.mutate(m)
			b, e := DecodeOTLP(wire(t, c, m), c, now)
			if e != nil || len(b.Samples) != 0 || len(b.Rejections) != 1 {
				t.Fatalf("accepted %s %+v %v", tc.name, b, e)
			}
		})
	}
	raw := wire(t, c, gauge(now, 0.2))
	c.Binding.AccountID = "999999999999"
	b, e := DecodeOTLP(raw, c, now)
	if e != nil || len(b.Samples) != 0 || len(b.Rejections) != 1 {
		t.Fatal("cross-account metric accepted")
	}
}
func TestOTLPTypedAttributesRemainDifferentStreams(t *testing.T) {
	now := time.Now().UTC()
	c := testConnection("OTLP")
	c.Definitions[0].Attributes = nil
	a, b := gauge(now, 0.2), gauge(now, 0.3)
	a.GetGauge().DataPoints[0].Attributes = []*commonpb.KeyValue{{Key: "shard", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 1}}}}
	b.GetGauge().DataPoints[0].Attributes = []*commonpb.KeyValue{kv("shard", `{"intValue":"1"}`)}
	batch, e := DecodeOTLP(wire(t, c, a, b), c, now)
	if e != nil || len(batch.Samples) != 2 || batch.Samples[0].StreamID == batch.Samples[1].StreamID {
		t.Fatal("typed attribute collision")
	}
}
