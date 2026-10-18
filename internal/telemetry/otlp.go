package telemetry

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func attributes(kvs []*commonpb.KeyValue) (map[string]string, model.Document, error) {
	out := map[string]string{}
	original := model.Document{}
	if len(kvs) > 64 {
		return nil, nil, errors.New("TELEMETRY_ATTRIBUTE_LIMIT")
	}
	for _, kv := range kvs {
		if kv.Key == "" || len(kv.Key) > 256 || kv.Value == nil {
			return nil, nil, errors.New("TELEMETRY_ATTRIBUTE_INVALID")
		}
		if _, ok := out[kv.Key]; ok {
			return nil, nil, errors.New("TELEMETRY_DUPLICATE_ATTRIBUTE")
		}
		raw, e := protojson.Marshal(kv.Value)
		if e != nil || len(raw) > 4096 {
			return nil, nil, errors.New("TELEMETRY_ATTRIBUTE_INVALID")
		}
		var value any
		switch x := kv.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			out[kv.Key] = x.StringValue
			value = model.Document{"type": "string", "value": x.StringValue}
		default:
			out[kv.Key] = string(raw)
			value = model.Document{"type": "otlp", "value": string(raw)}
		}
		original[kv.Key] = value
	}
	return out, original, nil
}
func matches(actual, required map[string]string) bool {
	for k, v := range required {
		if actual[k] != v {
			return false
		}
	}
	return true
}
func resourceMatches(c Connection, d Definition, attrs map[string]string) bool {
	return attrs["cloud.provider"] == "aws" && attrs["cloud.account.id"] == c.Binding.AccountID && attrs["cloud.region"] == c.Binding.Region && attrs["host.id"] == c.Binding.ProviderResourceID && matches(attrs, d.ResourceAttributes)
}
func otlpTime(n uint64) (time.Time, bool) {
	if n == 0 || n > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.Unix(0, int64(n)).UTC(), true
}
func newOTLPSample(c Connection, d Definition, res map[string]string, resOriginal model.Document, scope map[string]string, scopeOriginal model.Document, pointAttrs []*commonpb.KeyValue, start, end uint64, flags uint32) (Sample, error) {
	a, original, e := attributes(pointAttrs)
	if e != nil {
		return Sample{}, e
	}
	if !matches(a, d.Attributes) || !resourceMatches(c, d, res) {
		return Sample{}, errors.New("TELEMETRY_RESOURCE_OR_STREAM_MISMATCH")
	}
	at, ok := otlpTime(end)
	if !ok {
		return Sample{}, errors.New("TELEMETRY_POINT_TIME_INVALID")
	}
	s := Sample{DefinitionID: d.ID, Metric: d.Metric, Type: d.Type, Unit: d.Unit, Time: at, Attributes: a, ResourceAttributes: res, ScopeAttributes: scope, OriginalAttributes: model.Document{"point": original, "resource": resOriginal, "scope": scopeOriginal}, ReasonCodes: []string{}}
	if start != 0 {
		left, ok := otlpTime(start)
		if !ok || left.After(at) {
			return s, errors.New("TELEMETRY_POINT_TIME_INVALID")
		}
		s.StartTime = left
		s.Epoch = left.Format(time.RFC3339Nano)
	}
	if flags&1 != 0 {
		return s, errors.New("TELEMETRY_POINT_NOT_RECORDED")
	}
	s.StreamID = streamID(d, a, res, scope, s.OriginalAttributes)
	return s, nil
}
func numericPoint(p *metricspb.NumberDataPoint) (string, bool) {
	switch v := p.Value.(type) {
	case *metricspb.NumberDataPoint_AsInt:
		return strconv.FormatInt(v.AsInt, 10), true
	case *metricspb.NumberDataPoint_AsDouble:
		if !math.IsNaN(v.AsDouble) && !math.IsInf(v.AsDouble, 0) {
			return strconv.FormatFloat(v.AsDouble, 'g', -1, 64), true
		}
	}
	return "", false
}
func temporality(v metricspb.AggregationTemporality) string {
	switch v {
	case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA:
		return "DELTA"
	case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE:
		return "CUMULATIVE"
	}
	return ""
}

// DecodeOTLP parses the original protobuf request, preserving uint64 populations
// and actual epochs. Authentication and source selection precede this function.
// Invalid/unsupported points remain visible as rejections, never a complete batch.
func DecodeOTLP(raw []byte, c Connection, collectedAt time.Time) (Batch, error) {
	if e := ValidateConnection(c); e != nil {
		return Batch{}, e
	}
	if c.Kind != "OTLP" || !c.Enabled {
		return Batch{}, errors.New("TELEMETRY_CONNECTION_DISABLED")
	}
	if len(raw) == 0 || len(raw) > MaxBodyBytes {
		return Batch{}, errors.New("TELEMETRY_BODY_LIMIT")
	}
	var req collectorpb.ExportMetricsServiceRequest
	if e := proto.Unmarshal(raw, &req); e != nil {
		return Batch{}, errors.New("TELEMETRY_PROTOBUF_INVALID")
	}
	b := newBatch(c, raw, collectedAt)
	for _, rm := range req.ResourceMetrics {
		res, ro, e := attributes(rm.GetResource().GetAttributes())
		if e != nil {
			b.Rejections = append(b.Rejections, Rejection{Count: 1, ReasonCode: e.Error()})
			continue
		}
		for _, sm := range rm.ScopeMetrics {
			scope, so, e := attributes(sm.GetScope().GetAttributes())
			if e != nil {
				b.Rejections = append(b.Rejections, Rejection{Count: 1, ReasonCode: e.Error()})
				continue
			}
			scope["scope.name"], scope["scope.version"], scope["scope.schema_url"] = sm.GetScope().GetName(), sm.GetScope().GetVersion(), sm.SchemaUrl
			scope["resource.schema_url"] = rm.SchemaUrl
			for _, m := range sm.Metrics {
				defs := []Definition{}
				for _, d := range c.Definitions {
					if d.Name == m.Name {
						defs = append(defs, d)
					}
				}
				if len(defs) == 0 {
					b.Rejections = append(b.Rejections, Rejection{Metric: m.Name, Count: 1, ReasonCode: "TELEMETRY_METRIC_NOT_REGISTERED"})
					continue
				}
				for _, d := range defs {
					if m.Unit != d.Unit {
						reject(&b, d, 1, "TELEMETRY_UNIT_MISMATCH")
						continue
					}
					accept := func(s Sample, e error) {
						if e != nil {
							reject(&b, d, 1, e.Error())
							return
						}
						if s.Time.After(collectedAt.Add(5*time.Second)) || collectedAt.Sub(s.Time) > 2*time.Minute {
							reject(&b, d, 1, "TELEMETRY_CURRENT_RECEIVE_WINDOW_REQUIRED")
							return
						}
						if s.Type != "GAUGE" && (s.StartTime.IsZero() || !s.Time.After(s.StartTime) || s.Temporality == "" || s.Temporality == "DELTA" && s.Time.Sub(s.StartTime) > time.Duration(d.MaxGapSeconds)*time.Second) {
							reject(&b, d, 1, "TELEMETRY_EPOCH_OR_INTERVAL_INVALID")
							return
						}
						if len(b.Samples) >= MaxSamples {
							reject(&b, d, 1, "TELEMETRY_SAMPLE_LIMIT")
							return
						}
						b.Samples = append(b.Samples, s)
					}
					switch data := m.Data.(type) {
					case *metricspb.Metric_Gauge:
						if d.Type != "GAUGE" {
							reject(&b, d, len(data.Gauge.DataPoints), "TELEMETRY_TYPE_MISMATCH")
							continue
						}
						for _, p := range data.Gauge.DataPoints {
							s, e := newOTLPSample(c, d, res, ro, scope, so, p.Attributes, p.StartTimeUnixNano, p.TimeUnixNano, p.Flags)
							s.Statistic, s.Temporality = "SAMPLED_VALUE", "INSTANT"
							v, ok := numericPoint(p)
							if !ok {
								e = errors.New("TELEMETRY_NUMBER_INVALID")
							}
							s.Value = v
							accept(s, e)
						}
					case *metricspb.Metric_Sum:
						if d.Type != "SUM" || !data.Sum.IsMonotonic {
							reject(&b, d, len(data.Sum.DataPoints), "TELEMETRY_NON_MONOTONIC_OR_TYPE_UNSUPPORTED")
							continue
						}
						for _, p := range data.Sum.DataPoints {
							s, e := newOTLPSample(c, d, res, ro, scope, so, p.Attributes, p.StartTimeUnixNano, p.TimeUnixNano, p.Flags)
							s.Statistic, s.Temporality = "MONOTONIC_COUNTER", temporality(data.Sum.AggregationTemporality)
							v, ok := numericPoint(p)
							r, valid := number(v)
							if !ok || !valid || r.Sign() < 0 || d.Unit == "count" && !r.IsInt() {
								e = errors.New("TELEMETRY_COUNTER_INVALID")
							}
							if _, double := p.Value.(*metricspb.NumberDataPoint_AsDouble); double && (d.Unit == "count" || d.Unit == "bytes") && valid && r.Cmp(big.NewRat(9007199254740991, 1)) > 0 {
								e = errors.New("TELEMETRY_COUNTER_NOT_EXACT")
							}
							s.Value = v
							accept(s, e)
						}
					case *metricspb.Metric_Histogram:
						if d.Type != "HISTOGRAM" {
							reject(&b, d, len(data.Histogram.DataPoints), "TELEMETRY_TYPE_MISMATCH")
							continue
						}
						for _, p := range data.Histogram.DataPoints {
							s, e := newOTLPSample(c, d, res, ro, scope, so, p.Attributes, p.StartTimeUnixNano, p.TimeUnixNano, p.Flags)
							s.Statistic, s.Temporality = "EXPLICIT_BUCKET_POPULATION", temporality(data.Histogram.AggregationTemporality)
							h := &Histogram{Count: p.Count, BucketCounts: append([]uint64{}, p.BucketCounts...), Bounds: []string{}}
							for _, v := range p.ExplicitBounds {
								h.Bounds = append(h.Bounds, strconv.FormatFloat(v, 'g', -1, 64))
							}
							if !validHistogram(h) {
								e = errors.New("TELEMETRY_HISTOGRAM_INVALID")
							}
							s.Histogram = h
							accept(s, e)
						}
					case *metricspb.Metric_ExponentialHistogram:
						reject(&b, d, len(data.ExponentialHistogram.DataPoints), "TELEMETRY_EXPONENTIAL_HISTOGRAM_UNSUPPORTED")
					case *metricspb.Metric_Summary:
						reject(&b, d, len(data.Summary.DataPoints), "TELEMETRY_SUMMARY_QUANTILES_UNSUPPORTED")
					default:
						reject(&b, d, 1, "TELEMETRY_TYPE_UNSUPPORTED")
					}
				}
			}
		}
	}
	finish(&b)
	return b, nil
}

// OTLPResponse is a standard protocol response; partial acceptance is explicit.
func OTLPResponse(b Batch) []byte {
	n := int64(0)
	for _, r := range b.Rejections {
		n += int64(r.Count)
	}
	out := &collectorpb.ExportMetricsServiceResponse{}
	if n > 0 || len(b.Warnings) > 0 {
		out.PartialSuccess = &collectorpb.ExportMetricsPartialSuccess{RejectedDataPoints: n, ErrorMessage: "telemetry points rejected; inspect source health and receipt rejection codes"}
	}
	raw, _ := proto.Marshal(out)
	return raw
}
