package multicloud

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativeMetricPointSemanticsMissingZeroAndEpoch(t *testing.T) {
	p := Period{testNow.Add(-2 * time.Minute), testNow}
	definition, _ := NativeMetric("AZURE", "Percentage CPU")
	points, e := ParseAzureMetricPoints(definition, []any{Document{"timeStamp": "2026-10-18T11:58:00Z", "maximum": json.Number("0")}, Document{"timeStamp": "2026-10-18T11:59:00Z"}}, p, 60, "source-a")
	if e != nil {
		t.Fatal(e)
	}
	if points[0].Value == nil || *points[0].Value != "0" || points[1].Value != nil || !hasReason(points[1].ReasonCodes, "METRIC_VALUE_MISSING") || definition.Statistic != "INTERVAL_MAXIMUM" {
		t.Fatal("missing or maximum semantics changed", points)
	}
	_, e = ParseAzureMetricPoints(definition, []any{Document{"timeStamp": "2026-10-18T11:58:00Z", "average": json.Number("2")}}, p, 60, "source")
	wantError(t, e, "AGGREGATION_CHANGED")
	d := MetricDefinition{Name: "native-counter", Kind: "CUMULATIVE", ValueType: "INT64", Unit: "1", Statistic: "RAW_POINT"}
	points, e = ParseGCPMetricPoints(d, []any{Document{"interval": Document{"startTime": "2026-09-01T00:00:00Z", "endTime": "2026-10-18T11:59:00Z"}, "value": Document{"int64Value": "9007199254740993"}}, Document{"interval": Document{"startTime": "2026-10-18T11:59:01Z", "endTime": "2026-10-18T12:00:00Z"}, "value": Document{"int64Value": "1"}}}, p, "source-b")
	if e != nil {
		t.Fatal(e)
	}
	if *points[0].Value != "9007199254740993" || points[0].StartTime.Before(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || len(EpochChanges(points)) != 1 {
		t.Fatal("native epoch/count/reset lost")
	}
	_, e = ParseGCPMetricPoints(d, []any{Document{"interval": Document{"endTime": "2026-10-18T11:59:00Z"}, "value": Document{"int64Value": "1"}}}, p, "source")
	wantError(t, e, "EPOCH_REQUIRED")
	_, e = ParseGCPMetricPoints(d, []any{Document{"interval": Document{"startTime": "2026-10-18T11:58:00Z", "endTime": "2026-10-18T11:59:00Z"}, "value": Document{"int64Value": "-1"}}}, p, "source")
	wantError(t, e, "INTEGER_INVALID")
}
func TestNativeExplicitHistogramsKeepIntegerPrecision(t *testing.T) {
	native := Document{"count": "9007199254740993", "bucketOptions": Document{"explicitBuckets": Document{"bounds": []any{json.Number("0.1")}}}, "bucketCounts": []any{"9007199254740992", "1"}, "mean": json.Number("0.2")}
	hist, e := ParseGCPDistribution(native)
	if e != nil || hist.Count != "9007199254740993" || hist.BucketCounts[0] != "9007199254740992" || hist.Bounds[0] != "0.1" {
		t.Fatal(hist, e)
	}
	native["bucketCounts"] = []any{"9007199254740992", "2"}
	_, e = ParseGCPDistribution(native)
	wantError(t, e, "COUNT_MISMATCH")
	native["bucketOptions"] = Document{"exponentialBuckets": Document{"numFiniteBuckets": 2}}
	_, e = ParseGCPDistribution(native)
	wantError(t, e, "FORMAT_UNSUPPORTED")
}
func TestWarehouseMappingDoesNotRoundNativeValues(t *testing.T) {
	for _, text := range []string{"0.1234567890123", "123456789012345678901234567.1"} {
		original := text
		value, reasons := WarehouseDecimal(&text)
		if value != nil || !hasReason(reasons, "WAREHOUSE_DECIMAL_PRECISION_UNSUPPORTED") || text != original {
			t.Fatal("source rounded", text, value, reasons)
		}
	}
	text := "0.123456789012"
	value, reasons := WarehouseDecimal(&text)
	if value == nil || *value != text || len(reasons) != 0 {
		t.Fatal(value, reasons)
	}
}
func TestMetricPointDedupPinsAllRawSourcesAndRejectsCorrectionBlend(t *testing.T) {
	v := "0"
	p := MetricPoint{Time: testNow, Value: &v, ReasonCodes: []string{}, SourceSHA256: []string{"source-a"}}
	series := MetricSeries{Points: []MetricPoint{p}}
	copy := p
	copy.SourceSHA256 = []string{"source-b"}
	if e := mergeMetricPoints(&series, []MetricPoint{copy}); e != nil || len(series.Points) != 1 || len(series.Points[0].SourceSHA256) != 2 {
		t.Fatal("identical overlapping raw point rejected", e)
	}
	changed := "1"
	copy.Value = &changed
	wantError(t, mergeMetricPoints(&series, []MetricPoint{copy}), "POINT_CONFLICT")
}

type metricsDouble struct {
	t          *testing.T
	r          InventoryRegistration
	mutation   string
	calls      int
	pointPages int
}

func (d *metricsDouble) transport(req *http.Request) (*http.Response, error) {
	d.calls++
	if req.Header.Get("Authorization") != "Bearer test-machine-token" {
		d.t.Fatal("machine identity missing")
	}
	if d.r.Provider == "AZURE" {
		native := azureNativeInstance(d.r)
		resource := str(native, "id")
		if strings.HasSuffix(req.URL.Path, "/metricDefinitions") {
			definitions := []any{}
			for _, name := range []string{"Percentage CPU", "Available Memory Bytes", "Network In Total"} {
				definition, _ := NativeMetric("AZURE", name)
				definitions = append(definitions, Document{"id": resource + "/providers/Microsoft.Insights/metricDefinitions/" + name, "name": Document{"value": name}, "unit": definition.Unit, "supportedAggregationTypes": []any{metricAggregation(definition)}, "metricAvailabilities": []any{Document{"timeGrain": "PT1M"}}})
			}
			return response(200, wire(d.t, Document{"value": definitions}), nil), nil
		}
		if strings.HasSuffix(req.URL.Path, "/metrics") {
			d.pointPages++
			q := req.URL.Query()
			if q.Get("AutoAdjustTimegrain") != "false" || q.Get("ValidateDimensions") != "true" {
				d.t.Fatal("provider aggregation adjustments enabled")
			}
			name := q.Get("metricnames")
			definition, _ := NativeMetric("AZURE", name)
			aggregation := strings.ToLower(q.Get("aggregation"))
			unit := definition.Unit
			if d.mutation == "unit" {
				unit = "Count"
			}
			interval := q.Get("interval")
			if d.mutation == "interval" {
				interval = "PT5M"
			}
			return response(200, wire(d.t, Document{"timespan": q.Get("timespan"), "interval": interval, "namespace": "Microsoft.Compute/virtualMachines", "resourceregion": "westeurope", "value": []any{Document{"id": resource + "/providers/Microsoft.Insights/metrics/" + name, "name": Document{"value": name}, "unit": unit, "errorCode": "Success", "timeseries": []any{Document{"metadatavalues": []any{}, "data": []any{Document{"timeStamp": "2026-10-18T11:58:00Z", aggregation: json.Number("0")}, Document{"timeStamp": "2026-10-18T11:59:00Z"}}}}}}}), nil), nil
		}
		if d.mutation == "recreate" {
			obj(native["properties"])["vmId"] = directory
		}
		if d.mutation == "created" {
			obj(native["properties"])["timeCreated"] = "2026-10-18T11:59:00Z"
		}
		return response(200, wire(d.t, native), nil), nil
	}
	if req.URL.Host == "compute.googleapis.com" {
		native := gcpNativeInstance(d.r)
		if d.mutation == "recreate" {
			native["id"] = "123"
		}
		if d.mutation == "created" {
			native["creationTimestamp"] = "2026-10-18T11:59:00Z"
		}
		return response(200, wire(d.t, native), nil), nil
	}
	name := "compute.googleapis.com/instance/cpu/utilization"
	definition, _ := NativeMetric("GCP", name)
	if strings.Contains(req.URL.Path, "/metricDescriptors/") {
		unit := definition.Unit
		if d.mutation == "unit" {
			unit = "%"
		}
		return response(200, wire(d.t, Document{"name": "projects/usage-project/metricDescriptors/" + name, "type": name, "metricKind": definition.Kind, "valueType": definition.ValueType, "unit": unit}), nil), nil
	}
	if strings.HasSuffix(req.URL.Path, "/timeSeries") {
		d.pointPages++
		q := req.URL.Query()
		for key := range q {
			if strings.HasPrefix(key, "aggregation") || strings.HasPrefix(key, "secondaryAggregation") {
				d.t.Fatal("native points aligned or reduced")
			}
		}
		filter := q.Get("filter")
		if !strings.Contains(filter, `resource.labels.instance_id = "18446744073709551614"`) {
			d.t.Fatal("numeric identity not bound", filter)
		}
		labels := Document{"project_id": "usage-project", "zone": "europe-west1-b", "instance_id": "18446744073709551614"}
		if d.mutation == "target" {
			labels["instance_id"] = "123"
		}
		value := Document{"doubleValue": json.Number("0")}
		timestamp := "2026-10-18T11:59:00Z"
		if q.Get("pageToken") != "" {
			value = Document{}
			timestamp = "2026-10-18T11:58:00Z"
		}
		body := Document{"timeSeries": []any{Document{"metric": Document{"type": name, "labels": Document{"instance_name": "vm-a"}}, "resource": Document{"type": "gce_instance", "labels": labels}, "metricKind": definition.Kind, "valueType": definition.ValueType, "unit": definition.Unit, "points": []any{Document{"interval": Document{"endTime": timestamp}, "value": value}}}}}
		if q.Get("pageToken") == "" || d.mutation == "cycle" {
			body["nextPageToken"] = "page-two"
		}
		if d.mutation == "partial" {
			body["executionErrors"] = []any{Document{"code": 14}}
		}
		return response(200, wire(d.t, body), nil), nil
	}
	d.t.Fatal("unexpected metrics endpoint", req.URL.Path)
	return nil, nil
}
func metricsRequest(t *testing.T, r InventoryRegistration) MetricsRequest {
	t.Helper()
	var instance Instance
	var e error
	names := []string{"compute.googleapis.com/instance/cpu/utilization"}
	interval := int64(0)
	if r.Azure != nil {
		instance, e = ParseAzureInstance(r, azureNativeInstance(r), Document{}, testNow)
		names = []string{"Percentage CPU", "Network In Total"}
		interval = 60
	} else {
		instance, e = ParseGCPInstance(r, r.GCP.Zones[0], gcpNativeInstance(r), testNow)
	}
	if e != nil {
		t.Fatal(e)
	}
	return MetricsRequest{Instance: instance.Identity, Period: Period{testNow.Add(-2 * time.Minute), testNow}, MetricNames: names, IntervalSeconds: interval}
}
func TestNativeMetricsHTTPJourneysNeverInventCoverageOrQuantiles(t *testing.T) {
	for _, provider := range []string{"AZURE", "GCP"} {
		t.Run(provider, func(t *testing.T) {
			r := inventoryRegistration(provider)
			d := &metricsDouble{t: t, r: r}
			c := inventoryConfig(r, d.transport)
			in := metricsRequest(t, r)
			var s MetricsSnapshot
			var e error
			if provider == "AZURE" {
				s, e = (AzureMetricsReader{Config: c}).Collect(context.Background(), r, in)
			} else {
				s, e = (GCPMetricsReader{Config: c}).Collect(context.Background(), r, in)
			}
			if e != nil {
				t.Fatal(e)
			}
			if s.ExecutionReady() || s.CoverageStatus != "UNKNOWN" || !hasReason(s.ReasonCodes, "RAW_QUERY_SUCCESS_IS_NOT_OBSERVATION_COMPLETENESS") || len(s.Series) == 0 {
				t.Fatal("query success became evidence completeness")
			}
			for _, series := range s.Series {
				known, unknown := 0, 0
				for _, point := range series.Points {
					if point.Value == nil {
						unknown++
					} else {
						known++
						if *point.Value != "0" {
							t.Fatal("native zero changed")
						}
					}
				}
				if known != 1 || unknown != 1 {
					t.Fatal("missing became zero", series.Points)
				}
			}
			if provider == "AZURE" && s.Series[0].Definition.Statistic != "INTERVAL_MAXIMUM" {
				t.Fatal("maximum relabelled percentile")
			}
			if provider == "GCP" && s.Series[0].Definition.Unit != "10^2.%" {
				t.Fatal("CPU unit silently rescaled")
			}
		})
	}
}
func TestNativeMetricsHTTPFailsClosed(t *testing.T) {
	for _, provider := range []string{"AZURE", "GCP"} {
		for _, mutation := range []string{"recreate", "created", "unit", "interval", "target", "cycle", "partial"} {
			if provider == "AZURE" && (mutation == "target" || mutation == "cycle" || mutation == "partial") || provider == "GCP" && mutation == "interval" {
				continue
			}
			t.Run(provider+"/"+mutation, func(t *testing.T) {
				r := inventoryRegistration(provider)
				d := &metricsDouble{t: t, r: r, mutation: mutation}
				c := inventoryConfig(r, d.transport)
				in := metricsRequest(t, r)
				var e error
				if provider == "AZURE" {
					_, e = (AzureMetricsReader{Config: c}).Collect(context.Background(), r, in)
				} else {
					_, e = (GCPMetricsReader{Config: c}).Collect(context.Background(), r, in)
				}
				if e == nil {
					t.Fatal("accepted changed binding/native query", mutation)
				}
			})
		}
	}
}
