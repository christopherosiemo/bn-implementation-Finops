package multicloud

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AzureMetricsReader struct{ Config Config }

func (a AzureMetricsReader) Collect(ctx context.Context, r InventoryRegistration, in MetricsRequest) (MetricsSnapshot, error) {
	c := a.Config
	if e := c.validateInventory(r); e != nil {
		return MetricsSnapshot{}, e
	}
	if e := validateMetrics(r, in, c.now()); e != nil {
		return MetricsSnapshot{}, e
	}
	if r.Provider != "AZURE" {
		return MetricsSnapshot{}, errors.New("AZURE_METRICS_BINDING_INVALID")
	}
	s := newMetrics(r, in, c.now())
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resource := "https://management.azure.com" + in.Instance.ResourceID
	o, native, e := c.nativeRead(ctx, http.MethodGet, resource+"?api-version="+azureComputeAPI, armScope)
	if e != nil {
		return s, e
	}
	o.Kind = "AZURE_METRICS_INSTANCE_BINDING"
	if e = metricsObject(&s, o); e != nil {
		return s, e
	}
	instance, e := ParseAzureInstance(r, native, Document{}, c.now())
	if e != nil {
		return s, e
	}
	if Hash(instance.Identity) != Hash(in.Instance) {
		return s, errors.New("AZURE_METRICS_INSTANCE_CHANGED")
	}
	if instance.ProviderCreatedAt == nil || in.Period.Start.Before(*instance.ProviderCreatedAt) {
		return s, errors.New("METRICS_RESOURCE_CREATION_WINDOW_UNPROVEN")
	}
	o, metadata, e := c.nativeRead(ctx, http.MethodGet, resource+"/providers/Microsoft.Insights/metricDefinitions?api-version=2018-01-01", armScope)
	if e != nil {
		return s, e
	}
	o.Kind = "AZURE_NATIVE_METRIC_DEFINITIONS"
	if e = metricsObject(&s, o); e != nil {
		return s, e
	}
	definitions := map[string]Document{}
	for _, x := range list(metadata["value"]) {
		d := obj(x)
		name := str(obj(d["name"]), "value")
		if _, ok := definitions[name]; ok {
			return s, errors.New("AZURE_METRIC_DEFINITION_AMBIGUOUS")
		}
		definitions[name] = d
	}
	interval := "PT" + time.Duration(in.IntervalSeconds*int64(time.Second)).String()
	switch in.IntervalSeconds {
	case 60:
		interval = "PT1M"
	case 300:
		interval = "PT5M"
	case 3600:
		interval = "PT1H"
	}
	for _, name := range in.MetricNames {
		definition, _ := NativeMetric("AZURE", name)
		meta, ok := definitions[name]
		aggregation := metricAggregation(definition)
		if !ok || str(meta, "unit") != definition.Unit || !containsStrings(meta["supportedAggregationTypes"], aggregation) || !strings.EqualFold(str(meta, "id"), in.Instance.ResourceID+"/providers/Microsoft.Insights/metricDefinitions/"+name) {
			return s, errors.New("AZURE_METRIC_DEFINITION_MISMATCH")
		}
		grain := false
		for _, x := range list(meta["metricAvailabilities"]) {
			if str(obj(x), "timeGrain") == interval {
				grain = true
			}
		}
		if !grain {
			return s, errors.New("AZURE_NATIVE_TIMEGRAIN_UNSUPPORTED")
		}
		q := url.Values{"api-version": {"2023-10-01"}, "metricnamespace": {"Microsoft.Compute/virtualMachines"}, "metricnames": {name}, "aggregation": {aggregation}, "interval": {interval}, "timespan": {in.Period.Start.Format(time.RFC3339Nano) + "/" + in.Period.End.Format(time.RFC3339Nano)}, "AutoAdjustTimegrain": {"false"}, "ValidateDimensions": {"true"}}
		o, d, e := c.nativeRead(ctx, http.MethodGet, resource+"/providers/Microsoft.Insights/metrics?"+q.Encode(), armScope)
		if e != nil {
			return s, e
		}
		o.Kind = "AZURE_NATIVE_METRIC_POINTS"
		if e = metricsObject(&s, o); e != nil {
			return s, e
		}
		if str(d, "interval") != interval || !strings.EqualFold(str(d, "namespace"), "Microsoft.Compute/virtualMachines") || str(d, "resourceregion") != instance.Location || !samePeriodText(str(d, "timespan"), in.Period) {
			return s, errors.New("AZURE_METRIC_QUERY_CHANGED")
		}
		values := list(d["value"])
		if len(values) != 1 {
			return s, errors.New("AZURE_METRIC_RESULT_SCOPE_INVALID")
		}
		metric := obj(values[0])
		if str(obj(metric["name"]), "value") != name || str(metric, "unit") != definition.Unit || str(metric, "errorCode") != "Success" || !strings.EqualFold(str(metric, "id"), in.Instance.ResourceID+"/providers/Microsoft.Insights/metrics/"+name) {
			return s, errors.New("AZURE_METRIC_RESULT_BINDING_INVALID")
		}
		series := list(metric["timeseries"])
		if len(series) == 0 {
			s.ReasonCodes = append(s.ReasonCodes, "METRIC_OBSERVATIONS_MISSING")
			s.Series = append(s.Series, MetricSeries{ID: Hash(Document{"metric": definition, "instance": in.Instance}), Definition: definition, Attributes: Document{}, Points: []MetricPoint{}})
		}
		for _, x := range series {
			nativeSeries := obj(x)
			attributes := Document{"native_dimensions": nativeSeries["metadatavalues"]}
			result := MetricSeries{ID: Hash(Document{"metric": definition, "instance": in.Instance, "attributes": attributes}), Definition: definition, Attributes: attributes, Points: []MetricPoint{}}
			points, e := ParseAzureMetricPoints(definition, list(nativeSeries["data"]), in.Period, in.IntervalSeconds, o.SHA256)
			if e != nil {
				return s, e
			}
			result.Points = points
			s.Series = append(s.Series, result)
			if len(s.Series) > 10000 {
				return s, errors.New("METRICS_SERIES_LIMIT")
			}
		}
	}
	return sealMetrics(s), nil
}
func containsStrings(raw any, want string) bool {
	for _, v := range list(raw) {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
func samePeriodText(raw string, p Period) bool {
	parts := strings.Split(raw, "/")
	if len(parts) != 2 {
		return false
	}
	start, e := instant(parts[0])
	end, e2 := instant(parts[1])
	return e == nil && e2 == nil && start.Equal(p.Start) && end.Equal(p.End)
}
func ParseAzureMetricPoints(d MetricDefinition, raw []any, p Period, interval int64, hash string) ([]MetricPoint, error) {
	if len(raw) > 200000 {
		return nil, errors.New("METRICS_POINT_LIMIT")
	}
	key := strings.ToLower(metricAggregation(d))
	if key == "" || interval <= 0 {
		return nil, errors.New("AZURE_METRIC_AGGREGATION_INVALID")
	}
	out := []MetricPoint{}
	seen := map[string]bool{}
	for _, v := range raw {
		native := obj(v)
		start, e := instant(str(native, "timeStamp"))
		end := start.Add(time.Duration(interval) * time.Second)
		if e != nil || start.Before(p.Start) || !start.Before(p.End) || end.After(p.End) || seen[start.Format(time.RFC3339Nano)] {
			return nil, errors.New("AZURE_METRIC_TIMESTAMP_INVALID")
		}
		seen[start.Format(time.RFC3339Nano)] = true
		for _, other := range []string{"minimum", "maximum", "average", "total", "count"} {
			if other != key && native[other] != nil {
				return nil, errors.New("AZURE_METRIC_AGGREGATION_CHANGED")
			}
		}
		point := MetricPoint{Time: end, StartTime: &start, SourceSHA256: []string{hash}, ReasonCodes: []string{}, Native: native}
		value, e := moneyPtr(native[key])
		if e != nil {
			return nil, errors.New("AZURE_METRIC_VALUE_INVALID")
		}
		point.Value = value
		if value == nil {
			point.ReasonCodes = append(point.ReasonCodes, "METRIC_VALUE_MISSING")
		}
		out = append(out, point)
	}
	return out, nil
}
