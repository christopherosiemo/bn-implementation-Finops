package multicloud

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

type GCPMetricsReader struct{ Config Config }

func (g GCPMetricsReader) Collect(ctx context.Context, r InventoryRegistration, in MetricsRequest) (MetricsSnapshot, error) {
	c := g.Config
	if e := c.validateInventory(r); e != nil {
		return MetricsSnapshot{}, e
	}
	if e := validateMetrics(r, in, c.now()); e != nil {
		return MetricsSnapshot{}, e
	}
	if r.Provider != "GCP" {
		return MetricsSnapshot{}, errors.New("GCP_METRICS_BINDING_INVALID")
	}
	s := newMetrics(r, in, c.now())
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	identity := in.Instance
	o, native, e := c.nativeRead(ctx, http.MethodGet, computeAPI+"/projects/"+identity.ProjectID+"/zones/"+identity.Zone+"/instances/"+identity.Name, computeScope)
	if e != nil {
		return s, e
	}
	o.Kind = "GCP_METRICS_INSTANCE_BINDING"
	if e = metricsObject(&s, o); e != nil {
		return s, e
	}
	instance, e := ParseGCPInstance(r, identity.Zone, native, c.now())
	if e != nil {
		return s, e
	}
	if Hash(instance.Identity) != Hash(identity) {
		return s, errors.New("GCP_METRICS_INSTANCE_CHANGED")
	}
	if instance.ProviderCreatedAt == nil || in.Period.Start.Before(*instance.ProviderCreatedAt) {
		return s, errors.New("METRICS_RESOURCE_CREATION_WINDOW_UNPROVEN")
	}
	for _, name := range in.MetricNames {
		definition, _ := NativeMetric("GCP", name)
		o, descriptor, e := c.nativeRead(ctx, http.MethodGet, monitoringAPI+"/projects/"+identity.ProjectID+"/metricDescriptors/"+url.PathEscape(name), monitoringScope)
		if e != nil {
			return s, e
		}
		o.Kind = "GCP_NATIVE_METRIC_DESCRIPTOR"
		if e = metricsObject(&s, o); e != nil {
			return s, e
		}
		if str(descriptor, "type") != name || str(descriptor, "name") != "projects/"+identity.ProjectID+"/metricDescriptors/"+name || str(descriptor, "unit") != definition.Unit || str(descriptor, "metricKind") != definition.Kind || str(descriptor, "valueType") != definition.ValueType {
			return s, errors.New("GCP_METRIC_DESCRIPTOR_MISMATCH")
		}
		filter := `metric.type = "` + name + `" AND resource.type = "gce_instance" AND resource.labels.project_id = "` + identity.ProjectID + `" AND resource.labels.zone = "` + identity.Zone + `" AND resource.labels.instance_id = "` + identity.NumericID + `"`
		q := url.Values{"filter": {filter}, "interval.startTime": {in.Period.Start.Format(time.RFC3339Nano)}, "interval.endTime": {in.Period.End.Format(time.RFC3339Nano)}, "view": {"FULL"}, "pageSize": {"1000"}}
		seriesIndexes := map[string]int{}
		seenTokens := map[string]bool{}
		observed := false
		pointCount := 0
		for page := 0; ; page++ {
			if page >= 1000 {
				return s, errors.New("GCP_METRICS_PAGE_LIMIT")
			}
			o, d, e := c.nativeRead(ctx, http.MethodGet, monitoringAPI+"/projects/"+identity.ProjectID+"/timeSeries?"+q.Encode(), monitoringScope)
			if e != nil {
				return s, e
			}
			o.Kind = "GCP_NATIVE_METRIC_POINTS"
			if e = metricsObject(&s, o); e != nil {
				return s, e
			}
			if len(list(d["executionErrors"])) > 0 || len(list(d["unreachable"])) > 0 {
				return s, errors.New("GCP_METRICS_PARTIAL_RESULT")
			}
			for _, x := range list(d["timeSeries"]) {
				nativeSeries := obj(x)
				resource, metric := obj(nativeSeries["resource"]), obj(nativeSeries["metric"])
				labels := obj(resource["labels"])
				metricLabels := obj(metric["labels"])
				if str(resource, "type") != "gce_instance" || str(labels, "project_id") != identity.ProjectID || str(labels, "zone") != identity.Zone || str(labels, "instance_id") != identity.NumericID || str(metric, "type") != name || str(nativeSeries, "metricKind") != definition.Kind || str(nativeSeries, "valueType") != definition.ValueType || str(nativeSeries, "unit") != "" && str(nativeSeries, "unit") != definition.Unit || str(metricLabels, "instance_name") != "" && str(metricLabels, "instance_name") != identity.Name {
					return s, errors.New("GCP_METRIC_SERIES_BINDING_INVALID")
				}
				attributes := Document{"resource": resource, "metric": metric}
				id := Hash(Document{"instance": identity, "definition": definition, "attributes": attributes})
				index, ok := seriesIndexes[id]
				if !ok {
					index = len(s.Series)
					seriesIndexes[id] = index
					s.Series = append(s.Series, MetricSeries{ID: id, Definition: definition, Attributes: attributes, Points: []MetricPoint{}})
				}
				points, e := ParseGCPMetricPoints(definition, list(nativeSeries["points"]), in.Period, o.SHA256)
				if e != nil {
					return s, e
				}
				pointCount += len(points)
				if pointCount > 200000 || len(s.Series) > 10000 {
					return s, errors.New("METRICS_POINT_LIMIT")
				}
				if e = mergeMetricPoints(&s.Series[index], points); e != nil {
					return s, e
				}
				observed = observed || len(points) > 0
			}
			token := str(d, "nextPageToken")
			if token == "" {
				break
			}
			if len(token) > 4096 || seenTokens[token] {
				return s, errors.New("GCP_METRICS_PAGINATION_INVALID")
			}
			seenTokens[token] = true
			q.Set("pageToken", token)
		}
		if !observed {
			s.ReasonCodes = append(s.ReasonCodes, "METRIC_OBSERVATIONS_MISSING")
		}
	}
	return sealMetrics(s), nil
}
func mergeMetricPoints(series *MetricSeries, points []MetricPoint) error {
	seen := map[string]int{}
	key := func(p MetricPoint) string { return Hash(Document{"time": p.Time, "start": p.StartTime}) }
	semantic := func(p MetricPoint) string {
		return Hash(Document{"time": p.Time, "start": p.StartTime, "value": p.Value, "histogram": p.Histogram, "reasons": p.ReasonCodes})
	}
	for i, p := range series.Points {
		seen[key(p)] = i
	}
	for _, p := range points {
		if i, ok := seen[key(p)]; ok {
			if semantic(series.Points[i]) != semantic(p) {
				return errors.New("METRIC_NATIVE_POINT_CONFLICT")
			}
			series.Points[i].SourceSHA256 = unique(append(series.Points[i].SourceSHA256, p.SourceSHA256...))
			continue
		}
		seen[key(p)] = len(series.Points)
		series.Points = append(series.Points, p)
	}
	return nil
}
func ParseGCPMetricPoints(d MetricDefinition, raw []any, p Period, hash string) ([]MetricPoint, error) {
	if len(raw) > 200000 || !(d.Kind == "GAUGE" || d.Kind == "DELTA" || d.Kind == "CUMULATIVE") {
		return nil, errors.New("GCP_NATIVE_METRIC_KIND_INVALID")
	}
	out := []MetricPoint{}
	for _, v := range raw {
		native := obj(v)
		interval := obj(native["interval"])
		end, e := instant(str(interval, "endTime"))
		if e != nil || end.Before(p.Start) || end.After(p.End) {
			return nil, errors.New("GCP_METRIC_TIMESTAMP_INVALID")
		}
		point := MetricPoint{Time: end, SourceSHA256: []string{hash}, ReasonCodes: []string{}, Native: native}
		if text := str(interval, "startTime"); text != "" {
			start, e := instant(text)
			if e != nil || start.After(end) || d.Kind != "GAUGE" && !start.Before(end) {
				return nil, errors.New("GCP_METRIC_EPOCH_INVALID")
			}
			point.StartTime = &start
			if start.Before(p.Start) && d.Kind == "DELTA" {
				point.ReasonCodes = append(point.ReasonCodes, "NATIVE_INTERVAL_EXTENDS_BEFORE_QUERY_WINDOW")
			}
		} else if d.Kind != "GAUGE" {
			return nil, errors.New("GCP_METRIC_EPOCH_REQUIRED")
		}
		value := obj(native["value"])
		fields := 0
		for _, key := range []string{"int64Value", "doubleValue", "distributionValue", "stringValue", "boolValue"} {
			if _, ok := value[key]; ok {
				fields++
			}
		}
		if fields == 0 {
			point.ReasonCodes = append(point.ReasonCodes, "METRIC_VALUE_MISSING")
			out = append(out, point)
			continue
		}
		if fields != 1 {
			return nil, errors.New("GCP_METRIC_VALUE_AMBIGUOUS")
		}
		switch d.ValueType {
		case "INT64":
			text, ok := value["int64Value"].(string)
			n, e := strconv.ParseInt(text, 10, 64)
			if !ok || e != nil || strconv.FormatInt(n, 10) != text || d.Kind != "GAUGE" && n < 0 {
				return nil, errors.New("GCP_METRIC_INTEGER_INVALID")
			}
			point.Value = &text
		case "DOUBLE":
			value, e := decimal(value["doubleValue"])
			if e != nil {
				return nil, errors.New("GCP_METRIC_DOUBLE_INVALID")
			}
			if d.Kind != "GAUGE" {
				n, _ := new(big.Rat).SetString(value)
				if n.Sign() < 0 {
					return nil, errors.New("GCP_COUNTER_NEGATIVE_SEGMENT")
				}
			}
			point.Value = &value
		case "DISTRIBUTION":
			hist, e := ParseGCPDistribution(obj(value["distributionValue"]))
			if e != nil {
				return nil, e
			}
			point.Histogram = hist
		default:
			return nil, errors.New("GCP_METRIC_VALUE_TYPE_UNSUPPORTED")
		}
		out = append(out, point)
	}
	return out, nil
}

// EpochChanges makes native cumulative reset boundaries visible without
// subtracting counters or inventing reset-safe interval counts.
func EpochChanges(points []MetricPoint) []time.Time {
	copy := append([]MetricPoint{}, points...)
	sortMetricPoints(copy)
	out := []time.Time{}
	var prior *time.Time
	for _, p := range copy {
		if p.StartTime == nil {
			continue
		}
		if prior != nil && !prior.Equal(*p.StartTime) {
			out = append(out, p.Time)
		}
		value := *p.StartTime
		prior = &value
	}
	return out
}
func sortMetricPoints(points []MetricPoint) {
	sort.Slice(points, func(i, j int) bool { return points[i].Time.Before(points[j].Time) })
}
