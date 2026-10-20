package provider

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"net/http"
	"net/url"
	"time"
)

type objectTransport func(*http.Request) (*http.Response, error)

func (f objectTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// S3AccessMetrics uses only already-configured metric IDs and exact filter
// scopes. Sum/SampleCount remain provider period statistics, never proof that
// every request was accounted for or a missing period had zero requests.
func (a *AWS) S3AccessMetrics(ctx context.Context, s objectstorage.Scope, b objectstorage.Bucket, start, end time.Time) (model.Document, error) {
	if b.AccountID != s.AccountID || b.Region != s.Region || start.IsZero() || !start.Before(end) || end.Sub(start) > 90*24*time.Hour || end.After(time.Now().UTC()) {
		return nil, errors.New("S3_ACCESS_METRIC_SCOPE_INVALID")
	}
	cfg, capture, e := objectSDK(a, s)
	if e != nil {
		return nil, e
	}
	if e = objectIdentity(ctx, cfg, s); e != nil {
		return nil, e
	}
	read := *a
	read.client = &http.Client{Transport: objectTransport(capture.Do), Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	observation := b.Configurations["metrics"]
	if observation.Status != "OBSERVED" {
		return model.Document{"state": "ACCESS_UNKNOWN", "complete": false, "reason_code": "S3_REQUEST_METRICS_NOT_COMMISSIONED", "series": []any{}}, nil
	}
	configs := objectstorage.Rows(objectstorage.Doc(observation.Value)["Configurations"])
	if len(configs) == 0 {
		return model.Document{"state": "ACCESS_UNKNOWN", "complete": false, "reason_code": "S3_REQUEST_METRICS_NOT_COMMISSIONED", "series": []any{}}, nil
	}
	if len(configs) > 20 {
		return nil, errors.New("S3_ACCESS_METRIC_CONFIGURATION_LIMIT")
	}
	series := []model.Document{}
	for _, c := range configs {
		id := model.String(c, "Id")
		if id == "" {
			return nil, errors.New("S3_METRIC_CONFIGURATION_INVALID")
		}
		for _, metric := range []struct{ name, unit string }{{"AllRequests", "Count"}, {"GetRequests", "Count"}, {"BytesDownloaded", "Bytes"}, {"BytesUploaded", "Bytes"}, {"4xxErrors", "Count"}, {"5xxErrors", "Count"}} {
			v := url.Values{"Namespace": {"AWS/S3"}, "MetricName": {metric.name}, "Dimensions.member.1.Name": {"BucketName"}, "Dimensions.member.1.Value": {b.Name}, "Dimensions.member.2.Name": {"FilterId"}, "Dimensions.member.2.Value": {id}, "StartTime": {start.UTC().Format(time.RFC3339)}, "EndTime": {end.UTC().Format(time.RFC3339)}, "Period": {"3600"}, "Statistics.member.1": {"Sum"}, "Statistics.member.2": {"SampleCount"}, "Unit": {metric.unit}}
			var out struct {
				Result struct {
					Points []struct {
						Timestamp   string `xml:"Timestamp"`
						Sum         string `xml:"Sum"`
						SampleCount string `xml:"SampleCount"`
						Unit        string `xml:"Unit"`
					} `xml:"Datapoints>member"`
				} `xml:"GetMetricStatisticsResult"`
			}
			e = read.cloudWatchQuery(objectContext(ctx, "GetMetricStatistics"), s.Region, v, &out)
			if e != nil {
				return nil, errors.New("S3_REQUEST_METRICS_UNAVAILABLE")
			}
			points := []model.Document{}
			seen := map[string]bool{}
			for _, p := range out.Result.Points {
				at, e := time.Parse(time.RFC3339Nano, p.Timestamp)
				if e != nil || at.Before(start) || !at.Before(end) || p.Unit != metric.unit || !metricNumber.MatchString(p.Sum) || !metricNumber.MatchString(p.SampleCount) || seen[at.UTC().Format(time.RFC3339Nano)] {
					return nil, errors.New("S3_REQUEST_METRIC_POINT_INVALID")
				}
				seen[at.UTC().Format(time.RFC3339Nano)] = true
				points = append(points, model.Document{"source_time": at.UTC(), "sum": p.Sum, "sample_count": p.SampleCount, "unit": p.Unit, "period_seconds": 3600})
			}
			series = append(series, model.Document{"configuration_id": id, "filter": c["Filter"], "metric": metric.name, "statistic": "Sum", "sample_count_preserved": true, "unit": metric.unit, "period_seconds": 3600, "points": points, "missing_periods": "UNKNOWN", "accounting_complete": false})
		}
	}
	raw, _ := json.Marshal(model.Document{"scope": s, "frames": capture.frames})
	return model.Document{"state": "ACCESS_PATTERN_OBSERVED", "start": start, "end": end, "complete": false, "request_accounting_complete": false, "observation_basis": "AWS_S3_BEST_EFFORT_CONFIGURED_REQUEST_METRICS", "series": series, "raw": raw, "raw_sha256": objectstorage.BytesHash(raw)}, nil
}
