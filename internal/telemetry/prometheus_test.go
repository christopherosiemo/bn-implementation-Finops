package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func promReply(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": data})
}
func promMatrixReply(w http.ResponseWriter, name string, labels map[string]string, values ...[]any) {
	m := mergeLabels(labels)
	m["__name__"] = name
	promReply(w, map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": m, "values": values}}})
}
func TestPrometheusReadsActualRangeSamplesNoHeldValues(t *testing.T) {
	c := testConnection("PROMETHEUS")
	c.Definitions[0].Attributes = map[string]string{"instance": "i-0123456789abcdef0"}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Form.Get("query"))
		if r.URL.Path == "/api/v1/metadata" {
			promReply(w, map[string]any{"cpu_utilization": []any{map[string]any{"type": "gauge", "unit": "ratio"}}})
			return
		}
		q := r.Form.Get("query")
		if strings.Contains(q, "query_range") || strings.Contains(q, "increase(") || strings.Contains(q, "rate(") {
			t.Errorf("non-raw query: %s", q)
		}
		if !strings.HasPrefix(q, `cpu_utilization{instance="i-0123456789abcdef0"}[`) {
			t.Errorf("selector not exact: %s", q)
		}
		promMatrixReply(w, "cpu_utilization", c.Definitions[0].Attributes, []any{float64(now.Add(-30*time.Second).UnixNano()) / 1e9, "0.1"}, []any{float64(now.Add(-14*time.Second).UnixNano()) / 1e9, "0.2"}, []any{float64(now.Add(-time.Second).UnixNano()) / 1e9, "0.3"})
	}))
	defer srv.Close()
	p := PromReader{URL: srv.URL, AllowHTTP: true, AllowPrivate: true, Now: func() time.Time { return now }}
	b, e := p.Read(context.Background(), c, now.Add(-time.Minute), now)
	if e != nil || len(b.Samples) != 3 || len(calls) != 2 {
		t.Fatalf("read: %v %+v", e, calls)
	}
	if b.Samples[1].Time.Sub(b.Samples[0].Time) != 16*time.Second || b.Samples[2].Time.Sub(b.Samples[1].Time) != 13*time.Second {
		t.Fatal("scrape timestamps resampled")
	}
	if b.RawSHA256 != BytesHash(b.Raw) || len(b.Raw) == 0 || strings.Contains(string(b.Raw), "Authorization") {
		t.Fatal("raw response commitment wrong")
	}
	if calls[0][:3] != "GET" || !strings.HasPrefix(calls[1], "POST /api/v1/query") {
		t.Fatalf("wrong native API methods: %+v", calls)
	}
}
func TestPrometheusRejectsRedirectBindingMetadataAndNonfinite(t *testing.T) {
	c := testConnection("PROMETHEUS")
	now := time.Now().UTC()
	var forwarded atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer receiver.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, receiver.URL, http.StatusFound) }))
	defer redirect.Close()
	p := PromReader{URL: redirect.URL, AllowHTTP: true, AllowPrivate: true, Headers: http.Header{"Authorization": []string{"Bearer scoped-secret"}}}
	if _, e := p.Read(context.Background(), c, now.Add(-time.Minute), now); e == nil || forwarded.Load() != 0 {
		t.Fatal("redirect leaked source request")
	}
	for _, tc := range []string{"metadata", "labels", "nan"} {
		t.Run(tc, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/metadata" {
					unit := "ratio"
					if tc == "metadata" {
						unit = "percent"
					}
					promReply(w, map[string]any{"cpu_utilization": []any{map[string]any{"type": "gauge", "unit": unit}}})
					return
				}
				labels := map[string]string{"service": "checkout"}
				if tc == "labels" {
					labels["service"] = "other"
				}
				value := "0.2"
				if tc == "nan" {
					value = "NaN"
				}
				promMatrixReply(w, "cpu_utilization", labels, []any{now.Unix(), value})
			}))
			defer srv.Close()
			p.URL = srv.URL
			if _, e := p.Read(context.Background(), c, now.Add(-time.Minute), now); e == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
	for _, endpoint := range []string{"http://169.254.169.254/latest/meta-data", "https://user:secret@example.com", "https://example.com?target=elsewhere", "http://example.com", "https://127.0.0.1"} {
		if _, e := (PromReader{URL: endpoint}).endpoint(); e == nil {
			t.Fatalf("unsafe endpoint accepted %s", endpoint)
		}
	}
}
func TestPrometheusClassicHistogramRequiresEpochAndAllBuckets(t *testing.T) {
	c := testConnection("PROMETHEUS")
	c.Definitions = []Definition{{ID: "latency", Version: "1", Metric: "latency", Name: "request_duration", Type: "HISTOGRAM", Unit: "seconds", CadenceSeconds: 15, MaxGapSeconds: 30, Attributes: map[string]string{"instance": "one", "route": "checkout"}, EpochMetric: "process_start_time_seconds", EpochAttributes: map[string]string{"instance": "one"}}}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	omitInf := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/api/v1/metadata" {
			promReply(w, map[string]any{"request_duration": []any{map[string]any{"type": "histogram", "unit": "seconds"}}})
			return
		}
		q := r.Form.Get("query")
		if strings.HasPrefix(q, "process_start_time_seconds") {
			if strings.Contains(q, "route") {
				t.Error("epoch selector included route")
			}
			promMatrixReply(w, "process_start_time_seconds", map[string]string{"instance": "one"}, []any{now.Add(-15 * time.Second).Unix(), fmt.Sprint(now.Add(-time.Hour).Unix())}, []any{now.Unix(), fmt.Sprint(now.Add(-time.Hour).Unix())})
			return
		}
		if strings.HasPrefix(q, "request_duration_count") {
			promMatrixReply(w, "request_duration_count", c.Definitions[0].Attributes, []any{now.Add(-15 * time.Second).Unix(), "100"}, []any{now.Unix(), "200"})
			return
		}
		series := []any{}
		for _, bucket := range []struct{ le, a, b string }{{"0.1", "90", "180"}, {"1", "100", "199"}, {"+Inf", "100", "200"}} {
			if omitInf && bucket.le == "+Inf" {
				continue
			}
			labels := mergeLabels(c.Definitions[0].Attributes, map[string]string{"__name__": "request_duration_bucket", "le": bucket.le})
			series = append(series, map[string]any{"metric": labels, "values": [][]any{{now.Add(-15 * time.Second).Unix(), bucket.a}, {now.Unix(), bucket.b}}})
		}
		promReply(w, map[string]any{"resultType": "matrix", "result": series})
	}))
	defer srv.Close()
	p := PromReader{URL: srv.URL, AllowHTTP: true, AllowPrivate: true, Now: func() time.Time { return now }}
	b, e := p.Read(context.Background(), c, now.Add(-time.Minute), now)
	if e != nil || len(b.Samples) != 2 || len(b.Rejections) != 0 {
		t.Fatalf("histogram read %v %+v", e, b.Rejections)
	}
	segments := Segments(b.Samples, c.Definitions)
	h := segments[1].Histogram
	if h == nil || h.Count != 100 || h.BucketCounts[0] != 90 || h.BucketCounts[1] != 9 || h.BucketCounts[2] != 1 {
		t.Fatalf("classic histogram differencing incorrect: %+v", segments)
	}
	omitInf = true
	b, e = p.Read(context.Background(), c, now.Add(-time.Minute), now)
	if e != nil || len(b.Samples) != 0 || len(b.Rejections) != 2 {
		t.Fatalf("missing bucket accepted: %v %+v", e, b)
	}
}
