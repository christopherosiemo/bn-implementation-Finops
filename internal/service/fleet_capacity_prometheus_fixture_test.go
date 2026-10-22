package service

// Prometheus backfill is synthetic fixture history. The actual server, query
// parser, counter intervals and metadata transport are exercised; this does not
// represent fourteen elapsed days of customer observation.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

var fleetCapacityPromInstances = []string{"i-77777777777777771", "i-77777777777777772", "i-77777777777777773"}

type fleetCapacityPromSeed struct {
	SchemaVersion string    `json:"schema_version"`
	Kind          string    `json:"kind"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	Cadence       int       `json:"cadence_seconds"`
	Intervals     int       `json:"complete_intervals"`
	Instances     []string  `json:"instances"`
	SHA256        string    `json:"openmetrics_sha256"`
}

func fleetCapacityPromDefinition() telemetry.Connection {
	return fleetCapacityFixtureConnection(telemetry.Binding{TenantID: "seed", ResourceID: "seed", WorkloadID: "seed", Provider: "AWS", ProviderResourceID: fleetCapacityPromInstances[0], AccountID: nativeAssessmentAccount, Region: "eu-west-1"})
}

func fleetCapacityPromValue(metric string, member, point int) string {
	switch metric {
	case "cpu_utilization", "memory_utilization":
		if member == 1 && metric == "memory_utilization" {
			return "0.95"
		}
		return "0.2"
	case "cpu_capacity":
		return "2"
	case "memory_capacity":
		return "17179869184"
	default:
		rate := int64(1000)
		if strings.HasSuffix(metric, "operations") {
			rate = 10
		}
		if metric == "request_count" {
			rate = 60
		}
		return strconv.FormatInt(10000+int64(point)*300*rate, 10)
	}
}

func fleetCapacityPromOpenMetrics(end time.Time) []byte {
	var out strings.Builder
	start := end.AddDate(0, 0, -14).Add(-600 * time.Second)
	for _, d := range fleetCapacityPromDefinition().Definitions {
		family, kind := d.Name, "gauge"
		if d.Type == "SUM" {
			family, kind = strings.TrimSuffix(family, "_total"), "counter"
		}
		fmt.Fprintf(&out, "# TYPE %s %s\n# UNIT %s %s\n", family, kind, family, d.Unit)
		for member, instance := range fleetCapacityPromInstances {
			if member == 2 && d.Metric == "memory_utilization" {
				continue // Absence is a real missing series, never a zero sample.
			}
			for at, point := start, 0; !at.After(end); at, point = at.Add(300*time.Second), point+1 {
				fmt.Fprintf(&out, "%s{instance=%q} %s %d\n", d.Name, instance, fleetCapacityPromValue(d.Metric, member, point), at.Unix())
			}
		}
	}
	out.WriteString("# TYPE process_start_time_seconds gauge\n# UNIT process_start_time_seconds seconds\n")
	for _, instance := range fleetCapacityPromInstances {
		for at := start; !at.After(end); at = at.Add(300 * time.Second) {
			fmt.Fprintf(&out, "process_start_time_seconds{instance=%q} %d %d\n", instance, start.Add(-30*24*time.Hour).Unix(), at.Unix())
		}
	}
	out.WriteString("# EOF\n")
	return []byte(out.String())
}

func TestFleetCapacityPrometheusSeed(t *testing.T) {
	if os.Getenv("FLEET_CAPACITY_SEED") != "ISOLATED_SYNTHETIC_HISTORY" {
		t.Skip("owned Prometheus seed phase only")
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	raw := fleetCapacityPromOpenMetrics(end)
	if len(raw) < 1<<20 || len(raw) > 32<<20 {
		t.Fatal("synthetic OpenMetrics source bounds")
	}
	seed := fleetCapacityPromSeed{"1", "SYNTHETIC_14_DAY_CAPACITY_FIXTURE", end.AddDate(0, 0, -14), end, 300, 4032, append([]string{}, fleetCapacityPromInstances...), telemetry.BytesHash(raw)}
	for name, body := range map[string][]byte{"history.openmetrics": raw, "history.json": func() []byte { b, _ := json.Marshal(seed); return b }()} {
		f, e := os.OpenFile(filepath.Join("/seed", name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
		if e != nil {
			t.Fatal("seed exclusive create", e)
		}
		if _, e = f.Write(body); e != nil {
			t.Fatal(e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
	}
}

// Live instrumentation supplies real scrape metadata and counts completed
// fixture work. The separate historical utilization/capacity series above are
// explicitly configured synthetic observations, not OS utilization claims.
func fleetCapacityStartExporter(t *testing.T) {
	t.Helper()
	listener, e := net.Listen("tcp", "0.0.0.0:8099")
	if e != nil {
		t.Fatal("private exporter listen", e)
	}
	var completed atomic.Uint64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", func(w http.ResponseWriter, r *http.Request) {
		completed.Add(1)
		_, _ = w.Write([]byte("completed\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
		out := bufio.NewWriter(w)
		for _, d := range fleetCapacityPromDefinition().Definitions {
			family, kind := d.Name, "gauge"
			if d.Type == "SUM" {
				family, kind = strings.TrimSuffix(family, "_total"), "counter"
			}
			fmt.Fprintf(out, "# TYPE %s %s\n# UNIT %s %s\n", family, kind, family, d.Unit)
			for n, instance := range fleetCapacityPromInstances {
				value := fleetCapacityPromValue(d.Metric, n, 4035)
				if d.Metric == "request_count" {
					value = strconv.FormatUint(10000+4035*300*60+completed.Load(), 10)
				}
				fmt.Fprintf(out, "%s{instance=%q} %s\n", d.Name, instance, value)
			}
		}
		fmt.Fprintln(out, "# TYPE process_start_time_seconds gauge\n# UNIT process_start_time_seconds seconds")
		for _, instance := range fleetCapacityPromInstances {
			fmt.Fprintf(out, "process_start_time_seconds{instance=%q} %d\n", instance, time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -44).Add(-600*time.Second).Unix())
		}
		fmt.Fprintln(out, "# EOF")
		_ = out.Flush()
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(c)
	})
}

func fleetCapacityReadPromSeed(t *testing.T) fleetCapacityPromSeed {
	t.Helper()
	raw, e := os.ReadFile("/seed/history.json")
	if e != nil || len(raw) > 4096 {
		t.Fatal("private Prometheus seed manifest unavailable")
	}
	var seed fleetCapacityPromSeed
	if json.Unmarshal(raw, &seed) != nil || seed.SchemaVersion != "1" || seed.Kind != "SYNTHETIC_14_DAY_CAPACITY_FIXTURE" || seed.Cadence != 300 || seed.Intervals != 4032 || seed.End.Sub(seed.Start) != 14*24*time.Hour || seed.End != time.Now().UTC().Truncate(24*time.Hour) || strings.Join(seed.Instances, ",") != strings.Join(fleetCapacityPromInstances, ",") {
		t.Fatal("synthetic Prometheus history manifest differs")
	}
	body, e := os.ReadFile("/seed/history.openmetrics")
	if e != nil || len(body) > 32<<20 || telemetry.BytesHash(body) != seed.SHA256 {
		t.Fatal("synthetic Prometheus seed bytes differ")
	}
	return seed
}

func fleetCapacityReadRealProm(t *testing.T, c telemetry.Connection, seed fleetCapacityPromSeed) telemetry.Batch {
	t.Helper()
	if os.Getenv("FLEET_CAPACITY_PROMETHEUS_URL") != "http://prometheus:9090" {
		t.Fatal("owned fixed Prometheus endpoint required")
	}
	reader := telemetry.PromReader{URL: "http://prometheus:9090", AllowHTTP: true, AllowPrivate: true}
	var batch telemetry.Batch
	var e error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		batch, e = reader.Read(context.Background(), c, seed.Start, seed.End)
		if e == nil {
			return batch
		}
		if !strings.Contains(e.Error(), "SOURCE_UNAVAILABLE") && !strings.Contains(e.Error(), "METADATA_REQUIRED") {
			t.Fatal("actual raw Prometheus read failed", e)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("actual Prometheus metadata did not become available", e)
	return batch
}

func TestFleetCapacityActualPrometheusRawHistory(t *testing.T) {
	if os.Getenv("FLEET_CAPACITY_PROMETHEUS_URL") == "" {
		t.Skip("owned Prometheus TSDB/exporter required")
	}
	seed := fleetCapacityReadPromSeed(t)
	fleetCapacityStartExporter(t)
	for n, instance := range fleetCapacityPromInstances {
		binding := telemetry.Binding{TenantID: "component-prom", ResourceID: "component-" + instance, WorkloadID: "component", Provider: "AWS", ProviderResourceID: instance, AccountID: nativeAssessmentAccount, Region: "eu-west-1"}
		connection := fleetCapacityFixtureConnection(binding)
		batch := fleetCapacityReadRealProm(t, connection, seed)
		wantSamples := 4035 * 11
		if n == 2 {
			wantSamples -= 4035
		}
		if len(batch.Samples) != wantSamples || len(batch.Rejections) != 0 {
			t.Fatalf("actual raw matrix sample count differs: member=%d samples=%d rejections=%d", n, len(batch.Samples), len(batch.Rejections))
		}
		for _, sample := range batch.Samples {
			if sample.Time.Unix()%300 != 0 || sample.Time.Before(seed.Start.Add(-600*time.Second)) || sample.Time.After(seed.End) || sample.Type == "SUM" && sample.Epoch == "" {
				t.Fatal("actual matrix timestamps/counter epochs were rewritten")
			}
		}
		evaluation := telemetry.EvaluateHistory(telemetry.HistoryInput{Now: time.Now().UTC(), Definitions: connection.Definitions, Samples: batch.Samples, Days: 14, Timezone: "UTC"})
		if n < 2 && evaluation.Status != "READY" || n == 2 && evaluation.Status == "READY" {
			t.Fatalf("actual Prometheus completeness differs: member=%d status=%s reasons=%v", n, evaluation.Status, evaluation.ReasonCodes)
		}
	}
}

func TestFleetCapacityPrometheusSyntheticSeedHasExactIntervalsAndNoMissingZero(t *testing.T) {
	end := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	raw := string(fleetCapacityPromOpenMetrics(end))
	if !strings.HasSuffix(raw, "# EOF\n") || strings.Contains(raw, "memory_utilization_ratio{instance=\""+fleetCapacityPromInstances[2]+"\"}") {
		t.Fatal("OpenMetrics missing series/terminator")
	}
	if strings.Count(raw, "finops_capacity_cpu_utilization_ratio{") != 4035*3 || strings.Count(raw, "finops_capacity_memory_utilization_ratio{") != 4035*2 {
		t.Fatal("synthetic exact raw point count changed")
	}
	for _, point := range []string{" " + strconv.FormatInt(end.AddDate(0, 0, -14).Add(-600*time.Second).Unix(), 10) + "\n", " " + strconv.FormatInt(end.Unix(), 10) + "\n"} {
		if !strings.Contains(raw, point) {
			t.Fatal("OpenMetrics seconds/boundary changed")
		}
	}
}
