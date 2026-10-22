package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func nativeStorageBatchFixture() telemetry.Batch {
	return telemetry.Batch{SchemaVersion: "1", ConnectionID: "connection-a", ConfigHash: strings.Repeat("c", 64), RawSHA256: strings.Repeat("a", 64), Binding: telemetry.Binding{TenantID: "tenant-a", WorkloadID: "workload-a", ResourceID: "resource-a", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, Samples: []telemetry.Sample{
		{ID: "sample-z", DefinitionID: "definition-z", StreamID: "stream-z", Metric: "cpu", Unit: "ratio", Statistic: "gauge", Time: time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC), Value: "0.25", RawSHA256: strings.Repeat("a", 64)},
		{ID: "sample-a", DefinitionID: "definition-a", StreamID: "stream-a", Metric: "network", Unit: "bytes", Statistic: "sum", Time: time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC), Value: "0", Attributes: map[string]string{"source": "provider-\u03b1"}, RawSHA256: strings.Repeat("a", 64)},
		{ID: "sample-m", DefinitionID: "definition-m", StreamID: "stream-m", Metric: "memory", Unit: "bytes", Statistic: "gauge", Time: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Value: "1024", RawSHA256: strings.Repeat("a", 64)},
	}}
}

func TestNativeAnalyticsShrinkKeepsOriginalRowsAndReplay(t *testing.T) {
	batch := nativeStorageBatchFixture()
	before, _ := json.Marshal(batch)
	hash := telemetry.CanonicalHash(batch)
	var sampleBody, sampleQuery, manifestBody []byte
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		query := r.URL.Query()
		if r.Method != http.MethodPost || query.Get("insert_deduplicate") != "1" || query.Get("date_time_input_format") != "best_effort" {
			t.Error("existing acknowledged JSONEachRow insertion policy changed")
		}
		for _, key := range []string{"input_format_parallel_parsing", "max_insert_threads", "max_insert_block_size", "max_insert_block_size_bytes", "min_insert_block_size_rows", "min_insert_block_size_bytes", "use_strict_insert_block_limits"} {
			if query.Has(key) {
				t.Error("column shrinking changed block segmentation", key)
			}
		}
		if query.Get("query") == "INSERT INTO native_metric_samples FORMAT JSONEachRow" {
			if query.Get("shrink_over_allocated_columns_min_waste_ratio") != "1.1" || query.Get("shrink_over_allocated_columns_min_waste_bytes") != "1048576" || query.Get("insert_deduplication_token") != "tenant-a:batch-a:"+hash {
				t.Error("fixed sample allocation settings or original token changed")
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			for i, sample := range batch.Samples {
				var row model.Document
				if decoder.Decode(&row) != nil || model.String(row, "sample_id") != sample.ID || model.String(row, "canonical_hash") != hash || model.String(row, "tenant_id") != batch.Binding.TenantID || model.String(row, "batch_id") != "batch-a" || model.String(row, "resource_id") != batch.Binding.ResourceID || model.String(row, "workload_id") != batch.Binding.WorkloadID || model.String(row, "connection_id") != batch.ConnectionID || model.String(row, "config_hash") != batch.ConfigHash || model.String(row, "raw_sha256") != batch.RawSHA256 {
					t.Error("complete original row/order/binding was changed", i)
				}
				payload, _ := json.Marshal(sample)
				if model.String(row, "payload") != string(payload) {
					t.Error("original typed sample payload changed", i)
				}
			}
			var extra model.Document
			if decoder.Decode(&extra) != io.EOF {
				t.Error("unexpected extra sample row")
			}
			if sampleBody == nil {
				sampleBody, sampleQuery = append([]byte{}, raw...), []byte(r.URL.RawQuery)
			} else if !bytes.Equal(sampleBody, raw) || !bytes.Equal(sampleQuery, []byte(r.URL.RawQuery)) {
				t.Error("replay changed the original request body/order/token/settings")
			}
		} else if query.Get("query") == "INSERT INTO native_metric_batches FORMAT JSONEachRow" {
			if query.Has("shrink_over_allocated_columns_min_waste_ratio") || query.Has("shrink_over_allocated_columns_min_waste_bytes") || query.Get("insert_deduplication_token") != "tenant-a:batch-a:batch:"+hash {
				t.Error("manifest policy/token changed")
			}
			var row model.Document
			if json.Unmarshal(raw, &row) != nil || model.Number(row, "sample_count") != int64(len(batch.Samples)) || model.String(row, "canonical_hash") != hash {
				t.Error("manifest omits the complete original population")
			}
			if manifestBody == nil {
				manifestBody = append([]byte{}, raw...)
			} else if !bytes.Equal(manifestBody, raw) {
				t.Error("replay changed original manifest bytes")
			}
		} else {
			t.Error("unexpected analytics operation")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	storage := &Storage{Database: "finops", AnalyticsURL: server.URL, Client: server.Client()}
	for attempt := 0; attempt < 2; attempt++ {
		ref, err := storage.WriteFacts(context.Background(), "tenant-a", "batch-a", batch)
		if err != nil || model.String(ref, "canonical_hash") != hash || model.Number(ref, "sample_count") != int64(len(batch.Samples)) {
			t.Fatal("complete analytics publication/replay failed", err)
		}
	}
	after, _ := json.Marshal(batch)
	if calls != 4 || !bytes.Equal(before, after) {
		t.Fatal("writer changed caller data or the two acknowledged request boundary")
	}
}

func TestNativeAnalyticsRejectedSamplesDoNotPublishManifest(t *testing.T) {
	batch := nativeStorageBatchFixture()
	var firstBody, firstQuery []byte
	calls, manifests := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(r.URL.Query().Get("query"), "native_metric_batches") {
			manifests++
			w.WriteHeader(http.StatusOK)
			return
		}
		if calls == 1 {
			firstBody, firstQuery = append([]byte{}, raw...), []byte(r.URL.RawQuery)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !bytes.Equal(firstBody, raw) || !bytes.Equal(firstQuery, []byte(r.URL.RawQuery)) {
			t.Error("failed insertion retry changed original rows/order/token/settings")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	storage := &Storage{Database: "finops", AnalyticsURL: server.URL, Client: server.Client()}
	if ref, err := storage.WriteFacts(context.Background(), "tenant-a", "batch-a", batch); err == nil || err.Error() != "TELEMETRY_ANALYTICS_WRITE_REJECTED" || ref != nil || calls != 1 || manifests != 0 {
		t.Fatal("rejected samples published an analytics manifest or success")
	}
	if ref, err := storage.WriteFacts(context.Background(), "tenant-a", "batch-a", batch); err != nil || ref == nil || calls != 3 || manifests != 1 {
		t.Fatal("exact original retry did not finish the acknowledged manifest", err)
	}
}

func TestPinnedNativeObjectScopeAndIntegrity(t *testing.T) {
	ctx := context.Background()
	raw := []byte("original provider bytes")
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method == "PUT" {
			w.Header().Set("X-Amz-Version-Id", "pinned-version")
			w.WriteHeader(200)
			return
		}
		if r.URL.Query().Get("versionId") != "pinned-version" || !strings.HasPrefix(r.URL.Path, "/raw/tenant/tenant-a/native/batch-a/") {
			t.Error("read did not pin original object and tenant")
		}
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	cfg := aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("fixture", "fixture", ""), HTTPClient: srv.Client()}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(srv.URL); o.UsePathStyle = true })
	s := &Storage{S3: client, Bucket: "raw"}
	ref, err := s.Archive(ctx, "tenant-a", "wire", "batch-a", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Read(ctx, "tenant-a", ref); err != nil {
		t.Fatal(err)
	}
	before := requests
	if _, err = s.Read(ctx, "tenant-b", ref); err == nil || requests != before {
		t.Fatal("cross-tenant object reached transport")
	}
	ref["body_sha256"] = strings.Repeat("0", 64)
	if _, err = s.Read(ctx, "tenant-a", ref); err == nil {
		t.Fatal("altered bytes accepted")
	}
}

func TestEmptyNativeBatchRequiresAnalyticsAcknowledgement(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("query") != "INSERT INTO native_metric_batches FORMAT JSONEachRow" {
			t.Error("empty batch should persist its analytics manifest")
		}
		var body model.Document
		if json.NewDecoder(r.Body).Decode(&body) != nil || model.Number(body, "sample_count") != 0 || model.String(body, "tenant_id") != "tenant-a" {
			t.Error("manifest scope changed")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	s := &Storage{Database: "finops", AnalyticsURL: srv.URL, Client: srv.Client()}
	b := telemetry.Batch{Binding: telemetry.Binding{TenantID: "tenant-a"}, CollectedAt: time.Now()}
	if _, err := s.WriteFacts(context.Background(), "tenant-a", "batch-a", b); err == nil || calls != 1 {
		t.Fatal("analytics outage accepted as empty evidence")
	}
	if _, err := s.WriteFacts(context.Background(), "tenant-b", "batch-a", b); err == nil || calls != 1 {
		t.Fatal("cross-tenant analytics write reached transport")
	}
}
