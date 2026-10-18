package native

import (
	"context"
	"encoding/json"
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
