package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvidenceIsTenantBoundAndRawPrecedesCanonical(t *testing.T) {
	calls := []string{}
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "raw")
		if !strings.Contains(r.URL.Path, "/raw/tenant/tenant-a/raw/") {
			t.Errorf("unscoped key %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Error("evidence request is unsigned")
		}
		if r.Header.Get("Content-MD5") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Error("Object Lock payload checksums are absent")
		}
		w.WriteHeader(200)
	}))
	defer storage.Close()
	analytics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "canonical")
		body, _ := io.ReadAll(r.Body)
		var row model.Document
		if e := json.Unmarshal(body, &row); e != nil {
			t.Error(e)
		}
		if row["tenant_id"] != "tenant-a" {
			t.Error("analytics tenant was not enforced")
		}
		w.WriteHeader(200)
	}))
	defer analytics.Close()
	t.Setenv("OBJECT_ENDPOINT", storage.URL)
	t.Setenv("OBJECT_BUCKET_RAW", "raw")
	t.Setenv("OBJECT_ACCESS_KEY", "test-only")
	t.Setenv("OBJECT_SECRET_KEY", "test-only")
	t.Setenv("CLICKHOUSE_URL", analytics.URL)
	canonical := model.Document{"records": []model.Document{{"ChargePeriodStart": "2026-09-01T00:00:00Z", "x_SourceRecordId": "r1", "x_SourceVersion": "v1", "BilledCost": "0.100000000000", "EffectiveCost": "0.100000000000", "BillingCurrency": "GBP", "tenant_id": "tenant-attacker"}}}
	if e := PersistEvidence(context.Background(), "tenant-a", "source", model.Document{"secret": "not logged"}, canonical); e != nil {
		t.Fatal(e)
	}
	if strings.Join(calls, ",") != "raw,canonical" {
		t.Fatalf("wrong persistence order %v", calls)
	}
	if e := PersistEvidence(context.Background(), "../tenant-b", "source", nil, nil); e == nil {
		t.Fatal("path traversal tenant accepted")
	}
}

func TestRawFailureDoesNotPublishAnalytics(t *testing.T) {
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer storage.Close()
	t.Setenv("OBJECT_ENDPOINT", storage.URL)
	t.Setenv("OBJECT_BUCKET_RAW", "raw")
	t.Setenv("OBJECT_ACCESS_KEY", "test-only")
	t.Setenv("OBJECT_SECRET_KEY", "test-only")
	t.Setenv("CLICKHOUSE_URL", "http://should-not-be-called.invalid")
	if e := PersistEvidence(context.Background(), "tenant-a", "source", model.Document{}, model.Document{}); e == nil {
		t.Fatal("lost raw evidence was ignored")
	}
}
