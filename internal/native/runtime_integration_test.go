package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

type runtimeIdentity struct{ tenant, subject string }

func (a runtimeIdentity) Validate(r *http.Request) (auth.Identity, error) {
	if r.Header.Get("Authorization") == "Bearer console" {
		return auth.Identity{Tenant: a.tenant, Subject: a.subject, Roles: map[string]bool{"ORGANISATION_OWNER": true}}, nil
	}
	if r.Header.Get("Authorization") != "Bearer machine" {
		return auth.Identity{}, errors.New("invalid")
	}
	return auth.Identity{Tenant: a.tenant, Subject: a.subject, Roles: map[string]bool{}}, nil
}

type runtimeFixture struct {
	t                     *testing.T
	ctx                   context.Context
	admin, api, transport *store.Store
	tenant                string
	c                     telemetry.Connection
	p                     *Pipeline
	objects               map[string][]byte
	mu                    sync.Mutex
	rawWrites, facts      atomic.Int32
	failFacts             atomic.Bool
}

func newRuntimeFixture(t *testing.T, kind string) *runtimeFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Pool.Close)
	if e = admin.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	roleStore := func(role string) *store.Store {
		config, e := pgxpool.ParseConfig(dsn)
		if e != nil {
			t.Fatal(e)
		}
		config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, e := conn.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
			return e
		}
		pool, e := pgxpool.NewWithConfig(ctx, config)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(pool.Close)
		return &store.Store{Pool: pool}
	}
	f := &runtimeFixture{t: t, ctx: ctx, admin: admin, api: roleStore("finops_api"), tenant: "native-runtime-" + model.ID(), objects: map[string][]byte{}}
	role := "finops_telemetry_reader"
	if kind == "OTLP" {
		role = "finops_telemetry_ingress"
	}
	f.transport = roleStore(role)
	f.c = telemetry.Connection{SchemaVersion: "1", ID: "connection", Version: 1, Kind: kind, ReadBindingID: "approved", Issuer: "https://machine.example", Subject: "native-collector", Enabled: true, Binding: telemetry.Binding{TenantID: f.tenant, ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "123456789012", Region: "eu-west-1"}, Definitions: []telemetry.Definition{{ID: "cpu", Version: "1", Metric: "cpu_utilization", Name: "cpu_utilization", Type: "GAUGE", Unit: "ratio", CadenceSeconds: 300, MaxGapSeconds: 600, Attributes: map[string]string{"host_id": "i-0123456789abcdef0"}}}}
	e = f.api.Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO tenant_registry(tenant_id) VALUES($1)", f.tenant); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "workload_id": "workload", "provider": "AWS", "provider_resource_id": f.c.Binding.ProviderResourceID, "account_id": f.c.Binding.AccountID, "region": "eu-west-1"}); e != nil {
			return e
		}
		_, e := tx.TelemetryConnectionAppend(ctx, f.c.ID, 0, telemetry.Document(f.c))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	f.p = &Pipeline{Store: f.transport, Archive: func(_ context.Context, tenant, lane, id string, raw []byte) (model.Document, error) {
		key := "tenant/" + tenant + "/native/" + lane + "/" + id
		hash := telemetry.BytesHash(raw)
		f.mu.Lock()
		f.objects[key+"/"+hash] = append([]byte{}, raw...)
		f.mu.Unlock()
		if lane == "wire" {
			f.rawWrites.Add(1)
		}
		return model.Document{"bucket": "native-raw", "key": key, "version_id": hash, "body_sha256": hash}, nil
	}, ReadObject: func(_ context.Context, _ string, ref model.Document) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		raw := f.objects[model.String(ref, "key")+"/"+model.String(ref, "version_id")]
		if telemetry.BytesHash(raw) != model.String(ref, "body_sha256") {
			return nil, errors.New("object changed")
		}
		return append([]byte{}, raw...), nil
	}, WriteFacts: func(_ context.Context, _ string, id string, b telemetry.Batch) (model.Document, error) {
		if f.failFacts.CompareAndSwap(true, false) {
			return nil, errors.New("analytics unavailable")
		}
		f.facts.Add(1)
		return model.Document{"database": "finops", "table": "native_telemetry", "write_id": id, "canonical_hash": telemetry.CanonicalHash(b), "sample_count": len(b.Samples)}, nil
	}}
	return f
}
func runtimeKV(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}
func (f *runtimeFixture) wire(at time.Time, value float64) []byte {
	f.t.Helper()
	b := f.c.Binding
	point := &metricspb.NumberDataPoint{TimeUnixNano: uint64(at.UnixNano()), Attributes: []*commonpb.KeyValue{runtimeKV("host_id", b.ProviderResourceID)}, Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: value}}
	metric := &metricspb.Metric{Name: "cpu_utilization", Unit: "ratio", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{point}}}}
	resource := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{runtimeKV("cloud.provider", "aws"), runtimeKV("cloud.account.id", b.AccountID), runtimeKV("cloud.region", b.Region), runtimeKV("host.id", b.ProviderResourceID)}}
	req := &collectorpb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{Resource: resource, ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{metric}}}}}}
	raw, e := proto.Marshal(req)
	if e != nil {
		f.t.Fatal(e)
	}
	return raw
}
func (f *runtimeFixture) post(s *Server, raw []byte, key, token string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/x-protobuf")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Finops-Connection-ID", f.c.ID)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestRuntimeOTLPRestrictedIdentityExactReplayAndPersistenceResume(t *testing.T) {
	f := newRuntimeFixture(t, "OTLP")
	now := time.Now().UTC()
	s := &Server{Store: f.transport, Pipeline: f.p, Issuer: f.c.Issuer, Auth: runtimeIdentity{f.tenant, f.c.Subject}, Now: func() time.Time { return now }}
	raw := f.wire(now.Add(-time.Second), 0.2)
	if w := f.post(s, raw, "same", "console"); w.Code != 401 {
		t.Fatalf("console metric ingress %d", w.Code)
	}
	f.failFacts.Store(true)
	w := f.post(s, raw, "same", "machine")
	if w.Code != 503 {
		t.Fatalf("incomplete publication status %d %s", w.Code, w.Body.String())
	}
	var receipts []model.Document
	if e := f.transport.Do(f.ctx, f.tenant, func(tx *store.Tx) error { var e error; receipts, e = tx.TelemetryReceipts(f.ctx, f.c.ID); return e }); e != nil || len(receipts) != 0 {
		t.Fatal("checkpoint treated as trusted publication")
	}
	w = f.post(s, raw, "same", "machine")
	if w.Code != 200 || w.Header().Get("X-Finops-Receipt-ID") == "" {
		t.Fatalf("resumed ingress %d %s", w.Code, w.Body.String())
	}
	id := w.Header().Get("X-Finops-Receipt-ID")
	if f.rawWrites.Load() != 1 || f.facts.Load() != 1 {
		t.Fatal("resume repeated durable raw write")
	}
	now = now.Add(10 * time.Minute)
	w = f.post(s, raw, "same", "machine")
	if w.Code != 200 || w.Header().Get("X-Finops-Receipt-ID") != id || f.rawWrites.Load() != 1 || f.facts.Load() != 1 {
		t.Fatalf("aged exact replay changed publication: %d %s", w.Code, w.Body.String())
	}
	if w = f.post(s, f.wire(now.Add(-time.Second), 0.3), "same", "machine"); w.Code != 409 {
		t.Fatal("conflicting replay accepted")
	}
	now = time.Now().UTC()
	if w = f.post(s, f.wire(now.Add(-3*time.Minute), 0.2), "historical-new-key", "machine"); w.Code != 200 {
		t.Fatalf("rejected points should return standard partial response: %d %s", w.Code, w.Body.String())
	}
	var partial collectorpb.ExportMetricsServiceResponse
	if e := proto.Unmarshal(w.Body.Bytes(), &partial); e != nil || partial.GetPartialSuccess().GetRejectedDataPoints() != 1 {
		t.Fatal("new historical OTLP request not visibly rejected")
	}
	if e := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.TelemetryConnection(f.ctx, f.c.ID)
		if e != nil {
			return e
		}
		_, _, e = tx.TelemetryRevocationAppend(f.ctx, model.String(d, "revision_id"), "operator revocation")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if w = f.post(s, raw, "same", "machine"); w.Code != 403 {
		t.Fatal("revoked source replay remained authoritative")
	}
}
func TestRuntimeHistoricalQueueAndReaderUsesPublishedObjects(t *testing.T) {
	f := newRuntimeFixture(t, "PROMETHEUS")
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	var queries atomic.Int32
	var corrected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/api/v1/metadata" {
			_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": model.Document{"cpu_utilization": []any{model.Document{"type": "gauge", "unit": "ratio"}}}})
			return
		}
		queries.Add(1)
		at, e := time.Parse(time.RFC3339Nano, r.Form.Get("time"))
		if e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		query := r.Form.Get("query")
		open := strings.LastIndex(query, "[")
		seconds, e := strconv.Atoi(strings.TrimSuffix(query[open+1:], "s]"))
		if e != nil {
			t.Error(e)
		}
		from := at.Add(-time.Duration(seconds) * time.Second).Truncate(5 * time.Minute).Add(5 * time.Minute)
		points := [][]any{}
		for cursor := from; !cursor.After(at); cursor = cursor.Add(5 * time.Minute) {
			value := "0.35"
			if corrected.Load() {
				value = "0.4"
			}
			points = append(points, []any{cursor.Unix(), value})
		}
		_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": model.Document{"resultType": "matrix", "result": []any{model.Document{"metric": model.Document{"__name__": "cpu_utilization", "host_id": f.c.Binding.ProviderResourceID}, "values": points}}}})
	}))
	defer server.Close()
	binding := ReadBinding{Binding: f.c.Binding, Endpoint: server.URL, RequiredLabels: map[string]string{"host_id": f.c.Binding.ProviderResourceID}, AllowedCIDRs: []string{"127.0.0.1/32"}}
	s := &Server{Store: f.transport, Pipeline: f.p, Fixture: true, ReaderToken: "reader-secret", Bindings: map[string]ReadBinding{"approved": binding}, Now: func() time.Time { return now }}
	var job model.Document
	e := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		job, _, e = tx.TelemetrySyncRequest(f.ctx, f.c.ID, "history", model.Document{"start": start, "end": end, "history_days": 14})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.syncTick(f.ctx); e != nil {
		t.Fatal(e)
	}
	if e = f.transport.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		job, e = tx.TelemetrySyncGet(f.ctx, model.String(job, "id"))
		return e
	}); e != nil || model.String(job, "status") != "COMPLETED" || len(model.Strings(job, "receipt_ids")) != 14 {
		t.Fatalf("durable query not completed: %+v %v", job, e)
	}
	before := queries.Load()
	key := "sync:" + model.String(job, "id") + ":" + telemetry.Hash(model.Document{"index": 0, "start": start, "end": start.Add(24 * time.Hour)})
	if _, e = s.collect(f.ctx, f.c, key, start, start.Add(24*time.Hour)); e != nil || queries.Load() != before {
		t.Fatal("restart replay queried remote source again")
	}
	input, _ := json.Marshal(model.Document{"tenant_id": f.tenant, "connection_id": f.c.ID, "mode": "history", "days": 14, "timezone": "UTC"})
	r := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(input))
	r.Header.Set("Authorization", "Bearer reader-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("reader %d %s", w.Code, w.Body.String())
	}
	var result model.Document
	if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	evaluation := result["evaluation"].(map[string]any)
	if evaluation["status"] != "READY" || len(result["receipt_ids"].([]any)) != 14 {
		t.Fatalf("published history unavailable %s", w.Body.String())
	}
	if e = f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.TelemetryEvaluationCreate(f.ctx, result); return e }); e != nil {
		t.Fatalf("actual evaluation cannot seal %v", e)
	}
	if queries.Load() != before {
		t.Fatal("reader /evaluate fetched live source instead of immutable objects")
	}
	// A different raw query containing identical native observations must retain
	// provenance without becoming a second population or a false conflict.
	if _, e = s.collect(f.ctx, f.c, "overlapping-history", start, start.Add(25*time.Hour)); e != nil {
		t.Fatal(e)
	}
	points, _, problems, e := s.samples(f.ctx, f.c, start, end)
	if e != nil || len(problems) != 0 {
		t.Fatalf("identical overlapping points conflict: %v %+v", e, problems)
	}
	multiHash := false
	for _, p := range points {
		if len(p.SourceHashes) > 1 {
			multiHash = true
			break
		}
	}
	if !multiHash {
		t.Fatal("duplicate point source hashes lost")
	}
	corrected.Store(true)
	if _, e = s.collect(f.ctx, f.c, "conflicting-history", start, start.Add(12*time.Hour)); e != nil {
		t.Fatal(e)
	}
	_, _, problems, e = s.samples(f.ctx, f.c, start, end)
	if e != nil || !containsRuntime(problems, "TELEMETRY_SAMPLE_CONFLICT") {
		t.Fatalf("different same-timestamp native values blended: %v %+v", e, problems)
	}
}
func containsRuntime(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
