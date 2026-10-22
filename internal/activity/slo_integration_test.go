package activity

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type sloMachine struct{ identity auth.Identity }

func (v *sloMachine) Validate(*http.Request) (auth.Identity, error) { return v.identity, nil }
func sloRoleDB(t *testing.T, dsn, role string) *store.Store {
	t.Helper()
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return e
	}
	pool, e := pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	return &store.Store{Pool: pool}
}

// JWT cryptography has independent OIDC tests. This test exercises the HTTP
// contract and real least-privilege PostgreSQL persistence after authentication.
func TestSLOIngressUsesIndependentIdentityAndImmutableReplay(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Pool.Close()
	if e = admin.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "slo-http-" + model.ID()
	api := sloRoleDB(t, dsn, "finops_api")
	machineDB := sloRoleDB(t, dsn, "finops_activity")
	var source slo.Source
	if e = api.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "workload_id": "workload", "provider_resource_id": "i-slo", "account_id": "111122223333", "region": "eu-west-1"}); e != nil {
			return e
		}
		o := slo.Objective{SchemaVersion: "1", WorkloadID: "workload", Limits: slo.Limits{MaxErrorRatePPM: 10000, MinAvailabilityPPM: 990000, MaxP95LatencyMS: 180, MaxP99LatencyMS: 250, MinLatencySamples: 1}, EvaluationMinutes: 2, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []slo.Window{}}, Regression: slo.Regression{Enabled: false, MaxPercent: 15}}
		d, e := tx.SLOObjectiveAppend(ctx, "workload", 0, slo.Document(o))
		if e != nil {
			return e
		}
		source, e = tx.SLORegister(ctx, slo.Source{SchemaVersion: "1", ID: "source", ObjectiveID: model.String(d, "id"), WorkloadID: "workload", ResourceID: "resource", ProviderResourceID: "i-slo", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.invalid", Subject: "edge-collector", Enabled: true})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	identity := &sloMachine{auth.Identity{Tenant: tenant, Subject: source.Subject}}
	handler := NewServer(machineDB, identity, source.Issuer).Handler()
	end := time.Now().UTC().Truncate(time.Minute)
	upper := int64(100)
	interval := slo.Interval{SchemaVersion: "1", SourceID: source.ID, ObjectiveID: source.ObjectiveID, WorkloadID: source.WorkloadID, ResourceID: source.ResourceID, Sequence: 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, RequestCount: 100, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: 100, Buckets: []slo.Bucket{{UpperBoundMS: &upper, Count: 100}, {UpperBoundMS: nil, Count: 0}}}}
	send := func(raw []byte, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/slo/intervals", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	raw, _ := json.Marshal(interval)
	first := send(raw, "one")
	if first.Code != 201 {
		t.Fatalf("registered machine submission:%d %s", first.Code, first.Body.String())
	}
	var body struct {
		Receipt  slo.Receipt `json:"receipt"`
		Replayed bool        `json:"replayed"`
	}
	if e = json.Unmarshal(first.Body.Bytes(), &body); e != nil || body.Receipt.WriterRole != "finops_activity" || body.Receipt.Binding.TenantID != tenant {
		t.Fatal("untrusted receipt projection", e, body)
	}
	replay := send(raw, "one")
	if replay.Code != 200 {
		t.Fatal("exact replay did not return original receipt", replay.Code)
	}
	var second struct {
		Receipt  slo.Receipt `json:"receipt"`
		Replayed bool        `json:"replayed"`
	}
	_ = json.Unmarshal(replay.Body.Bytes(), &second)
	if !second.Replayed || second.Receipt.ID != body.Receipt.ID {
		t.Fatal("replay duplicated evidence")
	}
	changed := interval
	changed.ErrorCount = 1
	changedRaw, _ := json.Marshal(changed)
	if w := send(changedRaw, "one"); w.Code != 409 {
		t.Fatal("changed replay accepted", w.Code)
	}
	identity.identity.Subject = "console-owner"
	if w := send(raw, "one"); w.Code != 403 {
		t.Fatal("human identity reused collector receipt", w.Code)
	}
	identity.identity.Subject = source.Subject
	identity.identity.Tenant = tenant + "-other"
	if w := send(raw, "one"); w.Code != 403 {
		t.Fatal("cross-tenant collector accepted", w.Code)
	}
	identity.identity.Tenant = tenant
	var missing map[string]any
	_ = json.Unmarshal(raw, &missing)
	delete(missing, "error_count")
	invalid, _ := json.Marshal(missing)
	if w := send(invalid, "missing"); w.Code != 422 {
		t.Fatal("missing errors silently became zero", w.Code)
	}
	old := interval
	old.Sequence = 2
	old.IntervalStart = old.IntervalStart.Add(-time.Hour)
	old.IntervalEnd = old.IntervalEnd.Add(-time.Hour)
	oldRaw, _ := json.Marshal(old)
	if w := send(oldRaw, "old"); w.Code != 409 {
		t.Fatal("historical HTTP backfill accepted", w.Code)
	}
	if w := send(raw, ""); w.Code != 400 {
		t.Fatal("missing idempotency key accepted", w.Code)
	}
}
