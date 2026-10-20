package activity

// Existing PostgreSQL/HTTP trust-boundary infrastructure; only provider-shaped
// test observations are synthetic. No historical receive-clock override.
import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func TestObjectStorageAccessHTTPPersistedIdentityReplayAndCoverage(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tenant := "s3-access-http-" + model.ID()
	api, machine := sloRoleDB(t, dsn, "finops_api"), sloRoleDB(t, dsn, "finops_activity")
	var source store.ObjectStorageAccessSource
	if err = api.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": "bucket", "provider": "AWS", "resource_type": "S3_BUCKET", "workload_id": "workload", "provider_resource_id": "arn:aws:s3:::synthetic-access-bucket", "account_id": "111122223333", "region": "eu-west-1"}); e != nil {
			return e
		}
		if _, e := tx.ObjectStorageDatasetAppend(ctx, model.Document{"id": "dataset", "version": 1, "resource_id": "bucket", "name": "synthetic-prefix", "selector": model.Document{"kind": "PREFIX", "prefix": "logs/"}, "policy": model.Document{}}, "synthetic-admin"); e != nil {
			return e
		}
		var e error
		source, e = tx.ObjectStorageAccessRegister(ctx, store.ObjectStorageAccessSource{ResourceID: "bucket", DatasetID: "dataset", DatasetVersion: 1, ProviderResourceID: "arn:aws:s3:::synthetic-access-bucket", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.invalid", Subject: "synthetic-s3-app-collector", MetricDefinition: store.ActivityMetric{ID: "synthetic-all-get-paths", Version: "1", Unit: store.ObjectStorageAccessUnit}, AuthoritativeAccessScope: true})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	identity := &sloMachine{auth.Identity{Tenant: tenant, Subject: source.Subject}}
	handler := NewServer(machine, identity, source.Issuer).Handler()
	send := func(in store.ObjectStorageAccessInterval, key string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(in)
		r := httptest.NewRequest(http.MethodPost, "/v1/object-storage-access/intervals", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	end := time.Now().UTC().Truncate(time.Minute)
	interval := store.ObjectStorageAccessInterval{SchemaVersion: "1", SourceID: source.ID, ResourceID: source.ResourceID, DatasetID: source.DatasetID, DatasetVersion: source.DatasetVersion,
		Sequence: 1, IntervalStart: end.Add(-3 * time.Minute), IntervalEnd: end.Add(-2 * time.Minute), MetricDefinition: source.MetricDefinition, GetRequests: "0", RetrievedBytes: "0", Heartbeat: true}
	first := send(interval, "one")
	if first.Code != 201 {
		t.Fatalf("native scoped minute persistence: %d %s", first.Code, first.Body.String())
	}
	var original struct {
		Receipt store.ObjectStorageAccessReceipt `json:"receipt"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &original)
	if original.Receipt.ID == "" || original.Receipt.TenantID != tenant || model.String(original.Receipt.Binding, "account_id") != "111122223333" || original.Receipt.Issuer != source.Issuer {
		t.Fatal("receipt lost authenticated receive/provider identity")
	}
	if replay := send(interval, "one"); replay.Code != 200 {
		t.Fatalf("exact replay duplicated or refused: %d %s", replay.Code, replay.Body.String())
	}
	changed := interval
	changed.GetRequests = "1"
	if got := send(changed, "one"); got.Code != 409 {
		t.Fatalf("conflicting replay accepted: %d", got.Code)
	}
	identity.identity.Subject = "synthetic-console-owner"
	if got := send(interval, "one"); got.Code != 403 {
		t.Fatalf("wrong machine subject accepted: %d", got.Code)
	}
	identity.identity.Subject, identity.identity.Tenant = source.Subject, tenant+"-other"
	if got := send(interval, "one"); got.Code != 403 {
		t.Fatalf("cross-tenant source accepted: %d", got.Code)
	}
	identity.identity.Tenant = tenant
	changed = interval
	changed.DatasetVersion = 2
	if got := send(changed, "changed-dataset"); got.Code != 403 {
		t.Fatalf("dataset revision confusion accepted: %d", got.Code)
	}
	changed = interval
	changed.Sequence, changed.IntervalStart, changed.IntervalEnd = 2, interval.IntervalStart.Add(-time.Hour), interval.IntervalEnd.Add(-time.Hour)
	if got := send(changed, "historical-backfill"); got.Code != 409 {
		t.Fatalf("arbitrary historical backfill accepted: %d", got.Code)
	}
	for sequence := int64(2); sequence <= 3; sequence++ {
		in := interval
		in.Sequence, in.IntervalStart, in.IntervalEnd = sequence, interval.IntervalStart.Add(time.Duration(sequence-1)*time.Minute), interval.IntervalEnd.Add(time.Duration(sequence-1)*time.Minute)
		if got := send(in, "next-"+in.IntervalStart.Format(time.RFC3339)); got.Code != 201 {
			t.Fatalf("contiguous minute refused: %d %s", got.Code, got.Body.String())
		}
	}
	if err = api.Do(ctx, tenant, func(tx *store.Tx) error {
		full, e := tx.ObjectStorageAccessSummary(ctx, source.ID, source.ResourceID, source.DatasetID, source.DatasetVersion, interval.IntervalStart, end)
		if e != nil {
			return e
		}
		if full["contiguous_scoped_window"] != true || full["get_requests"] != "0" || full["retrieved_bytes"] != "0" || full["all_access_paths_independently_proven"] != false || full["eligible_cold_bytes_fraction"] != nil {
			t.Fatalf("genuine explicit zero scope became global coldness or missing: %+v", full)
		}
		missing, e := tx.ObjectStorageAccessSummary(ctx, source.ID, source.ResourceID, source.DatasetID, source.DatasetVersion, interval.IntervalStart.Add(-time.Minute), end)
		if e != nil {
			return e
		}
		if missing["contiguous_scoped_window"] != false || missing["get_requests"] != nil || missing["retrieved_bytes"] != nil {
			t.Fatal("missing interval became known zero")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = api.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO object_storage_access_receipts SELECT * FROM object_storage_access_receipts WHERE tenant_id=$1", tenant)
		return e
	}); err == nil {
		t.Fatal("console database identity manufactured machine access")
	}
	if err = machine.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE object_storage_access_receipts SET document=document WHERE tenant_id=$1", tenant)
		return e
	}); err == nil {
		t.Fatal("machine identity rewrote immutable receipt")
	}
	if err = api.Do(ctx, tenant, func(tx *store.Tx) error {
		out, e := tx.ObjectStorageAccessRevoke(ctx, source.ID, "synthetic-admin")
		if e == nil && (out.Enabled || out.Version != 2) {
			t.Fatal("revocation did not append effective disabled source revision")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if got := send(interval, "one"); got.Code != 403 {
		t.Fatalf("revoked source remains accepted: %d", got.Code)
	}
	if err = api.Do(ctx, tenant, func(tx *store.Tx) error {
		summary, e := tx.ObjectStorageAccessSummary(ctx, source.ID, source.ResourceID, source.DatasetID, source.DatasetVersion, interval.IntervalStart, end)
		if e == nil && (summary["contiguous_scoped_window"] != false || summary["get_requests"] != nil) {
			t.Fatal("revocation kept authoritative historical readiness")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}
