package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

type telemetryTest struct {
	t      *testing.T
	ctx    context.Context
	db     *Store
	tenant string
}

func newTelemetryTest(t *testing.T) *telemetryTest {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	f := &telemetryTest{t, ctx, db, "telemetry-" + model.ID()}
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO tenant_registry(tenant_id) VALUES($1)", f.tenant); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "workload_id": "workload", "provider": "AWS", "provider_resource_id": "i-0123456789abcdef0", "account_id": "111122223333", "region": "eu-west-1"})
		return e
	})
	return f
}
func (f *telemetryTest) run(role string, fn func(*Tx) error) error {
	return f.db.Do(f.ctx, f.tenant, func(tx *Tx) error {
		if _, e := tx.Exec(f.ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
			return e
		}
		return fn(tx)
	})
}
func (f *telemetryTest) must(role string, fn func(*Tx) error) {
	f.t.Helper()
	if e := f.run(role, fn); e != nil {
		f.t.Fatal(e)
	}
}
func (f *telemetryTest) connection(id, kind string) model.Document {
	f.t.Helper()
	c := telemetry.Connection{SchemaVersion: "1", ID: id, Version: 1, Kind: kind, ReadBindingID: "approved-prometheus", Issuer: "https://machine.invalid", Subject: "independent-native-collector", Enabled: true, Binding: telemetry.Binding{TenantID: f.tenant, ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, Definitions: []telemetry.Definition{{ID: "cpu", Version: "1", Metric: "cpu_utilization", Name: "node_cpu_usage", Unit: "percent", Type: "GAUGE", CadenceSeconds: 60, MaxGapSeconds: 120, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}}}}
	var out model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		out, e = tx.TelemetryConnectionAppend(f.ctx, id, 0, telemetry.Document(c))
		return e
	})
	return out
}
func telemetryMetadata(c model.Document, start, end time.Time) model.Document {
	d := model.Document{"raw_sha256": strings.Repeat("a", 64), "canonical_hash": strings.Repeat("b", 64), "binding": c["binding"], "source_kind": c["kind"], "collected_at": time.Now().UTC().Format(time.RFC3339Nano), "start": start.UTC().Format(time.RFC3339Nano), "end": end.UTC().Format(time.RFC3339Nano), "sample_count": 2, "rejection_count": 0, "warning_count": 0}
	if model.String(c, "kind") == "PROMETHEUS" {
		d["query_start"], d["query_end"] = d["start"], d["end"]
	}
	return d
}
func (f *telemetryTest) prepare(c model.Document, key string, d model.Document) model.Document {
	f.t.Helper()
	role := "finops_telemetry_reader"
	if model.String(c, "kind") == "OTLP" {
		role = "finops_telemetry_ingress"
	}
	var out model.Document
	f.must(role, func(tx *Tx) error {
		var e error
		out, _, e = tx.TelemetryBatchPrepare(f.ctx, model.String(c, "id"), model.String(c, "config_hash"), key, d)
		return e
	})
	return out
}
func (f *telemetryTest) publish(c, batch model.Document) model.Document {
	f.t.Helper()
	role := "finops_telemetry_reader"
	if model.String(c, "kind") == "OTLP" {
		role = "finops_telemetry_ingress"
	}
	var out model.Document
	f.must(role, func(tx *Tx) error {
		if _, _, e := tx.TelemetryCheckpointAppend(f.ctx, model.String(batch, "id"), "RAW_PERSISTED", model.Document{"bucket": "raw", "key": "tenant/" + f.tenant + "/native/raw.json", "version_id": "immutable-object-version", "body_sha256": batch["raw_sha256"]}); e != nil {
			return e
		}
		if _, _, e := tx.TelemetryCheckpointAppend(f.ctx, model.String(batch, "id"), "ANALYTICS_PERSISTED", model.Document{"database": "finops", "table": "native_telemetry", "write_id": batch["id"], "canonical_hash": batch["canonical_hash"], "sample_count": batch["sample_count"], "canonical_bucket": "raw", "canonical_key": "tenant/" + f.tenant + "/native/canonical.json", "canonical_version_id": "v-canonical", "canonical_body_sha256": strings.Repeat("c", 64)}); e != nil {
			return e
		}
		var e error
		out, _, e = tx.TelemetryPublish(f.ctx, model.String(batch, "id"))
		return e
	})
	return out
}

func TestTelemetryNativePublicationRequiresImmutablePersistenceAndProtocolIdentity(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("prometheus", "PROMETHEUS")
	end := time.Now().UTC().Add(-time.Minute)
	d := telemetryMetadata(c, end.Add(-14*24*time.Hour), end)
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_activity", "finops_telemetry_ingress"} {
		if e := f.run(role, func(tx *Tx) error {
			_, _, e := tx.TelemetryBatchPrepare(ctx, "prometheus", model.String(c, "config_hash"), "forbidden-"+role, d)
			return e
		}); e == nil {
			t.Fatalf("%s published Prometheus batch", role)
		}
	}
	batch := f.prepare(c, "first", d)
	if model.String(batch, "writer_role") != "finops_telemetry_reader" || model.String(batch, "revision_id") == "" || batch["definition_refs"] == nil {
		t.Fatal("lost immutable native provenance", batch)
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		r, replay, e := tx.TelemetryBatchPrepare(ctx, "prometheus", model.String(c, "config_hash"), "first", d)
		if e == nil && (!replay || r["id"] != batch["id"]) {
			t.Fatal("batch replay inserted a new record")
		}
		return e
	})
	retried := model.Clone(d)
	retried["collected_at"] = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		same, replay, e := tx.TelemetryBatchPrepare(ctx, "prometheus", model.String(c, "config_hash"), "first", retried)
		if e == nil && (!replay || same["id"] != batch["id"]) {
			t.Fatal("server receive time changed exact replay identity")
		}
		return e
	})
	changed := model.Clone(d)
	changed["sample_count"] = 3
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryBatchPrepare(ctx, "prometheus", model.String(c, "config_hash"), "first", changed)
		return e
	}); !errors.Is(e, ErrTelemetryConflict) {
		t.Fatal("changed replay accepted", e)
	}
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error { _, _, e := tx.TelemetryPublish(ctx, model.String(batch, "id")); return e }); e == nil {
		t.Fatal("published before persistence")
	}
	f.must("finops_api", func(tx *Tx) error {
		r, e := tx.TelemetryReceipts(ctx, "prometheus")
		if len(r) != 0 {
			t.Fatal("prepared metadata became trusted")
		}
		return e
	})
	raw := model.Document{"bucket": "raw", "key": "tenant/" + f.tenant + "/native/raw", "version_id": "v1", "body_sha256": d["raw_sha256"]}
	invalid := model.Clone(raw)
	invalid["body_sha256"] = strings.Repeat("f", 64)
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "RAW_PERSISTED", invalid)
		return e
	}); e == nil {
		t.Fatal("wrong archive hash accepted")
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "RAW_PERSISTED", raw)
		return e
	})
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error { _, _, e := tx.TelemetryPublish(ctx, model.String(batch, "id")); return e }); e == nil {
		t.Fatal("published without analytics durability")
	}
	analytics := model.Document{"database": "finops", "table": "native_telemetry", "write_id": "write-one", "canonical_hash": d["canonical_hash"], "sample_count": 2, "canonical_bucket": "raw", "canonical_key": "tenant/" + f.tenant + "/native/canonical.json", "canonical_version_id": "v-canonical", "canonical_body_sha256": strings.Repeat("c", 64)}
	invalid = model.Clone(analytics)
	invalid["sample_count"] = 1
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "ANALYTICS_PERSISTED", invalid)
		return e
	}); e == nil {
		t.Fatal("incomplete analytics count accepted")
	}
	var receipt model.Document
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		if _, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "ANALYTICS_PERSISTED", analytics); e != nil {
			return e
		}
		var e error
		receipt, _, e = tx.TelemetryPublish(ctx, model.String(batch, "id"))
		return e
	})
	if receipt["source_provenance"] != "NATIVE_TELEMETRY" || receipt["raw_checkpoint"] == nil || receipt["analytics_checkpoint"] == nil {
		t.Fatal("receipt lost persistence proofs")
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		r, replay, e := tx.TelemetryPublish(ctx, model.String(batch, "id"))
		if e == nil && (!replay || r["id"] != receipt["id"]) {
			t.Fatal("publication replay inserted evidence")
		}
		return e
	})
	invalid = model.Clone(raw)
	invalid["key"] = "changed"
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "RAW_PERSISTED", invalid)
		return e
	}); !errors.Is(e, ErrTelemetryConflict) {
		t.Fatal("checkpoint replacement accepted", e)
	}
	for _, table := range []string{"telemetry_connections", "telemetry_metric_definitions", "telemetry_source_revisions", "telemetry_batches", "telemetry_checkpoints", "telemetry_receipts"} {
		e := f.db.Do(ctx, f.tenant, func(tx *Tx) error {
			_, e := tx.Exec(ctx, "UPDATE "+pgx.Identifier{table}.Sanitize()+" SET document='{}' WHERE tenant_id=$1", f.tenant)
			return e
		})
		if e == nil {
			t.Fatalf("%s immutable history updated", table)
		}
	}
	for _, mutation := range []model.Document{{"samples": []any{model.Document{"value": 123}}}, {"binding": model.Document{"tenant_id": f.tenant, "resource_id": "forged"}}} {
		invalid = model.Clone(d)
		for k, v := range mutation {
			invalid[k] = v
		}
		if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
			_, _, e := tx.TelemetryBatchPrepare(ctx, "prometheus", model.String(c, "config_hash"), model.ID(), invalid)
			return e
		}); e == nil {
			t.Fatal("raw samples or foreign binding stored as metadata")
		}
	}
	// RLS applies even to queries lacking an explicit tenant predicate.
	if e := f.db.Do(ctx, "unrelated-"+model.ID(), func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		var n int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM telemetry_receipts").Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			t.Fatal("cross-tenant receipt visible")
		}
		_, e := tx.TelemetryConnection(ctx, "prometheus")
		if e != pgx.ErrNoRows {
			t.Fatal("foreign connection visible", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestTelemetryVersionRevocationEvaluationsAndNoActivityBackfill(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("native", "OTLP")
	now := time.Now().UTC().Add(-time.Second)
	d := telemetryMetadata(c, now.Add(-time.Minute), now)
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryBatchPrepare(ctx, "native", model.String(c, "config_hash"), "wrong-role", d)
		return e
	}); e == nil {
		t.Fatal("reader forged current OTLP observations")
	}
	stale := model.Clone(d)
	stale["start"] = now.Add(-24 * time.Hour).Format(time.RFC3339Nano)
	if e := f.run("finops_telemetry_ingress", func(tx *Tx) error {
		_, _, e := tx.TelemetryBatchPrepare(ctx, "native", model.String(c, "config_hash"), "backfill", stale)
		return e
	}); e == nil {
		t.Fatal("historical OTLP backfill accepted")
	}
	batch := f.prepare(c, "current", d)
	r := f.publish(c, batch)
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.TelemetryConnectionAppend(ctx, "native", 0, c)
		if !errors.Is(e, ErrConflict) {
			t.Fatal("stale connection CAS accepted", e)
		}
		return nil
	})
	evaluation := model.Document{"connection_id": "native", "config_hash": c["config_hash"], "receipt_ids": []string{model.String(r, "id")}, "evaluation": model.Document{"schema_version": "1", "start": d["start"], "end": d["end"], "status": "UNKNOWN", "metrics": []any{model.Document{"definition_id": "cpu", "metric": "cpu_utilization", "unit": "percent", "status": "UNKNOWN", "segment_ids": []string{}, "segment_count": 0, "segment_hash": telemetry.Hash([]string{}), "segment_ids_truncated": false}}}}
	f.must("finops_api", func(tx *Tx) error {
		e, eErr := tx.TelemetryEvaluationCreate(ctx, evaluation)
		if eErr == nil && (e["binding"] == nil || e["revision_id"] != c["revision_id"]) {
			t.Fatal("evaluation missing source binding")
		}
		return eErr
	})
	foreign := model.Clone(evaluation)
	foreign["receipt_ids"] = []string{"not-published"}
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, foreign); return e }); e == nil {
		t.Fatal("unpublished receipt authorized evaluation")
	}
	for _, role := range []string{"finops_telemetry_reader", "finops_telemetry_ingress", "finops_worker"} {
		if e := f.run(role, func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, evaluation); return e }); e == nil {
			t.Fatalf("%s minted API evaluation", role)
		}
	}
	// API cannot forge transport provenance even with a directly constructed INSERT.
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO telemetry_receipts(tenant_id,id,batch_id,revision_id,connection_id) VALUES($1,$2,$3,$4,$5)", f.tenant, model.ID(), batch["id"], c["revision_id"], "native")
		return e
	}); e == nil {
		t.Fatal("API fabricated trusted receipt")
	}
	var next model.Document
	f.must("finops_api", func(tx *Tx) error { var e error; next, e = tx.TelemetryConnectionAppend(ctx, "native", 1, c); return e })
	if model.Number(next, "version") != 2 || next["config_hash"] == c["config_hash"] {
		t.Fatal("revision did not pin exact version")
	}
	f.must("finops_api", func(tx *Tx) error {
		old, e := tx.TelemetryReceipt(ctx, model.String(r, "id"))
		if e == nil && model.Bool(old, "active_source") {
			t.Fatal("superseded source remains authoritative")
		}
		return e
	})
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, evaluation); return e }); !errors.Is(e, ErrTelemetrySource) {
		t.Fatal("superseded evaluation source accepted", e)
	}
	newer := telemetryMetadata(next, now.Add(-time.Minute), now)
	pending := f.prepare(next, "pending-after-config", newer)
	f.must("finops_api", func(tx *Tx) error {
		_, _, e := tx.TelemetryRevocationAppend(ctx, model.String(next, "revision_id"), "collector revoked")
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		_, replay, e := tx.TelemetryRevocationAppend(ctx, model.String(next, "revision_id"), "collector revoked")
		if e == nil && !replay {
			t.Fatal("revocation replay duplicated")
		}
		return e
	})
	if e := f.run("finops_api", func(tx *Tx) error {
		_, _, e := tx.TelemetryRevocationAppend(ctx, model.String(next, "revision_id"), "changed reason")
		return e
	}); !errors.Is(e, ErrTelemetryConflict) {
		t.Fatal("revocation overwritten", e)
	}
	if e := f.run("finops_telemetry_ingress", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(pending, "id"), "RAW_PERSISTED", model.Document{"bucket": "raw", "key": "tenant/" + f.tenant + "/native/pending", "version_id": "v1", "body_sha256": pending["raw_sha256"]})
		return e
	}); e == nil {
		t.Fatal("revoked source published new checkpoint")
	}
	// Durable exact replay remains inspectable after supersession/revocation.
	f.must("finops_telemetry_ingress", func(tx *Tx) error {
		same, replay, e := tx.TelemetryBatchPrepare(ctx, "native", model.String(c, "config_hash"), "current", d)
		if e == nil && (!replay || same["id"] != batch["id"]) {
			t.Fatal("historical replay lost")
		}
		return e
	})
	for _, table := range []string{"activity_receipts", "slo_receipts"} {
		if e := f.run("finops_telemetry_ingress", func(tx *Tx) error {
			_, e := tx.Exec(ctx, "SELECT 1 FROM "+pgx.Identifier{table}.Sanitize()+" LIMIT 1")
			return e
		}); e == nil {
			t.Fatalf("native ingress can access %s", table)
		}
	}
}

func TestTelemetryDurableSyncLeaseRetryAndReceiptCompletion(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("history", "PROMETHEUS")
	end := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	start := end.Add(-14 * 24 * time.Hour)
	request := model.Document{"start": start.Format(time.RFC3339Nano), "end": end.Format(time.RFC3339Nano), "history_days": 14}
	var job model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		job, _, e = tx.TelemetrySyncRequest(ctx, "history", "sync-one", request)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		same, replay, e := tx.TelemetrySyncRequest(ctx, "history", "sync-one", request)
		if e == nil && (!replay || same["id"] != job["id"]) {
			t.Fatal("sync replay duplicated request")
		}
		return e
	})
	changed := model.Clone(request)
	changed["history_days"] = 30
	if e := f.run("finops_api", func(tx *Tx) error { _, _, e := tx.TelemetrySyncRequest(ctx, "history", "sync-one", changed); return e }); !errors.Is(e, ErrTelemetryConflict) {
		t.Fatal("changed request replay accepted", e)
	}
	invalid := model.Clone(request)
	invalid["history_days"] = 365
	if e := f.run("finops_api", func(tx *Tx) error { _, _, e := tx.TelemetrySyncRequest(ctx, "history", "unbounded", invalid); return e }); e == nil {
		t.Fatal("unbounded sync accepted")
	}
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetrySyncRequest(ctx, "history", "reader-minted", request)
		return e
	}); e == nil {
		t.Fatal("reader registered request")
	}
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetrySyncClaim(ctx, "history", time.Minute); return e }); e == nil {
		t.Fatal("API claimed native reader work")
	}
	var first model.Document
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		pending, e := tx.TelemetryReaderPending(ctx, 20)
		if e == nil && len(pending) != 1 {
			t.Fatal("durable request missing")
		}
		if e != nil {
			return e
		}
		first, e = tx.TelemetrySyncClaim(ctx, "", time.Second)
		return e
	})
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error { _, e := tx.TelemetrySyncClaim(ctx, "history", time.Minute); return e }); e != pgx.ErrNoRows {
		t.Fatal("active lease claimed twice", e)
	}
	time.Sleep(1100 * time.Millisecond)
	var recovered model.Document
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		var e error
		recovered, e = tx.TelemetrySyncClaim(ctx, "history", time.Minute)
		return e
	})
	if model.Number(recovered, "attempts") != 2 || recovered["lease_token"] == first["lease_token"] {
		t.Fatal("expired lease not recovered")
	}
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, e := tx.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(first, "lease_token"), model.Document{"status": "RETRY", "reason_code": "STALE", "retry_after_seconds": 1})
		return e
	}); !errors.Is(e, ErrTelemetryConflict) {
		t.Fatal("expired owner finished replacement lease", e)
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		_, e := tx.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(recovered, "lease_token"), model.Document{"status": "RETRY", "reason_code": "ARCHIVE_UNAVAILABLE", "retry_after_seconds": 1})
		return e
	})
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error { _, e := tx.TelemetrySyncClaim(ctx, "history", time.Minute); return e }); e != pgx.ErrNoRows {
		t.Fatal("retry delay bypassed", e)
	}
	time.Sleep(1100 * time.Millisecond)
	var active model.Document
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		var e error
		active, e = tx.TelemetrySyncClaim(ctx, "history", time.Minute)
		return e
	})
	batch := f.prepare(c, "historical-batch", telemetryMetadata(c, start, end))
	receipt := f.publish(c, batch)
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, e := tx.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(active, "lease_token"), model.Document{"status": "COMPLETED", "receipt_id": "unpublished"})
		return e
	}); e == nil {
		t.Fatal("sync completed without published batch")
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		done, e := tx.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(active, "lease_token"), model.Document{"status": "COMPLETED", "receipt_id": receipt["id"]})
		if e == nil && (done["status"] != "COMPLETED" || model.Number(done, "attempts") != 3) {
			t.Fatal("completion lost retry history")
		}
		return e
	})
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "UPDATE telemetry_sync_requests SET status='RETRY' WHERE tenant_id=$1 AND id=$2", f.tenant, job["id"])
		return e
	}); e == nil {
		t.Fatal("completed request reopened")
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		var n int
		return tx.QueryRow(ctx, "SELECT count(*) FROM tenant_registry").Scan(&n)
	})
}

func TestTelemetryDefinitionAndTargetRegistrationCannotBeForged(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("guarded", "PROMETHEUS")
	invalid := model.Clone(c)
	binding := invalid["binding"].(map[string]any)
	binding["provider_resource_id"] = "i-fffffffffffffffff"
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetryConnectionAppend(ctx, "guarded", 1, invalid); return e }); e == nil {
		t.Fatal("different resource binding registered")
	}
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error { _, e := tx.TelemetryConnectionAppend(ctx, "reader-register", 0, c); return e }); e == nil {
		t.Fatal("reader registered source authority")
	}
	if e := f.run("finops_api", func(tx *Tx) error {
		b, _ := json.Marshal(model.Document{"id": "forged", "version": "1", "metric": "cpu_utilization"})
		_, e := tx.Exec(ctx, "INSERT INTO telemetry_metric_definitions(tenant_id,connection_id,connection_version,id,version,content_hash,document) VALUES($1,$2,1,'forged','1',$3,$4)", f.tenant, "guarded", strings.Repeat("a", 64), b)
		return e
	}); e == nil {
		t.Fatal("definition outside immutable connection accepted")
	}
	// Migration is repeatable and checksum-protected on the same disposable DB.
	if e := f.db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal("migration rerun", e)
	}
}

func TestTelemetryChunkCompletionDoesNotInventObservationCoverageAndRevocationBlocksQueuedWork(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("daily", "PROMETHEUS")
	end := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	start := end.Add(-14 * 24 * time.Hour)
	mid := start.Add(7 * 24 * time.Hour)
	request := model.Document{"start": start.Format(time.RFC3339Nano), "end": end.Format(time.RFC3339Nano), "history_days": 14}
	var job, claim model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		job, _, e = tx.TelemetrySyncRequest(ctx, "daily", "empty-history", request)
		return e
	})
	f.must("finops_telemetry_reader", func(tx *Tx) error { var e error; claim, e = tx.TelemetrySyncClaim(ctx, "daily", time.Minute); return e })
	first := telemetryMetadata(c, start, mid)
	first["sample_count"] = 0
	batch1 := f.prepare(c, "chunk-1", first)
	r1 := f.publish(c, batch1)
	if batch1["start"] != nil || batch1["end"] != nil {
		t.Fatal("empty native query invented observed timestamps")
	}
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, e := tx.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(claim, "lease_token"), model.Document{"status": "COMPLETED", "receipt_ids": []string{model.String(r1, "id")}})
		return e
	}); e == nil {
		t.Fatal("partial requested query ranges completed job")
	}
	second := telemetryMetadata(c, mid, end)
	second["sample_count"] = 0
	batch2 := f.prepare(c, "chunk-2", second)
	r2 := f.publish(c, batch2)
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		done, e := tx.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(claim, "lease_token"), model.Document{"status": "COMPLETED", "receipt_ids": []string{model.String(r2, "id"), model.String(r1, "id")}})
		if e == nil && (len(model.Strings(done, "receipt_ids")) != 2 || done["status"] != "COMPLETED") {
			t.Fatal("chunk receipts not retained")
		}
		return e
	})
	// Completion describes transport work, while both receipts honestly contain
	// zero observations. It does not manufacture a native coverage boolean.
	f.must("finops_api", func(tx *Tx) error {
		r, e := tx.TelemetryReceipt(ctx, model.String(r1, "id"))
		if e == nil && (model.Number(r, "sample_count") != 0 || r["start"] != nil || r["end"] != nil || r["coverage_complete"] != nil) {
			t.Fatal("empty query was promoted into coverage")
		}
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		_, _, e := tx.TelemetrySyncRequest(ctx, "daily", "revoked-work", request)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		_, _, e := tx.TelemetryRevocationAppend(ctx, model.String(c, "revision_id"), "retired source")
		return e
	})
	f.must("finops_telemetry_reader", func(tx *Tx) error { var e error; claim, e = tx.TelemetrySyncClaim(ctx, "daily", time.Minute); return e })
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, e := tx.TelemetrySyncFinish(ctx, model.String(claim, "id"), model.String(claim, "lease_token"), model.Document{"status": "COMPLETED", "receipt_ids": []string{model.String(r1, "id"), model.String(r2, "id")}})
		return e
	}); e == nil {
		t.Fatal("revoked source completed fresh query work")
	}
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		blocked, e := tx.TelemetrySyncFinish(ctx, model.String(claim, "id"), model.String(claim, "lease_token"), model.Document{"status": "BLOCKED", "reason_code": "SOURCE_REVISION_REVOKED"})
		if e == nil && blocked["status"] != "BLOCKED" {
			t.Fatal("stable blocker not retained")
		}
		return e
	})
	f.must("finops_telemetry_reader", func(tx *Tx) error {
		pending, e := tx.TelemetryReaderPending(ctx, 20)
		if e == nil && len(pending) != 0 {
			t.Fatal("blocked work retried forever")
		}
		return e
	})
}

func TestTelemetryInventoryReassignmentInvalidatesAuthorityAndArchivePathsAreTenantBound(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("bound", "PROMETHEUS")
	end := time.Now().UTC().Add(-time.Minute)
	d := telemetryMetadata(c, end.Add(-time.Hour), end)
	batch := f.prepare(c, "bound-batch", d)
	raw := model.Document{"bucket": "raw", "key": "tenant/somebody-else/native/raw", "version_id": "version-one", "body_sha256": d["raw_sha256"]}
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "RAW_PERSISTED", raw)
		return e
	}); e == nil {
		t.Fatal("another tenant's archive path accepted")
	}
	raw["key"] = "tenant/" + f.tenant + "/native/../escape"
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryCheckpointAppend(ctx, model.String(batch, "id"), "RAW_PERSISTED", raw)
		return e
	}); e == nil {
		t.Fatal("archive traversal accepted")
	}
	r := f.publish(c, batch)
	f.must("finops_api", func(tx *Tx) error {
		resource, e := tx.Get(ctx, "resources", "resource")
		if e != nil {
			return e
		}
		resource["provider_resource_id"] = "i-fffffffffffffffff"
		_, e = tx.Update(ctx, "resources", "resource", model.Number(resource, "version"), resource)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		receipt, e := tx.TelemetryReceipt(ctx, model.String(r, "id"))
		if e == nil && model.Bool(receipt, "active_source") {
			t.Fatal("inventory reassignment preserved native authority")
		}
		return e
	})
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryBatchPrepare(ctx, "bound", model.String(c, "config_hash"), "after-reassignment", d)
		return e
	}); e == nil {
		t.Fatal("stale identity produced fresh telemetry")
	}
	evaluation := model.Document{"connection_id": "bound", "config_hash": c["config_hash"], "receipt_ids": []string{model.String(r, "id")}, "evaluation": model.Document{"schema_version": "1", "status": "UNKNOWN", "metrics": []any{}}}
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, evaluation); return e }); e == nil {
		t.Fatal("stale resource snapshot authorized evaluation")
	}
}

func TestTelemetryHistoricalPredecessorPointIsBoundedSeparatelyFromRequestedRange(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	c := f.connection("counter-boundary", "PROMETHEUS")
	end := time.Now().UTC().Add(-time.Minute)
	start := end.Add(-24 * time.Hour)
	d := telemetryMetadata(c, start, end)
	d["start"] = start.Add(-120 * time.Second).Format(time.RFC3339Nano)
	batch := f.prepare(c, "one-real-predecessor", d)
	if batch["query_start"] != start.Format(time.RFC3339Nano) || batch["start"] != d["start"] {
		t.Fatal("requested and observed bounds were conflated")
	}
	invalid := model.Clone(d)
	invalid["start"] = start.Add(-121 * time.Second).Format(time.RFC3339Nano)
	if e := f.run("finops_telemetry_reader", func(tx *Tx) error {
		_, _, e := tx.TelemetryBatchPrepare(ctx, "counter-boundary", model.String(c, "config_hash"), "too-early", invalid)
		return e
	}); e == nil {
		t.Fatal("observation preceding definition maximum gap accepted")
	}
}

func TestTelemetryTypedCounterEvaluationPersistsNativeWindowAndDerivedRateUnit(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	registered := f.connection("counter-evaluation", "PROMETHEUS")
	c, e := telemetry.ParseConnection(registered)
	if e != nil {
		t.Fatal(e)
	}
	c.Definitions = []telemetry.Definition{{ID: "requests", Version: "1", Metric: "accepted_requests", Name: "accepted_requests_total", Unit: "requests", Type: "SUM", Monotonic: true, CadenceSeconds: 60, MaxGapSeconds: 120, EpochMetric: "process_start_time_seconds", Attributes: map[string]string{}, ResourceAttributes: map[string]string{}}}
	f.must("finops_api", func(tx *Tx) error {
		var e error
		registered, e = tx.TelemetryConnectionAppend(ctx, c.ID, 1, telemetry.Document(c))
		return e
	})
	now := time.Now().UTC()
	end := now.Truncate(time.Minute)
	start := end.Add(-2 * time.Minute)
	batch := f.prepare(registered, "typed-rate", telemetryMetadata(registered, start, end))
	receipt := f.publish(registered, batch)
	segments := []telemetry.Segment{}
	for n := 0; n < 2; n++ {
		left := start.Add(time.Duration(n) * time.Minute)
		segments = append(segments, telemetry.Segment{ID: model.ID(), DefinitionID: "requests", StreamID: "one-independent-stream", Metric: "accepted_requests", Type: "SUM", Unit: "requests", Start: left, End: left.Add(time.Minute), Status: "OBSERVED", Value: "600", SampleIDs: []string{model.ID()}, RawHashes: []string{strings.Repeat("a", 64)}})
	}
	evaluation := telemetry.EvaluateWindow(telemetry.WindowInput{Now: now, Definitions: c.Definitions, Segments: segments, Minutes: 2, RequiredMetrics: []string{"accepted_requests"}})
	if len(evaluation.Metrics) != 1 || evaluation.Metrics[0].Unit != "requests/second" || evaluation.Metrics[0].Start.IsZero() || evaluation.Metrics[0].Statistic != "OBSERVED_INTERVAL_RATE_DISTRIBUTION" {
		t.Fatal("typed rate contract drifted", evaluation)
	}
	d := model.Document{"connection_id": c.ID, "config_hash": registered["config_hash"], "receipt_ids": []string{model.String(receipt, "id")}, "evaluation": telemetry.Document(evaluation)}
	f.must("finops_api", func(tx *Tx) error {
		saved, e := tx.TelemetryEvaluationCreate(ctx, d)
		if e == nil && saved["evaluation"] == nil {
			t.Fatal("native evaluation dropped")
		}
		return e
	})
	for _, mutation := range []struct{ key, value string }{{"unit", "requests"}, {"unit", "bytes/second"}, {"statistic", "OBSERVED_SAMPLE_DISTRIBUTION"}} {
		changed := model.Clone(d)
		m := changed["evaluation"].(map[string]any)["metrics"].([]any)[0].(map[string]any)
		m[mutation.key] = mutation.value
		if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, changed); return e }); e == nil {
			t.Fatal("native rate unit/statistic was silently relabelled", mutation)
		}
	}
}

func TestTelemetryTypedHistoricalEvaluationUsesBoundedSegmentPreview(t *testing.T) {
	f := newTelemetryTest(t)
	ctx := f.ctx
	registered := f.connection("history-preview", "PROMETHEUS")
	c, e := telemetry.ParseConnection(registered)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	end := now.Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	samples := []telemetry.Sample{}
	for at := start; !at.After(end); at = at.Add(time.Minute) {
		samples = append(samples, telemetry.Sample{ID: telemetry.Hash(at), DefinitionID: "cpu", StreamID: "one-history-stream", Metric: "cpu_utilization", Type: "GAUGE", Unit: "percent", Statistic: "RAW_SAMPLE", Time: at, Value: "25", RawSHA256: strings.Repeat("a", 64)})
	}
	evaluation := telemetry.EvaluateHistory(telemetry.HistoryInput{Now: now, Definitions: c.Definitions, Samples: samples, Days: 14, Timezone: "UTC", RequiredMetrics: []string{"cpu_utilization"}})
	if len(evaluation.Metrics) != 1 {
		t.Fatal(evaluation)
	}
	metric := evaluation.Metrics[0]
	if !metric.SegmentIDsTruncated || len(metric.SegmentIDs) != 16 || metric.SegmentCount <= 16 || len(metric.SegmentHash) != 64 {
		t.Fatal("history did not bound segment evidence", metric.SegmentCount, len(metric.SegmentIDs))
	}
	encoded, e := json.Marshal(evaluation)
	if e != nil || len(encoded) > 16384 {
		t.Fatal("small native snapshot exceeded metadata budget", len(encoded), e)
	}
	batch := f.prepare(registered, "full-history-preview", telemetryMetadata(registered, start, end))
	receipt := f.publish(registered, batch)
	d := model.Document{"connection_id": c.ID, "config_hash": registered["config_hash"], "receipt_ids": []string{model.String(receipt, "id")}, "evaluation": telemetry.Document(evaluation)}
	f.must("finops_api", func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, d); return e })
	changed := model.Clone(d)
	changed["evaluation"].(map[string]any)["metrics"].([]any)[0].(map[string]any)["segment_count"] = 15
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.TelemetryEvaluationCreate(ctx, changed); return e }); e == nil {
		t.Fatal("truncated preview contradicting total count accepted")
	}
}
