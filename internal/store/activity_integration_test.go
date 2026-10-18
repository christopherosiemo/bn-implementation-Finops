package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func TestActivityReceiptsAreIndependentTenantScopedAndImmutable(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tenant := "activity-" + model.ID()
	source := ActivitySource{ID: "gateway", ResourceID: "resource", WorkloadID: "workload", ProviderResourceID: "i-test", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.invalid", Subject: "registered-machine", MetricDefinition: ActivityMetric{ID: "orders", Version: "1", Unit: "order"}, Enabled: true}
	do := func(role string, fn func(*Tx) error) error {
		return db.Do(ctx, tenant, func(tx *Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				return err
			}
			return fn(tx)
		})
	}
	if err = do("finops_api", func(tx *Tx) error { _, e := tx.ActivityRegister(ctx, source); return e }); err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	in := ActivityInterval{SchemaVersion: "1", SourceID: source.ID, ResourceID: source.ResourceID, WorkloadID: source.WorkloadID, Sequence: 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, MetricDefinition: source.MetricDefinition, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
	submit := func(tx *Tx, interval ActivityInterval, subject, key string) (ActivityReceipt, bool, error) {
		raw, _ := json.Marshal(interval)
		return tx.ActivityAppend(ctx, ActivitySubmission{Interval: interval, RawBody: raw, Issuer: source.Issuer, Subject: subject, IdempotencyKey: key})
	}
	var first, second ActivityReceipt
	if err = do("finops_activity", func(tx *Tx) error { var e error; first, _, e = submit(tx, in, source.Subject, "first"); return e }); err != nil {
		t.Fatal(err)
	}
	if err = do("finops_activity", func(tx *Tx) error {
		r, replay, e := submit(tx, in, source.Subject, "first")
		if e == nil && (!replay || r.ID != first.ID) {
			t.Fatal("exact replay created a new receipt")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	changed := in
	changed.Accepted = 2
	if err = do("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, changed, source.Subject, "first"); return e }); !errors.Is(err, ErrActivityConflict) {
		t.Fatalf("changed replay:%v", err)
	}
	newer := in
	newer.Sequence = 2
	newer.IntervalStart = in.IntervalEnd
	newer.IntervalEnd = in.IntervalEnd.Add(time.Minute)
	if err = do("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, newer, "unregistered-human", "second"); return e }); !errors.Is(err, ErrActivitySource) {
		t.Fatalf("unregistered subject:%v", err)
	}
	if err = do("finops_api", func(tx *Tx) error { _, _, e := submit(tx, newer, source.Subject, "second"); return e }); err == nil {
		t.Fatal("API forged independent activity")
	}
	if err = do("finops_activity", func(tx *Tx) error { var e error; second, _, e = submit(tx, newer, source.Subject, "second"); return e }); err != nil {
		t.Fatal(err)
	}
	if !second.PreviousIdle || second.PreviousIntervalEnd == nil || !second.PreviousIntervalEnd.Equal(newer.IntervalStart) {
		t.Fatal("contiguous previous evidence not retained")
	}
	old := newer
	old.Sequence = 3
	old.IntervalStart = old.IntervalStart.Add(-time.Hour)
	old.IntervalEnd = old.IntervalEnd.Add(-time.Hour)
	if err = do("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, old, source.Subject, "old"); return e }); !errors.Is(err, ErrActivityOrder) {
		t.Fatalf("historical backfill:%v", err)
	}
	if err = do("finops_signer", func(tx *Tx) error {
		samples, e := tx.ActivitySamples(ctx, source.ResourceID, in.IntervalStart, newer.IntervalEnd)
		if e == nil && (len(samples) != 2 || samples[0]["accepted"] != "0" || samples[0]["units"] != "0" || samples[0]["source_provenance"] != "INDEPENDENT_ACTIVITY") {
			t.Fatalf("incomplete normalized samples:%v", samples)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Do(ctx, tenant+"-other", func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		_, e := tx.ActivityLatest(ctx, source.ResourceID)
		if e != pgx.ErrNoRows {
			t.Fatalf("cross tenant activity:%v", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"finops_activity", "finops_api", "finops_ingester"} {
		if err = do(role, func(tx *Tx) error {
			_, e := tx.Exec(ctx, "UPDATE activity_receipts SET document='{}' WHERE tenant_id=$1", tenant)
			return e
		}); err == nil {
			t.Fatalf("%s modified activity history", role)
		}
	}
	if err = do("finops_activity", func(tx *Tx) error {
		_, e := tx.Create(ctx, "approvals", model.Document{"approved_by": "machine"})
		return e
	}); err == nil {
		t.Fatal("activity identity forged approval")
	}
}

// The override is private to a rolled-back owner transaction. Production roles
// have no clock setting or function-replacement privilege.
func TestActivityDatabaseClockPreservesExactReplayWithoutBackfill(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx, "clock-"+model.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `CREATE TEMP TABLE activity_test_clock(instant timestamptz NOT NULL); INSERT INTO activity_test_clock VALUES('2026-09-01T00:01:10Z'); GRANT SELECT ON activity_test_clock TO finops_activity; CREATE OR REPLACE FUNCTION activity_receive_time() RETURNS timestamptz LANGUAGE sql VOLATILE AS 'SELECT instant FROM pg_temp.activity_test_clock'`)
	if err != nil {
		t.Fatal(err)
	}
	source := ActivitySource{ID: "clock-gateway", ResourceID: "resource", WorkloadID: "workload", ProviderResourceID: "i-clock", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.invalid", Subject: "clock-machine", MetricDefinition: ActivityMetric{ID: "orders", Version: "1", Unit: "order"}, Enabled: true}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ActivityRegister(ctx, source); err != nil {
		t.Fatal(err)
	}
	in := ActivityInterval{SchemaVersion: "1", SourceID: source.ID, ResourceID: source.ResourceID, WorkloadID: source.WorkloadID, Sequence: 1, IntervalStart: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), IntervalEnd: time.Date(2026, 9, 1, 0, 1, 0, 0, time.UTC), MetricDefinition: source.MetricDefinition, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
	raw, _ := json.Marshal(in)
	submission := ActivitySubmission{Interval: in, RawBody: raw, Issuer: source.Issuer, Subject: source.Subject, IdempotencyKey: "original"}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE finops_activity"); err != nil {
		t.Fatal(err)
	}
	original, _, err := tx.ActivityAppend(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	if !original.ReceivedAt.Equal(time.Date(2026, 9, 1, 0, 1, 10, 0, time.UTC)) {
		t.Fatal("database receive clock not used")
	}
	if _, err = tx.Exec(ctx, "RESET ROLE; UPDATE activity_test_clock SET instant='2026-09-15T00:01:10Z'; SET LOCAL ROLE finops_activity"); err != nil {
		t.Fatal(err)
	}
	replayed, replay, err := tx.ActivityAppend(ctx, submission)
	if err != nil || !replay || replayed.ID != original.ID {
		t.Fatalf("old exact receipt lost:%v", err)
	}
	in.Sequence = 2
	in.IntervalStart = in.IntervalStart.Add(time.Minute)
	in.IntervalEnd = in.IntervalEnd.Add(time.Minute)
	raw, _ = json.Marshal(in)
	if _, _, err = tx.ActivityAppend(ctx, ActivitySubmission{Interval: in, RawBody: raw, Issuer: source.Issuer, Subject: source.Subject, IdempotencyKey: "backfill"}); !errors.Is(err, ErrActivityOrder) {
		t.Fatalf("historical interval accepted:%v", err)
	}
	// A runtime role cannot replace the receive clock to introduce backfill.
	if _, err = tx.Exec(ctx, "CREATE OR REPLACE FUNCTION activity_receive_time() RETURNS timestamptz LANGUAGE sql AS 'SELECT now()'"); err == nil {
		t.Fatal("runtime identity replaced trusted database clock")
	}
}
