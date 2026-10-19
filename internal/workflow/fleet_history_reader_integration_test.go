package workflow

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type historyCaptureFunc func(context.Context, string, string) (model.Document, error)

func (f historyCaptureFunc) Capture(ctx context.Context, tenant, registration string) (model.Document, error) {
	return f(ctx, tenant, registration)
}

// This test covers durable polling/replica ownership, not provider authenticity.
// Native read/archive publication is independently tested by the source factory.
// The injected clock advances only poll due times: it never changes activity
// receive time, creates historical receipts or grants execution/financial rights.
func TestFleetHistoryReaderDurableLeaseReplicaAndRestart(t *testing.T) {
	admin, roles := schedulerTestDatabase(t)
	ctx := context.Background()
	login := "history_reader_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-history-reader:" + login
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_ingester"); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	var db *store.Store
	t.Cleanup(func() {
		if db != nil {
			db.Pool.Close()
		}
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("history reader login cleanup ownership mismatch")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	dsn, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	dsn.User = url.UserPassword(login, password)
	db, e = store.OpenRuntime(ctx, dsn.String(), "fleet-history-reader")
	if e != nil {
		t.Fatal(e)
	}
	tenant := "history-poll-" + model.ID()
	src := source.FixtureRegistration(tenant, "history-readonly")
	r := fleethistory.Registration{SchemaVersion: "1", ID: "registered-history", Version: 1, FleetID: "fleet", Binding: fleethistory.Binding{TenantID: tenant, WorkloadID: "workload-dev", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1"}, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/history", SourceID: "history-readonly", SourceSystem: "AWS_SOURCE_CONNECTION", SourceRegistrationVersion: 1, SourceConfigHash: source.ConfigurationHash(src), CadenceSeconds: 60, MaxGapSeconds: 90}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.SourceCreate(ctx, src); e != nil {
			return e
		}
		_, e := tx.FleetHistoryRegistrationAppend(ctx, 0, r)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	target := fleetHistoryTarget{TenantID: tenant, RegistrationID: r.ID}
	checkpointKey := "history-poll:" + r.ID
	readCheckpoint := func() model.Document {
		t.Helper()
		var d model.Document
		if e := db.Do(ctx, tenant, func(tx *store.Tx) error {
			var e error
			d, e = tx.SourceCheckpointGet(ctx, r.SourceID, checkpointKey)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		return d
	}
	var calls atomic.Int64
	started, release := make(chan struct{}), make(chan struct{})
	now := time.Now().UTC()
	blocking := historyCaptureFunc(func(c context.Context, ten, id string) (model.Document, error) {
		if ten != tenant || id != r.ID {
			t.Error("capture escaped registered tenant")
		}
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return model.Document{"id": "fixture-observation"}, nil
		case <-c.Done():
			return nil, c.Err()
		}
	})
	primary := &fleetHistoryReader{Store: db, Capture: blocking, Now: func() time.Time { return now }}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- primary.capture(runCtx, target) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not commit durable observing lease")
	}
	checkpoint := readCheckpoint()
	if model.String(checkpoint, "status") != "OBSERVING" || model.String(checkpoint, "registration_hash") != fleethistory.RegistrationHash(r) {
		t.Fatal("capture began before durable scope lease")
	}
	next, e := time.Parse(time.RFC3339Nano, model.String(checkpoint, "next_poll_at"))
	if e != nil || !next.Equal(now.Add(3*time.Minute)) {
		t.Fatal("process failure lease was not persisted", e)
	}
	replica := &fleetHistoryReader{Store: db, Capture: historyCaptureFunc(func(context.Context, string, string) (model.Document, error) {
		calls.Add(1)
		return model.Document{"id": "replica-observation"}, nil
	}), Now: func() time.Time { return now }}
	if e = replica.capture(ctx, target); e != nil || calls.Load() != 1 {
		t.Fatal("concurrent replica duplicated current native read", e)
	}
	// Cancellation after the committed lease interrupts completion persistence;
	// its immutable prior OBSERVING record survives as an actual restart would.
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("interrupted reader did not return cancellation", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted read did not release owned session")
	}
	if d := readCheckpoint(); model.String(d, "status") != "OBSERVING" || model.String(d, "next_poll_at") != model.String(checkpoint, "next_poll_at") {
		t.Fatal("failed process erased durable in-flight lease")
	}
	restarted := &fleetHistoryReader{Store: db, Capture: replica.Capture, Now: func() time.Time { return now }}
	if e = restarted.capture(ctx, target); e != nil || calls.Load() != 1 {
		t.Fatal("restart ignored unexpired durable failure lease", e)
	}
	// Its session-scoped replica lock must be released even when the completion
	// transaction was cancelled; a distinct checked connection can acquire it.
	conn, e := db.Pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var acquired bool
	lockKey := tenant + ":fleet-history-poll:" + r.ID
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", lockKey).Scan(&acquired); e != nil || !acquired {
		conn.Release()
		t.Fatal("interruption leaked reader session lock", e)
	}
	if _, e = conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", lockKey); e != nil {
		conn.Release()
		t.Fatal(e)
	}
	conn.Release()
	now = next.Add(time.Second)
	if e = restarted.capture(ctx, target); e != nil || calls.Load() != 2 {
		t.Fatal("expired durable lease did not resume a single read", e)
	}
	completed := readCheckpoint()
	if model.String(completed, "status") != "OBSERVED_ONLY" || model.String(completed, "observation_id") != "replica-observation" || model.Number(completed, "consecutive_failures") != 0 {
		t.Fatal("successful restart was not durably checkpointed")
	}
	if e = replica.capture(ctx, target); e != nil || calls.Load() != 2 {
		t.Fatal("new process ignored successful native cadence", e)
	}
	// Error retries retain explicit unavailability and bounded exponential delay.
	failed := &fleetHistoryReader{Store: db, Capture: historyCaptureFunc(func(context.Context, string, string) (model.Document, error) {
		calls.Add(1)
		return nil, errors.New("fixture transport unavailable")
	}), Now: func() time.Time { return now }}
	for n := int64(1); n <= 5; n++ {
		now = now.Add(6 * time.Minute)
		if e = failed.capture(ctx, target); e == nil {
			t.Fatal("native integration failure became success")
		}
		status := readCheckpoint()
		actualCount := n
		if actualCount > 4 {
			actualCount = 4
		}
		if model.String(status, "status") != "UNAVAILABLE" || model.String(status, "reason_code") != "HISTORY_CAPTURE_UNAVAILABLE" || model.Number(status, "consecutive_failures") != actualCount {
			t.Fatal("retry state lost its explicit blocker")
		}
		at, e := time.Parse(time.RFC3339Nano, model.String(status, "next_poll_at"))
		if e != nil || at.Sub(now) != hardwareBackoff(actualCount) {
			t.Fatal("retry delay differs from bounded native reader backoff", e)
		}
		before := calls.Load()
		if e = failed.capture(ctx, target); e != nil || calls.Load() != before {
			t.Fatal("backoff was ignored across process instances", e)
		}
	}
	before := calls.Load()
	foreign := target
	foreign.TenantID += "-foreign"
	if e = failed.capture(ctx, foreign); e == nil || calls.Load() != before {
		t.Fatal("foreign tenant reached native transport", e)
	}
	// Dedicated reader cannot manufacture declaration or execution authority.
	if e = db.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "SELECT count(*) FROM signed_plans WHERE tenant_id=$1", tenant)
		return e
	}); e == nil {
		t.Fatal("ingestion reader gained signer-envelope access")
	}
}
