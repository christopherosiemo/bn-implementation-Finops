package workflow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"go.temporal.io/sdk/client"
)

// Only the administrator URL is reused. All migrations, fixture control rows
// and authenticated product logins belong to this new, comment-owned database.
func schedulerTestDatabase(t *testing.T) (*store.Store, map[string]*store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL enables a new disposable scheduler database")
	}
	ctx := context.Background()
	master, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal("scheduler test administrator unavailable")
	}
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, owner := "workflow_skip_"+suffix, "finops-local-scheduler:"+suffix
	if _, err = master.Pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		master.Pool.Close()
		t.Fatal(err)
	}
	var admin *store.Store
	roles, logins := map[string]*store.Store{}, []string{}
	t.Cleanup(func() {
		for _, role := range roles {
			if role != nil {
				role.Pool.Close()
			}
		}
		if admin != nil {
			admin.Pool.Close()
		}
		var actual string
		if err := master.Pool.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1", database).Scan(&actual); err != nil || actual != owner {
			t.Error("scheduler database cleanup ownership mismatch")
		} else if _, err := master.Pool.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		for _, login := range logins {
			if err := master.Pool.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); err != nil || actual != owner {
				t.Error("scheduler login cleanup ownership mismatch")
			} else if _, err := master.Pool.Exec(ctx, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); err != nil {
				t.Error(err)
			}
		}
		master.Pool.Close()
	})
	if _, err = master.Pool.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" IS '"+owner+"'"); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("scheduler administrator URL invalid")
	}
	parsed.Path = "/" + database
	admin, err = store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("scheduler owned database unavailable")
	}
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"api", "worker", "executor"} {
		login, password := "workflow_skip_"+role+"_"+suffix, model.ID()+model.ID()
		if _, err = master.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'"); err != nil {
			t.Fatal("scheduler product login creation failed")
		}
		logins = append(logins, login)
		if _, err = master.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+owner+"'"); err != nil {
			t.Fatal(err)
		}
		if _, err = master.Pool.Exec(ctx, "GRANT "+pgx.Identifier{"finops_" + role}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		roleURL := *parsed
		roleURL.User = url.UserPassword(login, password)
		roles[role], err = store.OpenRuntime(ctx, roleURL.String(), role)
		if err != nil {
			t.Fatal("dedicated scheduler product login rejected", role)
		}
	}
	return admin, roles
}

func TestSchedulerConsumedSkipPersistsForQueuedOccurrenceAcrossRestart(t *testing.T) {
	admin, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenant, executionID := "skip-"+model.ID(), model.ID()
	now := time.Now().UTC()
	location, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Fatal(err)
	}
	local := now.In(location)
	stopAt := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), local.Minute(), 0, 0, location).UTC()
	nextStop := time.Date(local.Year(), local.Month(), local.Day()+1, local.Hour(), local.Minute(), 0, 0, location).UTC()
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if err := tx.Seed(ctx, true); err != nil {
			return err
		}
		schedule, err := tx.Get(ctx, "schedules", "schedule-dev")
		if err != nil {
			return err
		}
		schedule["timezone"], schedule["stop_time"], schedule["skip_next_stop"] = "Europe/London", local.Format("15:04"), false
		if _, err = tx.Update(ctx, "schedules", "schedule-dev", model.Number(schedule, "version"), schedule); err != nil {
			return err
		}
		_, err = tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": model.ID(), "schedule_id": "schedule-dev", "resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "QUEUED", "stop_at": stopAt.Format(time.RFC3339Nano)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The API guard is held before the scheduler's first read. A worker queued
	// on that exact lock must see the committed skip, not an earlier snapshot.
	control, err := roles["api"].Begin(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Rollback(context.Background())
	if _, err = control.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":scheduling-control"); err != nil {
		t.Fatal(err)
	}
	worker, err := roles["worker"].Begin(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Rollback(context.Background())
	var workerPID int
	if err = worker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&workerPID); err != nil {
		t.Fatal(err)
	}
	a := &Activities{Store: roles["worker"], Config: service.Config{Fixture: true}}
	finished := make(chan error, 1)
	go func() {
		err := scheduleDueAt(ctx, a, worker, now)
		if err == nil {
			err = worker.Commit(ctx)
		}
		finished <- err
	}()
	waitSchedulerLock(t, ctx, admin, workerPID)
	schedule, err := control.Get(ctx, "schedules", "schedule-dev")
	if err != nil {
		t.Fatal(err)
	}
	schedule["skip_next_stop"] = true
	if _, err = control.Update(ctx, "schedules", "schedule-dev", model.Number(schedule, "version"), schedule); err != nil {
		t.Fatal(err)
	}
	if err = control.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	// Restart the reader with a fresh authenticated connection pool. The skip
	// decision is durable database evidence, not a scheduler/process variable.
	executorDSN := roles["executor"].Pool.Config().ConnConfig.ConnString()
	roles["executor"].Pool.Close()
	roles["executor"], err = store.OpenRuntime(ctx, executorDSN, "executor")
	if err != nil {
		t.Fatal(err)
	}
	if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		s, err := tx.Get(ctx, "schedules", "schedule-dev")
		if err != nil {
			return err
		}
		if model.Bool(s, "skip_next_stop") || model.String(s, "last_occurrence_date") != local.Format("2006-01-02") {
			return fmt.Errorf("scheduler did not consume this occurrence atomically")
		}
		for _, test := range []struct {
			at   time.Time
			want bool
		}{{stopAt, true}, {stopAt.Add(15 * time.Second), false}, {stopAt.Add(time.Minute), false}, {nextStop, false}} {
			skipped, err := service.ScheduleStopSkipped(ctx, tx, "schedule-dev", test.at)
			if err != nil || skipped != test.want {
				return fmt.Errorf("production skip gate lost occurrence binding: skipped=%v want=%v err=%v", skipped, test.want, err)
			}
		}
		x, err := tx.Get(ctx, "executions", executionID)
		if err != nil || model.String(x, "status") != "QUEUED" {
			return fmt.Errorf("skip must constrain the pending STOP without rewriting its recovery state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Same-minute scheduler retries do not append another receipt. A later day
	// consumes no additional skip and remains eligible for independent planning.
	for _, instant := range []time.Time{now, nextStop} {
		if err = roles["worker"].Do(ctx, tenant, func(tx *store.Tx) error { return scheduleDueAt(ctx, a, tx, instant) }); err != nil {
			t.Fatal(err)
		}
	}
	if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='schedule.stop_skipped' AND resource='schedule-dev'", tenant).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("skip receipt replay duplicated history: %d", count)
		}
		skipped, err := service.ScheduleStopSkipped(ctx, tx, "schedule-dev", nextStop)
		if err != nil || skipped {
			return fmt.Errorf("one skip cancelled a later occurrence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = roles["api"].Do(ctx, "another-tenant", func(tx *store.Tx) error { return tx.Seed(ctx, false) }); err != nil {
		t.Fatal(err)
	}
	if err = roles["executor"].Do(ctx, "another-tenant", func(tx *store.Tx) error {
		skipped, err := service.ScheduleStopSkipped(ctx, tx, "schedule-dev", stopAt)
		if err != nil || skipped {
			return fmt.Errorf("skip evidence crossed tenants")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Reset generations retain immutable audit. A new fixture generation must
	// not inherit a previous logical cycle's cancellation at the same instant.
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		org, err := tx.Get(ctx, "org", tenant)
		if err != nil {
			return err
		}
		org["fixture_generation"] = model.ID()
		_, err = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		skipped, err := service.ScheduleStopSkipped(ctx, tx, "schedule-dev", stopAt)
		if err != nil || skipped {
			return fmt.Errorf("old fixture-generation skip constrained a new cycle")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerHonorsPreassignedSkipBeforeAnyPlanning(t *testing.T) {
	_, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenant := "assigned-skip-" + model.ID()
	now := time.Now().UTC()
	stopAt := now.Truncate(time.Minute)
	if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		// This is an API-assigned calendar receipt under the actual API role.
		// No cloud evidence or new execution authority is introduced.
		if err := tx.Seed(ctx, false); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":scheduling-control"); err != nil {
			return err
		}
		if _, err := tx.Create(ctx, "schedules", model.Document{"id": "assigned", "workload_id": "workload", "timezone": "UTC", "stop_time": stopAt.Format("15:04"), "days": []int{1, 2, 3, 4, 5, 6, 7}, "mode": "ASSISTED_EXECUTION", "skip_next_stop": false}); err != nil {
			return err
		}
		// If the receipt is ignored, BuildPlan will visibly reject this
		// deliberately unavailable financial prerequisite and append blocked.
		if _, err := tx.Create(ctx, "recommendations", model.Document{"workload_id": "workload", "status": "VALIDATED", "pre_execution_ready": false}); err != nil {
			return err
		}
		if _, err := tx.Create(ctx, "executions", model.Document{"change_plan_id": model.ID(), "schedule_id": "assigned", "status": "QUEUED", "stop_at": stopAt.Format(time.RFC3339Nano)}); err != nil {
			return err
		}
		return tx.Audit(ctx, "operator", "schedule.stop_skipped", "assigned", model.Document{"schedule_id": "assigned", "stop_at": stopAt.Format(time.RFC3339Nano)})
	}); err != nil {
		t.Fatal(err)
	}
	a := &Activities{Store: roles["worker"], Config: service.Config{Fixture: false}}
	for n := 0; n < 2; n++ {
		if err := roles["worker"].Do(ctx, tenant, func(tx *store.Tx) error { return scheduleDueAt(ctx, a, tx, now) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		s, err := tx.Get(ctx, "schedules", "assigned")
		if err != nil {
			return err
		}
		if model.String(s, "last_occurrence_date") != stopAt.Format("2006-01-02") || model.Bool(s, "skip_next_stop") {
			return fmt.Errorf("assigned skip did not finish its exact schedule occurrence")
		}
		var skipped, planning int
		if err = tx.QueryRow(ctx, "SELECT count(*) FILTER(WHERE action='schedule.stop_skipped'), count(*) FILTER(WHERE action='schedule.blocked') FROM audit_events WHERE tenant_id=$1", tenant).Scan(&skipped, &planning); err != nil {
			return err
		}
		if skipped != 1 || planning != 0 {
			return fmt.Errorf("assigned skip appended duplicate receipt or attempted planning: %d %d", skipped, planning)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := roles["worker"].Do(ctx, tenant, func(tx *store.Tx) error { return scheduleDueAt(ctx, a, tx, now.AddDate(0, 0, 1)) }); err != nil {
		t.Fatal(err)
	}
	if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		var attempted int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='schedule.blocked'", tenant).Scan(&attempted); err != nil {
			return err
		}
		if attempted != 1 {
			return fmt.Errorf("previous skip prevented the next day's independent planning")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func waitSchedulerLock(t *testing.T, ctx context.Context, admin *store.Store, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := admin.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scheduler did not wait on the control guard before reading")
}

type schedulerStarter struct{ calls atomic.Int32 }

func (s *schedulerStarter) ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error) {
	s.calls.Add(1)
	return nil, nil
}

func TestSchedulerDispatchCommitsBeforeIndependentWebhookFailure(t *testing.T) {
	admin, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenant := "scheduler-outbox-" + model.ID()
	if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if err := tx.Seed(ctx, false); err != nil {
			return err
		}
		if _, err := tx.Create(ctx, "executions", model.Document{"change_plan_id": model.ID(), "status": "QUEUED"}); err != nil {
			return err
		}
		return tx.Event(ctx, "execution.started", model.Document{"fixture": true})
	}); err != nil {
		t.Fatal(err)
	}
	if err := roles["api"].Do(ctx, tenant+"-other", func(tx *store.Tx) error {
		if err := tx.Seed(ctx, false); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "executions", model.Document{"change_plan_id": model.ID(), "status": "QUEUED"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	starter := &schedulerStarter{}
	var received atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if starter.calls.Load() != 2 {
			t.Error("notification receiver delayed already-queued workflow dispatch")
		}
		if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
			var available bool
			if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", tenant+":scheduling-control").Scan(&available); err != nil {
				return err
			}
			if !available {
				return fmt.Errorf("webhook request retained the scheduling-control lock")
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer receiver.Close()
	a := &Activities{Store: roles["worker"], Config: service.Config{Fixture: true, WebhookURL: receiver.URL, WebhookSecret: "local-test-only"}, HTTP: receiver.Client()}
	if err := dispatchQueued(ctx, starter, a); err != nil {
		t.Fatal(err)
	}
	if starter.calls.Load() != 2 || received.Load() != 1 {
		t.Fatal("queued dispatch or notification attempt missing")
	}
	if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		var attempts int
		var pending bool
		if err := tx.QueryRow(ctx, "SELECT attempts,delivered_at IS NULL FROM outbox WHERE tenant_id=$1", tenant).Scan(&attempts, &pending); err != nil {
			return err
		}
		if attempts != 1 || !pending {
			return fmt.Errorf("webhook failure did not retain durable retry")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A configuration failure happens before querying the outbox. It must also
	// leave queued workflow dispatch independent and the retry rows untouched.
	a.Config.WebhookSecret = ""
	if err := dispatchQueued(ctx, starter, a); err != nil || starter.calls.Load() != 4 || received.Load() != 1 {
		t.Fatal("webhook configuration failure blocked queued dispatch", err)
	}
}
