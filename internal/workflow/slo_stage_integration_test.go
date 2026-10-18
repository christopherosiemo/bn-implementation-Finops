package workflow

import (
	"context"
	"os"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSLORolledBackStageProjectsRestoredRunningInventory(t *testing.T) {
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
	tenant, execution := "slo-stage-"+model.ID(), model.ID()
	if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		resource, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		resource["state"] = "stopped"
		if _, e = tx.Update(ctx, "resources", "resource-dev-api", model.Number(resource, "version"), resource); e != nil {
			return e
		}
		_, e = tx.Create(ctx, "executions", model.Document{"id": execution, "resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "RESTORING", "stage": "STARTING", "restoration_owned": true, "restoration_started_at": model.Now(), "error": "SLO_P95_HARD_BREACH"})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, e := connection.Exec(ctx, "SET ROLE finops_worker")
		return e
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	a := &Activities{Store: &store.Store{Pool: pool}, Config: service.Config{Fixture: true}}
	// Mandatory health and provider ownership completion are covered by executor
	// tests. This regression exercises the real worker's terminal projection of
	// that successful recovery while retaining the occurrence's SLO failure.
	terminal := StageInput{Input: model.WorkflowInput{TenantID: tenant, ExecutionID: execution}, Status: "FAILED", Stage: "ROLLED_BACK", Owned: false, Error: "SLO_P95_HARD_BREACH"}
	for n := 0; n < 2; n++ {
		if err = a.Stage(ctx, terminal); err != nil {
			t.Fatal(err)
		}
		if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
				return e
			}
			resource, e := tx.Get(ctx, "resources", "resource-dev-api")
			if e != nil {
				return e
			}
			if model.String(resource, "state") != "running" {
				t.Fatal("successfully restored rollback left inventory stopped")
			}
			x, e := tx.Get(ctx, "executions", execution)
			if e != nil {
				return e
			}
			if model.String(x, "status") != "FAILED" || model.String(x, "stage") != "ROLLED_BACK" || model.Bool(x, "restoration_owned") || model.String(x, "restoration_completed_at") == "" {
				t.Fatalf("terminal rollback lost failure or completion: %v", x)
			}
			for _, event := range []string{"execution.rolled_back", "restoration.completed", "execution.completed"} {
				var count int
				if e = tx.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE tenant_id=$1 AND event_type=$2 AND (payload->>'execution_id'=$3 OR payload->>'id'=$3)", tenant, event, execution).Scan(&count); e != nil {
					return e
				}
				want := 1
				if event == "execution.completed" {
					want = 0
				}
				if count != want {
					t.Fatalf("stage replay emitted %s %d times, want %d", event, count, want)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
