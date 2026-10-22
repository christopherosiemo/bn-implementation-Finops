package service

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// A valid STOP check must retain its dependency snapshot until the provider
// dispatch transaction completes. Concurrent API graph and inventory writers
// share that guard; lock timeout proves they cannot commit a changed snapshot
// while an executor still holds the authority it checked.
func TestDependencyReadinessSerializesGraphAndInventoryWriters(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	writer := trustedRoleStore(t, dsn, "finops_api")
	executor := trustedRoleStore(t, dsn, "finops_executor")
	api := API{Store: writer, Config: Config{Fixture: true}}

	for _, kind := range []string{"graph_revision", "resource_update", "workload_update", "resource_create"} {
		t.Run(kind, func(t *testing.T) {
			tenant := "dependency-lock-" + model.ID()
			if err := writer.Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
				t.Fatal(err)
			}
			review := seedDependencyReview(t, ctx, &api, writer, tenant, "resource-dev-api")
			guard, err := executor.Begin(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = guard.Rollback(context.Background()) }()
			if err = DependencyPlanReady(ctx, guard, "resource-dev-api", model.String(review, "id"), model.String(review, "graph_hash"), time.Now()); err != nil {
				t.Fatal(err)
			}
			mutate := func(tx *store.Tx) error {
				switch kind {
				case "graph_revision":
					graph, err := tx.DependencyGraph(ctx)
					if err != nil {
						return err
					}
					_, err = tx.DependencyGraphAppend(ctx, model.Number(graph, "version"), model.Document{"edges": graph["edges"], "reason": "concurrent operator review"})
					return err
				case "resource_update", "workload_update":
					entity, id, field, value := "resources", "resource-dev-api", "provider_resource_id", "i-changed-provider-binding"
					if kind == "workload_update" {
						entity, id, field, value = "workloads", "workload-dev", "owner", "changed-owner@example.test"
					}
					d, err := tx.Get(ctx, entity, id)
					if err != nil {
						return err
					}
					d[field] = value
					_, err = tx.Update(ctx, entity, id, model.Number(d, "version"), d)
					return err
				case "resource_create":
					_, err := tx.Create(ctx, "resources", model.Document{"id": "new-resource", "provider": "AWS", "provider_resource_id": "i-new-binding", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "workload-dev", "environment": "NON_PRODUCTION"})
					return err
				}
				return errors.New("unknown concurrency scenario")
			}
			err = writer.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='200ms'"); err != nil {
					return err
				}
				return mutate(tx)
			})
			var blocked *pgconn.PgError
			if !errors.As(err, &blocked) || blocked.Code != "55P03" {
				t.Fatalf("writer escaped the executor's checked snapshot: %v", err)
			}
			// A timed-out writer must not have changed the checked authority.
			if err = DependencyPlanReady(ctx, guard, "resource-dev-api", model.String(review, "id"), model.String(review, "graph_hash"), time.Now()); err != nil {
				t.Fatalf("blocked writer changed dependency authority: %v", err)
			}
			if err = guard.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = writer.Do(ctx, tenant, mutate); err != nil {
				t.Fatalf("writer did not progress after dispatch guard released: %v", err)
			}
			if err = executor.Do(ctx, tenant, func(tx *store.Tx) error {
				return DependencyPlanReady(ctx, tx, "resource-dev-api", model.String(review, "id"), model.String(review, "graph_hash"), time.Now())
			}); err == nil || err.Error() != "DEPENDENCY_GRAPH_CHANGED" {
				t.Fatalf("committed graph/inventory update retained stale authority: %v", err)
			}
		})
	}
}
