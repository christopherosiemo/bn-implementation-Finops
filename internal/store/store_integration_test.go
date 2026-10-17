package store

import (
	"context"
	"os"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func TestPostgresTenantIsolationVersionsAndAppendOnlyEvidence(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to a disposable PostgreSQL admin database")
	}
	ctx := context.Background()
	db, e := Open(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenantA, tenantB := "test-"+model.ID(), "test-"+model.ID()
	var id string
	if e = db.Do(ctx, tenantA, func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		d, e := tx.Create(ctx, "workloads", model.Document{"name": "private-a"})
		if e != nil {
			return e
		}
		id = model.String(d, "id")
		return tx.Audit(ctx, "test", "created", id, nil)
	}); e != nil {
		t.Fatal(e)
	}
	if e = db.Do(ctx, tenantB, func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if _, e := tx.Get(ctx, "workloads", id); e != pgx.ErrNoRows {
			t.Fatalf("cross-tenant read returned %v", e)
		}
		rows, e := tx.List(ctx, "workloads")
		if e != nil {
			return e
		}
		if len(rows) != 0 {
			t.Fatal("tenant B saw tenant A")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = db.Do(ctx, tenantA, func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		d, e := tx.Get(ctx, "workloads", id)
		if e != nil {
			return e
		}
		d["name"] = "updated"
		if _, e = tx.Update(ctx, "workloads", id, 1, d); e != nil {
			return e
		}
		if _, e = tx.Update(ctx, "workloads", id, 1, d); e != ErrConflict {
			t.Fatalf("stale update accepted: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	tx, e := db.Begin(ctx, tenantA)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "UPDATE audit_events SET action='tampered' WHERE tenant_id=$1", tenantA); e == nil {
		t.Fatal("audit UPDATE permitted")
	}
	// The same database identity must see zero rows without a tenant context.
	conn, e := db.Pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Release()
	raw, e := conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Rollback(ctx)
	if _, e = raw.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = raw.QueryRow(ctx, "SELECT count(*) FROM entities").Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n != 0 {
		t.Fatalf("unscoped database query saw %d rows", n)
	}
}
