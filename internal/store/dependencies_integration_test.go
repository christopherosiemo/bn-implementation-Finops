package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestDependencyGraphAndOwnerReviewDatabaseBoundaries(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL requires disposable administrator PostgreSQL")
	}
	ctx := context.Background()
	db, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "dependency-" + model.ID()
	run := func(role, scope string, fn func(*Tx) error) error {
		return db.Do(ctx, scope, func(tx *Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	var graph, review model.Document
	if e = run("finops_api", tenant, func(tx *Tx) error {
		g, e := tx.DependencyGraph(ctx)
		if e != nil {
			return e
		}
		if model.Number(g, "version") != 0 {
			t.Fatal("new tenant has an implicitly reviewed graph")
		}
		if _, e = tx.Create(ctx, "resources", model.Document{"id": "resource", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		graph, e = tx.DependencyGraphAppend(ctx, 0, model.Document{"edges": []model.Document{}, "writer_role": "forged", "created_at": "2000-01-01T00:00:00Z"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if graph["writer_role"] != "finops_api" || model.Number(graph, "version") != 1 || strings.HasPrefix(model.String(graph, "created_at"), "2000") {
		t.Fatal("graph provenance/time was caller-controlled")
	}
	if e = run("finops_api", tenant, func(tx *Tx) error {
		_, e := tx.DependencyGraphAppend(ctx, 0, model.Document{"edges": []model.Document{}})
		return e
	}); !errors.Is(e, ErrConflict) {
		t.Fatalf("stale graph update accepted: %v", e)
	}
	makeReview := func() model.Document {
		return model.Document{"resource_id": "resource", "graph_version": 1, "graph_hash": strings.Repeat("a", 64), "inventory_hash": strings.Repeat("b", 64), "reviewed_by": "actual-owner", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), "writer_role": "finops_ingester", "created_at": "2000-01-01T00:00:00Z"}
	}
	if e = run("finops_api", tenant, func(tx *Tx) error { var e error; review, e = tx.DependencyReviewCreate(ctx, makeReview()); return e }); e != nil {
		t.Fatal(e)
	}
	if review["writer_role"] != "finops_api" || strings.HasPrefix(model.String(review, "created_at"), "2000") {
		t.Fatal("review provenance/time was caller-controlled")
	}
	for _, role := range []string{"finops_worker", "finops_signer", "finops_executor", "finops_ingester"} {
		if e = run(role, tenant, func(tx *Tx) error { _, e := tx.DependencyReviewCreate(ctx, makeReview()); return e }); e == nil {
			t.Fatalf("%s forged an owner review", role)
		}
		if e = run(role, tenant, func(tx *Tx) error {
			_, e := tx.DependencyGraphAppend(ctx, 1, model.Document{"edges": []model.Document{}})
			return e
		}); e == nil {
			t.Fatalf("%s changed graph", role)
		}
		if e = run(role, tenant, func(tx *Tx) error {
			g, e := tx.DependencyGraph(ctx)
			if e != nil {
				return e
			}
			if model.Number(g, "version") != 1 {
				t.Fatal("read-only runtime lost graph visibility")
			}
			_, e = tx.DependencyReviewGet(ctx, model.String(review, "id"))
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	for _, duration := range []time.Duration{-time.Minute, 25 * time.Hour} {
		if e = run("finops_api", tenant, func(tx *Tx) error {
			d := makeReview()
			d["expires_at"] = time.Now().Add(duration).UTC().Format(time.RFC3339Nano)
			_, e := tx.DependencyReviewCreate(ctx, d)
			return e
		}); e == nil {
			t.Fatal("expired or excessive review lifetime accepted")
		}
	}
	if e = run("finops_api", tenant, func(tx *Tx) error {
		_, e := tx.Exec(ctx, "UPDATE dependency_reviews SET reviewed_by='forged' WHERE tenant_id=$1", tenant)
		return e
	}); e == nil {
		t.Fatal("API rewrote immutable review")
	}
	if e = db.Do(ctx, tenant, func(tx *Tx) error {
		_, e := tx.Exec(ctx, "DELETE FROM dependency_graph_revisions WHERE tenant_id=$1", tenant)
		return e
	}); e == nil {
		t.Fatal("owner rewrote immutable graph history")
	}
	if e = run("finops_api", "other-"+tenant, func(tx *Tx) error {
		g, e := tx.DependencyGraph(ctx)
		if e != nil {
			return e
		}
		if model.Number(g, "version") != 0 {
			t.Fatal("graph leaked across tenants")
		}
		rows, e := tx.DependencyReviewList(ctx, "")
		if len(rows) != 0 {
			t.Fatal("review leaked across tenants")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_api", tenant, func(tx *Tx) error {
		_, e := tx.DependencyGraphAppend(ctx, 1, model.Document{"edges": []model.Document{}})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_api", tenant, func(tx *Tx) error { _, e := tx.DependencyReviewCreate(ctx, makeReview()); return e }); !errors.Is(e, ErrConflict) {
		t.Fatalf("review for replaced graph accepted: %v", e)
	}
	if e = run("finops_api", tenant, func(tx *Tx) error {
		rows, e := tx.DependencyReviewList(ctx, "resource")
		if len(rows) != 1 {
			t.Fatal("immutable review history missing")
		}
		latest, e := tx.DependencyReviewLatest(ctx, "resource")
		if e != nil {
			return e
		}
		if latest["id"] != review["id"] {
			t.Fatal("latest review changed without append")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
