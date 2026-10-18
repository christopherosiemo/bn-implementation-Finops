package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func dependencyRequest(t *testing.T, ctx context.Context, api *API, db *store.Store, tenant, path string, version int64, body model.Document, viewer bool) (model.Document, error) {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/"+path, nil)
	r.Header.Set("If-Match", fmt.Sprintf("\"%d\"", version))
	var wire model.Document
	b, _ := json.Marshal(body)
	_ = json.Unmarshal(b, &wire)
	i := auth.Identity{Tenant: tenant, Subject: "dependency-reviewer", Roles: map[string]bool{"PLATFORM_ADMIN": !viewer, "VIEWER": viewer}}
	var out model.Document
	e := db.Do(ctx, tenant, func(tx *store.Tx) error { var e error; out, _, e = api.mutate(ctx, tx, i, r, wire); return e })
	return out, e
}

func seedDependencyReview(t *testing.T, ctx context.Context, api *API, db *store.Store, tenant, resource string) model.Document {
	t.Helper()
	var g, res model.Document
	if e := db.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		g, e = dependencyGraph(ctx, tx)
		if e != nil {
			return e
		}
		res, e = tx.Get(ctx, "resources", resource)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	g, e := dependencyRequest(t, ctx, api, db, tenant, "resource-graph", model.Number(g, "version"), model.Document{"edges": []any{}, "reason": "explicit standalone fixture dependency review"}, false)
	if e != nil {
		t.Fatal(e)
	}
	review, e := dependencyRequest(t, ctx, api, db, tenant, "resources/"+resource+"/dependency-reviews", model.Number(res, "version"), model.Document{"graph_version": g["version"], "valid_until": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), "acknowledgement": "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES", "note": "Operator reviewed discovered inventory and external relationships"}, false)
	if e != nil {
		t.Fatal(e)
	}
	if model.String(review, "status") != "READY" {
		t.Fatalf("standalone graph blocked:%v", review)
	}
	return review
}

func TestDependencyReviewsBindAuthorityAndCurrentInventory(t *testing.T) {
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
	tenant := "dependency-api-" + model.ID()
	db := trustedRoleStore(t, dsn, "finops_api")
	api := API{Store: db, Config: Config{Fixture: true}}
	if e = db.Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); e != nil {
		t.Fatal(e)
	}
	if e = db.Do(ctx, tenant, func(tx *store.Tx) error { return DependencyPlanReady(ctx, tx, "resource-dev-api", "", "", time.Now()) }); e == nil {
		t.Fatal("unknown graph authorized stop")
	}
	_, e = dependencyRequest(t, ctx, &api, db, tenant, "resource-graph", 0, model.Document{"edges": []any{}, "reason": "viewer mutation"}, true)
	var p *Problem
	if !errors.As(e, &p) || p.Status != 403 {
		t.Fatalf("viewer graph write:%v", e)
	}
	for _, edge := range []model.Document{{"from": "workload:workload-dev", "to": "resource:another-tenant", "type": "DEPENDS_ON"}, {"from": "resource:resource-dev-api", "to": "workload:workload-dev", "type": "DEPENDS_ON"}, {"from": "workload:workload-dev", "to": "resource:resource-dev-api", "type": "DEPENDS_ON", "source": "TRUSTED"}} {
		if _, e = dependencyRequest(t, ctx, &api, db, tenant, "resource-graph", 0, model.Document{"edges": []model.Document{edge}, "reason": "invalid edge"}, false); e == nil {
			t.Fatalf("invalid graph accepted:%v", edge)
		}
	}
	review := seedDependencyReview(t, ctx, &api, db, tenant, "resource-dev-api")
	check := func(at time.Time) error {
		return db.Do(ctx, tenant, func(tx *store.Tx) error {
			return DependencyPlanReady(ctx, tx, "resource-dev-api", model.String(review, "id"), model.String(review, "graph_hash"), at)
		})
	}
	if e = check(time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = check(time.Now().Add(2 * time.Hour)); e == nil {
		t.Fatal("expired dependency review remained ready")
	}
	if _, e = dependencyRequest(t, ctx, &api, db, tenant, "resource-graph", 0, model.Document{"edges": []any{}, "reason": "stale writer"}, false); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("stale graph version:%v", e)
	}
	if e = db.Do(ctx, tenant+"-other", func(tx *store.Tx) error {
		_, e := tx.DependencyReviewGet(ctx, model.String(review, "id"))
		if !errors.Is(e, pgx.ErrNoRows) {
			t.Fatalf("tenant review leak:%v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = db.Do(ctx, tenant, func(tx *store.Tx) error {
		w, e := tx.Get(ctx, "workloads", "workload-dev")
		if e != nil {
			return e
		}
		w["owner"] = "different-owner@example.test"
		_, e = tx.Update(ctx, "workloads", "workload-dev", model.Number(w, "version"), w)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = check(time.Now()); e == nil {
		t.Fatal("owner change retained graph authority")
	}
	// Review bodies cannot supply an actor, authority hash or invented nodes.
	if _, e = dependencyRequest(t, ctx, &api, db, tenant, "resources/resource-dev-api/dependency-reviews", 1, model.Document{"reviewed_by": "another-actor"}, false); e == nil {
		t.Fatal("forged review authority accepted")
	}
}
