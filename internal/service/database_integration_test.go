package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This exercises real authenticated API requests and a separately authenticated
// analytical database login. Missing evidence is a persisted blocked result,
// never an apparently successful zero-cost recommendation.
func TestDatabaseReadOnlyAssessmentQueueAndTenantIsolation(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	parsed, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + f.roles["api"].Pool.Config().ConnConfig.Database
	admin, err := store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	login := "database_" + model.ID()
	password := model.ID()
	if _, err = admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_database_analyst"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, e := admin.Pool.Exec(ctx, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	}()
	analystURL := *parsed
	analystURL.User = url.UserPassword(login, password)
	analyst, err := store.OpenRuntime(ctx, analystURL.String(), "database-assessor")
	if err != nil {
		t.Fatal(err)
	}
	defer analyst.Pool.Close()
	resource := model.Document{"id": "database-queue", "resource_type": "RDS_INSTANCE", "provider": "AWS", "provider_resource_id": "arn:aws:rds:eu-west-1:111122223333:db:review", "account_id": "111122223333", "region": "eu-west-1", "database_configuration": model.Document{"engine": "postgres", "class": "db.r6i.large"}}
	if err = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.Create(ctx, "resources", resource); return e }); err != nil {
		t.Fatal(err)
	}
	token := f.token(f.tenant, "db-finops", "FINOPS_ADMIN")
	code, request, _ := f.request("database-assessments", `"0"`, "database-request", token, model.Document{"resource_id": resource["id"]})
	if code != 202 || model.String(request, "status") != "QUEUED" {
		t.Fatal("queue", code, request)
	}
	again, replay, _ := f.request("database-assessments", `"0"`, "database-request", token, model.Document{"resource_id": resource["id"]})
	if again != 202 || replay["id"] != request["id"] {
		t.Fatal("idempotent queue", again, replay)
	}
	bad, _, _ := f.request("database-assessments", `"0"`, "database-amounts", token, model.Document{"resource_id": resource["id"], "amount": "0"})
	if bad != 422 {
		t.Fatal("authoritative amount accepted", bad)
	}
	api := &API{Store: analyst}
	calls := 0
	read := func(context.Context, string, model.Document) ([]byte, error) {
		calls++
		return nil, errors.New("must not read missing evidence")
	}
	if err = analyst.Do(ctx, f.tenant, func(tx *store.Tx) error { return databaseAssessmentOne(ctx, api, tx, read) }); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("missing snapshot was fetched")
	}
	code, result := fleetNativeHTTPGet(t, f, "database-assessments/"+model.String(request, "id"), token)
	if code != 200 || model.String(result, "status") != "BLOCKED" || databaseObject(result["assessment"])["verified_saving"] != nil {
		t.Fatal("persisted blocked result", code, result)
	}
	// A publication cannot redirect one resource's evidence to another owner's
	// resource, even through the analytical SQL identity. The BEFORE trigger must
	// reject the wrong binding before the existing publication's unique key.
	if err = analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		publication, e := api.databaseRecommendationGet(ctx, tx, model.String(request, "id"))
		if e != nil {
			return e
		}
		publication["resource_id"] = "different-owner-resource"
		raw, e := json.Marshal(publication)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO database_recommendation_publications(tenant_id,assessment_id,resource_id,document) VALUES($1,$2,$3,$4)", f.tenant, request["id"], resource["id"], raw)
		return e
	}); err == nil {
		t.Fatal("publication redirected another resource's evidence")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatal("wrong-bound publication did not reach binding guard", err)
		}
	}
	other := f.token("other-tenant", "db-finops", "FINOPS_ADMIN")
	code, _ = fleetNativeHTTPGet(t, f, "database-assessments/"+model.String(request, "id"), other)
	if code != 404 {
		t.Fatal("cross tenant assessment disclosed", code)
	}
	if err = analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE database_assessments SET status='QUEUED' WHERE tenant_id=$1 AND id=$2", f.tenant, request["id"])
		return e
	}); err == nil {
		t.Fatal("completed assessment mutated")
	}
	if err = analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO entities(tenant_id,kind,id,document) VALUES($1,'change_plans','forged','{}')", f.tenant)
		return e
	}); err == nil {
		t.Fatal("analyst acquired plan write authority")
	}
	if err = analyst.Do(ctx, "other-tenant", func(tx *store.Tx) error { _, e := tx.DatabaseAssessmentGet(ctx, model.String(request, "id")); return e }); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("analyst cross tenant boundary", err)
	}
}
