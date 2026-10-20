package activity

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"os"
	"strings"
	"testing"
)

// Database-boundary component only. Synthetic immutable references stand in for
// already validated archive/analytics writes; this does not claim ingress E2E.
func TestLambdaPerformanceAppendIdentityReplayRevisionAndIsolation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("existing disposable PostgreSQL required")
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
	tenant := "lambda-perf-" + model.ID()
	api, machine := sloRoleDB(t, dsn, "finops_api"), sloRoleDB(t, dsn, "finops_activity")
	arn := "arn:aws:lambda:eu-west-1:111122223333:function:component"
	source := model.ID()
	e = api.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": "function", "provider": "AWS", "resource_type": "LAMBDA_FUNCTION", "provider_resource_id": arn, "account_id": "111122223333", "region": "eu-west-1", "workload_id": "workload"}); e != nil {
			return e
		}
		_, e := tx.SourceCreate(ctx, model.Document{"id": source, "kind": "AWS_LAMBDA_PERFORMANCE_CURVE_V1", "enabled": true, "issuer": "https://machine.invalid", "audience": "finops-lambda-performance", "subject": "collector", "account_id": "111122223333", "region": "eu-west-1", "function_arn": arn, "qualifier": "live"})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	point := model.Clone(lambdaBenchmarkBody()["point"].(model.Document))
	point["binding"] = model.Document{"tenant_id": tenant, "provider": "AWS", "resource_id": "function", "provider_resource_id": arn, "workload_id": "workload", "account_id": "111122223333", "region": "eu-west-1"}
	receipt := model.Document{"schema_version": "1", "id": model.ID(), "source_id": source, "source_version": 1, "resource_id": "function", "qualifier": "live", "sequence": "1", "body_hash": strings.Repeat("a", 64), "idempotency_key": "first", "issuer": "https://machine.invalid", "audience": "finops-lambda-performance", "subject": "collector", "archive": model.Document{"version_id": "synthetic-immutable-version", "body_sha256": strings.Repeat("a", 64)}, "point": point}
	var original model.Document
	appendReceipt := func(in model.Document) error {
		return machine.Do(ctx, tenant, func(tx *store.Tx) error { var e error; original, e = tx.LambdaPerformanceAppend(ctx, in); return e })
	}
	if e = appendReceipt(receipt); e != nil {
		t.Fatal(e)
	}
	id := original["id"]
	if original["received_at"] == nil {
		t.Fatal("server receive timestamp absent")
	}
	if e = appendReceipt(receipt); e != nil || original["id"] != id {
		t.Fatal("exact replay changed receipt", e)
	}
	conflict := model.Clone(receipt)
	conflict["body_hash"] = strings.Repeat("b", 64)
	if e = appendReceipt(conflict); !errors.Is(e, store.ErrConflict) {
		t.Fatal("conflicting replay not rejected", e)
	}
	forged := model.Clone(receipt)
	forged["id"], forged["sequence"], forged["idempotency_key"] = model.ID(), "2", "console-forgery"
	if e = api.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.LambdaPerformanceAppend(ctx, forged); return e }); e == nil {
		t.Fatal("console database identity authored benchmark")
	}
	if e = api.Do(ctx, tenant+"-foreign", func(tx *store.Tx) error {
		points, e := tx.LambdaPerformanceForResource(ctx, "function", "live")
		if e == nil && len(points["receipts"].([]model.Document)) != 0 {
			t.Fatal("cross tenant receipt disclosed")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = api.Do(ctx, tenant, func(tx *store.Tx) error {
		points, e := tx.LambdaPerformanceForResource(ctx, "function", "live")
		if e != nil {
			return e
		}
		p := points["receipts"].([]model.Document)
		if len(p) != 1 || model.String(p[0], "id") != id {
			t.Fatal("receipt selection changed")
		}
		ref := p[0]["source_ref"].(model.Document)
		if ref["id"] != id || ref["version"] != "1" {
			t.Fatal("individual point immutable reference collision")
		}
		src, e := tx.SourceGet(ctx, source)
		if e != nil {
			return e
		}
		src["enabled"] = false
		_, e = tx.SourceUpdate(ctx, source, model.Number(src, "version"), src)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = api.Do(ctx, tenant, func(tx *store.Tx) error {
		points, e := tx.LambdaPerformanceForResource(ctx, "function", "live")
		if e == nil && len(points["receipts"].([]model.Document)) != 0 {
			t.Fatal("revocation retained current authority")
		}
		var n int
		err := tx.QueryRow(ctx, "SELECT count(*) FROM lambda_performance_receipts WHERE tenant_id=$1", tenant).Scan(&n)
		if err != nil {
			return err
		}
		if n != 1 {
			t.Fatal("revocation changed immutable history")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
