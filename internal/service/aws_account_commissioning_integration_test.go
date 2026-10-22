package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Real OIDC validation, API idempotency, separate database identities, leases
// and immutable tenant-RLS reports. The access report here is labelled synthetic;
// it creates no native billing or customer commissioning evidence.
func TestAWSAccountCommissioningScopedAPIAndImmutableRecovery(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	operator := f.token(f.tenant, "account-operator", "PLATFORM_ADMIN")
	for _, field := range []string{"role_arn", "external_id", "credentials", "execution_authorized", "billing", "complete"} {
		if code, _, _ := f.request("cloud-accounts", "", "account-inject-"+field, operator, model.Document{"provider": "AWS", field: "forbidden"}); code != 422 {
			t.Fatalf("caller field accepted %s %d", field, code)
		}
	}
	code, account, _ := f.request("cloud-accounts", "", "account-read-only-once", operator, model.Document{"provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "name": "Explicit synthetic commissioning"})
	if code != 201 || account["connection_mode"] != "READ_ONLY" || account["read_role_binding_id"] != "fixture-aws-readonly" {
		t.Fatalf("account registration %d %#v", code, account)
	}
	if status, bindings := fleetNativeHTTPGet(t, f, "aws-read-bindings", operator); status != 200 || len(storageRows(bindings["items"])) != 1 {
		t.Fatal("approved metadata unavailable", status)
	}
	path := "cloud-accounts/" + model.String(account, "id") + "/preflights"
	if code, _, _ := f.request(path, `"1"`, "preflight-inject-evidence", operator, model.Document{"complete": true}); code != 422 {
		t.Fatal("caller supplied readiness")
	}
	if code, _, _ := f.request(path, "", "preflight-require-version", operator, model.Document{}); code != 428 {
		t.Fatal("preflight omitted concurrency", code)
	}
	if code, _, _ := f.request(path, `"0"`, "preflight-stale-version", operator, model.Document{}); code != 409 {
		t.Fatal("preflight stale version", code)
	}
	code, queued, _ := f.request(path, `"1"`, "preflight-once-only", operator, model.Document{})
	if code != 202 {
		t.Fatalf("queue %d %#v", code, queued)
	}
	if code, replay, _ := f.request(path, `"1"`, "preflight-once-only", operator, model.Document{}); code != 202 || replay["id"] != queued["id"] {
		t.Fatal("idempotent request duplicated")
	}
	for _, role := range []string{"VIEWER", "AUDITOR", "APPROVER", "FINANCE", "APPLICATION_OWNER"} {
		if code, _, _ := f.request(path, `"1"`, "preflight-once-only", f.token(f.tenant, "account-operator", role), model.Document{}); code != 403 {
			t.Fatal("cached preflight escaped current role", role, code)
		}
	}
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.AWSAccountPreflightClaim(ctx, "api-must-not-claim", time.Now())
		return e
	}); e == nil {
		t.Fatal("API claimed provider job")
	}
	ingester := f.roles["ingester"]
	firstToken, secondToken := "stale-ingester-token", "recovered-ingester-token"
	id := model.String(queued, "id")
	if e := ingester.Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.AWSAccountPreflightClaim(ctx, firstToken, time.Now().Add(-10*time.Minute))
		if e == nil && d["id"] != id {
			t.Fatal("wrong job claimed")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := ingester.Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.AWSAccountPreflightClaim(ctx, secondToken, time.Now())
		if e == nil && d["id"] != id {
			t.Fatal("restart lost original job")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	report := model.Document{"schema_version": "1", "id": model.ID(), "tenant_id": f.tenant, "preflight_id": id, "cloud_account_id": account["id"], "cloud_account_version": account["version"], "account_id": account["account_id"], "region": account["region"], "read_role_binding_id": account["read_role_binding_id"], "fixture": true, "summary_state": "READ_ONLY_READY", "observation_basis": "SYNTHETIC_PERSISTENCE_COMPONENT_CHECK", "execution_authorized": false, "verified_saving": nil, "content_hash": "synthetic-component-hash"}
	if e := ingester.Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.AWSAccountPreflightComplete(ctx, id, firstToken, report) }); !errors.Is(e, store.ErrConflict) {
		t.Fatal("expired owner published a report", e)
	}
	if e := ingester.Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.AWSAccountPreflightComplete(ctx, id, secondToken, report) }); e != nil {
		t.Fatal(e)
	}
	if status, d := fleetNativeHTTPGet(t, f, path+"/"+id, operator); status != 200 || d["status"] != "COMPLETED" || storageObject(d["report"])["id"] != report["id"] {
		t.Fatal("normal persisted readback", status, d)
	}
	if status, d := fleetNativeHTTPGet(t, f, path+"/"+id+"/report", operator); status != 200 || d["id"] != report["id"] {
		t.Fatal("authenticated report export", status)
	}
	if status, _ := fleetNativeHTTPGet(t, f, path+"?limit=1", operator); status != 200 {
		t.Fatal("normal page unavailable", status)
	}
	if status, _ := fleetNativeHTTPGet(t, f, path+"/"+id, f.token(f.tenant, "owner", "APPLICATION_OWNER")); status != 403 {
		t.Fatal("scoped owner saw account finances", status)
	}
	if status, _ := fleetNativeHTTPGet(t, f, path+"/"+id+"/report", f.token("foreign-"+f.tenant, "foreign", "FINOPS_ADMIN")); status != 404 {
		t.Fatal("cross-tenant report disclosed", status)
	}
	for _, db := range []*store.Store{f.roles["api"], ingester} {
		if e := db.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "UPDATE aws_account_commissioning_reports SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, report["id"])
			return e
		}); e == nil {
			t.Fatal("immutable report changed")
		}
	}
	if e := ingester.Do(ctx, "foreign-"+f.tenant, func(tx *store.Tx) error {
		_, e := tx.AWSAccountCommissioningReport(ctx, model.String(account, "id"), id)
		return e
	}); e == nil {
		t.Fatal("database tenant RLS leaked report")
	}
	// Switching out of fixture commissioning leaves the stored/exported report
	// intact, while the synthetic binding has no live operator approval.
	f.api.Config.Fixture = false
	t.Setenv("AWS_ACCOUNT_APPROVED_BINDINGS_JSON", "{}")
	if status, d := fleetNativeHTTPGet(t, f, path+"/"+id, operator); status != 200 || d["binding_current"] != false || storageObject(d["report"])["content_hash"] != report["content_hash"] {
		t.Fatal("revoked binding hid or rewrote historical report", status, d)
	}
	if status, d := fleetNativeHTTPGet(t, f, path+"/"+id+"/report", operator); status != 200 || d["content_hash"] != report["content_hash"] {
		t.Fatal("binding revocation changed export", status)
	}
}
