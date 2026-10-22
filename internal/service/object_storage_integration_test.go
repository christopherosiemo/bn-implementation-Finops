package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObjectStorageIDsOnlyDatasetRevisionsIsolationAndBlockedPublication(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "object-storage-assessor", "finops_object_storage_analyst")
	var resource model.Document
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		resource, e = tx.Create(ctx, "resources", model.Document{"name": "Read-only S3 test", "provider": "AWS", "resource_type": "S3_BUCKET", "provider_resource_id": "arn:aws:s3:::scoped-bucket", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "replay-workload", "configuration_authority": "UNKNOWN"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	token := f.token(f.tenant, "s3-admin", "PLATFORM_ADMIN")
	rid := model.String(resource, "id")
	body := model.Document{"resource_id": rid, "name": "logs dataset", "selector": model.Document{"kind": "PREFIX", "prefix": "logs/"}, "policy": model.Document{"remaining_lifetime_days": nil, "rto_seconds": nil, "allow_onezone": nil}}
	code, dataset, _ := f.request("object-storage-datasets", `"0"`, "s3-dataset-create", token, body)
	if code != 201 || model.Number(dataset, "version") != 1 {
		t.Fatal("dataset create", code, dataset)
	}
	code, replay, _ := f.request("object-storage-datasets", `"0"`, "s3-dataset-create", token, body)
	if code != 201 || replay["id"] != dataset["id"] {
		t.Fatal("idempotent dataset", code, replay)
	}
	bad := model.Clone(body)
	bad["observed_requests"] = "0"
	if code, _, _ := f.request("object-storage-datasets", `"0"`, "s3-no-observations", token, bad); code != 422 {
		t.Fatal("dataset accepted observations", code)
	}
	did := model.String(dataset, "id")
	updated := model.Clone(body)
	updated["name"] = "revised dataset"
	if code, _, _ := f.request("object-storage-datasets/"+did+"/revisions", `"0"`, "s3-stale-policy", token, updated); code != 409 && code != 412 {
		t.Fatal("stale dataset revision", code)
	}
	code, version, _ := f.request("object-storage-datasets/"+did+"/revisions", `"1"`, "s3-policy-revision", token, updated)
	if code != 201 || model.Number(version, "version") != 2 {
		t.Fatal("dataset revision", code, version)
	}
	foreign := f.token("foreign-s3-tenant", "s3-admin", "PLATFORM_ADMIN")
	if status, _ := fleetNativeHTTPGet(t, f, "object-storage-datasets/"+did, foreign); status != 404 {
		t.Fatal("cross-tenant dataset", status)
	}
	if status, _ := fleetNativeHTTPGet(t, f, "object-storage-datasets?resource_id="+rid+"&limit=1", token); status != 200 {
		t.Fatal("scoped dataset list", status)
	}
	if code, _, _ := f.request("object-storage-assessments", `"0"`, "s3-caller-cost", token, model.Document{"resource_id": rid, "monthly_saving": "1000"}); code != 422 {
		t.Fatal("authoritative caller amount", code)
	}
	code, queued, _ := f.request("object-storage-assessments", `"0"`, "s3-assessment", token, model.Document{"resource_id": rid, "dataset_id": did})
	if code != 202 {
		t.Fatal("IDs-only queue", code, queued)
	}
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		return objectStorageAssessmentOne(ctx, f.api, tx, func(context.Context, string, model.Document) ([]byte, error) {
			return nil, errors.New("unexpected archive read")
		})
	}); e != nil {
		t.Fatal("missing source blocked publication", e)
	}
	status, record := fleetNativeHTTPGet(t, f, "object-storage-assessments/"+model.String(queued, "id"), token)
	assessment := storageObject(record["assessment"])
	if status != 200 || model.String(record, "status") != "BLOCKED" || model.String(assessment, "status") != "BLOCKED" || assessment["execution_authorized"] != false || assessment["verified_saving"] != nil {
		t.Fatal("persisted blocked result", status, record)
	}
	if model.String(assessment, "assessment_hash") == "" || storageObject(assessment["economics"])["current_monthly_cost"] != nil {
		t.Fatal("unknown became zero or missing immutable hash", assessment)
	}
	status, pub := fleetNativeHTTPGet(t, f, "recommendations/object-storage-"+model.String(queued, "id"), token)
	if status != 200 || pub["pre_execution_ready"] != false || pub["execution_authorized"] != false {
		t.Fatal("ordinary recommendation", status, pub)
	}
	if e := analyst.Do(ctx, "foreign-s3-tenant", func(tx *store.Tx) error {
		var count int
		e := tx.QueryRow(ctx, "SELECT count(*) FROM object_storage_assessments").Scan(&count)
		if e == nil && count != 0 {
			t.Fatal("analytical cross-tenant leak")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO object_storage_datasets(tenant_id,id,version,resource_id,document,created_by) VALUES($1,'forged',1,$2,'{}','forged')", f.tenant, rid)
		return e
	}); e == nil {
		t.Fatal("analytical identity declared policy")
	}
	if _, e := BuildPlan(ctx, nil, "object-storage-"+model.String(queued, "id"), "", true); e == nil {
		t.Fatal("S3 recommendation authorized execution")
	}
}

func TestObjectStoragePublicSourceRegistrationBindsIssuedDatasetOnly(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	var rid string
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		r, e := tx.Create(ctx, "resources", model.Document{"provider": "AWS", "resource_type": "S3_BUCKET", "provider_resource_id": "arn:aws:s3:::registered-bucket", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "replay-workload"})
		rid = model.String(r, "id")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	token := f.token(f.tenant, "s3-admin", "PLATFORM_ADMIN")
	code, dataset, _ := f.request("object-storage-datasets", `"0"`, "registered-s3-dataset", token, model.Document{"resource_id": rid, "name": "registered", "selector": model.Document{"kind": "BUCKET"}, "policy": model.Document{}})
	if code != 201 {
		t.Fatal(code, dataset)
	}
	body := model.Document{"kind": "AWS_S3_INVENTORY", "account_id": "111122223333", "region": "eu-west-1", "bucket": "registered-bucket", "report_bucket": "registered-reports", "report_owner": "111122223333", "prefix": "inventory/", "inventory_id": "existing-inventory", "read_role_binding_id": "approved-read", "dataset_ids": []string{model.String(dataset, "id")}}
	code, source, _ := f.request("source-connections", `"0"`, "s3-source-register", token, body)
	if code != 201 {
		t.Fatal(code, source)
	}
	selectors := storageRows(source["datasets"])
	if len(selectors) != 1 || model.Number(selectors[0], "dataset_version") != 1 || model.String(selectors[0], "dataset_hash") != objectStorageDatasetHash(dataset) {
		t.Fatal("source did not freeze dataset declaration", source)
	}
	for _, field := range []string{"datasets", "complete", "trusted", "observations", "credentials", "approved_writer_principal_arn"} {
		bad := model.Clone(body)
		bad[field] = true
		if code, _, _ := f.request("source-connections", `"0"`, "s3-reject-"+field, token, bad); code != 422 {
			t.Fatal("source accepted authority", field, code)
		}
	}
	status, detail := fleetNativeHTTPGet(t, f, "source-connections/"+model.String(source, "id"), token)
	if status != 200 || model.String(detail, "kind") != "AWS_S3_INVENTORY" {
		t.Fatal("typed source detail", status, detail)
	}
	req := httptest.NewRequest("GET", "/v1/object-storage-datasets?resource_id="+rid+"&cursor="+strings.Repeat("x", 1050), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, req)
	if w.Code != 422 {
		t.Fatal("oversized cursor", w.Code)
	}
}
