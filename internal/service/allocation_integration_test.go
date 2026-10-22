package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type allocationAPIFixture struct {
	t      *testing.T
	db     *store.Store
	api    *API
	tenant string
	who    auth.Identity
	dsn    string
}

func newAllocationAPI(t *testing.T) *allocationAPIFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Pool.Close)
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	db := trustedRoleStore(t, dsn, "finops_api")
	f := &allocationAPIFixture{t: t, db: db, dsn: dsn, tenant: "allocation-api-" + model.ID()}
	f.who = auth.Identity{Tenant: f.tenant, Subject: "finance", Roles: map[string]bool{"FINANCE": true}}
	f.api = &API{Store: db, Config: Config{Fixture: true}}
	if err = db.Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *allocationAPIFixture) mutate(path, version string, in model.Document, who auth.Identity) (model.Document, error) {
	f.t.Helper()
	var out model.Document
	r := httptest.NewRequest(http.MethodPost, "/v1/"+path, nil)
	if version != "" {
		r.Header.Set("If-Match", version)
	}
	err := f.db.Do(context.Background(), who.Tenant, func(tx *store.Tx) error {
		var err error
		out, _, _, err = f.api.allocationMutate(context.Background(), tx, who, r, in, strings.Split(path, "/"))
		return err
	})
	return out, err
}
func (f *allocationAPIFixture) policy() model.Document {
	f.t.Helper()
	out, err := f.mutate("allocation-policies", `"0"`, model.Document{"schema_version": "1", "name": "Current ownership", "rules": []any{}}, f.who)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}
func (f *allocationAPIFixture) job(id, version string, amount any, extra model.Document) {
	f.t.Helper()
	err := f.db.Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		row := model.Document{"x_SourceId": "customer", "x_SourceVersion": version, "x_SourceRecordId": "line-1", "SubAccountId": "111122223333", "RegionId": "eu-west-1", "ResourceId": "i-0123456789abcdef0", "BillingCurrency": "GBP", "BilledCost": amount}
		job := model.Document{"id": id, "source_id": "customer", "source_provenance": "CUSTOMER_IMPORT", "status": "PERSISTED", "raw": model.Document{"source_id": "customer", "source_version": version}, "canonical": model.Document{"records": []model.Document{row}}}
		for k, v := range extra {
			job[k] = v
		}
		_, err := tx.Create(context.Background(), "ingestion_jobs", job)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
}
func TestAllocationAPISelectsServerFactsScopesRevisionsAndCorrections(t *testing.T) {
	f := newAllocationAPI(t)
	policy := f.policy()
	f.job("original", "v1", "12.340000000001", nil)
	selection := model.Document{"policy_id": policy["id"], "source": model.Document{"kind": "CUSTOMER_IMPORT", "ingestion_job_id": "original"}}
	report, err := f.mutate("allocation-reports", `"1"`, selection, f.who)
	if err != nil {
		t.Fatal(err)
	}
	if report["execution_authorized"] != false || report["verified_saving"] != nil || model.String(evidence.Object(report["source"]), "coverage") != "UNKNOWN" {
		t.Fatal("customer observations gained authority")
	}
	if _, ok := report["lines"]; ok {
		t.Fatal("unbounded detail in summary")
	}
	totals := evidence.Rows(report["totals"])
	if len(totals) != 1 || model.String(totals[0], "known_billed_subtotal") != "12.340000000001" {
		t.Fatal("source amount changed")
	}
	for _, field := range []string{"amount", "records", "trusted", "verified_saving", "tenant_id"} {
		bad := model.Clone(selection)
		bad[field] = "caller"
		if _, err = f.mutate("allocation-reports", `"1"`, bad, f.who); err == nil {
			t.Fatalf("submitted authority %s accepted", field)
		}
	}
	for _, role := range []string{"VIEWER", "APPLICATION_OWNER", "PLATFORM_ADMIN", "AUDITOR"} {
		who := f.who
		who.Roles = map[string]bool{role: true}
		if _, err = f.mutate("allocation-reports", `"1"`, selection, who); err == nil {
			t.Fatalf("%s financial mutation allowed", role)
		}
	}
	if _, err = f.mutate("allocation-reports", `"0"`, selection, f.who); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale policy: %v", err)
	}
	if _, err = f.mutate("allocation-reports", "", selection, f.who); err == nil {
		t.Fatal("missing CAS accepted")
	}
	other := f.who
	other.Tenant = "other-" + f.tenant
	if _, err = f.mutate("allocation-reports", `"1"`, selection, other); err == nil {
		t.Fatal("cross tenant source accepted")
	}
	f.job("credit-correction", "v2", "-2.000000000001", nil)
	changed := model.Clone(selection)
	changed["source"] = model.Document{"kind": "CUSTOMER_IMPORT", "ingestion_job_id": "credit-correction"}
	correction, err := f.mutate("allocation-reports", `"1"`, changed, f.who)
	if err != nil {
		t.Fatal(err)
	}
	if model.String(correction, "input_hash") == model.String(report, "input_hash") {
		t.Fatal("source correction did not change immutable inputs")
	}
	if err = f.db.Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		original, err := tx.AllocationReportGet(context.Background(), model.String(report, "id"))
		if err != nil {
			return err
		}
		if evidence.Hash(original) != evidence.Hash(report) {
			return errors.New("old allocation report was rewritten")
		}
		page, err := tx.AllocationReportRowPage(context.Background(), model.String(report, "id"), "observations", "", 2)
		if err != nil {
			return err
		}
		if len(page) != 1 || model.String(page[0], "observed_billed_cost") != "12.340000000001" {
			return errors.New("native amount not retained separately")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Human roles and a cursor from another tenant/query cannot reveal a report.
	for _, role := range []string{"VIEWER", "APPLICATION_OWNER", "PLATFORM_ADMIN"} {
		who := f.who
		who.Roles = map[string]bool{role: true}
		r := httptest.NewRequest(http.MethodGet, "/v1/allocation-reports", nil)
		err = f.db.Do(context.Background(), f.tenant, func(tx *store.Tx) error {
			_, _, err := f.api.allocationGet(context.Background(), tx, who, r)
			return err
		})
		if err == nil {
			t.Fatalf("%s organizational spend read allowed", role)
		}
	}
}
func TestAllocationSourceRejectsMalformedAndUnpersistedInputs(t *testing.T) {
	f := newAllocationAPI(t)
	p := f.policy()
	cases := []struct {
		name  string
		extra model.Document
	}{
		{"pending", model.Document{"status": "PENDING"}},
		{"native-label", model.Document{"source_provenance": "AWS_CUR2_AUTHENTICATED"}},
		{"wrong-source", model.Document{"source_id": "different"}},
		{"missing-records", model.Document{"canonical": model.Document{}}},
		{"mixed-array", model.Document{"canonical": model.Document{"records": []any{model.Document{}, false}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.job(c.name, "v1", "1", c.extra)
			_, err := f.mutate("allocation-reports", `"1"`, model.Document{"policy_id": p["id"], "source": model.Document{"kind": "CUSTOMER_IMPORT", "ingestion_job_id": c.name}}, f.who)
			if err == nil {
				t.Fatal("malformed source accepted")
			}
		})
	}
	f.job("binary-float", "v1", 1.01, nil)
	if _, err := f.mutate("allocation-reports", `"1"`, model.Document{"policy_id": p["id"], "source": model.Document{"kind": "CUSTOMER_IMPORT", "ingestion_job_id": "binary-float"}}, f.who); err == nil {
		t.Fatal("float money accepted")
	}
	f.job("unknown", "v1", nil, nil)
	unknown, err := f.mutate("allocation-reports", `"1"`, model.Document{"policy_id": p["id"], "source": model.Document{"kind": "CUSTOMER_IMPORT", "ingestion_job_id": "unknown"}}, f.who)
	if err != nil {
		t.Fatal(err)
	}
	if model.String(unknown, "status") != "PARTIAL_OBSERVATIONS" || evidence.Rows(unknown["totals"])[0]["observed_billed_total"] != nil {
		t.Fatal("unknown cost became known zero")
	}
}
func TestAllocationNativeReceiptSelectionThroughProviderShapedPipeline(t *testing.T) {
	f := newAllocationAPI(t)
	ctx := context.Background()
	p := f.policy()
	endpoint, token := trustedEconomics(t)
	f.api.Config.EconomicsURL, f.api.Config.EconomicsToken = endpoint, token
	f.api.Client = &http.Client{Timeout: 60 * time.Second}
	registration := source.FixtureRegistration(f.tenant, "allocation-native")
	parsed, err := source.ParseRegistration(registration)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := source.NewFixtureReader(parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.Do(ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.SourceCreate(ctx, registration); return err }); err != nil {
		t.Fatal(err)
	}
	persists, archives := 0, 0
	pipeline := source.Pipeline{Store: trustedRoleStore(t, f.dsn, "finops_ingester"), ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: func(ctx context.Context, raw model.Document) (model.Document, error) {
		return f.api.economics(ctx, "v3/normalize", raw)
	}, Persist: func(context.Context, string, string, model.Document, model.Document) error { persists++; return nil }, ArchiveObject: func(context.Context, string, string, string, []byte) error { archives++; return nil }, Now: func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) }}
	// Real PostgreSQL/API selection. Native calls and archive persistence are
	// explicit transport doubles here; existing storage acceptance is separate.
	if err = pipeline.Sync(ctx, f.tenant, parsed.ID); err != nil {
		t.Fatal(err)
	}
	if persists == 0 || archives == 0 {
		t.Fatal("receipt published without persistence boundary")
	}
	in := model.Document{"policy_id": p["id"], "source": model.Document{"kind": "AWS_CUR2_CONNECTION", "source_connection_id": parsed.ID, "billing_period_start": "2026-09-01T00:00:00Z"}}
	report, err := f.mutate("allocation-reports", `"1"`, in, f.who)
	if err != nil {
		t.Fatal(err)
	}
	ref := evidence.Object(report["source"])
	if model.String(ref, "source_receipt_id") == "" || model.String(ref, "coverage") != "AUTHENTICATED_EXPORT_REVISION" || report["verified_saving"] != nil {
		t.Fatal("native receipt not bound provisionally")
	}
	// An in-flight provider sync owns publication. Report selection refuses it
	// immediately instead of presenting an older month head as current.
	blocked := func() error {
		conn, e := f.db.Pool.Acquire(ctx)
		if e != nil {
			return e
		}
		defer conn.Release()
		key := f.tenant + ":trusted-source:" + parsed.ID
		if _, e = conn.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", key); e != nil {
			return e
		}
		defer conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key)
		_, e = f.mutate("allocation-reports", `"1"`, in, f.who)
		var p *Problem
		if !errors.As(e, &p) || p.Code != "ALLOCATION_SOURCE_SYNC_IN_PROGRESS" {
			return errors.New("in-flight source publication did not block allocation")
		}
		for _, check := range []string{"current", "receipt"} {
			e = f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
				if check == "current" {
					_, e := currentSourceGate(ctx, tx, parsed.ID, model.Document{}, time.Now())
					return e
				}
				job, e := tx.Get(ctx, "ingestion_jobs", model.String(ref, "ingestion_job_id"))
				if e != nil {
					return e
				}
				_, e = trustedJob(ctx, tx, job, model.Document{"account_id": "111122223333", "region": "eu-west-1"})
				return e
			})
			if e == nil || e.Error() != "SOURCE_SYNC_IN_PROGRESS" {
				return errors.New("in-flight source publication did not block financial " + check + " authority")
			}
		}
		return nil
	}()
	if blocked != nil {
		t.Fatal(blocked)
	}
	// Exercise the actual producer's lock/status boundary, rather than only
	// reconstructing its lock key. Cancellation makes the deferred status write
	// unavailable; the durable start record must still refuse old authority.
	started := make(chan struct{})
	syncDone := make(chan error, 1)
	syncCtx, cancelSync := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSync()
	pipeline.ProviderFactory = func(ctx context.Context, _ source.Registration) (source.Reader, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { syncDone <- pipeline.Sync(syncCtx, f.tenant, parsed.ID) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("actual source sync did not start")
	}
	if _, err = f.mutate("allocation-reports", `"1"`, in, f.who); err == nil {
		t.Fatal("actual producer sync did not block a new report")
	}
	cancelSync()
	select {
	case err = <-syncDone:
		if err == nil {
			t.Fatal("cancelled native sync succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled sync did not release ownership")
	}
	if err = f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.SourceGet(ctx, parsed.ID)
		if e != nil {
			return e
		}
		if model.String(d, "status") != "SYNCING" {
			return errors.New("interrupted source lost durable in-progress refusal")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate("allocation-reports", `"1"`, in, f.who); err == nil {
		t.Fatal("cancelled producer exposed old healthy authority")
	}
	pipeline.ProviderFactory = func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }
	if err = pipeline.Sync(ctx, f.tenant, parsed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate("allocation-reports", `"1"`, in, f.who); err != nil {
		t.Fatal("complete native sync did not recover source", err)
	}
	// Same current source, wrong historical period is not a reusable receipt.
	wrong := model.Clone(in)
	wrong["source"] = model.Document{"kind": "AWS_CUR2_CONNECTION", "source_connection_id": parsed.ID, "billing_period_start": "2025-09-01T00:00:00Z"}
	if _, err = f.mutate("allocation-reports", `"1"`, wrong, f.who); err == nil {
		t.Fatal("historical period reused native receipt")
	}
	ingester := trustedRoleStore(t, f.dsn, "finops_ingester")
	if err = ingester.Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, parsed.ID, "status", model.Document{"status": "DEGRADED", "reason_code": "SOURCE_EXECUTION_ORDER_AMBIGUOUS"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate("allocation-reports", `"1"`, in, f.who); err == nil {
		t.Fatal("an earlier good receipt hid uncertain source currentness")
	}
	if err = ingester.Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, parsed.ID, "status", model.Document{"status": "HEALTHY"})
	}); err != nil {
		t.Fatal(err)
	}
	if err = f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, err := tx.SourceGet(ctx, parsed.ID)
		if err != nil {
			return err
		}
		d["enabled"] = false
		_, err = tx.SourceUpdate(ctx, parsed.ID, model.Number(d, "version"), d)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate("allocation-reports", `"1"`, in, f.who); err == nil {
		t.Fatal("revoked source generated new native allocation")
	}
	if err = f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, err := tx.AllocationReportGet(ctx, model.String(report, "id"))
		return err
	}); err != nil {
		t.Fatal("source revocation erased old allocation")
	}
}
