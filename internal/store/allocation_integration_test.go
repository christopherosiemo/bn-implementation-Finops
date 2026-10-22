package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/allocation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type allocationDBTest struct {
	t      *testing.T
	ctx    context.Context
	db     *Store
	tenant string
}

func newAllocationDBTest(t *testing.T) *allocationDBTest {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("test PostgreSQL unavailable")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := "allocation_" + strings.ReplaceAll(model.ID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error("remove only test-owned allocation database", e)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("test database configuration invalid")
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := &Store{pool}
	// The feature has no dependency on concurrent draft020/021 or fleet clocks.
	// Copy these exact inputs before migrating a brand-new disposable database.
	dir := t.TempDir()
	for _, base := range []string{"001_control_plane.sql", "002_ingestion_and_approval_boundary.sql", "005_trusted_sources.sql", "023_allocation.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", base))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, base), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, role := range []string{"API", "WORKER", "SIGNER", "EXECUTOR", "INGESTER", "ACTIVITY", "TELEMETRY_READER", "TELEMETRY_INGRESS", "DEPLOYMENT_OBSERVER", "HARDWARE_READER"} {
		t.Setenv("DB_"+role+"_PASSWORD", "")
	}
	if err = db.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	f := &allocationDBTest{t, ctx, db, "allocation-" + model.ID()}
	f.must("finops_api", func(tx *Tx) error {
		for _, workload := range []string{"workload-a", "workload-b"} {
			if _, e := tx.Create(ctx, "workloads", model.Document{"id": workload}); e != nil {
				return e
			}
		}
		_, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": "i-source", "workload_id": "workload-a"})
		return e
	})
	return f
}
func (f *allocationDBTest) run(role string, fn func(*Tx) error) error {
	return f.db.Do(f.ctx, f.tenant, func(tx *Tx) error {
		if _, e := tx.Exec(f.ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
			return e
		}
		return fn(tx)
	})
}
func (f *allocationDBTest) must(role string, fn func(*Tx) error) {
	f.t.Helper()
	if err := f.run(role, fn); err != nil {
		f.t.Fatal(err)
	}
}
func allocationTestPolicy() allocation.Policy {
	return allocation.Policy{SchemaVersion: "1", Name: "explicit shared ownership", Rules: []allocation.Rule{{ResourceIDs: []string{"resource"}, Recipients: []allocation.Recipient{{WorkloadID: "workload-b", WeightPPM: 500000}, {WorkloadID: "workload-a", WeightPPM: 500000}}}}}
}
func allocationTestSource() model.Document {
	return model.Document{"kind": "CUSTOMER_IMPORT", "coverage": "UNKNOWN", "finality": "UNPROVEN", "execution_authorized": false, "verified_saving": nil, "provenance": "CUSTOMER_IMPORT", "reason_code": "CUSTOMER_REPORTED_COVERAGE_UNKNOWN", "ingestion_job_id": "server-import-job", "source_id": "server-import", "source_version": "immutable-version", "raw_hash": strings.Repeat("a", 64), "canonical_hash": strings.Repeat("b", 64)}
}
func allocationTestRecords() []allocation.Record {
	text := func(s string) *string { return &s }
	return []allocation.Record{
		{ID: "usage", SourceID: "server-import", SourceVersion: "immutable-version", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "i-source", Currency: "GBP", BilledCost: text("1.000000000001")},
		{ID: "credit", SourceID: "server-import", SourceVersion: "immutable-version", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "i-source", Currency: "GBP", BilledCost: text("-0.000000000001")},
		{ID: "unmapped", SourceID: "server-import", SourceVersion: "immutable-version", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "i-unmapped", Currency: "USD", BilledCost: text("2")},
		{ID: "unknown", SourceID: "server-import", SourceVersion: "immutable-version", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "i-source", Currency: "GBP"},
	}
}
func (f *allocationDBTest) policy() model.Document {
	var out model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		out, e = tx.AllocationPolicyAppend(f.ctx, 0, "operator", allocationTestPolicy())
		return e
	})
	return out
}

func TestAllocationPostgresExactSignedConservationHistoryPaginationAndReset(t *testing.T) {
	f := newAllocationDBTest(t)
	p := f.policy()
	var report model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		report, e = tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	})
	if model.String(report, "status") != "PARTIAL_OBSERVATIONS" || model.Bool(report, "execution_authorized") || report["verified_saving"] != nil || report["lines"] != nil || report["observed_records"] != nil || model.String(report, "mapping_hash") == "" || model.String(report, "mapping_as_of") == "" {
		t.Fatal("report summary authority, bounds or snapshot invalid", report)
	}
	f.must("finops_api", func(tx *Tx) error {
		lines, e := tx.AllocationReportRowPage(f.ctx, model.String(report, "id"), "lines", "", 2)
		if e != nil {
			return e
		}
		if len(lines) != 2 || model.String(lines[0], "id") != "1" || model.String(lines[0], "workload_id") != "workload-a" || model.String(lines[0], "allocated_billed_cost") != "0.500000000001" {
			return errors.New("largest-remainder split or ordinal cursor changed")
		}
		next, e := tx.AllocationReportRowPage(f.ctx, model.String(report, "id"), "lines", model.String(lines[1], "id"), 101)
		if e != nil || len(next) != 4 || model.String(next[0], "allocated_billed_cost") != "-0.000000000001" || next[len(next)-1]["allocated_billed_cost"] != nil {
			return errors.New("credit/unknown value or complete row pagination changed")
		}
		rows, e := tx.AllocationReportRowPage(f.ctx, model.String(report, "id"), "observations", "", 101)
		if e != nil || len(rows) != 4 || rows[3]["observed_billed_cost"] != nil {
			return errors.New("immutable original observations missing")
		}
		for _, kind := range []string{"workloads", "resources"} {
			if _, e := tx.Exec(f.ctx, "DELETE FROM entities WHERE tenant_id=$1 AND kind=$2", f.tenant, kind); e != nil {
				return e
			}
		}
		old, e := tx.AllocationReportGet(f.ctx, model.String(report, "id"))
		if e != nil || model.String(old, "mapping_hash") != model.String(report, "mapping_hash") {
			return errors.New("fixture reset erased immutable report mapping/history")
		}
		return nil
	})
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	}); e == nil {
		t.Fatal("new report accepted a policy whose inventory disappeared")
	}
}

func TestAllocationPostgresPolicyCASAndSealedRoleTenantBoundaries(t *testing.T) {
	f := newAllocationDBTest(t)
	p := f.policy()
	var report model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		report, e = tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	})
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcomes <- f.run("finops_api", func(tx *Tx) error {
				_, e := tx.AllocationPolicyAppend(f.ctx, 1, "concurrent", allocationTestPolicy())
				return e
			})
		}()
	}
	wg.Wait()
	close(outcomes)
	success, conflicts := 0, 0
	for e := range outcomes {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("tenant-wide policy CAS was not serialized")
	}
	f.must("finops_api", func(tx *Tx) error {
		page, e := tx.AllocationPolicyPage(f.ctx, "", 1)
		if e != nil || len(page) != 1 || model.Number(page[0], "version") != 2 {
			return errors.New("newest policy page invalid")
		}
		older, e := tx.AllocationPolicyPage(f.ctx, model.String(page[0], "id"), 101)
		if e != nil || len(older) != 1 || model.String(older[0], "id") != model.String(p, "id") {
			return errors.New("policy cursor skipped immutable history")
		}
		return nil
	})
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	}); !errors.Is(e, ErrConflict) {
		t.Fatal("superseded policy created a fresh report", e)
	}
	for _, role := range []string{"finops_worker", "finops_ingester", "finops_signer", "finops_executor"} {
		for _, table := range []string{"allocation_policy_revisions", "allocation_reports", "allocation_observations", "allocation_lines", "allocation_report_seals"} {
			if e := f.run(role, func(tx *Tx) error { _, e := tx.Exec(f.ctx, "SELECT * FROM "+table); return e }); e == nil {
				t.Fatal("non-API identity read analytical observations", role, table)
			}
		}
	}
	for _, table := range []string{"allocation_policy_revisions", "allocation_reports", "allocation_observations", "allocation_lines", "allocation_report_seals"} {
		for _, statement := range []string{"UPDATE " + table + " SET writer_role=writer_role", "DELETE FROM " + table} {
			if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.Exec(f.ctx, statement); return e }); e == nil {
				t.Fatal("API changed immutable allocation history", table)
			}
		}
	}
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Exec(f.ctx, "SELECT set_config('app.tenant_id','other-tenant',true)"); e != nil {
			return e
		}
		var n int
		if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM allocation_reports WHERE id=$1", report["id"]).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return errors.New("forced RLS exposed another tenant report")
		}
		return nil
	})
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, "INSERT INTO allocation_report_seals(tenant_id,report_id) VALUES('other-tenant',$1)", report["id"])
		return e
	}); e == nil {
		t.Fatal("cross-tenant seal permitted")
	}
}

func TestAllocationPostgresRejectsUnsealedIncompleteForgedOrLateRows(t *testing.T) {
	f := newAllocationDBTest(t)
	p := f.policy()
	var report model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		report, e = tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	})
	// Clone only a header/observation in a rolled-back test transaction. Missing
	// or forged splits must fail at the same SQL seal used by the real store.
	for _, mode := range []string{"incomplete", "wrong-total", "wrong-share", "wrong-sign", "unknown-zero", "snapshot", "execution", "mapping_hash", "input_hash", "result_hash"} {
		e := f.run("finops_api", func(tx *Tx) error {
			var header, mapping []byte
			if e := tx.QueryRow(f.ctx, "SELECT document,mapping_snapshot FROM allocation_reports WHERE tenant_id=$1 AND id=$2", f.tenant, report["id"]).Scan(&header, &mapping); e != nil {
				return e
			}
			d := model.Document{}
			_ = json.Unmarshal(header, &d)
			id := model.ID()
			d["id"] = id
			delete(d, "created_at")
			delete(d, "mapping_as_of")
			if mode == "snapshot" {
				mapping = []byte(`{"resources":[],"workloads":[]}`)
			}
			if mode == "execution" {
				d["execution_authorized"] = true
			}
			if mode == "wrong-total" {
				d["totals"] = []model.Document{}
			}
			if strings.HasSuffix(mode, "_hash") {
				d[mode] = strings.Repeat("0", 64)
			}
			raw, _ := json.Marshal(d)
			if _, e := tx.Exec(f.ctx, "INSERT INTO allocation_reports(tenant_id,id,policy_id,record_count,line_count,mapping_snapshot,document,created_by) VALUES($1,$2,$3,4,6,$4,$5,'forgery-test')", f.tenant, id, p["id"], mapping, raw); e != nil {
				return e
			}
			if _, e := tx.AllocationReportGet(f.ctx, id); !errors.Is(e, pgx.ErrNoRows) {
				return errors.New("unsealed report became readable")
			}
			if mode != "incomplete" {
				if _, e := tx.Exec(f.ctx, "INSERT INTO allocation_observations SELECT tenant_id,$3,ordinal,source_id,source_version,record_id,currency,observed_amount,document,writer_role,created_at FROM allocation_observations WHERE tenant_id=$1 AND report_id=$2", f.tenant, report["id"], id); e != nil {
					return e
				}
				change := "allocated_amount,document"
				switch mode {
				case "wrong-share":
					change = "CASE WHEN ordinal=1 THEN allocated_amount+0.000000000001 WHEN ordinal=2 THEN allocated_amount-0.000000000001 ELSE allocated_amount END,jsonb_set(document,'{allocated_billed_cost}',to_jsonb((CASE WHEN ordinal=1 THEN allocated_amount+0.000000000001 WHEN ordinal=2 THEN allocated_amount-0.000000000001 ELSE allocated_amount END)::text))"
				case "wrong-sign":
					change = "-allocated_amount,jsonb_set(document,'{allocated_billed_cost}',to_jsonb((-allocated_amount)::text))"
				case "unknown-zero":
					change = "coalesce(allocated_amount,0),jsonb_set(document,'{allocated_billed_cost}',to_jsonb(coalesce(allocated_amount,0)::text))"
				}
				if _, e := tx.Exec(f.ctx, "INSERT INTO allocation_lines SELECT tenant_id,$3,ordinal,observation_ordinal,currency,"+change+",writer_role,created_at FROM allocation_lines WHERE tenant_id=$1 AND report_id=$2", f.tenant, report["id"], id); e != nil {
					return e
				}
			}
			_, e := tx.Exec(f.ctx, "INSERT INTO allocation_report_seals(tenant_id,report_id) VALUES($1,$2)", f.tenant, id)
			return e
		})
		if e == nil {
			t.Fatal("allocation forgery sealed", mode)
		}
	}
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, "INSERT INTO allocation_lines SELECT tenant_id,report_id,7,observation_ordinal,currency,allocated_amount,document,writer_role,created_at FROM allocation_lines WHERE tenant_id=$1 AND report_id=$2 AND ordinal=1", f.tenant, report["id"])
		return e
	}); e == nil {
		t.Fatal("sealed report accepted an additional row")
	}
}

func TestAllocationPostgresCanonicalJSONClosureAndBounds(t *testing.T) {
	f := newAllocationDBTest(t)
	plain := `{"text":"<>&\"雪é","weights":[333333,666667],"null":null,"flag":false}`
	escaped := `{"weights": [333333, 666667], "flag": false,"text":"\u003c\u003e\u0026\"\u96ea\u00e9","null":null}`
	wantCanonical := `{"flag":false,"null":null,"text":"<>&\"雪é","weights":[333333,666667]}`
	wantHash := sha256.Sum256([]byte(wantCanonical))
	f.must("finops_api", func(tx *Tx) error {
		var a, b, canonical string
		if e := tx.QueryRow(f.ctx, "SELECT allocation_json_hash($1::jsonb),allocation_json_hash($2::jsonb),allocation_json_canonical($1::jsonb)", plain, escaped).Scan(&a, &b, &canonical); e != nil {
			return e
		}
		if canonical != wantCanonical || a != b || a != hex.EncodeToString(wantHash[:]) {
			return errors.New("DB canonical JSON changed Unicode/HTML/quotes, integer weights or key ordering")
		}
		return nil
	})
	tooManyKeys := model.Document{}
	for i := range 65 {
		tooManyKeys[fmt.Sprintf("key%d", i)] = true
	}
	rawKeys, _ := json.Marshal(tooManyKeys)
	longString, _ := json.Marshal(strings.Repeat("a", 65537))
	longKey, _ := json.Marshal(model.Document{strings.Repeat("k", 257): true})
	for _, raw := range []string{
		strings.Repeat("[", 13) + "null" + strings.Repeat("]", 13),
		string(rawKeys), string(longKey), "[" + strings.Repeat("0,", 25000) + "0]", "1.5", "10000000000000000000", string(longString),
	} {
		if e := f.run("finops_api", func(tx *Tx) error {
			var hash string
			return tx.QueryRow(f.ctx, "SELECT allocation_json_hash($1::jsonb)", raw).Scan(&hash)
		}); e == nil {
			t.Fatal("canonical JSON accepted unsupported shape, depth or numeric/scalar bound")
		}
	}
	var policy model.Document
	p := allocationTestPolicy()
	p.Name = `allocation <>&" 雪é`
	f.must("finops_api", func(tx *Tx) error {
		var e error
		policy, e = tx.AllocationPolicyAppend(f.ctx, 0, "operator", p)
		return e
	})
	var first, second model.Document
	f.must("finops_api", func(tx *Tx) error {
		source := allocationTestSource()
		source["reason_code"] = `customer <>&" 雪é`
		var e error
		first, e = tx.AllocationReportCreate(f.ctx, model.String(policy, "id"), "operator", source, allocationTestRecords())
		if e != nil {
			return e
		}
		source["reason_code"] = "DIFFERENT_FROZEN_SOURCE_CONTEXT"
		second, e = tx.AllocationReportCreate(f.ctx, model.String(policy, "id"), "operator", source, allocationTestRecords())
		if e != nil {
			return e
		}
		if first["input_hash"] == second["input_hash"] || first["result_hash"] != second["result_hash"] {
			return errors.New("input hash failed to bind source context or result hash ceased being amount projection")
		}
		page, e := tx.AllocationReportPage(f.ctx, "", 1)
		if e != nil || len(page) != 1 || page[0]["id"] != second["id"] {
			return errors.New("newest sealed report page invalid")
		}
		page, e = tx.AllocationReportPage(f.ctx, model.String(second, "id"), 101)
		if e != nil || len(page) != 1 || page[0]["id"] != first["id"] {
			return errors.New("sealed report cursor skipped immutable history")
		}
		return nil
	})
	for _, definition := range []string{`{"schema_version":1,"name":"bad","rules":[]}`, `{"schema_version":"1","name":1,"rules":[]}`, `{"schema_version":"1","name":"bad","rules":null}`, `[]`} {
		if e := f.run("finops_api", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, "INSERT INTO allocation_policy_revisions(tenant_id,id,version,content_hash,definition,created_by) VALUES($1,$2,2,allocation_json_hash($3::jsonb),$3::jsonb,'invalid-shape')", f.tenant, model.ID(), definition)
			return e
		}); e == nil {
			t.Fatal("direct SQL accepted unsupported policy JSON shape")
		}
	}
}

func TestAllocationPostgresEmptyCurrentOwnerZeroAndMaximumBoundedReport(t *testing.T) {
	f := newAllocationDBTest(t)
	var p model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		p, e = tx.AllocationPolicyAppend(f.ctx, 0, "operator", allocation.Policy{SchemaVersion: "1", Name: "current owner only", Rules: []allocation.Rule{}})
		if e != nil {
			return e
		}
		empty, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), nil)
		if e != nil || model.String(empty, "status") != "NO_OBSERVATIONS" || model.Number(empty, "record_count") != 0 || model.Number(empty, "line_count") != 0 {
			return errors.New("empty observations did not remain empty/unproven")
		}
		records := allocationTestRecords()[:1]
		zero := "0"
		records[0].BilledCost = &zero
		r, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), records)
		if e != nil {
			return e
		}
		lines, e := tx.AllocationReportRowPage(f.ctx, model.String(r, "id"), "lines", "", 101)
		if e != nil || len(lines) != 1 || model.String(lines[0], "method") != "CURRENT_RESOURCE_OWNER" || model.String(lines[0], "workload_id") != "workload-a" || model.String(lines[0], "allocated_billed_cost") != "0.000000000000" {
			return errors.New("observed zero/current-owner fallback changed")
		}
		for _, id := range []string{"workload-c", "workload-d", "workload-e"} {
			if _, e := tx.Create(f.ctx, "workloads", model.Document{"id": id}); e != nil {
				return e
			}
		}
		definition := allocationTestPolicy()
		definition.Rules[0].Recipients = []allocation.Recipient{}
		for _, id := range []string{"workload-a", "workload-b", "workload-c", "workload-d", "workload-e"} {
			definition.Rules[0].Recipients = append(definition.Rules[0].Recipients, allocation.Recipient{WorkloadID: id, WeightPPM: 200000})
		}
		p, e = tx.AllocationPolicyAppend(f.ctx, 1, "operator", definition)
		return e
	})
	records := make([]allocation.Record, allocation.MaxRecords)
	for i := range records {
		records[i] = allocationTestRecords()[0]
		records[i].ID = fmt.Sprintf("bounded-fact-%d", i)
		amount := "0.000000000001"
		if i%7 == 0 {
			amount = "-0.000000000001"
		} else if i%11 == 0 {
			amount = "0"
		}
		records[i].BilledCost = &amount
	}
	start := time.Now()
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Exec(f.ctx, "SET LOCAL statement_timeout='90s'"); e != nil {
			return e
		}
		r, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), records)
		if e != nil {
			return e
		}
		if model.Number(r, "record_count") != 5000 || model.Number(r, "line_count") != 25000 || model.String(r, "status") != "ALLOCATED_OBSERVATIONS" || model.Bool(r, "execution_authorized") || r["verified_saving"] != nil {
			return errors.New("maximum bounded report did not seal exact provisional counts")
		}
		last, e := tx.AllocationReportRowPage(f.ctx, model.String(r, "id"), "lines", "24999", 101)
		if e != nil || len(last) != 1 || model.String(last[0], "id") != "25000" {
			return errors.New("maximum line cursor did not terminate exactly")
		}
		return nil
	})
	t.Logf("sealed 5000 facts / 25000 entries with independent SQL checks in %s", time.Since(start).Round(time.Millisecond))
}

func TestAllocationPostgresPreservesHighPrecisionAndRejectsMetadataPayloads(t *testing.T) {
	f := newAllocationDBTest(t)
	p := f.policy()
	records := allocationTestRecords()[:1]
	amount := "9999999999999999999999999.999999999999"
	records[0].BilledCost = &amount
	f.must("finops_api", func(tx *Tx) error {
		r, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), records)
		if e != nil {
			return e
		}
		lines, e := tx.AllocationReportRowPage(f.ctx, model.String(r, "id"), "lines", "", 101)
		if e != nil || len(lines) != 2 || model.String(lines[0], "allocated_billed_cost") != "5000000000000000000000000.000000000000" {
			return errors.New("decimal38,12 or largest remainder was rounded")
		}
		return nil
	})
	for _, key := range []string{"records", "raw", "canonical", "lines", "amount"} {
		source := allocationTestSource()
		source[key] = []string{"must-not-leak"}
		if e := f.run("finops_api", func(tx *Tx) error {
			_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", source, records)
			return e
		}); !errors.Is(e, ErrAllocationInvalid) {
			t.Fatal("source metadata accepted a payload", key, e)
		}
	}
	for _, cursor := range []string{"-1", "0", "01", "1;DROP TABLE allocation_lines", "2147483648"} {
		if e := f.run("finops_api", func(tx *Tx) error {
			_, e := tx.AllocationReportRowPage(f.ctx, "unknown", "lines", cursor, 10)
			return e
		}); !errors.Is(e, ErrAllocationInvalid) {
			t.Fatal("unsafe ordinal cursor accepted", cursor, e)
		}
	}
}

func TestAllocationPostgresCompleteSourceClassificationAndUnknownRegion(t *testing.T) {
	f := newAllocationDBTest(t)
	p := f.policy()
	var report model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		report, e = tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	})
	invalid := []model.Document{}
	for _, key := range []string{"provenance", "reason_code", "ingestion_job_id", "source_id", "source_version", "raw_hash", "canonical_hash", "verified_saving"} {
		d := allocationTestSource()
		delete(d, key)
		invalid = append(invalid, d)
	}
	for _, patch := range []model.Document{
		{"coverage": "AUTHENTICATED_EXPORT_REVISION"}, {"kind": "DETERMINISTIC_FIXTURE"}, {"provenance": "AWS_CUR2_AUTHENTICATED"},
		{"source_receipt_id": "misclassified-import"}, {"raw_hash": "not-a-hash"}, {"canonical_hash": strings.Repeat("A", 64)},
		{"reason_code": " "}, {"source_version": strings.Repeat("x", 513)}, {"provenance": model.Document{"nested": true}},
	} {
		d := allocationTestSource()
		for k, v := range patch {
			d[k] = v
		}
		invalid = append(invalid, d)
	}
	for i, source := range invalid {
		if e := f.run("finops_api", func(tx *Tx) error {
			_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", source, allocationTestRecords())
			return e
		}); e == nil {
			t.Fatalf("incomplete or misclassified source accepted by Go %d", i)
		}
		if e := f.run("finops_api", func(tx *Tx) error {
			var header []byte
			if e := tx.QueryRow(f.ctx, "SELECT document FROM allocation_reports WHERE tenant_id=$1 AND id=$2", f.tenant, report["id"]).Scan(&header); e != nil {
				return e
			}
			d := model.Document{}
			_ = json.Unmarshal(header, &d)
			d["id"], d["source"] = model.ID(), source
			delete(d, "created_at")
			delete(d, "mapping_as_of")
			raw, _ := json.Marshal(d)
			_, e := tx.Exec(f.ctx, "INSERT INTO allocation_reports(tenant_id,id,policy_id,record_count,line_count,mapping_snapshot,document,created_by) SELECT tenant_id,$3,policy_id,record_count,line_count,mapping_snapshot,$4,'invalid-source' FROM allocation_reports WHERE tenant_id=$1 AND id=$2", f.tenant, report["id"], d["id"], raw)
			return e
		}); e == nil {
			t.Fatalf("incomplete or misclassified source accepted by SQL %d", i)
		}
	}
	// This is a private metadata protocol fixture issued by the real ingester DB
	// role. It does not represent an AWS export or new financial authority.
	native := allocationTestSource()
	native["kind"], native["provenance"], native["coverage"] = "AWS_CUR2_CONNECTION", "AWS_CUR2_AUTHENTICATED", "AUTHENTICATED_EXPORT_REVISION"
	native["source_connection_id"], native["source_id"] = "native-connection", "native-connection"
	native["source_receipt_id"], native["source_revision_id"] = "native-receipt", "native-revision"
	native["payer_account_id"], native["billing_period_start"], native["source_proof_hash"] = "111122223333", "2026-09-01T00:00:00Z", strings.Repeat("c", 64)
	rows := allocationTestRecords()
	for i := range rows {
		rows[i].SourceID = "native-connection"
	}
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", native, rows)
		return e
	}); e == nil {
		t.Fatal("native classification accepted without issued receipt")
	}
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.SourceCreate(f.ctx, model.Document{"id": "native-connection", "kind": "AWS_CUR2", "enabled": true, "payer_account_id": "111122223333"})
		return e
	})
	f.must("finops_ingester", func(tx *Tx) error {
		if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": "native-revision", "source_id": "native-connection", "revision_hash": strings.Repeat("d", 64)}); e != nil {
			return e
		}
		_, e := tx.SourceReceiptCreate(f.ctx, model.Document{"id": "native-receipt", "source_id": "native-connection", "registration_id": "native-connection", "revision_id": "native-revision", "kind": "AWS_CUR2", "ingestion_job_id": native["ingestion_job_id"], "source_version": native["source_version"], "raw_hash": native["raw_hash"], "canonical_hash": native["canonical_hash"], "source_proof": model.Document{"billing_period_start": native["billing_period_start"]}})
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", native, rows)
		return e
	})
	for _, patch := range []model.Document{{"source_revision_id": "missing"}, {"payer_account_id": "999900001111"}, {"raw_hash": strings.Repeat("f", 64)}, {"billing_period_start": "2026-08-01T00:00:00Z"}, {"billing_period_start": "2026-09-02T00:00:00Z"}} {
		d := model.Clone(native)
		for k, v := range patch {
			d[k] = v
		}
		if e := f.run("finops_api", func(tx *Tx) error {
			_, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", d, rows)
			return e
		}); e == nil {
			t.Fatal("native classification accepted mismatched issued metadata")
		}
	}
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Update(f.ctx, "resources", "resource", 1, model.Document{"provider": "AWS", "account_id": "111122223333", "provider_resource_id": "i-source", "region": "", "workload_id": "workload-a"}); e != nil {
			return e
		}
		records := allocationTestRecords()[:1]
		records[0].Region = ""
		r, e := tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), records)
		if e != nil {
			return e
		}
		lines, e := tx.AllocationReportRowPage(f.ctx, model.String(r, "id"), "lines", "", 101)
		if e != nil || len(lines) != 1 || lines[0]["resource_id"] != nil || lines[0]["workload_id"] != nil || model.String(lines[0], "method") != "UNALLOCATED" || model.String(lines[0], "allocated_billed_cost") != "1.000000000001" {
			return errors.New("unknown region equality invented a resource allocation")
		}
		return nil
	})
}

func TestAllocationPostgresCancellationAtSealRollsBackUnpublishedRows(t *testing.T) {
	f := newAllocationDBTest(t)
	p := f.policy()
	var previous model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		previous, e = tx.AllocationReportCreate(f.ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
		return e
	})
	// Install a barrier only in this test-owned disposable database. The real
	// publication method must reach its final seal after inserting pending rows.
	// No production migration, application clock or source observation changes.
	barrier := "allocation-seal-test-" + model.ID()
	if _, e := f.db.Pool.Exec(f.ctx, `CREATE FUNCTION test_allocation_seal_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(TG_ARGV[0],0));RETURN NEW;END $$`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Pool.Exec(f.ctx, "CREATE TRIGGER a_test_allocation_barrier BEFORE INSERT ON allocation_report_seals FOR EACH ROW EXECUTE FUNCTION test_allocation_seal_barrier("+pgxQuoteLiteral(barrier)+")"); e != nil {
		t.Fatal(e)
	}
	guard, e := f.db.Pool.Acquire(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer guard.Release()
	if _, e = guard.Exec(f.ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", barrier); e != nil {
		t.Fatal(e)
	}
	defer guard.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", barrier)
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- f.db.Do(ctx, f.tenant, func(tx *Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
				return e
			}
			_, e := tx.AllocationReportCreate(ctx, model.String(p, "id"), "operator", allocationTestSource(), allocationTestRecords())
			return e
		})
	}()
	waiting := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if e = f.db.Pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.locktype='advisory' AND NOT l.granted)").Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
	}
	if !waiting {
		t.Fatal("real report creation did not reach the controlled seal barrier")
	}
	f.must("finops_api", func(tx *Tx) error {
		page, e := tx.AllocationReportPage(f.ctx, "", 101)
		if e != nil || len(page) != 1 || page[0]["id"] != previous["id"] {
			return errors.New("unsealed pending report became visible before cancellation")
		}
		return nil
	})
	select {
	case e = <-done:
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatalf("expected request deadline while blocked before commit, got %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled report did not release its transaction")
	}
	f.must("finops_api", func(tx *Tx) error {
		for table, want := range map[string]int{"allocation_reports": 1, "allocation_observations": 4, "allocation_lines": 6, "allocation_report_seals": 1} {
			var count int
			if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", f.tenant).Scan(&count); e != nil {
				return e
			}
			if count != want {
				return fmt.Errorf("pre-commit cancellation retained partial %s rows: got %d want %d", table, count, want)
			}
		}
		_, e := tx.AllocationReportGet(f.ctx, model.String(previous, "id"))
		return e
	})
}

func pgxQuoteLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
