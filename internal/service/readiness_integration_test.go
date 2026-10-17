package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestImmutableReadinessBindsPlanAndRejectsLegacyStop(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	// The economics boundary is exercised through HTTP. Financial-model semantics
	// have independent Python tests; ECONOMICS_TEST_URL enables the real evaluator.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in model.Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.URL.Path == "/normalize" {
			rows := []model.Document{}
			for _, raw := range evidence.Rows(in["records"]) {
				rows = append(rows, model.Document{"ResourceId": raw["line_item_resource_id"], "SubAccountId": raw["line_item_usage_account_id"], "RegionId": raw["product_region_code"], "BillingCurrency": "GBP", "x_SourceId": in["source_id"], "x_SourceVersion": in["source_version"], "x_SourceRecordId": raw["identity_line_item_id"], "BilledCost": raw["line_item_unblended_cost"], "EffectiveCost": raw["line_item_unblended_cost"], "ContractedCost": raw["ContractedCost"], "ChargePeriodStart": raw["line_item_usage_start_date"], "ChargePeriodEnd": raw["line_item_usage_end_date"], "ServiceName": "AmazonEC2", "x_ProviderFields": raw})
			}
			JSON(w, 200, model.Document{"records": rows, "totals": in["invoice_totals"]})
			return
		}
		JSON(w, 200, model.Document{"status": "MEASURING", "reason_code": "VERIFICATION_WINDOW_INCOMPLETE", "pre_execution_ready": true, "baseline_id": in["baseline_id"], "fingerprint": evidence.Hash(in), "claim_key": "claim", "coverage_intervals": []model.Document{}})
	}))
	defer mock.Close()
	endpoint := os.Getenv("ECONOMICS_TEST_URL")
	if endpoint == "" {
		endpoint = mock.URL
	}
	api := API{Store: db, Config: Config{Fixture: true, EconomicsURL: endpoint}, Client: &http.Client{Timeout: 30 * time.Second}}
	tenant := "readiness-" + model.ID()
	do := func(role string, fn func(*store.Tx) error) error {
		return db.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	if e = do("finops_api", func(tx *store.Tx) error { return tx.Seed(ctx, true) }); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_ingester", func(tx *store.Tx) error {
		if e := api.PrepareFixtureEvidence(ctx, tx); e != nil {
			return e
		}
		jobs, e := tx.List(ctx, "ingestion_jobs")
		if e != nil {
			return e
		}
		for _, j := range jobs {
			j["status"] = "PERSISTED"
			j, e = tx.Update(ctx, "ingestion_jobs", model.String(j, "id"), model.Number(j, "version"), j)
			if e != nil {
				return e
			}
			if e = api.SealFixtureEvidence(ctx, tx, j); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var p model.Plan
	var baseline model.Document
	if e = do("finops_api", func(tx *store.Tx) error {
		ready, e := api.readiness(ctx, tx, "resource-dev-api", true)
		if e != nil {
			return e
		}
		if !model.Bool(ready, "pre_execution_ready") || model.String(ready, "verification_status") != "MEASURING" {
			t.Fatalf("ready baseline must allow first cycle whilemeasuring:%v", ready)
		}
		if model.String(ready, "measurement_id") == "" {
			t.Fatal("measurement reservation missing")
		}
		baseline, e = tx.EvidenceGet(ctx, "baseline", model.String(ready, "baseline_id"))
		if e != nil {
			return e
		}
		rec, e := tx.Create(ctx, "recommendations", model.Document{"resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "readiness_id": ready["id"]})
		if e != nil {
			return e
		}
		plan, e := BuildPlan(ctx, tx, model.String(rec, "id"), "schedule-dev", true)
		if e != nil {
			return e
		}
		p, e = decodePlan(plan)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if p.SchemaVersion != "2" || p.BaselineID == "" || p.MeasurementID == "" || p.ReadinessID == "" {
		t.Fatal("plan omitted signed evidence bindings")
	}
	if e = do("finops_signer", func(tx *store.Tx) error { return precheck(ctx, tx, p, time.Now()) }); e != nil {
		t.Fatal(e)
	}
	execution := model.ID()
	actualStop := time.Now().UTC().Add(-20 * time.Second).Format(time.RFC3339Nano)
	actualRun := time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	if e = do("finops_api", func(tx *store.Tx) error {
		_, e := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": p.ID, "resource_id": "resource-dev-api", "status": "COMPLETED"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_executor", func(tx *store.Tx) error {
		b, _ := json.Marshal(model.Document{"stopped_at": actualStop, "running_at": actualRun, "state": "running"})
		_, e := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,restored,document) VALUES($1,$2,$3,true,true,true,$4)", tenant, execution, "111122223333:eu-west-1:i-0123456789abcdef0", b)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_ingester", func(tx *store.Tx) error {
		if e := api.PrepareFixtureEvidence(ctx, tx); e != nil {
			return e
		}
		jobs, e := tx.List(ctx, "ingestion_jobs")
		if e != nil {
			return e
		}
		for _, j := range jobs {
			if model.String(j, "status") == "PERSISTED" {
				continue
			}
			j["status"] = "PERSISTED"
			j, e = tx.Update(ctx, "ingestion_jobs", model.String(j, "id"), model.Number(j, "version"), j)
			if e != nil {
				return e
			}
			if e = api.SealFixtureEvidence(ctx, tx, j); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_api", func(tx *store.Tx) error {
		x, e := tx.Get(ctx, "executions", execution)
		if e != nil {
			return e
		}
		input, e := api.measurementInput(ctx, tx, x)
		if e != nil {
			return e
		}
		measurement := evidence.Object(input["measurement"])
		owned := evidence.Rows(measurement["owned_intervals"])
		if len(owned) != 1 || model.String(owned[0], "execution_id") != execution {
			t.Fatal("measurement lacks exact executor attribution")
		}
		result, e := api.economics(ctx, "v2/evaluate", input)
		if e != nil {
			return e
		}
		if os.Getenv("ECONOMICS_TEST_URL") != "" && (model.String(result, "status") != "VERIFIED" || model.String(result, "verified_saving") != "5.160000000000") {
			t.Fatalf("actual Python fixture result:%v", result)
		}
		snapshots, e := tx.EvidenceList(ctx, "measurement_snapshot", "resource-dev-api")
		if e != nil {
			return e
		}
		last := snapshots[len(snapshots)-1]
		_, e = api.createMeasurement(ctx, tx, model.Document{"measurement_id": p.MeasurementID, "ingestion_job_id": last["ingestion_job_id"], "start": last["start"], "end": last["end"], "workload_samples": last["workload_samples"], "invoice": model.Document{"invoice_id": "unrelated", "total": "1"}})
		if e == nil {
			t.Fatal("caller replaced immutable invoice")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	legacy := p
	legacy.SchemaVersion = ""
	if e = do("finops_signer", func(tx *store.Tx) error { return precheck(ctx, tx, legacy, time.Now()) }); e == nil {
		t.Fatal("legacy plan authorized new stop")
	}
	stale := p
	if e = do("finops_api", func(tx *store.Tx) error {
		ready, e := tx.EvidenceGet(ctx, "readiness", p.ReadinessID)
		if e != nil {
			return e
		}
		ready["id"], ready["checked_at"], ready["expires_at"] = model.ID(), time.Now().Add(-6*time.Minute).UTC().Format(time.RFC3339Nano), time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		ready, e = tx.EvidenceCreate(ctx, "readiness", ready)
		stale.ReadinessID = model.String(ready, "id")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_executor", func(tx *store.Tx) error { return precheck(ctx, tx, stale, time.Now()) }); e == nil {
		t.Fatal("executor accepted expired readiness")
	}
	// A reset keeps immutable evidence, but must not reuse its old measurement
	// while the new generation's source is still waiting for ingestion.
	if e = do("finops_api", func(tx *store.Tx) error {
		org, e := tx.Get(ctx, "org", tenant)
		if e != nil {
			return e
		}
		org["fixture_generation"] = model.ID()
		if _, e = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org); e != nil {
			return e
		}
		ready, e := api.readiness(ctx, tx, "resource-dev-api", true)
		if e != nil {
			return e
		}
		if model.Bool(ready, "pre_execution_ready") || model.String(ready, "reason_code") != "BASELINE_REQUIRED" {
			t.Fatal("reset reused old baseline before fresh generation persisted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_ingester", func(tx *store.Tx) error {
		if e := api.PrepareFixtureEvidence(ctx, tx); e != nil {
			return e
		}
		jobs, e := tx.List(ctx, "ingestion_jobs")
		if e != nil {
			return e
		}
		for _, j := range jobs {
			if model.String(j, "status") == "PERSISTED" {
				continue
			}
			j["status"] = "PERSISTED"
			j, e = tx.Update(ctx, "ingestion_jobs", model.String(j, "id"), model.Number(j, "version"), j)
			if e != nil {
				return e
			}
			if e = api.SealFixtureEvidence(ctx, tx, j); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_api", func(tx *store.Tx) error {
		ready, e := api.readiness(ctx, tx, "resource-dev-api", true)
		if e != nil {
			return e
		}
		if !model.Bool(ready, "pre_execution_ready") || model.String(ready, "baseline_id") == p.BaselineID || model.String(ready, "measurement_id") == p.MeasurementID {
			t.Fatal("fresh reset generation did not receive fresh financial contract")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_api", func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE readiness_evidence SET document=document||'{\"forged\":true}'::jsonb WHERE tenant_id=$1 AND kind='baseline' AND id=$2", tenant, baseline["id"])
		return e
	}); e == nil {
		t.Fatal("immutable baseline changed")
	}
	if e = db.Do(ctx, "other-"+tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		_, e := tx.EvidenceGet(ctx, "baseline", p.BaselineID)
		if e != pgx.ErrNoRows {
			t.Fatalf("cross-tenant baseline visible:%v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// A post-seal source correction cannot silently change a signed occurrence.
	if e = do("finops_ingester", func(tx *store.Tx) error {
		j, e := tx.Get(ctx, "ingestion_jobs", model.String(baseline, "ingestion_job_id"))
		if e != nil {
			return e
		}
		raw := evidence.Object(j["raw"])
		raw["source_version"] = "corrected"
		j["raw"] = raw
		_, e = tx.Update(ctx, "ingestion_jobs", model.String(j, "id"), model.Number(j, "version"), j)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = do("finops_executor", func(tx *store.Tx) error { return precheck(ctx, tx, p, time.Now()) }); e == nil {
		t.Fatal("source replacement accepted byexecutor")
	}
}
