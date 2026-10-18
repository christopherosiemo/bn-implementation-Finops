package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// These cases exercise the real API-only ledger append and worker-only latch
// identities. They make no claim to prove SLO statistics or financial arithmetic.
func sloSavingsDatabase(t *testing.T) (context.Context, *store.Store, *store.Store, *store.Store, *store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Pool.Close)
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	return ctx, admin, trustedRoleStore(t, dsn, "finops_api"), trustedRoleStore(t, dsn, "finops_worker"), trustedRoleStore(t, dsn, "finops_executor")
}

func seedSLOSavingsOccurrence(t *testing.T, ctx context.Context, api, executor *store.Store, tenant, suffix string) (string, string, string) {
	t.Helper()
	planID, executionID, measurementID := "slo-plan-"+suffix, "slo-execution-"+suffix, "slo-measurement-"+suffix
	payload := model.Plan{SchemaVersion: "3", ID: planID, TenantID: tenant, WorkloadID: "slo-workload", SLOObjectiveID: "slo-objective", MeasurementID: measurementID, Nonce: model.ID()}
	if err := api.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "change_plans", model.Document{"id": planID, "resource_id": "slo-resource", "workload_id": "slo-workload", "payload": payload}); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": planID, "resource_id": "slo-resource", "workload_id": "slo-workload", "status": "EXECUTING", "stage": "STOPPED", "restoration_owned": true})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := safety.Sign(payload, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	signer := trustedRoleStore(t, os.Getenv("TEST_DATABASE_URL"), "finops_signer")
	if err := signer.Do(ctx, tenant, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, planID, payload.Nonce, raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := executor.Do(ctx, tenant, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,restored,document) VALUES($1,$2,$3,true,true,false,'{}')", tenant, executionID, "slo-resource-"+suffix)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return planID, executionID, measurementID
}

func latchSLOSavingsOccurrence(t *testing.T, ctx context.Context, worker *store.Store, tenant, plan, execution, measurement string) model.Document {
	t.Helper()
	var violation model.Document
	if err := worker.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		violation, _, err = tx.SLOViolationAppend(ctx, execution, plan, measurement, model.Document{"objective_id": "slo-objective", "workload_id": "slo-workload", "resource_id": "slo-resource", "evaluation_id": "trusted-evaluation", "evaluation_hash": "a", "receipt_ids": []string{"trusted-receipt"}, "reason_codes": []string{"SLO_LATENCY_REGRESSION"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return violation
}

func insertSLOPriorClaim(ctx context.Context, tx *store.Tx, d model.Document) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document) VALUES($1,$2,$3,$4,$5)", tx.Tenant, d["id"], d["execution_id"], d["fingerprint"], raw)
	return err
}

func TestSLOSavingsDisqualificationAppendsOnceAndRetainsFinancialHistory(t *testing.T) {
	ctx, _, api, worker, executor := sloSavingsDatabase(t)
	tenant := "slo-claims-" + model.ID()
	plan, execution, measurement := seedSLOSavingsOccurrence(t, ctx, api, executor, tenant, model.ID())
	windows := []model.Document{{"start": "2026-09-16T20:00:00Z", "end": "2026-09-17T07:00:00Z"}}
	negative := model.Document{"id": "negative", "execution_id": execution, "measurement_id": measurement, "resource_id": "slo-resource", "status": "VERIFIED", "claim_key": "native-claim", "attribution_key": "native-claim", "coverage_intervals": windows, "currency": "GBP", "verified_saving": "-1.000000000000", "fingerprint": "negative-evidence"}
	positive := model.Clone(negative)
	positive["id"], positive["supersedes_id"], positive["verified_saving"], positive["fingerprint"] = "positive", "negative", "5.160000000000", "positive-evidence"
	positive["actual_cost"], positive["expected_baseline_cost"], positive["incremental_cost"], positive["observed_saving"], positive["annualised_estimate"] = "1", "7", "0.84", "5.16", "134.16"
	if err := api.Do(ctx, tenant, func(tx *store.Tx) error { return insertSLOPriorClaim(ctx, tx, negative) }); err != nil {
		t.Fatal(err)
	}
	if err := api.Do(ctx, tenant, func(tx *store.Tx) error { return insertSLOPriorClaim(ctx, tx, positive) }); err != nil {
		t.Fatal(err)
	}
	violation := latchSLOSavingsOccurrence(t, ctx, worker, tenant, plan, execution, measurement)
	if err := worker.Do(ctx, tenant, func(tx *store.Tx) error {
		_, _, err := reconcileSLOClaims(ctx, tx)
		return err
	}); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("workflow identity acquired financial correction authority: %v", err)
	}
	var correctionID string
	for index := 0; index < 3; index++ {
		if err := api.Do(ctx, tenant, func(tx *store.Tx) error {
			results, latched, err := reconcileSLOClaims(ctx, tx)
			if err != nil {
				return err
			}
			if !latched[measurement] || len(results) != 1 {
				t.Fatalf("missing measurement disqualification: %v %v", results, latched)
			}
			head := results[0]
			if model.String(head, "status") != "BLOCKED" || model.String(head, "reason_code") != sloSavingsReason || !model.Bool(head, "is_current") || !model.Bool(head, "slo_disqualified") {
				t.Fatalf("invalid blocked correction: %v", head)
			}
			for _, field := range []string{"verified_saving", "actual_cost", "expected_baseline_cost", "incremental_cost", "observed_saving", "annualised_estimate"} {
				if head[field] != nil {
					t.Fatalf("blocked projection retained %s", field)
				}
			}
			if model.String(head, "claim_key") != "native-claim" || model.String(head, "attribution_key") != "native-claim" || model.String(head, "currency") != "GBP" || evidence.Hash(head["coverage_intervals"]) != evidence.Hash(windows) || model.String(head, "supersedes_id") != "positive" {
				t.Fatal("disqualification changed financial attribution or coverage")
			}
			if index == 0 {
				correctionID = model.String(head, "id")
			} else if model.String(head, "id") != correctionID {
				t.Fatal("reverification duplicated the correction")
			}
			if ids := model.Strings(head, "slo_violation_ids"); len(ids) != 1 || ids[0] != model.String(violation, "id") {
				t.Fatal("correction lost the immutable worker violation identity")
			}
			history, err := tx.Evidence(ctx, "savings_ledger")
			if err != nil {
				return err
			}
			if len(history) != 3 {
				t.Fatalf("history contains %d rows, expected 3", len(history))
			}
			current := 0
			for _, row := range history {
				if model.Bool(row, "is_current") {
					current++
					if row["verified_saving"] != nil {
						t.Fatal("a verified amount survived as current")
					}
				}
				if model.String(row, "id") == "negative" && model.String(row, "verified_saving") != "-1.000000000000" || model.String(row, "id") == "positive" && model.String(row, "verified_saving") != "5.160000000000" {
					t.Fatal("immutable positive or negative history changed")
				}
			}
			if current != 1 {
				t.Fatalf("expected one current blocked claim, got %d", current)
			}
			var events int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE tenant_id=$1 AND event_type='savings.disqualified'", tenant).Scan(&events); err != nil {
				return err
			}
			if events != 1 {
				t.Fatalf("disqualification emitted %d notifications", events)
			}
			return nil
		}); err != nil {
			t.Fatalf("reconciliation %d: %v", index, err)
		}
	}
	if err := api.Do(ctx, tenant+"-other", func(tx *store.Tx) error {
		results, latched, err := reconcileSLOClaims(ctx, tx)
		if err == nil && (len(results) != 0 || len(latched) != 0) {
			t.Fatal("another tenant observed SLO claim authority")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSLOSavingsWithoutFinancialHeadDoesNotManufactureLedgerEvidence(t *testing.T) {
	ctx, _, api, worker, executor := sloSavingsDatabase(t)
	tenant := "slo-no-claim-" + model.ID()
	plan, execution, measurement := seedSLOSavingsOccurrence(t, ctx, api, executor, tenant, model.ID())
	latchSLOSavingsOccurrence(t, ctx, worker, tenant, plan, execution, measurement)
	if err := api.Do(ctx, tenant, func(tx *store.Tx) error {
		results, latched, err := reconcileSLOClaims(ctx, tx)
		if err != nil {
			return err
		}
		if !latched[measurement] || len(results) != 1 || model.String(results[0], "status") != "BLOCKED" || results[0]["verified_saving"] != nil {
			t.Fatal("missing nonfinancial blocked status")
		}
		for _, field := range []string{"claim_key", "coverage_intervals", "currency", "actual_cost", "expected_baseline_cost"} {
			if _, exists := results[0][field]; exists {
				t.Fatalf("summary manufactured %s", field)
			}
		}
		var count int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM savings_ledger WHERE tenant_id=$1", tenant).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("a violation without a financial head created a billing claim")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSLOLatchingCannotBeRevivedThroughAnotherCompletedOccurrence(t *testing.T) {
	ctx, _, apiDB, worker, executor := sloSavingsDatabase(t)
	tenant := "slo-sibling-" + model.ID()
	plan, execution, measurement := seedSLOSavingsOccurrence(t, ctx, apiDB, executor, tenant, model.ID())
	latchSLOSavingsOccurrence(t, ctx, worker, tenant, plan, execution, measurement)
	if err := apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "change_plans", model.Document{"id": "completed-plan", "payload": model.Document{"schema_version": "3", "id": "completed-plan", "measurement_id": measurement}}); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "executions", model.Document{"id": "completed-execution", "change_plan_id": "completed-plan", "resource_id": "slo-resource", "status": "COMPLETED"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	workerHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		JSON(w, 500, model.Document{"error": "economics must not be called for a latched measurement"})
	}))
	defer workerHTTP.Close()
	api := API{Store: apiDB, Config: Config{Fixture: true, EconomicsURL: workerHTTP.URL}, Client: workerHTTP.Client()}
	for attempt := 0; attempt < 2; attempt++ {
		if err := apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
			result, _, err := api.verifySavings(ctx, tx, nil, model.Document{"execution_id": "completed-execution"})
			if err == nil {
				rows := evidence.Rows(result["savings"])
				if len(rows) != 1 || model.String(rows[0], "status") != "BLOCKED" || rows[0]["verified_saving"] != nil {
					t.Fatalf("sibling occurrence revived or hid the disqualification: %v", result)
				}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("a later completed occurrence called economics for a breached measurement")
	}
}

func TestSLOSavingsReconciliationSerializesAFirstWorkerLatch(t *testing.T) {
	ctx, _, api, worker, executor := sloSavingsDatabase(t)
	tenant := "slo-financial-guard-" + model.ID()
	plan, execution, measurement := seedSLOSavingsOccurrence(t, ctx, api, executor, tenant, model.ID())
	guard, err := api.Begin(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Rollback(context.Background()) }()
	if _, latched, err := reconcileSLOClaims(ctx, guard); err != nil || len(latched) != 0 {
		t.Fatalf("unexpected initial financial guard: %v %v", latched, err)
	}
	err = worker.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='200ms'"); err != nil {
			return err
		}
		_, _, err := tx.SLOViolationAppend(ctx, execution, plan, measurement, model.Document{"objective_id": "slo-objective", "workload_id": "slo-workload", "reason_codes": []string{"SLO_LATENCY_REGRESSION"}})
		return err
	})
	var blocked *pgconn.PgError
	if !errors.As(err, &blocked) || blocked.Code != "55P03" {
		t.Fatalf("a new latch escaped the financial transaction guard: %v", err)
	}
	if err = guard.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	latchSLOSavingsOccurrence(t, ctx, worker, tenant, plan, execution, measurement)
	if err = api.Do(ctx, tenant, func(tx *store.Tx) error {
		_, latched, err := reconcileSLOClaims(ctx, tx)
		if err == nil && !latched[measurement] {
			t.Fatal("the committed first violation did not disqualify its measurement")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
