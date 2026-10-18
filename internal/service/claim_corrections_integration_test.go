package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// The transport double supplies alternating authentic-result fingerprints. This
// tests the real API append/dedup path and restricted PostgreSQL projection, not
// financial semantics (which have independent real-Python integration tests).
func TestSavingsRepeatedEvidenceRevivalRetiresEveryPriorHead(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tenant := "claim-revival-" + model.ID()
	var blocked atomic.Bool
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := model.Document{"schema_version": "3", "status": "VERIFIED", "fingerprint": "financial-evidence-A", "claim_key": "same-period", "coverage_intervals": []model.Document{{"start": "2026-09-16T20:00:00Z", "end": "2026-09-17T07:00:00Z"}}, "verified_saving": "5.160000000000", "baseline_model": "test-ledger-orchestration"}
		if blocked.Load() {
			result["status"], result["fingerprint"], result["verified_saving"], result["reason_code"] = "BLOCKED", "financial-evidence-B", nil, "SOURCE_REVOKED"
		}
		JSON(w, http.StatusOK, result)
	}))
	defer worker.Close()
	api := API{Store: db, Config: Config{Fixture: true, EconomicsURL: worker.URL}, Client: &http.Client{Timeout: 5 * time.Second}}
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		res := model.Document{"id": "resource", "provider_resource_id": "i-0123456789abcdef0", "account_id": "111122223333", "region": "eu-west-1", "currency": "GBP"}
		if _, err := tx.Create(ctx, "resources", res); err != nil {
			return err
		}
		raw := model.Document{"source_id": "fixture-source", "source_version": "v1"}
		canonical := model.Document{"records": []model.Document{{"ResourceId": res["provider_resource_id"], "SubAccountId": res["account_id"], "RegionId": res["region"], "BillingCurrency": "GBP", "x_SourceId": "fixture-source", "x_SourceVersion": "v1"}}}
		if _, err := tx.Create(ctx, "ingestion_jobs", model.Document{"id": "job", "status": "PERSISTED", "source_id": "fixture-source", "source_provenance": "DETERMINISTIC_FIXTURE", "raw": raw, "canonical": canonical}); err != nil {
			return err
		}
		binding := evidence.Binding(tenant, res, "GBP")
		if _, err := tx.EvidenceCreate(ctx, "baseline", model.Document{"id": "baseline", "resource_id": "resource", "binding": binding, "ingestion_job_id": "job", "source_hash": evidence.Hash(raw), "canonical_hash": evidence.Hash(canonical), "activation_at": "2026-09-15T20:00:00Z"}); err != nil {
			return err
		}
		if _, err := tx.EvidenceCreate(ctx, "measurement", model.Document{"id": "measurement", "baseline_id": "baseline", "resource_id": "resource", "binding": binding, "activation_at": "2026-09-15T20:00:00Z"}); err != nil {
			return err
		}
		payload := model.Plan{ID: "plan", TenantID: tenant, SchemaVersion: "2", BaselineID: "baseline", MeasurementID: "measurement", Fixture: true}
		if _, err := tx.Create(ctx, "change_plans", model.Document{"id": "plan", "payload": payload}); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "executions", model.Document{"id": "execution", "change_plan_id": "plan", "resource_id": "resource", "status": "COMPLETED"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var previous string
	for index, state := range []bool{false, true, false, true, true} {
		blocked.Store(state)
		if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
				return err
			}
			result, _, err := api.verifySavings(ctx, tx, nil, model.Document{"execution_id": "execution"})
			if err != nil {
				return err
			}
			returned := evidence.Rows(result["savings"])
			if len(returned) != 1 || !model.Bool(returned[0], "is_current") {
				t.Fatalf("step %d did not return current result: %v", index, result)
			}
			history, err := tx.Evidence(ctx, "savings_ledger")
			if err != nil {
				return err
			}
			wantCount := index + 1
			if index == 4 {
				wantCount = 4
			}
			if len(history) != wantCount {
				t.Fatalf("step %d history=%d want=%d", index, len(history), wantCount)
			}
			current, currentVerified := 0, 0
			var head model.Document
			for _, row := range history {
				if model.Bool(row, "is_current") {
					current++
					head = row
					if model.String(row, "status") == "VERIFIED" {
						currentVerified++
					}
				}
			}
			wantStatus := "VERIFIED"
			if state {
				wantStatus = "BLOCKED"
			}
			if current != 1 || model.String(head, "status") != wantStatus || (state && currentVerified != 0) {
				t.Fatalf("step %d current=%d verified=%d head=%v", index, current, currentVerified, head)
			}
			if index > 0 && index < 4 && model.String(head, "supersedes_id") != previous {
				t.Fatalf("step %d did not supersede previous current head", index)
			}
			if index == 4 && model.String(head, "id") != previous {
				t.Fatal("repeated blocked verification appended duplicate history")
			}
			previous = model.String(head, "id")
			return nil
		}); err != nil {
			t.Fatalf("step %d: %v", index, err)
		}
	}
}
