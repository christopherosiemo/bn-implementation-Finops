package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A rejected first StopInstances request cannot own a later manual stop. This
// exercises the transaction boundary that intentionally commits the rejection
// before Store.Do returns the provider error, using the real executor role.
func TestDefinitivelyRejectedFirstStopCannotAcquireManualStop(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to disposable admin PostgreSQL")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE finops_executor")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	executorDB := &store.Store{Pool: pool}
	for _, tc := range []struct {
		name          string
		firstDispatch bool
		cause         error
		consumed      bool
	}{
		{"first_definitive_rejection", true, &provider.QueryRejection{Action: "StopInstances", Code: "UnauthorizedOperation", StatusCode: 403}, true},
		{"prior_uncertain_intent_then_rejection", false, &provider.QueryRejection{Action: "StopInstances", Code: "UnauthorizedOperation", StatusCode: 403}, false},
		{"first_transport_failure", true, errors.New("fixture transport response lost"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := "rejected-stop-" + model.ID()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			operation := model.Operation{Type: "EC2_STOP", ResourceID: "resource", ProviderResourceID: "i-fixture-manual-stop", AccountID: "111122223333", Region: "eu-west-1"}
			start := operation
			start.Type = "EC2_START"
			plan := model.Plan{ID: model.ID(), TenantID: tenant, WorkloadID: "workload", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now.Add(-48 * time.Hour), StopAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-47 * time.Hour), Operations: []model.Operation{operation, start}}
			envelope, err := safety.Sign(plan, private)
			if err != nil {
				t.Fatal(err)
			}
			executionID := model.ID()
			if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				if _, err := tx.Create(ctx, "workloads", model.Document{"id": "workload", "owner": "test", "environment": "NON_PRODUCTION"}); err != nil {
					return err
				}
				_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": plan.ID, "status": "RESTORING"})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_signer"); err != nil {
					return err
				}
				body, _ := json.Marshal(envelope)
				_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, plan.ID, plan.Nonce, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// This is the already committed intent from before the provider call.
			state := model.Document{"state": "running", "nonce": plan.Nonce}
			if err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
				body, _ := json.Marshal(state)
				_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,document) VALUES($1,$2,$3,true,$4)", tenant, executionID, operation.AccountID+":"+operation.Region+":"+operation.ProviderResourceID, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			type authority struct {
				intent, owned, restored bool
				document                []byte
			}
			read := func() authority {
				t.Helper()
				var row authority
				if err := executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
					return tx.QueryRow(ctx, "SELECT stop_intent,stop_owned,restored,document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", tenant, executionID).Scan(&row.intent, &row.owned, &row.restored, &row.document)
				}); err != nil {
					t.Fatal(err)
				}
				return row
			}
			auditCount := func(action string) int {
				t.Helper()
				var count int
				if err := executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
					return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action=$2 AND document->'details'->>'execution_id'=$3", tenant, action, executionID).Scan(&count)
				}); err != nil {
					t.Fatal(err)
				}
				return count
			}
			original := read()
			err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
				return finalizeStopError(ctx, tx, executionID, state, operation, tc.firstDispatch, tc.cause)
			})
			if !errors.Is(err, tc.cause) {
				t.Fatalf("provider cause changed across transaction boundary: %v", err)
			}
			row := read()
			if tc.consumed {
				if row.intent || row.owned || !row.restored || auditCount("provider.stop.rejected") != 1 {
					t.Fatalf("definitive rejection was rolled back or retained restoration authority: %+v", row)
				}
				var rejected model.Document
				if err := json.Unmarshal(row.document, &rejected); err != nil || !model.Bool(rejected, "stop_rejected") || model.String(rejected, "reason_code") != "STOP_DEFINITIVELY_REJECTED" {
					t.Fatalf("durable rejection lacks its safe reason: %s, %v", row.document, err)
				}
			} else if !row.intent || row.owned || row.restored || !bytes.Equal(original.document, row.document) || auditCount("provider.stop.rejected") != 0 {
				t.Fatalf("uncertain provider outcome lost restoration duty: %+v", row)
			}
			// Represent a later independent manual stop in the fixture adapter. Only
			// provider state changes; rejection/ownership/consumption stay intact.
			if err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
				_, err := tx.Exec(ctx, "UPDATE provider_operations SET document=jsonb_set(document,'{state}','\"stopped\"'::jsonb) WHERE tenant_id=$1 AND execution_id=$2", tenant, executionID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			manual := read()
			service := SecureService{Store: executorDB, Config: Config{Fixture: true, Role: "executor"}, Public: public}
			for _, op := range []string{"HEALTH", "DESCRIBE", "START"} {
				current, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: op})
				if err != nil {
					t.Fatal(err)
				}
				if tc.consumed {
					row := read()
					if current.State != "stopped" || row.intent || row.owned || !row.restored || !bytes.Equal(manual.document, row.document) || auditCount("provider.start") != 0 {
						t.Fatalf("old %s acquired or altered a manually stopped instance: %+v %+v", op, current, row)
					}
				} else if op == "START" && current.State != "running" {
					t.Fatalf("uncertain stop could not restore: %+v", current)
				}
			}
			if tc.consumed {
				return
			}
			// Pending/uncertain stops still restore once and consume their recovery
			// capability only after successful application-health verification.
			if row := read(); !row.intent || !row.owned || row.restored || auditCount("provider.start") != 1 {
				t.Fatalf("uncertain restoration did not retain one actual start: %+v", row)
			}
			for n := 0; n < 3; n++ {
				if _, err = service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "HEALTH"}); err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					time.Sleep(2100 * time.Millisecond)
				}
			}
			if row := read(); !row.restored || auditCount("provider.start") != 1 {
				t.Fatalf("pending restoration did not complete exactly once: %+v", row)
			}
		})
	}
	for _, providerState := range []string{"running", "stopping"} {
		t.Run("existing_intent_observes_"+providerState, func(t *testing.T) {
			tenant := "pending-stop-" + model.ID()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			operation := model.Operation{Type: "EC2_STOP", ResourceID: "resource", ProviderResourceID: "i-fixture-pending-stop", AccountID: "111122223333", Region: "eu-west-1"}
			start := operation
			start.Type = "EC2_START"
			plan := model.Plan{ID: model.ID(), TenantID: tenant, WorkloadID: "workload", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now, StopAt: now, ExpiresAt: now.Add(15 * time.Minute), Operations: []model.Operation{operation, start}}
			envelope, err := safety.Sign(plan, private)
			if err != nil {
				t.Fatal(err)
			}
			executionID := model.ID()
			if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				if _, err := tx.Create(ctx, "workloads", model.Document{"id": "workload", "owner": "test", "environment": "NON_PRODUCTION"}); err != nil {
					return err
				}
				_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": plan.ID, "status": "RUNNING"})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_signer"); err != nil {
					return err
				}
				body, _ := json.Marshal(envelope)
				_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, plan.ID, plan.Nonce, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
				body, _ := json.Marshal(model.Document{"state": providerState, "nonce": plan.Nonce})
				_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,document) VALUES($1,$2,$3,true,$4)", tenant, executionID, operation.AccountID+":"+operation.Region+":"+operation.ProviderResourceID, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			read := func() []byte {
				t.Helper()
				var body []byte
				var intent, owned, restored bool
				if err := executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
					return tx.QueryRow(ctx, "SELECT stop_intent,stop_owned,restored,document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", tenant, executionID).Scan(&intent, &owned, &restored, &body)
				}); err != nil {
					t.Fatal(err)
				}
				if !intent || owned || restored {
					t.Fatalf("reconciliation altered uncertain ownership: intent=%v owned=%v restored=%v", intent, owned, restored)
				}
				return body
			}
			original := read()
			service := SecureService{Store: executorDB, Config: Config{Fixture: true, Role: "executor"}, Public: public}
			// There is deliberately no resource or baseline to pass a new-stop
			// precheck. A prior uncertain request must only reconcile its outcome.
			for n := 0; n < 2; n++ {
				current, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "STOP"})
				if err != nil || current.State != providerState {
					t.Fatalf("uncertain %s intent was redispatched: %+v, %v", providerState, current, err)
				}
				if !bytes.Equal(original, read()) {
					t.Fatal("reconciliation rewrote the pending receipt")
				}
			}
			var mutations int
			if err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
				return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action IN ('provider.stop','provider.start') AND document->'details'->>'execution_id'=$2", tenant, executionID).Scan(&mutations)
			}); err != nil {
				t.Fatal(err)
			}
			if mutations != 0 {
				t.Fatalf("reconciliation dispatched %d provider mutations", mutations)
			}
		})
	}
}
