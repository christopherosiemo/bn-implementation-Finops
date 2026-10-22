package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConsumedRestorationCannotRestartManuallyStoppedInstance(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to disposable admin PostgreSQL")
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
	tenant := "test-" + model.ID()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	op := model.Operation{Type: "EC2_STOP", ResourceID: "resource", ProviderResourceID: "i-fixture", Region: "eu-west-1", AccountID: "111122223333"}
	restore := op
	restore.Type = "EC2_START"
	p := model.Plan{ID: model.ID(), TenantID: tenant, WorkloadID: "workload", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now.Add(-48 * time.Hour), StopAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-47 * time.Hour), Operations: []model.Operation{op, restore}}
	envelope, _ := safety.Sign(p, priv)
	execution := model.ID()
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload", "owner": "test", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": p.ID, "status": "COMPLETED"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_signer"); e != nil {
			return e
		}
		b, _ := json.Marshal(envelope)
		_, e := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, b)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_executor"); e != nil {
			return e
		}
		b, _ := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce})
		_, e := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,restored,document) VALUES($1,$2,$3,true,true,true,$4)", tenant, execution, "111122223333:eu-west-1:i-fixture", b)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// A fresh executor connection runs the actual low-privilege database role.
	pc, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_executor")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	svc := SecureService{Store: &store.Store{Pool: pool}, Config: Config{Fixture: true, Role: "executor"}, Public: pub}
	// Fixture state represents an independent manual stop after the successful
	// occurrence. An old HEALTH must not clear consumption before old DESCRIBE
	// and START replay the same expired recovery capability.
	readAuthority := func() (bool, []byte) {
		t.Helper()
		var consumed bool
		var document []byte
		if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_executor"); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT restored,document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", tenant, execution).Scan(&consumed, &document)
		}); err != nil {
			t.Fatal(err)
		}
		return consumed, document
	}
	_, original := readAuthority()
	for _, operation := range []string{"HEALTH", "DESCRIBE", "START"} {
		state, err := svc.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: operation})
		if err != nil {
			t.Fatal(err)
		}
		if state.State != "stopped" {
			t.Fatalf("old %s changed a manually stopped instance: %+v", operation, state)
		}
		consumed, document := readAuthority()
		if !consumed || !bytes.Equal(original, document) {
			t.Fatalf("old %s revived or rewrote consumed restoration authority", operation)
		}
	}
	// Pending application-health verification can observe an already-running
	// instance repeatedly. These observations must not fabricate provider starts.
	setState := func(value string) {
		t.Helper()
		e := admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_executor"); e != nil {
				return e
			}
			b, _ := json.Marshal(model.Document{"state": value, "nonce": p.Nonce})
			_, e := tx.Exec(ctx, "UPDATE provider_operations SET restored=false,document=$3 WHERE tenant_id=$1 AND execution_id=$2", tenant, execution, b)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	starts := func() int {
		t.Helper()
		var count int
		e := admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_executor"); e != nil {
				return e
			}
			return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='provider.start' AND document->'details'->>'execution_id'=$2", tenant, execution).Scan(&count)
		})
		if e != nil {
			t.Fatal(e)
		}
		return count
	}
	setState("running")
	for n := 0; n < 3; n++ {
		if _, e = svc.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "START"}); e != nil {
			t.Fatal(e)
		}
	}
	if n := starts(); n != 0 {
		t.Fatalf("readiness observations fabricated %d provider.start events", n)
	}
	setState("stopped")
	for n := 0; n < 4; n++ {
		if _, e = svc.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "START"}); e != nil {
			t.Fatal(e)
		}
	}
	if n := starts(); n != 1 {
		t.Fatalf("one actual start plus health polling produced %d provider.start events", n)
	}
}
