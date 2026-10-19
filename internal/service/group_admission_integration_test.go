package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// This test isolates executor admission plumbing under authenticated database
// roles. Its private DB owner replaces the decision function with a recording
// refusal; it does not manufacture a real issued group obligation. Repository
// acceptance independently exercises the actual 030 admission implementation.
func TestGroupAdmissionBlocksEveryNewStopSchemaAndPreservesOwnedStart(t *testing.T) {
	admin, roles := financialSourceTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tenant := "group-admission-" + model.ID()
	if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Pool.Exec(ctx, `CREATE SEQUENCE public.test_group_admission_calls;
CREATE OR REPLACE FUNCTION public.fleet_group_admission(p_tenant text,p_workload text,p_family text,p_owned_chain text DEFAULT NULL) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR p_workload IS DISTINCT FROM 'workload-dev' OR p_family IS DISTINCT FROM 'R1' OR p_owned_chain IS NOT NULL THEN RAISE EXCEPTION 'test scope mismatch';END IF;
 -- A sequence is intentional: denied executor transactions roll back their
 -- writes, while this private probe must retain the number of decisions.
 PERFORM nextval('public.test_group_admission_calls');
 RETURN false;
END $$`); err != nil {
		t.Fatal("private admission probe installation failed", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	executor := &SecureService{Store: roles["executor"], Public: public, Config: Config{Role: "executor", Fixture: true}}
	seed := func(schema string, owned bool) (model.Envelope, string) {
		t.Helper()
		now := time.Now().UTC()
		op := model.Operation{Type: "EC2_STOP", ResourceID: "resource-dev-api", ProviderResourceID: "i-model-" + model.ID(), AccountID: "111122223333", Region: "eu-west-1"}
		start := op
		start.Type = "EC2_START"
		p := model.Plan{SchemaVersion: schema, ID: model.ID(), TenantID: tenant, WorkloadID: "workload-dev", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now, StopAt: now, ExpiresAt: now.Add(10 * time.Minute), Operations: []model.Operation{op, start}}
		if owned {
			p.CreatedAt, p.StopAt, p.ExpiresAt = now.Add(-time.Hour), now.Add(-time.Hour), now.Add(-time.Minute)
		}
		envelope, err := safety.Sign(p, private)
		if err != nil {
			t.Fatal(err)
		}
		execution := model.ID()
		if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "status": "RESTORING"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
			body, err := json.Marshal(envelope)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, body)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if owned {
			if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
				body, err := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce})
				if err != nil {
					return err
				}
				_, err = tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,true,$4)", tenant, execution, op.AccountID+":"+op.Region+":"+op.ProviderResourceID, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		return envelope, execution
	}
	for _, schema := range []string{"", "2", "3"} {
		envelope, execution := seed(schema, false)
		_, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "STOP"})
		var blocked *Problem
		if !errors.As(err, &blocked) || blocked.Code != "FLEET_WORKLOAD_MUTATION_PENDING" {
			t.Fatal("new STOP escaped workload admission", schema, err)
		}
		var intents, mutations int
		if err = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", tenant, execution).Scan(&intents); err != nil {
			t.Fatal(err)
		}
		if err = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action IN('provider.stop','provider.start') AND document->'details'->>'execution_id'=$2", tenant, execution).Scan(&mutations); err != nil || intents != 0 || mutations != 0 {
			t.Fatal("denied admission persisted provider intent or mutation", schema, err)
		}
	}
	envelope, execution := seed("", true)
	state, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "START"})
	if err != nil || state.State != "running" {
		t.Fatal("expired owned legacy restoration was blocked by new family", state, err)
	}
	var decisions, starts int
	if err = admin.Pool.QueryRow(ctx, "SELECT last_value FROM public.test_group_admission_calls").Scan(&decisions); err != nil || decisions != 3 {
		t.Fatal("restoration called new-stop admission", decisions, err)
	}
	if err = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='provider.start' AND document->'details'->>'execution_id'=$2", tenant, execution).Scan(&starts); err != nil || starts != 1 {
		t.Fatal("owned recovery did not perform exactly one start", starts, err)
	}
}
