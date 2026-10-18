package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func TestUncertainRunningStopCannotConsumeLateRestoration(t *testing.T) {
	_, roles := financialSourceTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tenant := "late-stop-" + model.ID()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := &SecureService{Store: roles["executor"], Config: Config{Fixture: true, Role: "executor"}, Public: public}
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	type authority struct {
		intent, owned, restored bool
		body                    []byte
		document                model.Document
	}
	seed := func(state string, owned, startNow, receipt bool) (model.Envelope, string) {
		t.Helper()
		now := time.Now().UTC()
		op := model.Operation{Type: "EC2_STOP", ResourceID: "resource-dev-api", ProviderResourceID: "i-fixture-" + model.ID(), AccountID: "111122223333", Region: "eu-west-1"}
		start := op
		start.Type = "EC2_START"
		p := model.Plan{ID: model.ID(), TenantID: tenant, WorkloadID: "workload-dev", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now, StopAt: now, ExpiresAt: now.Add(10 * time.Minute), Operations: []model.Operation{op, start}}
		envelope, err := safety.Sign(p, private)
		if err != nil {
			t.Fatal(err)
		}
		executionID := model.ID()
		if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "status": "RESTORING", "start_now": startNow})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
			body, _ := json.Marshal(envelope)
			_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, body)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if receipt {
			if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
				// An old healthy timer must not be enough to discharge an
				// unresolved request. No production clock or duration is changed.
				body, _ := json.Marshal(model.Document{"state": state, "nonce": p.Nonce, "healthy_since": now.Add(-2 * time.Minute).Format(time.RFC3339Nano), "healthy_checks": 10})
				_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,$4,$5)", tenant, executionID, op.AccountID+":"+op.Region+":"+op.ProviderResourceID, owned, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		return envelope, executionID
	}
	read := func(executionID string) authority {
		t.Helper()
		var row authority
		if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT stop_intent,stop_owned,restored,document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", tenant, executionID).Scan(&row.intent, &row.owned, &row.restored, &row.body)
		}); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(row.body, &row.document); err != nil {
			t.Fatal(err)
		}
		return row
	}
	setState := func(executionID, state string) {
		t.Helper()
		if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.Exec(ctx, "UPDATE provider_operations SET document=jsonb_set(document,'{state}',to_jsonb($3::text)) WHERE tenant_id=$1 AND execution_id=$2", tenant, executionID, state)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	mutations := func(executionID string) int {
		t.Helper()
		var count int
		if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action IN ('provider.stop','provider.start') AND document->'details'->>'execution_id'=$2", tenant, executionID).Scan(&count)
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	envelope, executionID := seed("running", false, true, true)
	for _, operation := range []string{"START", "HEALTH", "DESCRIBE", "HEALTH", "HEALTH"} {
		state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: operation})
		if err != nil || state.State != "running" || state.Healthy || state.Reason != "STOP_OUTCOME_UNRESOLVED" {
			t.Fatalf("unresolved running %s advertised completed recovery: %+v %v", operation, state, err)
		}
		row := read(executionID)
		if !row.intent || row.owned || row.restored || mutations(executionID) != 0 {
			t.Fatal("running health consumed uncertain STOP duty", operation, row)
		}
		if operation == "HEALTH" && (model.Number(row.document, "healthy_checks") != 0 || model.String(row.document, "healthy_since") != "") {
			t.Fatal("unresolved health retained old stabilization evidence")
		}
	}
	setState(executionID, "pending")
	if state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"}); err != nil || state.State != "pending" || state.Healthy || read(executionID).owned || mutations(executionID) != 0 {
		t.Fatal("unowned pending fabricated a start or stop ownership", state, err)
	}
	// A delayed provider transition arrives after those healthy observations.
	// Describe now establishes ownership, but never invents a completed stop.
	setState(executionID, "stopping")
	if state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "DESCRIBE"}); err != nil || state.State != "stopping" || state.Healthy || !read(executionID).owned || read(executionID).restored {
		t.Fatal("late stopping transition was not reconciled accurately", state, err)
	}
	setState(executionID, "stopped")
	if state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"}); err != nil || state.State != "running" || !read(executionID).owned || read(executionID).restored || mutations(executionID) != 1 {
		t.Fatal("late STOP could not restore exactly once", state, err)
	}
	for n := 0; n < 3; n++ {
		state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "HEALTH"})
		if err != nil {
			t.Fatal(err)
		}
		if n < 2 && (state.Healthy || state.Reason != "RESTORATION_HEALTH_PENDING") || n == 2 && !state.Healthy {
			t.Fatal("returned health did not wait for the persisted recovery proof", n, state)
		}
		if n == 0 {
			if read(executionID).restored {
				t.Fatal("late STOP reused old unowned healthy timer")
			}
			time.Sleep(2100 * time.Millisecond)
		}
	}
	if !read(executionID).restored {
		t.Fatal("normal fixture health span did not complete owned restoration")
	}
	setState(executionID, "stopped")
	manual := read(executionID)
	for _, operation := range []string{"HEALTH", "DESCRIBE", "START"} {
		state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: operation})
		if err != nil || state.State != "stopped" || !read(executionID).restored || !bytes.Equal(manual.body, read(executionID).body) || mutations(executionID) != 1 {
			t.Fatal("consumed capability acquired a later manual stop", operation, state, err)
		}
	}
	for _, observed := range []string{"stopping", "running"} {
		t.Run("owned-stop-replay-observes-"+observed, func(t *testing.T) {
			envelope, id := seed(observed, true, false, true)
			state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: "STOP"})
			if err != nil || state.State != observed || mutations(id) != 0 {
				t.Fatal("owned STOP replay altered actual state or redispatched", state, err)
			}
		})
	}
	for _, operation := range []string{"DESCRIBE", "START"} {
		t.Run("late-stopping-persists-ownership-through-"+operation, func(t *testing.T) {
			envelope, id := seed("stopping", false, true, true)
			state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: operation})
			if err != nil || state.State != "stopping" || !read(id).owned || read(id).restored || mutations(id) != 0 {
				t.Fatal("known stopping transition did not persist ownership", state, err)
			}
			if row := read(id); model.String(row.document, "healthy_since") != "" || model.Number(row.document, "healthy_checks") != 0 {
				t.Fatal("late stopping retained a previous healthy streak")
			}
		})
	}
	t.Run("owned-health-streak-interruption-needs-new-persisted-proof", func(t *testing.T) {
		envelope, id := seed("running", true, true, true)
		setState(id, "stopping")
		if state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: "DESCRIBE"}); err != nil || state.State != "stopping" {
			t.Fatal(state, err)
		}
		if row := read(id); model.String(row.document, "healthy_since") != "" || model.Number(row.document, "healthy_checks") != 0 {
			t.Fatal("interrupted owned recovery retained old healthy counts")
		}
		setState(id, "stopped")
		if state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: "START"}); err != nil || state.State != "running" {
			t.Fatal(state, err)
		}
		for n := 0; n < 3; n++ {
			state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: "HEALTH"})
			if err != nil || n < 2 && (state.Healthy || state.Reason != "RESTORATION_HEALTH_PENDING" || read(id).restored) || n == 2 && (!state.Healthy || !read(id).restored) {
				t.Fatal("cached workflow successes could bypass a fresh persisted health proof", n, state, err)
			}
			if n == 0 {
				time.Sleep(2100 * time.Millisecond)
			}
		}
	})
	for _, operation := range []string{"DESCRIBE", "START"} {
		t.Run("running-unhealthy-breaks-streak-through-"+operation, func(t *testing.T) {
			envelope, id := seed("running", true, true, true)
			unhealthy := func(value bool) {
				t.Helper()
				if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
					w, err := tx.Get(ctx, "workloads", "workload-dev")
					if err != nil {
						return err
					}
					w["fixture_unhealthy"] = value
					_, err = tx.Update(ctx, "workloads", "workload-dev", model.Number(w, "version"), w)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			unhealthy(true)
			state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: operation})
			if err != nil || state.State != "running" || state.Healthy {
				t.Fatal("unhealthy running observation was lost", state, err)
			}
			if row := read(id); model.String(row.document, "healthy_since") != "" || model.Number(row.document, "healthy_checks") != 0 {
				t.Fatal("unhealthy running observation retained a stale proof")
			}
			unhealthy(false)
			state, err = service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: "HEALTH"})
			if err != nil || state.Healthy || state.Reason != "RESTORATION_HEALTH_PENDING" || read(id).restored {
				t.Fatal("healthy observation borrowed the interrupted old streak", state, err)
			}
		})
	}
	for _, receipt := range []bool{false, true} {
		t.Run(fmt.Sprintf("health-without-stop-intent-receipt-%t", receipt), func(t *testing.T) {
			envelope, id := seed("running", false, false, receipt)
			if receipt {
				if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
					_, err := tx.Exec(ctx, "UPDATE provider_operations SET stop_intent=false WHERE tenant_id=$1 AND execution_id=$2", tenant, id)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: id, Operation: "HEALTH"})
			if err != nil || state.Healthy || state.Reason != "RESTORATION_NOT_OWNED" || receipt && read(id).restored {
				t.Fatal("unowned health advertised eligible recovery", state, err)
			}
			if count := mutations(id); count != 0 {
				t.Fatalf("unowned health performed %d mutations", count)
			}
		})
	}
}
