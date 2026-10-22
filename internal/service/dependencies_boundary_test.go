package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// This helper reuses the trusted integration's server-selected v3 evidence. Its
// positive control prevents missing approvals or unrelated preconditions from
// accidentally making negative signer/executor assertions pass.
func trustedDependencyServiceBoundaries(t *testing.T, ctx context.Context, apiDB, executorDB *store.Store, tenant string, api *API, original model.Plan) func() {
	t.Helper()
	signerDB := trustedRoleStore(t, os.Getenv("TEST_DATABASE_URL"), "finops_signer")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := SecureService{Store: signerDB, Config: Config{Fixture: true, Role: "signer", SignerToken: "dependency-boundary-test"}, Private: private, Public: public}
	executor := SecureService{Store: executorDB, Config: Config{Fixture: true, Role: "executor"}, Public: public}

	approved := func(p model.Plan) string {
		t.Helper()
		if err := apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.Create(ctx, "change_plans", model.Document{"id": p.ID, "workload_id": p.WorkloadID, "resource_id": p.Operations[0].ResourceID, "status": "AWAITING_APPROVAL", "policy_version": p.PolicyVersion, "expires_at": p.ExpiresAt.Format(time.RFC3339Nano), "payload": p})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := dependencyRequest(t, ctx, api, apiDB, tenant, "approvals", 1, model.Document{"change_plan_id": p.ID}, false); err != nil {
			t.Fatal(err)
		}
		execution := model.ID()
		if err := apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": p.ID, "resource_id": p.Operations[0].ResourceID, "status": "RUNNING"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return execution
	}
	sign := func(p model.Plan, execution string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(model.Document{"tenant_id": tenant, "plan_id": p.ID, "execution_id": execution})
		r := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer dependency-boundary-test")
		w := httptest.NewRecorder()
		signer.Handler().ServeHTTP(w, r)
		return w
	}
	assertRejected := func(w *httptest.ResponseRecorder, code string) {
		t.Helper()
		var response model.Document
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != 422 || model.String(response, "error") != code || response["signature"] != nil || response["plan"] != nil {
			t.Fatalf("signer returned authority instead of %s: status%d %v", code, w.Code, response)
		}
	}
	count := func(db *store.Store, table, key, id string) int {
		t.Helper()
		var n int
		if err := db.Do(ctx, tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1 AND "+key+"=$2", tenant, id).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	valid := original
	valid.ID, valid.Nonce = model.ID(), model.ID()
	execution := approved(valid)
	w := sign(valid, execution)
	var envelope model.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || w.Code != http.StatusOK || envelope.Signature == "" || envelope.Plan.ID != valid.ID {
		t.Fatalf("valid v3 dependency control did not reach signer: status%d %s (%v)", w.Code, w.Body.String(), err)
	}
	if n := count(signerDB, "signed_plans", "plan_id", valid.ID); n != 1 {
		t.Fatalf("independent signer did not persist its envelope: %d", n)
	}
	for _, missing := range []bool{true, false} {
		invalid := original
		invalid.ID, invalid.Nonce = model.ID(), model.ID()
		if missing {
			invalid.DependencyReviewID = ""
		} else {
			invalid.DependencyGraphHash = strings.Repeat("0", 64)
		}
		invalidExecution := approved(invalid)
		assertRejected(sign(invalid, invalidExecution), "DEPENDENCY_REVIEW_REQUIRED")
		if n := count(signerDB, "signed_plans", "plan_id", invalid.ID); n != 0 {
			t.Fatal("missing or mismatched review yielded a persisted signed envelope")
		}
	}
	for _, missing := range []bool{true, false} {
		invalid := original
		invalid.ID, invalid.Nonce = model.ID(), model.ID()
		if missing {
			invalid.SLOEvaluationID = ""
		} else {
			invalid.SLOEvaluationHash = strings.Repeat("0", 64)
		}
		invalidExecution := approved(invalid)
		assertRejected(sign(invalid, invalidExecution), "SLO_READINESS_BINDING_INVALID")
		if n := count(signerDB, "signed_plans", "plan_id", invalid.ID); n != 0 {
			t.Fatal("missing or tampered SLO snapshot yielded a signature")
		}
	}
	return func() {
		t.Helper()
		assertRejected(sign(valid, execution), "DEPENDENCY_GRAPH_CHANGED")
		_, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "STOP"})
		var blocked *Problem
		if !errors.As(err, &blocked) || blocked.Code != "DEPENDENCY_GRAPH_CHANGED" {
			t.Fatalf("restricted executor did not reject the stale signed graph: %v", err)
		}
		if n := count(executorDB, "provider_operations", "execution_id", execution); n != 0 {
			t.Fatal("stale graph created a stop intent or dispatched provider mutation")
		}
	}
}
