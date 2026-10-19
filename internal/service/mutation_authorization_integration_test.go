package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgconn"
)

type mutationReplayFixture struct {
	t      *testing.T
	api    *API
	roles  map[string]*store.Store
	tenant string
	sign   jose.Signer
}

func newMutationReplayFixture(t *testing.T) *mutationReplayFixture {
	t.Helper()
	_, roles := financialSourceTestDatabase(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "mutation-replay"))
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "mutation-replay", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(jwks.Close)
	validator, err := auth.New(context.Background(), "https://mutation-issuer.invalid/realms/test", "finops", jwks.URL)
	if err != nil {
		t.Fatal(err)
	}
	f := &mutationReplayFixture{t: t, roles: roles, tenant: "mutation-replay-" + model.ID(), sign: signer}
	f.api = &API{Store: roles["api"], Auth: validator, Config: Config{Fixture: true}}
	if err = roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		if err := tx.Seed(context.Background(), true); err != nil {
			return err
		}
		_, err := tx.Create(context.Background(), "workloads", model.Document{"id": "replay-workload", "name": "Replay authorization", "owner": "application-user", "environment": "NON_PRODUCTION", "health_url": "https://health.invalid/ready"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *mutationReplayFixture) token(tenant, subject string, roles ...string) string {
	f.t.Helper()
	v, err := jwt.Signed(f.sign).Claims(map[string]any{"iss": "https://mutation-issuer.invalid/realms/test", "aud": "finops", "sub": subject, "tenant_id": tenant, "exp": time.Now().Add(time.Hour).Unix(), "realm_access": map[string]any{"roles": roles}}).Serialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *mutationReplayFixture) request(path, etag, key, token string, in model.Document) (int, model.Document, string) {
	f.t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/"+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	if etag != "" {
		r.Header.Set("If-Match", etag)
	}
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	out := model.Document{}
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatal("HTTP mutation did not return JSON", w.Code)
	}
	return w.Code, out, w.Header().Get("ETag")
}

func (f *mutationReplayFixture) update(kind, id string, change func(model.Document)) model.Document {
	f.t.Helper()
	var out model.Document
	if err := f.roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		d, err := tx.Get(context.Background(), kind, id)
		if err != nil {
			return err
		}
		change(d)
		out, err = tx.Update(context.Background(), kind, id, model.Number(d, "version"), d)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *mutationReplayFixture) counts() (audit, outbox int) {
	f.t.Helper()
	if err := f.roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT (SELECT count(*) FROM audit_events WHERE tenant_id=$1),(SELECT count(*) FROM outbox WHERE tenant_id=$1)", f.tenant).Scan(&audit, &outbox)
	}); err != nil {
		f.t.Fatal(err)
	}
	return
}

// Uses real JWT/JWKS validation and independently authenticated, restricted
// PostgreSQL logins. It creates only an owned disposable DB; no live providers,
// deployment, source history or execution-readiness claim is involved.
func TestMutationReplayAuthorizationCurrentRolesAndCommittedPreconditions(t *testing.T) {
	f := newMutationReplayFixture(t)
	platform := f.token(f.tenant, "operator", "PLATFORM_ADMIN")
	in := model.Document{"paused": true}
	status, first, etag := f.request("control/pause", `"1"`, "role-pause-once", platform, in)
	if status != 200 || model.Number(first, "version") != 2 || etag != `"2"` {
		t.Fatal("initial authorized control did not commit", status, first, etag)
	}
	audit, events := f.counts()
	for _, role := range []string{"APPROVER", "APPLICATION_OWNER", "FINOPS_ADMIN", "FINANCE", "VIEWER", "AUDITOR"} {
		if code, _, _ := f.request("control/pause", `"1"`, "role-pause-once", f.token(f.tenant, "operator", role), in); code != 403 {
			t.Fatal("cached control escaped current role", role, code)
		}
	}
	status, replay, replayTag := f.request("control/pause", `"1"`, "role-pause-once", platform, in)
	if status != 200 || model.Number(replay, "version") != 2 || replayTag != etag || replay["paused"] != first["paused"] {
		t.Fatal("authorized retry reran current ETag or control", status, replay, replayTag)
	}
	if code, _, _ := f.request("control/pause", "", "role-pause-no-cas", platform, in); code != 428 {
		t.Fatal("fresh mutation lost required If-Match", code)
	}
	if code, _, _ := f.request("control/pause", `"1"`, "role-pause-stale", platform, in); code != 409 {
		t.Fatal("fresh mutation lost stale If-Match protection", code)
	}
	if code, _, _ := f.request("control/pause", `"1"`, "role-pause-once", platform, model.Document{"paused": false}); code != 409 {
		t.Fatal("changed body borrowed committed key", code)
	}
	if code, _, _ := f.request("control/pause", `"1"`, "role-pause-once", f.token(f.tenant, "different-subject", "PLATFORM_ADMIN"), in); code != 409 {
		t.Fatal("different subject borrowed committed key", code)
	}
	if gotAudit, gotEvents := f.counts(); gotAudit != audit || gotEvents != events {
		t.Fatal("replay or rejected authorization emitted writes", gotAudit, gotEvents)
	}
	// Finance routes intentionally do not grant standalone PLATFORM_ADMIN.
	finance := f.token(f.tenant, "finance", "FINANCE")
	policy := model.Document{"schema_version": "1", "name": "Bounded observations", "rules": []any{}}
	if code, _, _ := f.request("allocation-policies", `"0"`, "finance-policy-once", finance, policy); code != 201 {
		t.Fatal("finance policy did not commit", code)
	}
	for _, role := range []string{"APPROVER", "APPLICATION_OWNER", "PLATFORM_ADMIN"} {
		if code, _, _ := f.request("allocation-policies", `"0"`, "finance-policy-once", f.token(f.tenant, "finance", role), policy); code != 403 {
			t.Fatal("financial response escaped current policy", role, code)
		}
	}
	if code, _, _ := f.request("allocation-policies", `"0"`, "finance-policy-once", finance, policy); code != 201 {
		t.Fatal("financial retry reran current CAS", code)
	}
	// Being the current workload owner does not preserve the platform-only
	// Autopilot opt-in after the creator's role has been downgraded.
	f.update("policies", "policy-default", func(d model.Document) { d["workload_autopilot_ids"] = []string{"replay-workload"} })
	schedule := model.Document{"workload_id": "replay-workload", "timezone": "UTC", "days": []int{1, 2, 3, 4, 5, 6, 7}, "stop_time": "20:00", "ready_time": "07:00", "mode": "AUTOPILOT", "autopilot_opt_in": true, "memory_state_acknowledged": true, "public_ip_change_acknowledged": true}
	if code, _, _ := f.request("schedules", "", "autopilot-role-once", f.token(f.tenant, "application-user", "PLATFORM_ADMIN"), schedule); code != 201 {
		t.Fatal("scoped platform Autopilot schedule did not commit", code)
	}
	if code, _, _ := f.request("schedules", "", "autopilot-role-once", f.token(f.tenant, "application-user", "APPLICATION_OWNER"), schedule); code != 403 {
		t.Fatal("owned Autopilot response survived platform role withdrawal", code)
	}
	if code, _, _ := f.request("schedules", "", "autopilot-new-owner", f.token(f.tenant, "application-user", "APPLICATION_OWNER"), schedule); code != 422 {
		t.Fatal("fresh Autopilot owner request lost existing explicit-opt-in precondition", code)
	}
}

func TestMutationReplayAuthorizationUsesCurrentWorkloadAndSerializesReassignment(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	owner := f.token(f.tenant, "application-user", "APPLICATION_OWNER")
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		for _, d := range []struct {
			kind string
			body model.Document
		}{
			{"schedules", model.Document{"id": "replay-schedule", "workload_id": "replay-workload", "paused": false}},
			{"change_plans", model.Document{"id": "replay-plan", "workload_id": "replay-workload", "status": "AWAITING_APPROVAL", "policy_version": 1}},
		} {
			if _, err := tx.Create(ctx, d.kind, d.body); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path, tag, key string
		body           model.Document
		roles          []string
		status         int
	}{
		{"schedules", "", "owner-schedule-once", model.Document{"workload_id": "replay-workload", "timezone": "UTC", "days": []int{1, 2, 3, 4, 5, 6, 7}, "stop_time": "20:00", "ready_time": "07:00", "mode": "ASSISTED_EXECUTION", "memory_state_acknowledged": true, "public_ip_change_acknowledged": true}, []string{"APPLICATION_OWNER"}, 201},
		{"schedules/replay-schedule/pause", `"1"`, "owner-pause-once", model.Document{"paused": true}, []string{"APPLICATION_OWNER"}, 200},
		{"workloads/replay-workload/signals", "", "owner-signals-once", model.Document{"incident": "CLEAR", "deployment": "CLEAR", "job": "CLEAR"}, []string{"APPLICATION_OWNER"}, 200},
		{"approvals", `"1"`, "owner-approval-once", model.Document{"change_plan_id": "replay-plan"}, []string{"APPROVER", "APPLICATION_OWNER"}, 201},
	} {
		t.Run(test.path, func(t *testing.T) {
			w := f.update("workloads", "replay-workload", func(d model.Document) { d["owner"] = "application-user" })
			tag := test.tag
			if tag == "" {
				tag = fmt.Sprintf(`"%d"`, model.Number(w, "version"))
			}
			bearer := f.token(f.tenant, "application-user", test.roles...)
			code, first, _ := f.request(test.path, tag, test.key, bearer, test.body)
			if code != test.status {
				t.Fatal("owned mutation did not commit", code, first)
			}
			audit, events := f.counts()
			f.update("workloads", "replay-workload", func(d model.Document) { d["owner"] = "different-owner" })
			if code, out, _ := f.request(test.path, tag, test.key, bearer, test.body); code != 403 || model.String(out, "error") != "WORKLOAD_SCOPE_DENIED" {
				t.Fatal("cached response ignored current workload owner", code, out)
			}
			if gotAudit, gotEvents := f.counts(); gotAudit != audit || gotEvents != events {
				t.Fatal("denied replay mutated durable state")
			}
			// Reassignment is not a permanent revocation of the key: current
			// ownership can be restored without replaying the original mutation.
			f.update("workloads", "replay-workload", func(d model.Document) { d["owner"] = "application-user" })
			if code, replay, _ := f.request(test.path, tag, test.key, bearer, test.body); code != test.status || model.Number(replay, "version") != model.Number(first, "version") {
				t.Fatal("authorized replay reran already advanced mutation state", code, replay)
			}
		})
	}
	// The replay checker holds the same guard as actual owner updates, rather
	// than authorizing a mapping that can change before its transaction ends.
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		i := auth.Identity{Tenant: f.tenant, Subject: "application-user", Roles: map[string]bool{"APPLICATION_OWNER": true}}
		if err := authorizeMutationReplay(ctx, tx, i, "/v1/schedules/replay-schedule/pause", nil); err != nil {
			return err
		}
		err := f.roles["api"].Do(ctx, f.tenant, func(other *store.Tx) error {
			if _, err := other.Exec(ctx, "SET LOCAL lock_timeout='200ms'"); err != nil {
				return err
			}
			w, err := other.Get(ctx, "workloads", "replay-workload")
			if err != nil {
				return err
			}
			w["owner"] = "different-owner"
			_, err = other.Update(ctx, "workloads", "replay-workload", model.Number(w, "version"), w)
			return err
		})
		var blocked *pgconn.PgError
		if !errors.As(err, &blocked) || blocked.Code != "55P03" {
			return fmt.Errorf("owner update escaped replay authorization guard: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.request("schedules/replay-schedule/pause", `"1"`, "owner-pause-once", owner, model.Document{"paused": true}); code != 200 {
		t.Fatal("ownership guard did not release after replay transaction", code)
	}
}

func TestMutationReplayAuthorizationDoesNotRevokeOwnedRestoration(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	stop := model.Operation{Type: "EC2_STOP", ResourceID: "owned-resource", ProviderResourceID: "i-fixture-" + model.ID(), AccountID: "111122223333", Region: "eu-west-1"}
	start := stop
	start.Type = "EC2_START"
	plan := model.Plan{ID: model.ID(), TenantID: f.tenant, WorkloadID: "replay-workload", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now.Add(-48 * time.Hour), StopAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-47 * time.Hour), Operations: []model.Operation{stop, start}}
	envelope, err := safety.Sign(plan, private)
	if err != nil {
		t.Fatal(err)
	}
	execution := model.ID()
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, err := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": plan.ID, "workload_id": plan.WorkloadID, "status": "RESTORING"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = f.roles["signer"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		raw, _ := json.Marshal(envelope)
		_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", f.tenant, plan.ID, plan.Nonce, raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Explicit test-owned fixture ownership models a stop already dispatched by
	// this occurrence. It is not a shortcut to any new STOP authorization.
	if err = f.roles["executor"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		raw, _ := json.Marshal(model.Document{"state": "stopped", "nonce": plan.Nonce})
		_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,true,$4)", f.tenant, execution, stop.AccountID+":"+stop.Region+":"+stop.ProviderResourceID, raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	path, key := "executions/"+execution+"/start-now", "owned-restoration-once"
	owner := f.token(f.tenant, "application-user", "APPLICATION_OWNER")
	if code, _, _ := f.request(path, `"1"`, key, owner, model.Document{}); code != 202 {
		t.Fatal("owned restoration request incorrectly required current stop readiness", code)
	}
	f.update("org", f.tenant, func(d model.Document) { d["paused"] = true })
	f.update("workloads", plan.WorkloadID, func(d model.Document) { d["owner"] = "different-owner" })
	if code, _, _ := f.request(path, `"1"`, key, owner, model.Document{}); code != 403 {
		t.Fatal("former owner read cached execution response", code)
	}
	if code, _, _ := f.request(path, `"1"`, key, f.token(f.tenant+"-foreign", "application-user", "PLATFORM_ADMIN"), model.Document{}); code != 404 {
		t.Fatal("foreign tenant borrowed cached execution", code)
	}
	service := &SecureService{Store: f.roles["executor"], Config: Config{Fixture: true, Role: "executor"}, Public: public}
	state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "START"})
	if err != nil || state.State != "running" {
		t.Fatal("current API authorization revoked owned recovery", state, err)
	}
	for n := 0; n < 2; n++ {
		state, err = service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "HEALTH"})
		if err != nil || state.Healthy {
			t.Fatal("restoration health consumed before persisted stabilization", state, err)
		}
	}
	time.Sleep(2100 * time.Millisecond)
	state, err = service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "HEALTH"})
	if err != nil || !state.Healthy {
		t.Fatal("owned recovery did not finish independently", state, err)
	}
	var restored bool
	if err = f.roles["executor"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, "SELECT restored FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", f.tenant, execution).Scan(&restored)
	}); err != nil || !restored {
		t.Fatal("owned restoration proof not retained", err)
	}
	audit, events := f.counts()
	if code, out, _ := f.request(path, `"1"`, key, f.token(f.tenant, "application-user", "PLATFORM_ADMIN"), model.Document{}); code != 202 || model.Number(out, "version") != 2 {
		t.Fatal("authorized reconciliation reran expired occurrence or ETag", code, out)
	}
	if gotAudit, gotEvents := f.counts(); gotAudit != audit || gotEvents != events {
		t.Fatal("authorized reconciliation dispatched or emitted another restoration request")
	}
}
