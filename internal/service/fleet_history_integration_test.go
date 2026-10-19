package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
)

// This is a real HTTP handler/JWKS/PostgreSQL test with independently
// authenticated restricted API/ingester roles. The issuer is a local RSA/JWKS
// double, not a claim of customer identity commissioning. Historical activity
// is never backfilled; the selected fourteen-day scope honestly remains missing.
func TestFleetHistoryAuthenticatedAPISealsOnlyServerSelectedBlockedScopes(t *testing.T) {
	admin, roles := financialSourceTestDatabase(t)
	ctx := context.Background()
	tenant := "history-http-" + model.ID()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "history-test"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "history-test", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	validator, e := auth.New(ctx, "https://history-issuer.invalid/realms/test", "finops", jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	api := &API{Store: roles["api"], Auth: validator, Config: Config{Fixture: true}}
	token := func(ten, subject, role string) string {
		v, e := jwt.Signed(signer).Claims(map[string]any{"iss": "https://history-issuer.invalid/realms/test", "aud": "finops", "sub": subject, "tenant_id": ten, "exp": time.Now().Add(time.Hour).Unix(), "realm_access": map[string]any{"roles": []string{role}}}).Serialize()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	request := func(method, path, etag, idem, bearer string, in model.Document) (int, model.Document) {
		t.Helper()
		var raw []byte
		if in != nil {
			raw, e = json.Marshal(in)
			if e != nil {
				t.Fatal(e)
			}
		}
		r := httptest.NewRequest(method, "/v1/"+path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+bearer)
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		if idem != "" {
			r.Header.Set("Idempotency-Key", idem)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		out := model.Document{}
		if e = json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal("API returned non-JSON", w.Code)
		}
		return w.Code, out
	}
	owner := token(tenant, "platform", "PLATFORM_ADMIN")
	viewer := token(tenant, "viewer", "VIEWER")
	assigned := token(tenant, "app-owner", "APPLICATION_OWNER")
	unassigned := token(tenant, "unassigned", "APPLICATION_OWNER")
	foreign := token(tenant+"-other", "platform", "PLATFORM_ADMIN")
	src := source.FixtureRegistration(tenant, "history-native")
	activity := store.ActivitySource{ID: "external-completed", WorkloadID: "history-workload", ResourceID: "history-resource", ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://independent-machine.invalid", Subject: "orders-collector", MetricDefinition: store.ActivityMetric{ID: "committed-orders", Version: "native-v1", Unit: "completed_orders"}, Enabled: true}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": activity.WorkloadID, "owner": "app-owner", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "other-workload", "owner": "someone-else"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": activity.ResourceID, "workload_id": activity.WorkloadID, "provider": "AWS", "provider_resource_id": activity.ProviderResourceID, "account_id": activity.AccountID, "region": activity.Region}); e != nil {
			return e
		}
		if _, e := tx.SourceCreate(ctx, src); e != nil {
			return e
		}
		_, e := tx.ActivityRegister(ctx, activity)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = roles["ingester"].Do(ctx, tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, "history-native", "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(src), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); e != nil {
		t.Fatal(e)
	}
	registration := model.Document{"workload_id": activity.WorkloadID, "fleet_id": "orders-fleet", "asg_arn": "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/orders", "source_connection_id": "history-native", "cadence_seconds": 60, "max_gap_seconds": 90}
	busySource := func(fn func()) {
		connection, e := admin.Pool.Acquire(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer connection.Release()
		key := tenant + ":trusted-source:history-native"
		var held bool
		if e = connection.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&held); e != nil || !held {
			t.Fatal("isolated source synchronization guard unavailable", e)
		}
		defer func() {
			_, _ = connection.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", key)
		}()
		fn()
	}
	if status, _ := request("POST", "fleet-history-registrations", `"0"`, "", owner, registration); status != 400 {
		t.Fatal("missing idempotency accepted", status)
	}
	if status, _ := request("POST", "fleet-history-registrations", "", "history-missing-cas", owner, registration); status != 428 {
		t.Fatal("missing CAS accepted", status)
	}
	if status, _ := request("POST", "fleet-history-registrations", `"0"`, "history-viewer-denied", viewer, registration); status != 403 {
		t.Fatal("viewer could register history", status)
	}
	busySource(func() {
		if code, body := request("POST", "fleet-history-registrations", `"0"`, "history-registration-once", owner, registration); code != 503 || model.String(body, "error") != "FLEET_HISTORY_SOURCE_BUSY" {
			t.Fatal("registration borrowed currentness during source synchronization", code, body)
		}
	})
	status, registered := request("POST", "fleet-history-registrations", `"0"`, "history-registration-once", owner, registration)
	if status != 201 {
		t.Fatal("native registration failed", status, registered)
	}
	regID := model.String(registered, "id")
	if regID == "" || model.Number(registered, "version") != 1 {
		t.Fatal("server did not issue registry identity")
	}
	status, replay := request("POST", "fleet-history-registrations", `"0"`, "history-registration-once", owner, registration)
	if status != 201 || model.String(replay, "id") != regID || model.String(replay, "hash") != model.String(registered, "hash") {
		t.Fatal("idempotent HTTP replay created a new registration")
	}
	for _, role := range []string{"FINOPS_ADMIN", "APPROVER", "APPLICATION_OWNER", "FINANCE"} {
		downgraded := token(tenant, "platform", role)
		if status, _ := request("POST", "fleet-history-registrations", `"0"`, "history-registration-once", downgraded, registration); status != 403 {
			t.Fatal("idempotent response bypassed current platform role", role, status)
		}
	}
	changed := model.Clone(registration)
	changed["cadence_seconds"] = 30
	if status, _ := request("POST", "fleet-history-registrations", `"0"`, "history-registration-once", owner, changed); status != 409 {
		t.Fatal("same idempotency key accepted changed body", status)
	}
	for _, field := range []string{"members", "complete", "trusted", "tenant_id", "source_config_hash"} {
		bad := model.Clone(registration)
		bad[field] = true
		if status, _ := request("POST", "fleet-history-registrations", `"0"`, "history-upload-"+field, owner, bad); status != 422 {
			t.Fatal("caller-supplied evidence accepted", field, status)
		}
	}
	wrongAccount := model.Clone(registration)
	wrongAccount["asg_arn"] = strings.Replace(model.String(registration, "asg_arn"), "111122223333", "999900001111", 1)
	if status, _ := request("POST", "fleet-history-registrations", `"0"`, "history-wrong-native-account", owner, wrongAccount); status != 422 {
		t.Fatal("unapproved source account did not fail as typed unavailable", status)
	}
	if status, _ := request("POST", "fleet-history-registrations/"+regID+"/revisions", `"0"`, "history-stale-version", owner, registration); status != 409 {
		t.Fatal("stale registry revision accepted", status)
	}
	if status, _ := request("GET", "fleet-history-registrations/"+regID, "", "", foreign, nil); status != 404 {
		t.Fatal("foreign tenant registration readable", status)
	}
	if status, _ := request("GET", "fleet-history-registrations/"+regID, "", "", unassigned, nil); status != 403 {
		t.Fatal("unassigned application owner could read workload", status)
	}
	if status, _ := request("GET", "fleet-history-registrations/"+regID, "", "", assigned, nil); status != 200 {
		t.Fatal("assigned application owner could not inspect history", status)
	}
	definitionRequest := model.Document{"registration_id": regID, "activity_source_id": activity.ID, "business_operation": "order_committed", "semantic_contract_id": "orders-meaning-v1", "semantic_contract_hash": strings.Repeat("a", 64)}
	status, definition := request("POST", "fleet-demand-definitions", `"0"`, "history-definition-once", owner, definitionRequest)
	if status != 201 {
		t.Fatal("independent demand definition failed", status, definition)
	}
	defID := model.String(definition, "id")
	d := evidence.Object(definition["definition"])
	if model.String(d, "metric") != "activity.Completed" || model.String(d, "unit") != "completed_orders" || d["source_registration_version"] != nil {
		t.Fatal("server invented demand metric/unit/registry version", d)
	}
	badDefinition := model.Clone(definitionRequest)
	badDefinition["completed"] = 100
	if status, _ := request("POST", "fleet-demand-definitions", `"0"`, "history-forged-count", owner, badDefinition); status != 422 {
		t.Fatal("public completed counts became evidence", status)
	}
	// A genuinely current guarded zero is accepted by its dedicated activity
	// process. It cannot become fourteen days of historical observed zero.
	login := "history_activity_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-history-http-" + login
	if _, e = admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_activity"); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	var activityDB *store.Store
	t.Cleanup(func() {
		if activityDB != nil {
			activityDB.Pool.Close()
		}
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("activity test login cleanup ownership mismatch")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("activity test login cleanup failed", e)
		}
	})
	activityURL, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	activityURL.User = url.UserPassword(login, password)
	activityDB, e = store.OpenRuntime(ctx, activityURL.String(), "activity-ingress")
	if e != nil {
		t.Fatal(e)
	}
	end := time.Now().UTC().Truncate(time.Minute)
	in := store.ActivityInterval{SchemaVersion: "1", SourceID: activity.ID, WorkloadID: activity.WorkloadID, ResourceID: activity.ResourceID, Sequence: 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, MetricDefinition: activity.MetricDefinition, Completed: 0, Accepted: 0, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
	raw, _ := json.Marshal(in)
	if e = activityDB.Do(ctx, tenant, func(tx *store.Tx) error {
		_, _, e := tx.ActivityAppend(ctx, store.ActivitySubmission{Interval: in, RawBody: raw, Issuer: activity.Issuer, Subject: activity.Subject, IdempotencyKey: "history-current-zero"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	selection := model.Document{"registration_id": regID, "definition_id": defID, "definition_version": 1}
	if status, _ := request("POST", "fleet-history-scopes", `"1"`, "history-wrong-def-version", owner, model.Document{"registration_id": regID, "definition_id": defID, "definition_version": 2}); status != 409 {
		t.Fatal("stale definition selection accepted", status)
	}
	busySource(func() {
		if code, body := request("POST", "fleet-history-scopes", `"1"`, "history-scope-once", owner, selection); code != 503 || model.String(body, "error") != "FLEET_HISTORY_SOURCE_BUSY" {
			t.Fatal("scope read borrowed currentness during in-flight synchronization", code, body)
		}
	})
	// The failed transaction leaves no half-sealed scope or idempotency reply;
	// retrying the same key after source synchronization is safe.
	status, scope := request("POST", "fleet-history-scopes", `"1"`, "history-scope-once", owner, selection)
	if status != 201 {
		t.Fatal("server-selected scope failed", status, scope)
	}
	if model.String(scope, "status") != "BLOCKED" || model.String(scope, "membership_status") != "INTERVAL_OWNERSHIP_UNPROVEN" {
		t.Fatal("current point became historical completeness", scope)
	}
	demand := evidence.Object(scope["demand"])
	start, e := time.Parse(time.RFC3339Nano, model.String(scope, "start"))
	if e != nil {
		t.Fatal(e)
	}
	finish, e := time.Parse(time.RFC3339Nano, model.String(scope, "end"))
	if e != nil || finish.Sub(start) != 14*24*time.Hour || finish.Hour() != 0 || finish.Minute() != 0 {
		t.Fatal("public request changed historical range")
	}
	// At exactly UTC midnight the real just-completed minute belongs to the
	// previous complete day. Preserve that genuine zero if selected; never
	// require a test-only clock or turn it into a fourteen-day zero population.
	wantCount := int64(0)
	if !in.IntervalStart.Before(start) && !in.IntervalEnd.After(finish) {
		wantCount = 1
	}
	if model.Number(scope, "demand_receipt_count") != wantCount || demand["window_units"] != nil {
		t.Fatal("historical range selected invented or complete workload", demand)
	}
	if wantCount == 0 && demand["observed_units"] != nil || wantCount == 1 && model.String(demand, "observed_units") != "0" {
		t.Fatal("missing and genuinely observed zero were conflated", demand)
	}
	if model.String(scope, "reference_root") == "" || model.String(scope, "input_hash") == "" || model.String(scope, "analysis_hash") == "" {
		t.Fatal("scope lacks immutable selected population roots")
	}
	if status, again := request("POST", "fleet-history-scopes", `"1"`, "history-scope-once", owner, selection); status != 201 || model.String(again, "id") != model.String(scope, "id") {
		t.Fatal("scope idempotency changed physical snapshot")
	}
	for _, field := range []string{"start", "as_of", "samples", "source_states", "complete"} {
		bad := model.Clone(selection)
		bad[field] = true
		if status, _ := request("POST", "fleet-history-scopes", `"1"`, "history-scope-upload-"+field, owner, bad); status != 422 {
			t.Fatal("public scope accepted authoritative arrays/times", field, status)
		}
	}
	scopeID := model.String(scope, "id")
	status, page := request("GET", "fleet-history-scopes/"+scopeID+"/references?limit=1", "", "", owner, nil)
	if status != 200 || len(evidence.Rows(page["items"])) != 1 || model.String(page, "next_cursor") == "" {
		t.Fatal("bounded reference page/cursor missing", status, page)
	}
	cursor := model.String(page, "next_cursor")
	if status, _ := request("GET", "fleet-history-scopes/"+scopeID+"/references?limit=1&cursor="+cursor, "", "", owner, nil); status != 200 {
		t.Fatal("same-query cursor could not advance", status)
	}
	if status, _ := request("GET", "fleet-history-scopes/"+scopeID+"/references?limit=1&kind=REGISTRATION&cursor="+cursor, "", "", owner, nil); status != 422 {
		t.Fatal("cursor borrowed another reference selection", status)
	}
	for _, after := range []string{"not-an-ordinal", "-1", "9223372036854775808", "50001"} {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		var forged map[string]any
		if err != nil || json.Unmarshal(raw, &forged) != nil {
			t.Fatal("test could not read issued opaque cursor")
		}
		forged["After"] = after
		raw, _ = json.Marshal(forged)
		invalid := base64.RawURLEncoding.EncodeToString(raw)
		if code, body := request("GET", "fleet-history-scopes/"+scopeID+"/references?limit=1&cursor="+invalid, "", "", owner, nil); code != 422 || model.String(body, "error") != "CURSOR_INVALID" {
			t.Fatal("invalid reference ordinal was reported as a server capacity failure", after, code, body)
		}
	}
	if status, _ := request("GET", "fleet-history-scopes/"+scopeID, "", "", unassigned, nil); status != 403 {
		t.Fatal("unassigned owner read immutable snapshot", status)
	}
	// Deactivation changes a NEW snapshot and cannot rewrite the old root or
	// allow a new native registration to borrow a previously healthy checkpoint.
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		s, e := tx.SourceGet(ctx, "history-native")
		if e != nil {
			return e
		}
		s["enabled"] = false
		_, e = tx.SourceUpdate(ctx, "history-native", model.Number(s, "version"), s)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if status, _ := request("POST", "fleet-history-registrations", `"0"`, "history-revoked-new", owner, registration); status != 422 {
		t.Fatal("revoked source should be typed unavailable", status)
	}
	status, newScope := request("POST", "fleet-history-scopes", `"1"`, "history-revoked-scope", owner, selection)
	if status != 201 || model.String(newScope, "input_hash") == model.String(scope, "input_hash") {
		t.Fatal("new scope reused former active source", status, newScope)
	}
	status, oldScope := request("GET", "fleet-history-scopes/"+scopeID, "", "", owner, nil)
	if status != 200 || model.String(oldScope, "hash") != model.String(scope, "hash") {
		t.Fatal("source revocation rewrote captured history")
	}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		for _, table := range []string{"signed_plans", "savings_ledger"} {
			var n int
			if e := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n); e != nil {
				return e
			}
			if n != 0 {
				return fmt.Errorf("observational API created %s authority", table)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
