package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual restricted PG and JWT/JWKS regression. No native history, money,
// artificial clock, production test gate or historical CI causality claim.
func TestFleetConfigurationJWTSourceBusyRetryRechecksFreshBindings(t *testing.T) {
	f, _ := newFleetFixtureHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const zero, one, two = "\"0\"", "\"1\"", "\"2\""
	platform := f.token(f.tenant, "contention-operator", "PLATFORM_ADMIN")
	src := source.FixtureRegistration(f.tenant, "contention-source")
	activity := store.ActivitySource{
		ID: "contention-activity", WorkloadID: "fixture-workload", ResourceID: "contention-resource",
		ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1",
		Issuer: "https://independent-machine.invalid", Subject: "fixture-business-collector",
		MetricDefinition: store.ActivityMetric{ID: "committed-orders", Version: "1", Unit: "completed_orders"}, Enabled: true,
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "resources", model.Document{"id": activity.ResourceID, "workload_id": activity.WorkloadID,
			"provider": "AWS", "provider_resource_id": activity.ProviderResourceID, "account_id": activity.AccountID, "region": activity.Region}); err != nil {
			return err
		}
		if _, err := tx.SourceCreate(ctx, src); err != nil {
			return err
		}
		_, err := tx.ActivityRegister(ctx, activity)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	must := func(path, tag, key string, body model.Document) model.Document {
		t.Helper()
		code, out, _ := f.request(path, tag, key, platform, body)
		if code != http.StatusCreated {
			t.Fatal("fixture API setup", path, code, model.String(out, "error"))
		}
		return out
	}
	registration := must("fleet-history-registrations", zero, "contention-register", model.Document{
		"workload_id": activity.WorkloadID, "fleet_id": "contention-group",
		"asg_arn":              "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/contention-group",
		"source_connection_id": src["id"], "cadence_seconds": 60, "max_gap_seconds": 120,
	})
	registrationID := model.String(registration, "id")
	definition := must("fleet-demand-definitions", zero, "contention-definition", model.Document{
		"registration_id": registrationID, "activity_source_id": activity.ID, "business_operation": "fixture-declared completed orders",
		"semantic_contract_id": "contention-contract", "semantic_contract_hash": strings.Repeat("c", 64),
	})
	scope := must("fleet-history-scopes", one, "contention-scope", model.Document{
		"registration_id": registrationID, "definition_id": definition["id"], "definition_version": definition["version"],
	})
	if model.Number(scope, "selected_observation_count") != 0 || model.String(scope, "status") != "BLOCKED" ||
		model.String(scope, "membership_status") != "INTERVAL_OWNERSHIP_UNPROVEN" {
		t.Fatal("scope was not genuinely empty and blocked")
	}
	metadata := model.Document{
		"schema_version": "1", "authority": "TERRAFORM",
		"repository": model.Document{"url": "https://github.com/example/fixture", "ref": "main", "directory": "infra/api"},
		"pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{
			"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer",
			"subject": "repo:example/fixture:ref:refs/heads/main", "pipeline_id": "fixture-contention-declaration",
		}},
		"terraform": model.Document{"workspace": "development", "state_lineage": "12345678-1234-1234-1234-123456789abc",
			"asg_address": "module.api.aws_autoscaling_group.api", "launch_template_address": "module.api.aws_launch_template.api"},
	}
	base := "fleet-history-registrations/" + registrationID
	declarations, proposals := base+"/configuration-authorities", base+"/configuration-proposals"
	first := must(declarations, zero, "contention-declaration-1", metadata)
	metadata["repository"] = model.Document{"url": "https://github.com/example/fixture", "ref": "fixture-review", "directory": "infra/api"}
	declaration := must(declarations, one, "contention-declaration-2", metadata)
	if model.Number(first, "version") != 1 || model.Number(declaration, "version") != 2 {
		t.Fatal("actual declaration CAS revisions differ")
	}
	selection := model.Document{"declaration_id": declaration["id"], "scope_id": scope["id"]}
	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("private isolated administrator config")
	}
	cfg.ConnConfig.Database = f.roles["api"].Pool.Config().ConnConfig.Database
	if !strings.HasPrefix(cfg.ConnConfig.Database, "fixture_http_") {
		t.Fatal("marked child database required")
	}
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	apiLogin := f.roles["api"].Pool.Config().ConnConfig.User
	raw, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		code       int
		body       model.Document
		retryAfter string
	}
	post := func(key string) result {
		r := httptest.NewRequest(http.MethodPost, "/v1/"+proposals, bytes.NewReader(raw)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+platform)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("If-Match", two)
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		var body model.Document
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			return result{code: w.Code}
		}
		return result{w.Code, body, w.Header().Get("Retry-After")}
	}
	guard := func() *store.Tx {
		t.Helper()
		tx, err := f.roles["ingester"].Begin(ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", f.tenant+":trusted-source:"+model.String(src, "id")); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	launch := func(key string) (time.Time, <-chan result) {
		t.Helper()
		var start time.Time
		if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&start); err != nil {
			t.Fatal(err)
		}
		ch := make(chan result, 1)
		go func() { ch <- post(key) }()
		return start, ch
	}
	rolledBack := func(start time.Time, ch <-chan result) {
		t.Helper()
		witnessCtx, stop := context.WithTimeout(ctx, fleetConfigurationBusyBudget)
		defer stop()
		for {
			var observed bool
			// The API login and child DB are unique to this fixture; only this
			// request is active. A new idle ROLLBACK witnesses a completed real
			// transaction before the retry delay, never a simulated source error.
			if err := admin.QueryRow(witnessCtx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND usename=$2 AND state='idle' AND lower(query)='rollback' AND state_change>$3)", cfg.ConnConfig.Database, apiLogin, start).Scan(&observed); err != nil {
				t.Fatal("actual rollback witness", err)
			}
			if observed {
				return
			}
			select {
			case done := <-ch:
				t.Fatal("request finished before a real busy rollback was witnessed", done.code)
			case <-witnessCtx.Done():
				t.Fatal("actual rollback witness timed out")
			case <-time.After(2 * time.Millisecond):
			}
		}
	}
	countKey := func(key string) int {
		t.Helper()
		var n int
		if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM idempotency WHERE tenant_id=$1 AND key=$2", f.tenant, key).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The guard remains held beyond the complete bounded retry interval.
	held := guard()
	auditBefore, outboxBefore := f.counts()
	before := time.Now()
	exhausted := post("perpetually-busy-key")
	busyElapsed := time.Since(before)
	if exhausted.code != 503 || model.String(exhausted.body, "error") != "FLEET_HISTORY_SOURCE_BUSY" || exhausted.retryAfter != "1" {
		t.Fatal("perpetual contention did not return typed503", exhausted.code, model.String(exhausted.body, "error"))
	}
	if countKey("perpetually-busy-key") != 0 {
		t.Fatal("busy exhaustion retained partial idempotency")
	}
	if audit, outbox := f.counts(); audit != auditBefore || outbox != outboxBefore {
		t.Fatal("busy exhaustion retained audit/outbox writes")
	}
	if err = held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Release only after the real first attempt has rolled back.
	held = guard()
	start, response := launch("released-during-request")
	rolledBack(start, response)
	if err = held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	published := <-response
	if published.code != 201 || model.String(published.body, "status") != "BLOCKED" || published.body["execution_authorized"] != false ||
		published.body["estimated_saving"] != nil || published.body["verified_saving"] != nil || published.body["change_plan_id"] != nil {
		t.Fatal("guard release did not publish exactly blocked metadata", published.code, model.String(published.body, "error"))
	}
	if countKey("released-during-request") != 1 {
		t.Fatal("successful retry lacks one idempotency record")
	}
	auditPublished, outboxPublished := f.counts()
	replayed := post("released-during-request")
	if replayed.code != 201 || model.String(replayed.body, "id") != model.String(published.body, "id") ||
		model.String(replayed.body, "hash") != model.String(published.body, "hash") {
		t.Fatal("retry replay duplicated metadata", replayed.code)
	}
	if audit, outbox := f.counts(); audit != auditPublished || outbox != outboxPublished {
		t.Fatal("retry replay duplicated audit/outbox")
	}

	// A separately authorized config writer takes the graph fence after the
	// failed attempt. Its changed binding commits before a fresh retry can read.
	held = guard()
	start, response = launch("changed-during-busy-request")
	rolledBack(start, response)
	change, err := f.roles["api"].Begin(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = change.Rollback(context.Background()) }()
	if _, err = change.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", f.tenant+":dependency-graph"); err != nil {
		t.Fatal(err)
	}
	if err = held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := change.SourceGet(ctx, model.String(src, "id"))
	if err != nil {
		t.Fatal(err)
	}
	current["prefix"] = "changed-config/"
	if _, err = change.SourceUpdate(ctx, model.String(src, "id"), model.Number(current, "version"), current); err != nil {
		t.Fatal(err)
	}
	if err = change.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	changed := <-response
	if changed.code != 422 || model.String(changed.body, "error") != "FLEET_CONFIGURATION_CURRENT_BINDING_REQUIRED" || changed.retryAfter != "" {
		t.Fatal("retry borrowed changed bindings", changed.code, model.String(changed.body, "error"))
	}
	if countKey("changed-during-busy-request") != 0 {
		t.Fatal("changed binding retained partial idempotency")
	}
	var proposalsCount int
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM fleet_configuration_proposals WHERE tenant_id=$1 AND registration_id=$2", f.tenant, registrationID).Scan(&proposalsCount)
	}); err != nil || proposalsCount != 1 {
		t.Fatal("failed attempts created extra proposals", err, proposalsCount)
	}
	t.Logf("actualPG: perpetual busy503 with Retry-After1 in%s; real rollback→release201/replay; real changed binding422; one immutable proposal and no partial idempotency/audit on failures", busyElapsed)
}
