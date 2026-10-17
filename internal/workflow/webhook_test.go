package workflow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWebhookConfigurationFailsBeforeDelivery(t *testing.T) {
	for _, c := range []struct {
		name, url, secret string
		fixture           bool
	}{{"empty-key", "https://example.test/hooks", "", false}, {"insecure-live", "http://example.test/hooks", "test-key", false}, {"credentials-in-url", "https://user:password@example.test/hooks", "test-key", false}, {"fragment", "https://example.test/hooks#fragment", "test-key", true}, {"invalid", "not-a-url", "test-key", true}} {
		t.Run(c.name, func(t *testing.T) {
			a := &Activities{Config: service.Config{WebhookURL: c.url, WebhookSecret: c.secret, Fixture: c.fixture}}
			if e := deliverOutbox(context.Background(), a, nil); e == nil {
				t.Fatal("unsafe webhook configuration was accepted")
			}
		})
	}
	if e := deliverOutbox(context.Background(), &Activities{}, nil); e != nil {
		t.Fatal("unconfigured webhook should be disabled", e)
	}
}
func TestSignedWebhookTenantEnvelopeRetryAndDelivery(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to a disposable PostgreSQL admin database")
	}
	ctx := context.Background()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "webhook-" + model.ID()
	secret := "test-webhook-only-secret"
	var mu sync.Mutex
	var bodies [][]byte
	var ids, signatures []string
	redirect := false
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		destinationCalls++
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		ids = append(ids, r.Header.Get("Idempotency-Key"))
		signatures = append(signatures, r.Header.Get("X-Autopilot-Signature"))
		count := len(bodies)
		isRedirect := redirect
		mu.Unlock()
		if isRedirect {
			w.Header().Set("Location", destination.URL)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if count == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	a := &Activities{Store: db, Config: service.Config{Fixture: true, WebhookURL: server.URL, WebhookSecret: secret}, HTTP: server.Client()}
	workerTx := func(fn func(*store.Tx) error) error {
		return db.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_worker"); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	if e = workerTx(func(tx *store.Tx) error {
		return tx.Event(ctx, "execution.completed", model.Document{"execution_id": "execution-test", "status": "COMPLETED"})
	}); e != nil {
		t.Fatal(e)
	}
	deliver := func() {
		t.Helper()
		if e := workerTx(func(tx *store.Tx) error { return deliverOutbox(ctx, a, tx) }); e != nil {
			t.Fatal(e)
		}
	}
	state := func() (int, bool) {
		t.Helper()
		var attempts int
		var delivered bool
		if e := workerTx(func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT attempts,delivered_at IS NOT NULL FROM outbox WHERE tenant_id=$1 ORDER BY created_at LIMIT 1", tenant).Scan(&attempts, &delivered)
		}); e != nil {
			t.Fatal(e)
		}
		return attempts, delivered
	}
	ready := func() {
		t.Helper()
		if e := workerTx(func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "UPDATE outbox SET next_attempt=now()-interval '1 second' WHERE tenant_id=$1", tenant)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	deliver()
	if n, done := state(); n != 1 || done {
		t.Fatalf("failed receiver must retain pending retry: attempts=%d delivered=%v", n, done)
	}
	// A queued retry is not sent before next_attempt.
	deliver()
	mu.Lock()
	calls := len(bodies)
	mu.Unlock()
	if calls != 1 {
		t.Fatal("retry ignored next_attempt")
	}
	ready()
	deliver()
	if n, done := state(); n != 2 || !done {
		t.Fatalf("successful delivery not recorded: attempts=%d delivered=%v", n, done)
	}
	deliver()
	mu.Lock()
	if len(bodies) != 2 {
		t.Fatalf("delivered event was sent again: %d", len(bodies))
	}
	for n, b := range bodies {
		var event model.Document
		if e = json.Unmarshal(b, &event); e != nil {
			t.Fatal(e)
		}
		if model.String(event, "tenant_id") != tenant || model.String(event, "type") != "execution.completed" || model.String(event, "id") == "" || model.String(event, "id") != ids[n] {
			t.Fatalf("unbound event envelope: %v", event)
		}
		if strings.Contains(string(b), secret) {
			t.Fatal("secret entered delivery payload")
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(b)
		if signatures[n] != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("HMAC does not authenticate exact body")
		}
	}
	if ids[0] != ids[1] || string(bodies[0]) != string(bodies[1]) {
		t.Fatal("retry changed event identity or signed content")
	}
	redirect = true
	mu.Unlock()
	if e = workerTx(func(tx *store.Tx) error {
		return tx.Event(ctx, "rollback.completed", model.Document{"execution_id": "execution-redirect"})
	}); e != nil {
		t.Fatal(e)
	}
	deliver()
	mu.Lock()
	defer mu.Unlock()
	if destinationCalls != 0 {
		t.Fatal("webhook redirect forwarded signed payload to another destination")
	}
}
func TestIntegrationAndRestorationEventsEmitOnlyOnTransitions(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to a disposable PostgreSQL admin database")
	}
	ctx := context.Background()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "events-" + model.ID()
	for _, status := range []string{"DEGRADED", "DEGRADED", "HEALTHY", "HEALTHY"} {
		if e = db.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_ingester"); e != nil {
				return e
			}
			return recordIngestionQuality(ctx, tx, status)
		}); e != nil {
			t.Fatal(e)
		}
	}
	execution, resource := model.ID(), model.ID()
	if e = db.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": resource, "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": "i-event-test", "state": "stopped"}); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": model.ID(), "resource_id": resource, "status": "EXECUTING", "stage": "STOPPED", "restoration_owned": true})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	pc, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error { _, e := c.Exec(ctx, "SET ROLE finops_worker"); return e }
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	a := Activities{Store: &store.Store{Pool: pool}}
	input := model.WorkflowInput{TenantID: tenant, ExecutionID: execution}
	for _, stage := range []StageInput{{Input: input, Status: "RESTORING", Stage: "STARTING", Owned: true}, {Input: input, Status: "RESTORING", Stage: "STARTING", Owned: true}, {Input: input, Status: "RESTORING", Stage: "HEALTH_ALERT", Owned: false}, {Input: input, Status: "RESTORING", Stage: "HEALTH_ALERT", Owned: false}, {Input: input, Status: "COMPLETED", Stage: "VERIFY_ECONOMICS", Owned: false}, {Input: input, Status: "COMPLETED", Stage: "VERIFY_ECONOMICS", Owned: false}} {
		if e = a.Stage(ctx, stage); e != nil {
			t.Fatal(e)
		}
	}
	if e = db.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_worker"); e != nil {
			return e
		}
		for _, event := range []string{"integration.failed", "integration.recovered", "restoration.started", "restoration.completed", "execution.completed"} {
			var n int
			if e := tx.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE tenant_id=$1 AND event_type=$2", tenant, event).Scan(&n); e != nil {
				return e
			}
			if n != 1 {
				t.Errorf("%s emitted %d times instead of once", event, n)
			}
		}
		var leaked int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE tenant_id=$1 AND event_type LIKE 'integration.%' AND (payload ? 'error' OR payload::text LIKE '%test-webhook-only-secret%')", tenant).Scan(&leaked); e != nil {
			return e
		}
		if leaked != 0 {
			t.Error("integration payload exposed raw error or secret")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
