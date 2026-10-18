package deploymentobserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const observerIntegrationIssuer = "https://pipeline.example.invalid"
const observerIntegrationAudience = "finops-deployment-observer"

type observerProtocolFixture struct {
	t        *testing.T
	ctx      context.Context
	admin    *store.Store
	observer *store.Store
	tenant   string
	login    string
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
}

// This test owns a fresh database and a random, non-superuser LOGIN whose only
// membership is finops_deployment_observer. It never changes shared credentials
// or migrates the caller's TEST_DATABASE_URL database. Explicitly copying 001–016
// keeps later draft migrations outside this frozen protocol acceptance slice.
func newObserverProtocolFixture(t *testing.T) *observerProtocolFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	rootConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid TEST_DATABASE_URL")
	}
	root, err := pgx.ConnectConfig(ctx, rootConfig)
	if err != nil {
		t.Fatal("cannot connect to disposable PostgreSQL administrator")
	}
	t.Cleanup(func() { _ = root.Close(context.Background()) })
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, login := "observer_http_"+suffix, "observer_login_"+suffix
	if _, err = root.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal("cannot create isolated observer database", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, e := root.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
			t.Error("cannot remove test-owned observer database", e)
		}
	})
	adminPoolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated database configuration")
	}
	adminPoolConfig.ConnConfig.Database = database
	adminPool, err := pgxpool.NewWithConfig(ctx, adminPoolConfig)
	if err != nil {
		t.Fatal("cannot connect to isolated observer database")
	}
	t.Cleanup(adminPool.Close)
	admin := &store.Store{Pool: adminPool}
	dir := t.TempDir()
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	copied := 0
	for _, file := range files {
		name := filepath.Base(file)
		if len(name) < 4 || name[3] != '_' {
			continue
		}
		number, e := strconv.Atoi(name[:3])
		if e != nil || number < 1 || number > 16 {
			continue
		}
		body, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), body, 0600); e != nil {
			t.Fatal(e)
		}
		copied++
	}
	if copied != 16 {
		t.Fatalf("expected frozen migrations 001–016, found %d", copied)
	}
	// Migrate can provision production LOGIN secrets when explicitly configured;
	// this isolated test must never invoke that optional shared-role operation.
	for _, role := range []string{"API", "WORKER", "SIGNER", "EXECUTOR", "INGESTER", "ACTIVITY", "TELEMETRY_READER", "TELEMETRY_INGRESS", "DEPLOYMENT_OBSERVER"} {
		t.Setenv("DB_"+role+"_PASSWORD", "")
	}
	if err = admin.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		t.Fatal("cannot generate test-owned observer credential")
	}
	password := hex.EncodeToString(secret)
	if _, err = root.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN IN ROLE finops_deployment_observer NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
		t.Fatal("cannot create test-owned observer login", err)
	}
	t.Cleanup(func() {
		if _, e := root.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("cannot remove test-owned observer login", e)
		}
	})
	observerConfig := adminPoolConfig.Copy()
	observerConfig.ConnConfig.User, observerConfig.ConnConfig.Password = login, password
	observerConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, e := conn.Exec(ctx, "SET ROLE finops_deployment_observer")
		return e
	}
	observerPool, err := pgxpool.NewWithConfig(ctx, observerConfig)
	if err != nil {
		t.Fatal("cannot create restricted observer pool")
	}
	t.Cleanup(observerPool.Close)
	var current, session string
	var superuser, bypass bool
	if err = observerPool.QueryRow(ctx, "SELECT current_user,session_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user").Scan(&current, &session, &superuser, &bypass); err != nil {
		t.Fatal("cannot authenticate test-owned observer login", err)
	}
	if current != "finops_deployment_observer" || session != login || superuser || bypass {
		t.Fatal("HTTP repository did not use the restricted observer identity")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	f := &observerProtocolFixture{t, ctx, admin, &store.Store{Pool: observerPool}, "observer-" + suffix, login, private, private.Public().(ed25519.PublicKey)}
	f.must("finops_api", func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO tenant_registry(tenant_id) VALUES($1)", f.tenant); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "workload_id": "workload", "provider": "AWS", "provider_resource_id": "asg-blue", "account_id": "111122223333", "region": "eu-west-1"})
		return e
	})
	return f
}

func (f *observerProtocolFixture) must(role string, fn func(*store.Tx) error) {
	f.t.Helper()
	if err := f.admin.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(f.ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
			return e
		}
		return fn(tx)
	}); err != nil {
		f.t.Fatal(err)
	}
}

func observerProtocolDocument(v any) model.Document {
	raw, _ := json.Marshal(v)
	var d model.Document
	_ = json.Unmarshal(raw, &d)
	return d
}

// These private API-owned proof documents deliberately test only the signed
// protocol boundary. They are NOT native factory provenance, billing evidence,
// a complete customer pipeline, or permission to enable a live R2 execution.
func (f *observerProtocolFixture) proof(kind, suffix string, b fleet.Binding, now time.Time) fleet.ProofRef {
	d := model.Document{"id": kind + suffix, "kind": kind, "version": "1", "binding": observerProtocolDocument(b), "expires_at": now.Add(5 * time.Hour), "source_refs": []any{model.Document{"table": "fixture-only-protocol-authority", "id": "not-live"}}}
	f.must("finops_api", func(tx *store.Tx) error {
		raw, _ := json.Marshal(d)
		_, e := tx.Exec(f.ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,$3,'1',$4,$5)", f.tenant, d["id"], kind, fleet.Digest(d), raw)
		return e
	})
	return fleet.ProofRef{Kind: kind, ID: model.String(d, "id"), Version: "1", SHA256: fleet.Digest(d), ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Hour)}
}

func (f *observerProtocolFixture) parent() (fleet.Envelope, string) {
	now, suffix := time.Now().UTC(), model.ID()
	p := fleet.Plan{
		SchemaVersion: "4", Kind: fleet.Kind, ID: "parent-" + suffix,
		Binding:   fleet.Binding{TenantID: f.tenant, ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "asg-blue", AccountID: "111122223333", Region: "eu-west-1"},
		CreatorID: "requester", Environment: "NON_PRODUCTION",
		IaC:        fleet.IaCBinding{Authority: "TERRAFORM", Repository: "https://github.com/customer/config", GitCommit: strings.Repeat("a", 40), Workspace: "sandbox", StateLineage: "state-lineage", StateSerial: 10, ConfigurationSHA256: strings.Repeat("b", 64), TerraformVersion: "1.13.3", PipelineID: "customer-pipeline"},
		Governance: fleet.Governance{RiskClass: "R2", Enabled: true, PolicyID: "policy", PolicyVersion: 1, PolicySHA256: strings.Repeat("c", 64), ApproverRole: fleet.ApproverRole},
		Old:        fleet.Cohort{ID: "asg-blue", ASGAddress: "aws_autoscaling_group.blue", LaunchTemplateAddress: "aws_launch_template.blue", LaunchTemplateVersion: 1, InstanceType: "m6i.4xlarge", DesiredCount: 20, Stateless: true},
		Candidate:  fleet.Cohort{ID: "asg-green", ASGAddress: "aws_autoscaling_group.green", LaunchTemplateAddress: "aws_launch_template.green", LaunchTemplateVersion: 2, InstanceType: "m6i.2xlarge", DesiredCount: 0, Stateless: true},
		Traffic:    fleet.TrafficControl{Authority: "CUSTOMER_TERRAFORM_PIPELINE", Address: "aws_lb_listener_rule.app", OldTargetGroupARN: "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/blue/id", CandidateTargetGroupARN: "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/green/id"},
		Budget:     fleet.Budget{BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 2, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, Currency: "GBP", MaximumCost: "48", OldInstanceHourlyCost: "0.4", CandidateInstanceHourlyCost: "0.2", MaximumDurationSeconds: 14400},
		CreatedAt:  now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Hour), Nonce: "parent-nonce-" + suffix,
	}
	for _, kind := range []string{"NATIVE_HISTORY", "CAPACITY_ASSESSMENT", "WORKLOAD_SAFETY_PROFILE", "CONFIGURATION_AUTHORITY", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "BILLING_PRICE"} {
		p.Proofs = append(p.Proofs, f.proof(kind, suffix, p.Binding, now))
	}
	p.Stages = fleet.DefaultStages(p, false)
	f.must("finops_api", func(tx *store.Tx) error { _, e := tx.FleetPlanCreate(f.ctx, p); return e })
	a := fleet.Approval{ID: model.ID(), TenantID: f.tenant, ActorID: "independent-approver", Role: fleet.ApproverRole, PlanSHA256: fleet.Digest(p), ApprovedAt: now}
	f.must("finops_api", func(tx *store.Tx) error { _, _, e := tx.FleetApprovalAppend(f.ctx, p.ID, a); return e })
	env, err := fleet.Sign(p, []fleet.Approval{a}, f.private, now)
	if err != nil {
		f.t.Fatal(err)
	}
	f.must("finops_signer", func(tx *store.Tx) error { _, _, e := tx.FleetEnvelopeAppend(f.ctx, env, f.public); return e })
	sourceID := "observer-" + suffix
	f.must("finops_api", func(tx *store.Tx) error {
		_, e := tx.FleetObserverRegister(f.ctx, model.Document{"id": sourceID, "pipeline_id": p.IaC.PipelineID, "issuer": observerIntegrationIssuer, "subject": "pipeline-observer", "audience": observerIntegrationAudience, "binding": observerProtocolDocument(p.Binding)})
		return e
	})
	return env, sourceID
}

func (f *observerProtocolFixture) child(p fleet.Envelope, stage int, sequence uint64, transition fleet.Transition) fleet.ChildEnvelope {
	now, suffix := time.Now().UTC(), model.ID()
	s := p.Plan.Stages[stage]
	iac := p.Plan.IaC
	iac.ConfigurationSHA256 = s.ConfigurationSHA256
	c := fleet.ChildPlan{SchemaVersion: "4", ID: "child-" + suffix, ParentID: p.Plan.ID, ParentSHA256: fleet.Digest(p.Plan), StageID: s.ID, StageSHA256: fleet.Digest(s), Sequence: sequence, Binding: p.Plan.Binding, IaC: iac, SavedPlanSHA256: fleet.BytesDigest([]byte(suffix)), PlanJSONSHA256: strings.Repeat("f", 64), Changes: []fleet.AllowedChange{}, Transition: transition, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "nonce-" + suffix}
	for _, kind := range []string{"NATIVE_CURRENT", "WORKLOAD_SAFETY_PROFILE", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "INCIDENT_STATE", "HEALTH_CHECK", "CANDIDATE_HEALTH"} {
		c.Proofs = append(c.Proofs, f.proof(kind, suffix, p.Plan.Binding, now))
	}
	env, err := fleet.SignChild(c, p, f.private, now)
	if err != nil {
		f.t.Fatal(err)
	}
	f.must("finops_signer", func(tx *store.Tx) error { _, _, e := tx.FleetChildAppend(f.ctx, env, f.public); return e })
	return env
}

func (f *observerProtocolFixture) authorize(execution string, child fleet.ChildEnvelope) model.Document {
	var command model.Document
	f.must("finops_worker", func(tx *store.Tx) error {
		var delivery bool
		var err error
		command, delivery, err = tx.FleetAuthorize(f.ctx, execution, child.Plan.ID, child.Plan.ID)
		if err == nil && !delivery {
			return errors.New("private fixture's initial dispatch was suppressed")
		}
		return err
	})
	return command
}

func observerProtocolBody(t *testing.T, child fleet.ChildEnvelope, command model.Document, outcome string) []byte {
	t.Helper()
	b := store.FleetCallback{SchemaVersion: "4", CommandID: model.String(command, "id"), ChildID: child.Plan.ID, ChildSHA256: fleet.Digest(child.Plan), SavedPlanSHA256: child.Plan.SavedPlanSHA256, ChildNonce: child.Plan.Nonce, StateLineage: child.Plan.IaC.StateLineage, BeforeStateSerial: child.Plan.IaC.StateSerial, AfterStateSerial: child.Plan.IaC.StateSerial + 1, Outcome: outcome, ObservedAt: time.Now().UTC(), OldInstanceIDs: []string{}, CandidateInstanceIDs: []string{}}
	for i := child.Plan.Transition.OldAfter; i > 0; i-- {
		b.OldInstanceIDs = append(b.OldInstanceIDs, fmt.Sprintf("i-%017x", i))
	}
	for i := child.Plan.Transition.CandidateAfter; i > 0; i-- {
		b.CandidateInstanceIDs = append(b.CandidateInstanceIDs, fmt.Sprintf("i-%017x", i+100))
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestObserverHTTPPostgresSignedJWKSIsolationReplayAndUnknownReservation(t *testing.T) {
	f := newObserverProtocolFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "observer-postgres-test"))
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "observer-postgres-test", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(jwks.Close)
	token := func(tenant, subject, audience string, roles ...string) string {
		t.Helper()
		value, e := jwt.Signed(signer).Claims(map[string]any{"iss": observerIntegrationIssuer, "aud": audience, "sub": subject, "tenant_id": tenant, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "roles": roles}).Serialize()
		if e != nil {
			t.Fatal("cannot sign observer test token")
		}
		return value
	}
	start := func() *httptest.Server {
		t.Helper()
		s, e := New(f.ctx, f.observer, observerIntegrationIssuer, observerIntegrationAudience, jwks.URL, true)
		if e != nil {
			t.Fatal(e)
		}
		h := httptest.NewServer(s.Handler())
		t.Cleanup(h.Close)
		return h
	}
	h := start()
	client := &http.Client{Timeout: 15 * time.Second}
	request := func(h *httptest.Server, command, source, idempotency, bearer string, raw []byte, expected int) model.Document {
		t.Helper()
		r, e := http.NewRequest(http.MethodPost, h.URL+"/v1/deployment-callbacks/"+command, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		r.Header.Set("Idempotency-Key", idempotency)
		r.Header.Set("X-Finops-Source-ID", source)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal("observer HTTP transport failed", e)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 128<<10))
		if e != nil {
			t.Fatal(e)
		}
		var out model.Document
		if e = json.Unmarshal(body, &out); e != nil {
			t.Fatal("observer returned invalid JSON")
		}
		if response.StatusCode != expected {
			t.Fatalf("observer HTTP status %d, expected %d (reason %s)", response.StatusCode, expected, model.String(out, "reason_code"))
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("observer receipt response was cacheable")
		}
		return out
	}
	parent, sourceID := f.parent()
	var execution model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		execution, _, e = tx.FleetExecutionCreate(f.ctx, parent.Plan.ID, "private-protocol-start")
		return e
	})
	machine := token(f.tenant, "pipeline-observer", observerIntegrationAudience)
	prepare := f.child(parent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	prepared := f.authorize(model.String(execution, "id"), prepare)
	request(h, model.String(prepared, "id"), sourceID, "prepare-noop", machine, observerProtocolBody(t, prepare, prepared, "NO_OP"), 201)
	child := f.child(parent, 1, 2, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	command := f.authorize(model.String(execution, "id"), child)
	commandID := model.String(command, "id")
	raw := observerProtocolBody(t, child, command, "UNKNOWN")
	t.Run("dedicated machine and tenant claims", func(t *testing.T) {
		for _, tc := range []struct {
			name, tenant, subject, audience, role string
			status                                int
		}{
			{"wrong-subject", f.tenant, "another-pipeline", observerIntegrationAudience, "", 403},
			{"wrong-tenant", f.tenant + "-other", "pipeline-observer", observerIntegrationAudience, "", 403},
			{"console-audience", f.tenant, "pipeline-observer", "finops", "", 401},
			{"missing-tenant", "", "pipeline-observer", observerIntegrationAudience, "", 401},
			{"owner", f.tenant, "pipeline-observer", observerIntegrationAudience, "ORGANISATION_OWNER", 401},
			{"approver", f.tenant, "pipeline-observer", observerIntegrationAudience, "FLEET_APPROVER", 401},
			{"viewer", f.tenant, "pipeline-observer", observerIntegrationAudience, "VIEWER", 401},
		} {
			t.Run(tc.name, func(t *testing.T) {
				request(h, commandID, sourceID, "rejected-identity", token(tc.tenant, tc.subject, tc.audience, tc.role), raw, tc.status)
			})
		}
		request(h, commandID, "not-registered", "missing-source", machine, raw, 403)
		var count int
		if e := f.admin.Pool.QueryRow(f.ctx, "SELECT count(*) FROM fleet_callbacks WHERE command_id=$1", commandID).Scan(&count); e != nil || count != 0 {
			t.Fatal("rejected machine identities reached receipt storage", e)
		}
	})
	created := request(h, commandID, sourceID, "uncertain-callback", machine, raw, 201)
	receipt := observerProtocolDocument(created["receipt"])
	if model.Bool(created, "replayed") || model.String(receipt, "writer_role") != "finops_deployment_observer" || model.String(receipt, "tenant_id") != f.tenant || model.String(receipt, "body_sha256") != fleet.BytesDigest(raw) {
		t.Fatal("authenticated receipt provenance was lost")
	}
	assertUnknown := func() {
		t.Helper()
		if e := f.observer.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
			var stored []byte
			if e := tx.QueryRow(f.ctx, "SELECT raw_body FROM fleet_callbacks WHERE id=$1", receipt["id"]).Scan(&stored); e != nil {
				return e
			}
			if !bytes.Equal(stored, raw) {
				return errors.New("authenticated raw callback bytes changed")
			}
			var flight int
			var active bool
			if e := tx.QueryRow(f.ctx, "SELECT in_flight,released_at IS NULL FROM fleet_reservations WHERE command_id=$1", commandID).Scan(&flight, &active); e != nil {
				return e
			}
			d, e := tx.FleetCommand(f.ctx, commandID)
			if e == nil && (flight != 2 || !active || model.String(d, "outcome") != "UNKNOWN" || !model.Bool(d, "dispatch_intent") || model.String(d, "owned_receipt_id") != "") {
				return errors.New("uncertainty lost its dispatch intent or two-slot reservation")
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	assertUnknown()
	t.Run("exact replay and conflict", func(t *testing.T) {
		replayed := request(h, commandID, sourceID, "uncertain-callback", machine, raw, 200)
		if !model.Bool(replayed, "replayed") || observerProtocolDocument(replayed["receipt"])["id"] != receipt["id"] {
			t.Fatal("exact retry created a new receipt")
		}
		request(h, commandID, sourceID, "uncertain-callback", machine, append(append([]byte{}, raw...), ' '), 409)
		request(h, commandID, sourceID, "uncertain-callback", token(f.tenant, "another-pipeline", observerIntegrationAudience), raw, 403)
		request(h, commandID, sourceID, "strict-callback", machine, []byte(`{"schema_version":"4","trusted":true}`), 422)
		assertUnknown()
	})
	t.Run("fresh server replays durable uncertainty without redispatch", func(t *testing.T) {
		h.Close()
		h = start()
		replayed := request(h, commandID, sourceID, "uncertain-callback", machine, raw, 200)
		if !model.Bool(replayed, "replayed") || observerProtocolDocument(replayed["receipt"])["id"] != receipt["id"] {
			t.Fatal("server restart lost immutable replay identity")
		}
		f.must("finops_worker", func(tx *store.Tx) error {
			_, delivery, e := tx.FleetAuthorize(f.ctx, model.String(execution, "id"), child.Plan.ID, child.Plan.ID)
			if e == nil && delivery {
				return errors.New("uncertain command was dispatched again")
			}
			return e
		})
		assertUnknown()
	})
	t.Run("RLS and observer has no approval execution or financial authority", func(t *testing.T) {
		if e := f.observer.Do(f.ctx, f.tenant+"-other", func(tx *store.Tx) error {
			var count int
			if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_callbacks").Scan(&count); e != nil {
				return e
			}
			if count != 0 {
				return errors.New("another tenant's receipts escaped forced RLS")
			}
			_, e := tx.FleetCommand(f.ctx, commandID)
			if !errors.Is(e, pgx.ErrNoRows) {
				return errors.New("another tenant's command escaped forced RLS")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		for _, table := range []string{"fleet_proof_sets", "fleet_plans", "fleet_approvals", "fleet_envelopes", "fleet_children", "fleet_executions", "fleet_commands", "fleet_health_evidence", "fleet_release_events", "provider_operations", "savings_ledger"} {
			e := f.observer.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
				_, e := tx.Exec(f.ctx, "INSERT INTO "+pgx.Identifier{table}.Sanitize()+" DEFAULT VALUES")
				return e
			})
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != "42501" {
				t.Fatalf("observer write to %s did not fail at the SQL privilege boundary", table)
			}
		}
		for _, sql := range []string{"UPDATE fleet_command_states SET dispatch_intent=false", "UPDATE fleet_reservations SET released_at=clock_timestamp()", "SET ROLE finops_api", "SET ROLE finops_signer", "SET ROLE finops_worker"} {
			e := f.observer.Do(f.ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.Exec(f.ctx, sql); return e })
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != "42501" {
				t.Fatal("observer obtained state-mutation or another service's authority")
			}
		}
		assertUnknown()
	})
	t.Run("APPLIED callback records ownership but cannot release budget", func(t *testing.T) {
		out := request(h, commandID, sourceID, "eventually-applied", machine, observerProtocolBody(t, child, command, "APPLIED"), 201)
		applied := observerProtocolDocument(out["receipt"])
		if e := f.observer.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
			d, e := tx.FleetCommand(f.ctx, commandID)
			if e == nil && (model.String(d, "outcome") != "APPLIED" || model.String(d, "owned_receipt_id") != model.String(applied, "id") || d["reservation_released_at"] != nil) {
				return errors.New("APPLIED callback released budget before independent health")
			}
			var count int
			if e == nil {
				e = tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_callbacks WHERE command_id=$1", commandID).Scan(&count)
			}
			if e == nil && count != 2 {
				return errors.New("rejected or replayed callbacks inserted extra immutable rows")
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
	})
}
