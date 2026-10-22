package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// This is an actual restricted-role PostgreSQL upgrade regression. The retained
// historical stopped observation is a fixture dependency double; no AWS call,
// process restart, API restart or native group reconstruction is claimed.
func TestGroupNativeUpgrade032To033PreservesSignedR1OwnedRestoration(t *testing.T) {
	admin, roles := fleetFixtureHTTPDatabase(t) // Own marked child DB, initially <=029.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	migrations := t.TempDir()
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		if name > "032_group_artifacts.sql" {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(migrations, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = admin.Migrate(ctx, migrations); err != nil {
		t.Fatal("owned pre-upgrade schema", err)
	}
	// Only unique test-owned logins receive memberships. Existing shared role
	// memberships and the main database are never modified.
	for _, process := range []string{"signer", "executor"} {
		login, password, marker := "native_upgrade_"+strings.ReplaceAll(model.ID(), "-", ""), model.ID()+model.ID(), "owned-native-upgrade-"+model.ID()
		identifier := pgx.Identifier{login}.Sanitize()
		setup, err := admin.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = setup.Exec(ctx, "CREATE ROLE "+identifier+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{"finops_" + process}.Sanitize()); err == nil {
			_, err = setup.Exec(ctx, "COMMENT ON ROLE "+identifier+" IS '"+marker+"'")
		}
		if err != nil {
			_ = setup.Rollback(ctx)
			t.Fatal("owned upgrade login", err)
		}
		if err = setup.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var runtime *store.Store
		t.Cleanup(func() {
			if runtime != nil {
				runtime.Pool.Close()
			}
			var actual string
			if err := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); err != nil || actual != marker {
				t.Error("upgrade login cleanup ownership mismatch")
				return
			}
			if _, err := admin.Pool.Exec(context.Background(), "DROP ROLE "+identifier); err != nil {
				t.Error("upgrade login cleanup", err)
			}
		})
		u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
		if err != nil {
			t.Fatal("owned upgrade administrator URL invalid")
		}
		u.Path = "/" + admin.Pool.Config().ConnConfig.Database
		u.User = url.UserPassword(login, password)
		runtime, err = store.OpenRuntime(ctx, u.String(), process)
		if err != nil {
			t.Fatal("restricted upgrade runtime", process, err)
		}
		roles[process] = runtime
	}
	tenant, sourceID := "native-upgrade-"+model.ID(), "pre-upgrade-source"
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if err := tx.Seed(ctx, true); err != nil {
			return err
		}
		_, err := tx.SourceCreate(ctx, source.FixtureRegistration(tenant, sourceID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	executor := SecureService{Store: roles["executor"], Config: Config{Fixture: true, Role: "executor"}, Public: public}
	type occurrence struct {
		envelope     model.Envelope
		execution    string
		signed, body []byte
	}
	rows := []occurrence{}
	persist := func(p model.Plan, owned bool) occurrence {
		t.Helper()
		envelope, err := safety.Sign(p, private)
		if err != nil {
			t.Fatal(err)
		}
		o := occurrence{envelope: envelope, execution: model.ID()}
		if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.Create(ctx, "executions", model.Document{"id": o.execution, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "status": "RESTORING"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
			raw, _ := json.Marshal(envelope)
			_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, raw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if owned {
			if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
				raw, _ := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce, "stopped_at": p.StopAt.Format(time.RFC3339Nano)})
				op := p.Operations[0]
				_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,true,$4)", tenant, o.execution, op.AccountID+":"+op.Region+":"+op.ProviderResourceID, raw)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		return o
	}
	now := time.Now().UTC()
	for _, schema := range []string{"", "2", "3"} {
		op := model.Operation{Type: "EC2_STOP", ResourceID: "resource-dev-api", ProviderResourceID: "i-upgrade-" + model.ID(), AccountID: "111122223333", Region: "eu-west-1"}
		start := op
		start.Type = "EC2_START"
		p := model.Plan{SchemaVersion: schema, ID: model.ID(), TenantID: tenant, WorkloadID: "workload-dev", Nonce: model.ID(), Fixture: true, RiskClass: "R1", ScheduleID: "schedule-dev", CreatedAt: now.Add(-48 * time.Hour), StopAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-47 * time.Hour), BaselineID: "historical-unavailable", MeasurementID: "historical-unavailable", ProofSetID: "historical-unavailable", Operations: []model.Operation{op, start}}
		o := persist(p, true)
		if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
			if err := tx.QueryRow(ctx, "SELECT envelope FROM signed_plans WHERE tenant_id=$1 AND plan_id=$2", tenant, p.ID).Scan(&o.signed); err != nil {
				return err
			}
			return tx.QueryRow(ctx, "SELECT document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2 AND stop_intent AND stop_owned AND NOT restored", tenant, o.execution).Scan(&o.body)
		}); err != nil {
			t.Fatal("pre-upgrade durable signed ownership", err)
		}
		rows = append(rows, o)
	}
	checksums := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		rs, err := admin.Pool.Query(ctx, "SELECT filename,sha256 FROM schema_migrations ORDER BY filename")
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		for rs.Next() {
			var name, hash string
			if err = rs.Scan(&name, &hash); err != nil {
				t.Fatal(err)
			}
			out[name] = hash
		}
		if err = rs.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := checksums()
	if _, exists := before["033_group_native_reconstruction.sql"]; exists {
		t.Fatal("033 was applied before signed ownership")
	}
	upgrade := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "033_group_native_reconstruction.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(upgrade, "033_group_native_reconstruction.sql"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = admin.Migrate(ctx, upgrade); err != nil {
		t.Fatal("032 to033 actual upgrade", err)
	}
	after := checksums()
	hash := sha256.Sum256(raw)
	if len(after) != len(before)+1 || after["033_group_native_reconstruction.sql"] != hex.EncodeToString(hash[:]) {
		t.Fatal("upgrade history did not append exactly033")
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatal("upgrade modified prior applied checksum", name)
		}
	}
	for _, o := range rows {
		if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
			var signed, body []byte
			if err := tx.QueryRow(ctx, "SELECT envelope FROM signed_plans WHERE tenant_id=$1 AND plan_id=$2", tenant, o.envelope.Plan.ID).Scan(&signed); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, "SELECT document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2 AND stop_intent AND stop_owned AND NOT restored", tenant, o.execution).Scan(&body); err != nil {
				return err
			}
			if !bytes.Equal(signed, o.signed) || !bytes.Equal(body, o.body) {
				return errors.New("upgrade rewrote signed plan or owned observation")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		org, err := tx.Get(ctx, "org", tenant)
		if err != nil {
			return err
		}
		org["paused"] = true
		if _, err = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org); err != nil {
			return err
		}
		d, err := tx.SourceGet(ctx, sourceID)
		if err != nil {
			return err
		}
		d["enabled"], d["revoked"] = false, true
		_, err = tx.SourceUpdate(ctx, sourceID, model.Number(d, "version"), d)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		_, err := currentSourceGate(ctx, tx, sourceID, model.Document{"payer_account_id": "111122223333", "account_id": "111122223333"}, time.Now().UTC())
		return err
	}); err == nil || err.Error() != "SOURCE_REVOKED" {
		t.Fatal("source invalidation was not active", err)
	}
	for _, o := range rows {
		t.Run("schema-"+o.envelope.Plan.SchemaVersion, func(t *testing.T) {
			state, err := executor.dispatch(ctx, model.Dispatch{Envelope: o.envelope, ExecutionID: o.execution, Operation: "START"})
			if err != nil || state.State != "running" {
				t.Fatal("upgrade/pause/expiry/revocation blocked owned START", state, err)
			}
			if _, err = executor.dispatch(ctx, model.Dispatch{Envelope: o.envelope, ExecutionID: o.execution, Operation: "START"}); err != nil {
				t.Fatal("owned START replay", err)
			}
			var starts int
			if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
				return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='provider.start' AND document->'details'->>'execution_id'=$2", tenant, o.execution).Scan(&starts)
			}); err != nil || starts != 1 {
				t.Fatal("owned START replay dispatched again", starts, err)
			}
			for i := 0; i < 2; i++ {
				s, err := executor.dispatch(ctx, model.Dispatch{Envelope: o.envelope, ExecutionID: o.execution, Operation: "HEALTH"})
				if err != nil || s.Healthy || s.Reason != "RESTORATION_HEALTH_PENDING" {
					t.Fatal("recovery skipped persisted stabilization", s, err)
				}
			}
			timer := time.NewTimer(2100 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			s, err := executor.dispatch(ctx, model.Dispatch{Envelope: o.envelope, ExecutionID: o.execution, Operation: "HEALTH"})
			if err != nil || !s.Healthy {
				t.Fatal("actual fixture stabilization did not complete", s, err)
			}
			fresh := o.envelope.Plan
			fresh.ID, fresh.Nonce = model.ID(), model.ID()
			fresh.CreatedAt, fresh.StopAt = time.Now().UTC(), time.Now().UTC()
			fresh.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
			unowned := persist(fresh, false)
			_, err = executor.dispatch(ctx, model.Dispatch{Envelope: unowned.envelope, ExecutionID: unowned.execution, Operation: "STOP"})
			var blocked *Problem
			if !errors.As(err, &blocked) || blocked.Code != "BLOCKED_AUTOPILOT_PAUSED" {
				t.Fatal("upgrade widened new STOP authority", err)
			}
			_, err = executor.dispatch(ctx, model.Dispatch{Envelope: unowned.envelope, ExecutionID: unowned.execution, Operation: "START"})
			if !errors.As(err, &blocked) || blocked.Code != "RESTORATION_NOT_OWNED" {
				t.Fatal("upgrade invented unowned restoration", err)
			}
		})
	}
}
