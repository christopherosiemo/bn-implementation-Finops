package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// All migrations and fixture rows live in a newly created, comment-owned DB.
// TEST_DATABASE_URL supplies local test administration, never a schema to mutate.
func financialSourceTestDatabase(t *testing.T) (*store.Store, map[string]*store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL enables a separately owned disposable database")
	}
	ctx := context.Background()
	master, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal("private test administrator unavailable")
	}
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, owner := "financial_source_"+suffix, "finops-local-financial-source:"+suffix
	if _, err = master.Pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		master.Pool.Close()
		t.Fatal(err)
	}
	var admin *store.Store
	roles := map[string]*store.Store{}
	logins := []string{}
	t.Cleanup(func() {
		for _, role := range roles {
			if role != nil {
				role.Pool.Close()
			}
		}
		if admin != nil {
			admin.Pool.Close()
		}
		var comment string
		if err := master.Pool.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1", database).Scan(&comment); err != nil || comment != owner {
			t.Error("financial source DB cleanup ownership mismatch")
		} else if _, err := master.Pool.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("financial source DB cleanup failed")
		}
		for _, login := range logins {
			if err := master.Pool.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&comment); err != nil || comment != owner {
				t.Error("financial source login cleanup ownership mismatch")
			} else if _, err := master.Pool.Exec(ctx, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); err != nil {
				t.Error("financial source login cleanup failed")
			}
		}
		master.Pool.Close()
	})
	if _, err = master.Pool.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" IS '"+owner+"'"); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("private test administrator URL invalid")
	}
	parsed.Path = "/" + database
	admin, err = store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("owned financial source database unavailable")
	}
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"api", "worker", "signer", "executor", "ingester"} {
		login, password := "financial_"+role+"_"+suffix, model.ID()+model.ID()
		if _, err = master.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'"); err != nil {
			t.Fatal("owned financial source login creation failed")
		}
		logins = append(logins, login)
		if _, err = master.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+owner+"'"); err != nil {
			t.Fatal(err)
		}
		if _, err = master.Pool.Exec(ctx, "GRANT "+pgx.Identifier{"finops_" + role}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		roleURL := *parsed
		roleURL.User = url.UserPassword(login, password)
		roles[role], err = store.OpenRuntime(ctx, roleURL.String(), role)
		if err != nil {
			t.Fatal("dedicated financial source runtime rejected", role, err)
		}
	}
	return admin, roles
}

func TestFinancialSourceAuthoritySerializesRevocationAndPreservesOwnedStart(t *testing.T) {
	admin, roles := financialSourceTestDatabase(t)
	ctx := context.Background()
	tenant := "financial-lock-" + model.ID()
	now := time.Now().UTC()
	binding := model.Document{"payer_account_id": "111122223333", "account_id": "111122223333"}
	allowed := map[string]bool{"finops_api": true, "finops_worker": true, "finops_signer": true, "finops_executor": true}
	groups := []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_activity", "finops_telemetry_reader", "finops_telemetry_ingress", "finops_deployment_observer", "finops_hardware_reader", "finops_configuration_attestor", "finops_multicloud_ingester"}
	rows, err := admin.Pool.Query(ctx, "SELECT rolname,has_function_privilege(rolname,'public.financial_source_current_lock(text,text)','EXECUTE') FROM pg_roles WHERE rolname=ANY($1::text[])", groups)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var role string
		var canLock bool
		if err = rows.Scan(&role, &canLock); err != nil || canLock != allowed[role] {
			rows.Close()
			t.Fatal("financial row-lock helper crossed process identity", role, err)
		}
		seen++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	if seen != len(groups) {
		t.Fatal("financial source ACL did not cover all product process groups")
	}
	var publicExecute bool
	if err = admin.Pool.QueryRow(ctx, "SELECT coalesce(bool_or(a.grantee=0 AND a.privilege_type='EXECUTE'),false) FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='public.financial_source_current_lock(text,text)'::regprocedure").Scan(&publicExecute); err != nil || publicExecute {
		t.Fatal("financial source helper executable by PUBLIC", err)
	}
	if err = roles["ingester"].Do(ctx, tenant, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, "SELECT financial_source_current_lock($1,$2)", tenant, "absent-source")
		return err
	}); err == nil {
		t.Fatal("non-financial ingestion identity can invoke financial lock helper")
	} else {
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("ingester helper call was not rejected by function ACL", err)
		}
	}
	t.Run("missing-source-is-a-typed-blocker-with-a-usable-transaction", func(t *testing.T) {
		if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			for _, connection := range []string{"", "absent-source"} {
				err := holdTrustedSourceSnapshot(ctx, tx, connection)
				var blocked *Problem
				if err == nil || err.Error() != "TRUSTED_SOURCE_REQUIRED" || !errors.As(evidenceProblem(err), &blocked) || blocked.Status != 422 || blocked.Code != "TRUSTED_SOURCE_REQUIRED" {
					return fmt.Errorf("missing source did not remain a typed evidence blocker")
				}
				var usable bool
				if err := tx.QueryRow(ctx, "SELECT true").Scan(&usable); err != nil || !usable {
					return fmt.Errorf("missing source aborted readiness transaction")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("source-selection-lock-precedes-first-receipt-read", func(t *testing.T) {
		const sourceID = "selection-source"
		if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.SourceCreate(ctx, source.FixtureRegistration(tenant, sourceID))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		selectors := []struct {
			name, expected string
			selectSource   func(context.Context, *store.Tx) error
		}{
			{"selectedTrustedSource", "TRUSTED_SOURCE_REQUIRED", func(ctx context.Context, tx *store.Tx) error {
				_, _, err := selectedTrustedSource(ctx, tx, sourceID, nil)
				return err
			}},
			{"periodReceipts", "TRUSTED_SOURCE_PERIOD_REQUIRED", func(ctx context.Context, tx *store.Tx) error {
				_, err := periodReceipts(ctx, tx, sourceID, now.Add(-14*24*time.Hour), now)
				return err
			}},
		}
		for _, selector := range selectors {
			t.Run(selector.name, func(t *testing.T) {
				selectionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				table, err := admin.Pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer table.Rollback(ctx)
				if _, err = table.Exec(ctx, "LOCK TABLE source_receipts IN ACCESS EXCLUSIVE MODE"); err != nil {
					t.Fatal(err)
				}
				authority, err := roles["api"].Begin(selectionCtx, tenant)
				if err != nil {
					t.Fatal(err)
				}
				var backend int
				if err = authority.QueryRow(selectionCtx, "SELECT pg_backend_pid()").Scan(&backend); err != nil {
					_ = authority.Rollback(ctx)
					t.Fatal(err)
				}
				done := make(chan error, 1)
				finished := false
				go func() {
					err := selector.selectSource(selectionCtx, authority)
					_ = authority.Rollback(ctx)
					done <- err
				}()
				defer func() {
					cancel()
					_ = table.Rollback(ctx)
					if !finished {
						select {
						case <-done:
						case <-time.After(3 * time.Second):
							t.Error("owned selection goroutine did not terminate")
						}
					}
				}()
				// Confirm the private API transaction has actually reached its first
				// receipt SELECT, rather than relying on scheduler timing or sleeps.
				waiting := false
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if err = admin.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.source_receipts'::regclass AND mode='AccessShareLock' AND NOT granted)", backend).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !waiting {
					t.Fatal("selection never reached the blocked source receipt read")
				}
				sync, err := admin.Pool.Acquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer sync.Release()
				key := tenant + ":trusted-source:" + sourceID
				var available bool
				if err = sync.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&available); err != nil {
					t.Fatal(err)
				}
				if available {
					_, _ = sync.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key)
					t.Fatal("receipt-head selection preceded the shared source-sync guard")
				}
				if err = table.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-done:
					finished = true
				case <-selectionCtx.Done():
					t.Fatal("source selection did not complete after table release")
				}
				if err == nil || err.Error() != selector.expected {
					t.Fatal("empty source selection returned unexpected result", err)
				}
				if err = sync.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&available); err != nil || !available {
					t.Fatal("source-sync guard did not release at transaction completion", err)
				}
				if _, err = sync.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
	for _, role := range []string{"api", "worker", "signer", "executor"} {
		t.Run(role, func(t *testing.T) {
			sourceID := "source-" + role
			var registration model.Document
			if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
				var err error
				registration, err = tx.SourceCreate(ctx, source.FixtureRegistration(tenant, sourceID))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := roles["ingester"].Do(ctx, tenant, func(tx *store.Tx) error {
				if err := tx.SourceCheckpointSet(ctx, sourceID, "status", model.Document{"status": "HEALTHY", "last_sync_at": now.Format(time.RFC3339Nano)}); err != nil {
					return err
				}
				_, err := tx.SourceReceiptCreate(ctx, model.Document{"id": "commitment-" + role, "source_id": sourceID, "kind": "AWS_COMMITMENT", "config_hash": source.ConfigurationHash(registration), "commitment_scope": model.Document{"receipt_id": "commitment-" + role, "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0, "observed_at": now.Format(time.RFC3339Nano)}})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			authority, err := roles[role].Begin(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			defer authority.Rollback(ctx)
			if _, err = currentSourceGate(ctx, authority, sourceID, binding, now); err != nil {
				t.Fatal("valid current financial source unavailable", err)
			}
			revoke := func(timeout bool) error {
				return roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
					if timeout {
						if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='200ms'"); err != nil {
							return err
						}
					}
					d, err := tx.SourceGet(ctx, sourceID)
					if err != nil {
						return err
					}
					d["enabled"] = false
					_, err = tx.SourceUpdate(ctx, sourceID, model.Number(d, "version"), d)
					return err
				})
			}
			var pgError *pgconn.PgError
			if err = revoke(true); !errors.As(err, &pgError) || pgError.Code != "55P03" {
				t.Fatal("revocation committed while financial authority transaction held snapshot", err)
			}
			if err = authority.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = revoke(false); err != nil {
				t.Fatal("source revocation remained blocked after snapshot transaction", err)
			}
			if err = roles[role].Do(ctx, tenant, func(tx *store.Tx) error { _, err := currentSourceGate(ctx, tx, sourceID, binding, now); return err }); err == nil || err.Error() != "SOURCE_REVOKED" {
				t.Fatal("committed revocation did not block new authority", err)
			}
			if role != "api" {
				var canUpdate bool
				if err = roles[role].Pool.QueryRow(ctx, "SELECT has_table_privilege(current_user,'source_registrations','UPDATE')").Scan(&canUpdate); err != nil || canUpdate {
					t.Fatal("row lock granted source mutation privilege", err)
				}
			}
			if err = roles[role].Do(ctx, tenant, func(tx *store.Tx) error {
				_, err := tx.Exec(ctx, "SELECT financial_source_current_lock($1,$2)", "other-tenant", sourceID)
				return err
			}); err == nil {
				t.Fatal("row-lock helper accepted a foreign tenant")
			}
			if err = roles[role].Do(ctx, tenant, func(tx *store.Tx) error {
				var found bool
				if err := tx.QueryRow(ctx, "SELECT financial_source_current_lock($1,$2)", tenant, "absent-source").Scan(&found); err != nil {
					return err
				}
				if found {
					return errors.New("nonexistent source was reported as locked")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Seed only an already-owned recovery capability through the real signer and
	// executor identities. This deliberately grants no new STOP authority.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "org", model.Document{"id": tenant, "paused": true}); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "workloads", model.Document{"id": "owned-workload", "owner": "fixture", "environment": "NON_PRODUCTION"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sync, err := admin.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sync.Release()
	if _, err = sync.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", tenant+":trusted-source:source-executor"); err != nil {
		t.Fatal(err)
	}
	defer sync.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", tenant+":trusted-source:source-executor")
	for _, schema := range []string{"", "3"} {
		t.Run("owned-start-schema-"+schema, func(t *testing.T) {
			op := model.Operation{Type: "EC2_STOP", ResourceID: "owned-resource-" + schema, ProviderResourceID: "i-owned-" + schema, AccountID: "111122223333", Region: "eu-west-1"}
			start := op
			start.Type = "EC2_START"
			plan := model.Plan{ID: model.ID(), SchemaVersion: schema, TenantID: tenant, WorkloadID: "owned-workload", Nonce: model.ID(), Fixture: true, RiskClass: "R1", CreatedAt: now.Add(-48 * time.Hour), StopAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-47 * time.Hour), BaselineID: "historical-unavailable", MeasurementID: "historical-unavailable", ProofSetID: "historical-unavailable", Operations: []model.Operation{op, start}}
			envelope, err := safety.Sign(plan, private)
			if err != nil {
				t.Fatal(err)
			}
			execution := model.ID()
			if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
				_, err := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": plan.ID, "status": "RESTORING"})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
				body, _ := json.Marshal(envelope)
				_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, plan.ID, plan.Nonce, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
				body, _ := json.Marshal(model.Document{"state": "stopped", "nonce": plan.Nonce})
				_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,true,$4)", tenant, execution, op.AccountID+":"+op.Region+":"+op.ProviderResourceID, body)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			executor := SecureService{Store: roles["executor"], Config: Config{Fixture: true, Role: "executor"}, Public: public}
			state, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "START"})
			if err != nil || state.State != "running" {
				t.Fatal("source lock/revocation or stale financial authority blocked owned recovery", fmt.Sprint(err), state.State)
			}
		})
	}
}
