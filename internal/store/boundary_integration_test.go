package store

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"os"
	"strings"
	"testing"
)

func TestIngestionAndApprovalDatabaseTrustBoundary(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL requires a disposable administrator database")
	}
	ctx := context.Background()
	s, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Pool.Close()
	if e = s.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "boundary-" + model.ID()
	if e = s.Do(ctx, tenant, func(tx *Tx) error {
		if e := tx.Seed(ctx, false); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "state": "running", "configuration_authority": "TERRAFORM"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	run := func(role string, fn func(*Tx) error) error {
		return s.Do(ctx, tenant, func(tx *Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	if e = run("finops_ingester", func(tx *Tx) error {
		_, e := tx.Create(ctx, "data_quality", model.Document{"id": "ingest", "status": "HEALTHY"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_ingester", func(tx *Tx) error {
		p, e := tx.Get(ctx, "policies", "policy-default")
		if e != nil {
			return e
		}
		p["mode"] = "AUTOPILOT"
		_, e = tx.Update(ctx, "policies", "policy-default", model.Number(p, "version"), p)
		return e
	}); e == nil {
		t.Fatal("ingestion identity changed execution policy")
	}
	if e = run("finops_worker", func(tx *Tx) error {
		_, e := tx.Create(ctx, "approvals", model.Document{"approved_by": "forged-human", "change_plan_id": "forged"})
		return e
	}); e == nil {
		t.Fatal("worker forged a human approval")
	}
	if e = run("finops_worker", func(tx *Tx) error {
		r, e := tx.Get(ctx, "resources", "resource")
		if e != nil {
			return e
		}
		r["runtime_stop_start_delegated"] = true
		_, e = tx.Update(ctx, "resources", "resource", model.Number(r, "version"), r)
		return e
	}); e == nil {
		t.Fatal("worker changed resource authority")
	}
	if e = run("finops_worker", func(tx *Tx) error {
		r, e := tx.Get(ctx, "resources", "resource")
		if e != nil {
			return e
		}
		r["state"] = "stopped"
		r["last_seen_at"] = model.Now()
		_, e = tx.Update(ctx, "resources", "resource", model.Number(r, "version"), r)
		return e
	}); e != nil {
		t.Fatalf("legitimate workflow state transition blocked: %v", e)
	}
	if e = run("finops_api", func(tx *Tx) error {
		_, e := tx.Create(ctx, "approvals", model.Document{"id": "human-approval", "approved_by": "actual-user", "change_plan_id": "plan"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_signer", func(tx *Tx) error {
		var writer string
		if e := tx.QueryRow(ctx, "SELECT writer_role FROM entities WHERE tenant_id=$1 AND kind='approvals' AND id='human-approval'", tenant).Scan(&writer); e != nil {
			return e
		}
		if writer != "finops_api" {
			t.Errorf("wrong unforgeable approval provenance %s", writer)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_worker", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document) VALUES($1,'fake','fake','fake','{}')", tenant)
		return e
	}); e == nil {
		t.Fatal("execution worker forged financial evidence")
	} else if !strings.Contains(e.Error(), "permission denied") {
		t.Fatalf("unexpected evidence denial: %v", e)
	}
}
