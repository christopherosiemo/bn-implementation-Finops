package store

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func newJointDecisionDBTest(t *testing.T) (*fleetHistoryDBTest, SelectionPair) {
	t.Helper()
	f, pair := newFleetCapacityDBTest(t)
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "037_fleet_joint_decisions.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "037_fleet_joint_decisions.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = f.admin.Migrate(f.ctx, dir); e != nil {
		var p *pgconn.PgError
		if errors.As(e, &p) {
			t.Fatalf("candidate migration SQLSTATE=%s position=%d internal_position=%d context=%s", p.Code, p.Position, p.InternalPosition, p.Where)
		}
		t.Fatal(e)
	}
	login := "joint_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e = f.admin.Pool.Exec(f.ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_decision"); e != nil {
		t.Fatal(e)
	}
	c := f.admin.Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))), Path: "/" + c.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	db, e := OpenRuntime(f.ctx, dsn.String(), "group-decision-reader")
	if e != nil {
		t.Fatal(e)
	}
	f.roles["finops_group_decision"] = db
	t.Cleanup(func() {
		db.Pool.Close()
		if _, e := f.admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	return f, pair
}

func TestJointDecisionRefusesUnassessedIDsAndHasNoAuthorityGrants(t *testing.T) {
	f, pair := newJointDecisionDBTest(t)
	assessment := fleetNativeRequest(t, f, pair)
	capacity := fleetCapacityRequest(t, f, pair)
	e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.FleetJointDecisionCreate(f.ctx, f.activity.WorkloadID, "actual-owner", model.String(assessment, "id"), model.String(capacity, "id"), 1)
		return e
	})
	if !errors.Is(e, ErrFleetJointDecision) {
		t.Fatal("unassessed inputs were admitted or wrong error class", e)
	}
	f.must("finops_group_decision", func(tx *Tx) error {
		pending, e := tx.FleetJointDecisionPending(f.ctx, "", 100)
		if e != nil {
			return e
		}
		if len(pending) != 0 {
			return errors.New("refused request acquired queue row")
		}
		for _, table := range []string{"native_capacity_results", "fleet_native_assessments", "fleet_native_capacity_members", "source_receipts", "savings_ledger"} {
			var allowed bool
			if e = tx.QueryRow(f.ctx, `SELECT has_table_privilege(current_user,$1,'INSERT')`, "public."+table).Scan(&allowed); e != nil {
				return e
			}
			if allowed {
				return errors.New("analytical join writer acquired other writer authority")
			}
		}
		var broad bool
		if e = tx.QueryRow(f.ctx, `SELECT has_table_privilege(current_user,'public.source_receipts','SELECT')`).Scan(&broad); e != nil {
			return e
		}
		if broad {
			return errors.New("join role acquired broad raw-source reader")
		}
		return nil
	})
	for _, role := range []string{"finops_api", "finops_group_assessor", "finops_group_capacity", "finops_signer", "finops_executor", "finops_ingester"} {
		f.denied(role, func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_joint_decisions(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,'not-issued','not-issued',$2,$2,'{}','{}')`, f.tenant, strings.Repeat("a", 64))
			return e
		})
	}
	f.must("finops_group_decision", func(tx *Tx) error {
		_, e := tx.FleetJointDecisionPage(f.ctx, f.activity.WorkloadID, "", 102)
		if !errors.Is(e, ErrConflict) {
			return errors.New("unbounded page accepted")
		}
		return nil
	})
}
