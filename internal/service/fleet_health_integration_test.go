package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fleetHealthProtocolTest struct {
	t      *testing.T
	ctx    context.Context
	db     *store.Store
	tenant string
}

// Only disposable protocol databases are created. No existing database is
// migrated/reset and no shared LOGIN secret is provisioned by these tests.
func newFleetHealthProtocolTest(t *testing.T) *fleetHealthProtocolTest {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	root, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("test PostgreSQL administrator unavailable")
	}
	t.Cleanup(func() { _ = root.Close(context.Background()) })
	name := "fleet_health_" + strings.ReplaceAll(model.ID(), "-", "")
	if _, err = root.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, e := root.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error("remove test-owned fleet database", e)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test PostgreSQL pool configuration")
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("isolated test PostgreSQL unavailable")
	}
	t.Cleanup(pool.Close)
	db := &store.Store{Pool: pool}
	dir := t.TempDir()
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, file := range files {
		base := filepath.Base(file)
		if len(base) < 4 || base[3] != '_' {
			continue
		}
		n, e := strconv.Atoi(base[:3])
		if e != nil || n < 1 || n > 18 && n != 22 {
			continue
		}
		raw, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, base), raw, 0600); e != nil {
			t.Fatal(e)
		}
		count++
	}
	if count != 19 {
		t.Fatal("explicit001–018 plus022 are required;019–021 are excluded")
	}
	snapshot, e := os.ReadFile(filepath.Join(dir, "018_fleet_cohort_health.sql"))
	if e != nil {
		t.Fatal(e)
	}
	guard, e := os.ReadFile(filepath.Join(dir, "022_fleet_forward_observation.sql"))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("private test snapshot copied001–018 plus022; immutable018 sha256=%s;022 sha256=%s;019–021 excluded", fleet.BytesDigest(snapshot), fleet.BytesDigest(guard))
	for _, role := range []string{"API", "WORKER", "SIGNER", "EXECUTOR", "INGESTER", "ACTIVITY", "TELEMETRY_READER", "TELEMETRY_INGRESS", "DEPLOYMENT_OBSERVER", "HARDWARE_READER"} {
		t.Setenv("DB_"+role+"_PASSWORD", "")
	}
	if err = db.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	return &fleetHealthProtocolTest{t, ctx, db, "fleet-health-" + model.ID()}
}
func (f *fleetHealthProtocolTest) run(role string, fn func(*store.Tx) error) error {
	return f.db.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.Exec(f.ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			return err
		}
		return fn(tx)
	})
}
func (f *fleetHealthProtocolTest) must(role string, fn func(*store.Tx) error) {
	f.t.Helper()
	if err := f.run(role, fn); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fleetHealthProtocolTest) member(minimum ...int64) (fleet.Binding, slo.Objective, slo.Source, time.Time, time.Time, []fleetSLOReceipt) {
	b, o, s, _, _, rows := fleetHealthWindowFixture(2)
	if len(minimum) > 0 {
		o.Limits.MinLatencySamples = minimum[0]
	}
	b.TenantID = f.tenant
	s.TenantID = f.tenant
	var objectiveDoc model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		if _, e := tx.Exec(f.ctx, "INSERT INTO tenant_registry(tenant_id) VALUES($1)", f.tenant); e != nil {
			return e
		}
		if _, e := tx.Create(f.ctx, "workloads", model.Document{"id": b.WorkloadID, "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		if _, e := tx.Create(f.ctx, "resources", model.Document{"id": b.ResourceID, "workload_id": b.WorkloadID, "provider": "AWS", "provider_resource_id": b.ProviderResourceID, "account_id": b.AccountID, "region": b.Region}); e != nil {
			return e
		}
		var e error
		objectiveDoc, e = tx.SLOObjectiveAppend(f.ctx, b.WorkloadID, 0, slo.Document(o))
		return e
	})
	var err error
	o, err = slo.ParseObjective(objectiveDoc)
	if err != nil {
		f.t.Fatal(err)
	}
	s.ObjectiveID = o.ID
	f.must("finops_api", func(tx *store.Tx) error { var e error; s, e = tx.SLORegister(f.ctx, s); return e })
	if remaining := time.Minute - time.Duration(time.Now().Second())*time.Second; remaining < 2*time.Second {
		time.Sleep(remaining + 100*time.Millisecond)
	}
	end := time.Now().UTC().Truncate(time.Minute)
	start := end.Add(-2 * time.Minute)
	for i := range rows {
		in := rows[i].Receipt.Interval
		in.SourceID, in.ObjectiveID = s.ID, o.ID
		in.IntervalStart, in.IntervalEnd = start.Add(time.Duration(i)*time.Minute), start.Add(time.Duration(i+1)*time.Minute)
		in.Sequence = in.IntervalEnd.Unix() / 60
		raw, _ := json.Marshal(in)
		f.must("finops_activity", func(tx *store.Tx) error {
			r, _, e := tx.SLOAppend(f.ctx, store.SLOSubmission{Interval: in, RawBody: raw, Issuer: s.Issuer, Subject: s.Subject, IdempotencyKey: "protocol-" + strconv.Itoa(i)})
			rows[i] = fleetSLOReceipt{r, raw}
			return e
		})
	}
	return b, o, s, start, end, rows
}

func TestFleetMemberSQLCannotAssertClearBelowExplicitLatencySampleMinimum(t *testing.T) {
	f := newFleetHealthProtocolTest(t)
	b, o, s, start, end, rows := f.member(3000)
	e := fleetBuildMemberWindow(b, o, s, start, end, time.Now().UTC(), rows)
	if e.Status != "BLOCKED" {
		t.Fatal("pure window ignored sample minimum")
	}
	e.Status, e.ReasonCodes = "CLEAR", []string{}
	e.Hash = fleetMemberEvaluationHash(e)
	e.Member.EvaluationID, e.Member.EvaluationSHA256 = "fleet-member-"+e.Hash, e.Hash
	if err := f.run("finops_api", func(tx *store.Tx) error { _, err := fleetHealthPersistMember(f.ctx, tx, e); return err }); err == nil {
		t.Fatal("API metadata bypassed explicit native sample minimum")
	}
}

func TestFleetMemberWindowPostgresOriginalReceiptsReplayAndWriterIsolation(t *testing.T) {
	f := newFleetHealthProtocolTest(t)
	b, o, s, start, end, rows := f.member()
	window := fleetBuildMemberWindow(b, o, s, start, end, time.Now().UTC(), rows)
	if window.Status != "CLEAR" {
		t.Fatal(window.ReasonCodes)
	}
	var stored model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		stored, e = fleetHealthPersistMember(f.ctx, tx, window)
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		again, e := fleetHealthPersistMember(f.ctx, tx, window)
		if e == nil && again["id"] != stored["id"] {
			return errors.New("member replay inserted a new immutable window")
		}
		return e
	})
	if model.String(stored, "writer_role") != "finops_api" {
		t.Fatal("untrusted writer published a member evaluation")
	}
	for name, mutate := range map[string]func(*fleetMemberEvaluation){
		"fabricated request count": func(e *fleetMemberEvaluation) { e.Member.RequestCount++ },
		"changed histogram":        func(e *fleetMemberEvaluation) { e.Member.LatencyBuckets[0].Count++; e.Member.LatencyBuckets[1].Count-- },
		"missing minute":           func(e *fleetMemberEvaluation) { e.Member.ReceiptIDs = e.Member.ReceiptIDs[1:] },
		"reused minute":            func(e *fleetMemberEvaluation) { e.Member.ReceiptIDs[1] = e.Member.ReceiptIDs[0] },
		"cross account":            func(e *fleetMemberEvaluation) { e.Member.Binding.AccountID = "999988887777" },
		"changed objective hash":   func(e *fleetMemberEvaluation) { e.Member.ObjectiveSHA256 = strings.Repeat("0", 64) },
		"hidden non-clear minute":  func(e *fleetMemberEvaluation) { e.MinuteChecks[0].Status = "BREACH" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed fleetMemberEvaluation
			if e := fleetHealthDecode(evidence.Object(window), &changed); e != nil {
				t.Fatal(e)
			}
			mutate(&changed)
			changed.Hash = fleetMemberEvaluationHash(changed)
			changed.Member.EvaluationID, changed.Member.EvaluationSHA256 = "fleet-member-"+changed.Hash, changed.Hash
			if e := f.run("finops_api", func(tx *store.Tx) error { _, e := fleetHealthPersistMember(f.ctx, tx, changed); return e }); e == nil {
				t.Fatal("API metadata replaced original per-minute receipt evidence")
			}
		})
	}
	for _, role := range []string{"finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_activity", "finops_telemetry_reader", "finops_telemetry_ingress", "finops_deployment_observer", "finops_hardware_reader"} {
		err := f.run(role, func(tx *store.Tx) error {
			_, e := tx.Exec(f.ctx, "INSERT INTO fleet_member_slo_windows DEFAULT VALUES")
			return e
		})
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("non-API role could publish a cohort member window", role)
		}
	}
	f.must("finops_api", func(tx *store.Tx) error {
		if _, e := tx.Exec(f.ctx, "SELECT set_config('app.tenant_id',$1,true)", f.tenant+"-other"); e != nil {
			return e
		}
		var n int
		if e := tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_member_slo_windows").Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return errors.New("full member windows escaped forced tenant RLS")
		}
		return nil
	})
	for _, sql := range []string{"UPDATE fleet_member_slo_windows SET document='{}'", "DELETE FROM fleet_member_slo_windows"} {
		if err := f.run("finops_api", func(tx *store.Tx) error { _, e := tx.Exec(f.ctx, sql); return e }); err == nil {
			t.Fatal("immutable member history was changed")
		}
	}
}

func TestFleetDurationDatabaseModelMatchesPureCommandAndObservationArithmetic(t *testing.T) {
	f := newFleetHealthProtocolTest(t)
	for _, cleanup := range []bool{false, true} {
		p := fleet.Plan{Budget: fleet.Budget{BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 2}}
		p.Stages = fleet.DefaultStages(p, cleanup)
		want, e := fleet.MinimumProgramDuration(p)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(p)
		f.must("finops_worker", func(tx *store.Tx) error {
			var got int64
			if e := tx.QueryRow(f.ctx, "SELECT fleet_cohort_minimum_program_seconds($1::jsonb)", raw).Scan(&got); e != nil {
				return e
			}
			if got != want {
				return errors.New("SQL and signed pure duration models differ")
			}
			return nil
		})
	}
}
