package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests use a new database and independently authenticated restricted
// logins. Native source transport/object bytes are explicit dependency fixtures;
// no AWS authentication, public upload, historical clock or main fixture is used.
type fleetHistoryDBTest struct {
	t            *testing.T
	ctx          context.Context
	admin        *Store
	roles        map[string]*Store
	tenant       string
	registration fleethistory.Registration
	definition   fleethistory.DemandDefinition
	activity     ActivitySource
}

func fleetHistoryDocument(v any) model.Document {
	raw, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(raw, &d)
	return d
}
func fleetHistoryHash(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func newFleetHistoryDBTest(t *testing.T) *fleetHistoryDBTest {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("test PostgreSQL unavailable")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := "fleet_history_" + strings.ReplaceAll(model.ID(), "-", "")
	marker := "owned-fleet-history-test-" + model.ID()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+marker+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var actual string
		if e := admin.QueryRow(context.Background(), "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=$1", name).Scan(&actual); e != nil || actual != marker || !strings.HasPrefix(name, "fleet_history_") {
			t.Error("test-owned database cleanup identity mismatch")
			return
		}
		if _, e := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error("remove only test-owned Fleet history database", e)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("test database configuration invalid")
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f := &fleetHistoryDBTest{t: t, ctx: ctx, admin: &Store{Pool: pool}, roles: map[string]*Store{}, tenant: "fleet-history-" + model.ID()}
	dir := t.TempDir()
	for _, file := range []string{"001_control_plane.sql", "002_ingestion_and_approval_boundary.sql", "005_trusted_sources.sql", "006_activity.sql", "025_fleet_history.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", file))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, file), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = f.admin.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"finops_api", "finops_ingester", "finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		login := "fh_" + strings.ReplaceAll(model.ID(), "-", "")
		password := model.ID()
		_, err = admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{group}.Sanitize())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, e := admin.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
				t.Error("remove only test-created login", e)
			}
		})
		roleCfg := cfg.Copy()
		roleCfg.ConnConfig.User, roleCfg.ConnConfig.Password = login, password
		roleCfg.ConnConfig.RuntimeParams = map[string]string{}
		roleCfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, e := c.Exec(ctx, "SET ROLE "+pgx.Identifier{group}.Sanitize())
			return e
		}
		rolePool, e := pgxpool.NewWithConfig(ctx, roleCfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(rolePool.Close)
		var user, current string
		var elevated bool
		if e = rolePool.QueryRow(ctx, "SELECT session_user,current_user,(SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=session_user)").Scan(&user, &current, &elevated); e != nil || user != login || current != group || elevated {
			t.Fatal("restricted authenticated role not established", e)
		}
		f.roles[group] = &Store{Pool: rolePool}
	}
	return f
}
func (f *fleetHistoryDBTest) run(role string, fn func(*Tx) error) error {
	return f.roles[role].Do(f.ctx, f.tenant, fn)
}
func (f *fleetHistoryDBTest) must(role string, fn func(*Tx) error) {
	f.t.Helper()
	if e := f.run(role, fn); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fleetHistoryDBTest) denied(role string, fn func(*Tx) error) {
	f.t.Helper()
	if e := f.run(role, fn); e == nil {
		f.t.Fatal("restricted mutation unexpectedly accepted", role)
	}
}

func (f *fleetHistoryDBTest) seedBindings() {
	f.t.Helper()
	f.activity = ActivitySource{ID: "completed-activity", WorkloadID: "workload-history", ResourceID: "resource-history", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.example.test", Subject: "completed-work-machine", MetricDefinition: ActivityMetric{ID: "orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	source := model.Document{"id": "inventory-history", "kind": "AWS_CUR2", "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "region": "eu-west-1", "export_arn": "arn:aws:bcm-data-exports:us-east-1:111122223333:export/fixture-export", "bucket": "finops-test-cur", "bucket_owner": "111122223333", "prefix": "cur/", "read_role_binding_id": "fixture-only-read", "enabled": true}
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Create(f.ctx, "workloads", model.Document{"id": f.activity.WorkloadID, "name": "History workload"}); e != nil {
			return e
		}
		if _, e := tx.Create(f.ctx, "resources", model.Document{"id": f.activity.ResourceID, "workload_id": f.activity.WorkloadID, "provider": "AWS", "provider_resource_id": f.activity.ProviderResourceID, "account_id": f.activity.AccountID, "region": f.activity.Region}); e != nil {
			return e
		}
		if _, e := tx.SourceCreate(f.ctx, source); e != nil {
			return e
		}
		_, e := tx.ActivityRegister(f.ctx, f.activity)
		return e
	})
	config := model.Document{}
	for _, key := range []string{"kind", "payer_account_id", "usage_account_ids", "region", "export_arn", "bucket", "bucket_owner", "prefix", "read_role_binding_id"} {
		config[key] = source[key]
	}
	binding := fleethistory.Binding{TenantID: f.tenant, WorkloadID: f.activity.WorkloadID, Provider: "AWS", AccountID: f.activity.AccountID, Region: f.activity.Region}
	f.registration = fleethistory.Registration{SchemaVersion: "1", ID: "history-registration", Version: 1, FleetID: "fleet-history", Binding: binding, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/history", SourceID: "inventory-history", SourceSystem: "AWS_SOURCE_CONNECTION", SourceRegistrationVersion: 1, SourceConfigHash: fleetHistoryHash(config), CadenceSeconds: 60, MaxGapSeconds: 90}
	f.definition = fleethistory.DemandDefinition{SchemaVersion: "1", ID: "history-completed-orders", Version: 1, Binding: binding, Aggregation: "SINGLE_EXTERNAL_TOTAL", Meaning: "COMPLETED_WORK", BusinessOperation: "order_committed", Unit: f.activity.MetricDefinition.Unit, Metric: "activity.Completed", MetricDefinitionID: f.activity.MetricDefinition.ID, MetricDefinitionVersion: f.activity.MetricDefinition.Version, ValueField: "COMPLETED", Origin: "INDEPENDENT_EXTERNAL_SYSTEM", SemanticContractID: "reviewed-orders", SemanticContractHash: strings.Repeat("b", 64), SourceID: f.activity.ID, SourceSystem: "ACTIVITY_SOURCE", SourceConfigHash: fleetHistoryHash(fleetHistoryDocument(f.activity)), Temporality: "DELTA", CadenceSeconds: 60, MaxGapSeconds: 90}
	f.must("finops_ingester", func(tx *Tx) error {
		return tx.SourceCheckpointSet(f.ctx, f.registration.SourceID, "status", model.Document{"status": "HEALTHY", "config_hash": f.registration.SourceConfigHash, "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	})
}

func (f *fleetHistoryDBTest) appendCurrentActivity(completed int64) ActivityReceipt {
	f.t.Helper()
	end := time.Now().UTC().Truncate(time.Minute)
	in := ActivityInterval{SchemaVersion: "1", SourceID: f.activity.ID, WorkloadID: f.activity.WorkloadID, ResourceID: f.activity.ResourceID, Sequence: 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, MetricDefinition: f.activity.MetricDefinition, Accepted: completed, Completed: completed, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
	raw, _ := json.Marshal(in)
	var receipt ActivityReceipt
	f.must("finops_activity", func(tx *Tx) error {
		var e error
		receipt, _, e = tx.ActivityAppend(f.ctx, ActivitySubmission{Interval: in, RawBody: raw, Issuer: f.activity.Issuer, Subject: f.activity.Subject, IdempotencyKey: "history-current"})
		return e
	})
	return receipt
}

func (f *fleetHistoryDBTest) register() {
	f.t.Helper()
	f.seedBindings()
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, f.registration); e != nil {
			return e
		}
		_, e := tx.FleetDemandDefinitionAppend(f.ctx, f.registration.ID, 0, f.definition)
		return e
	})
}

func (f *fleetHistoryDBTest) nativeObservation(suffix string, observed time.Time, members bool) fleethistory.MembershipObservation {
	f.t.Helper()
	id, revisionID := "membership-"+suffix, "native-revision-"+suffix
	groupMembers := []any{}
	observedMembers := []fleethistory.Member{}
	if members {
		groupMembers = append(groupMembers, model.Document{"instance_id": f.activity.ProviderResourceID, "launch_template": model.Document{"id": "lt-0123456789abcdef0", "version": "7"}})
		observedMembers = append(observedMembers, fleethistory.Member{InstanceID: f.activity.ProviderResourceID, LaunchTemplateID: "lt-0123456789abcdef0", LaunchTemplateVersion: 7, ResourceID: f.activity.ResourceID})
	}
	rawObject := model.Document{"bucket": "history-raw-fixture", "key": "tenant/" + f.tenant + "/history/" + id, "version_id": "version-" + suffix, "body_sha256": strings.Repeat("d", 64)}
	receipt := model.Document{"id": id, "kind": "AWS_FLEET_MEMBERSHIP", "source_id": f.registration.SourceID, "revision_id": revisionID, "registration_version": f.registration.SourceRegistrationVersion, "read_role_binding_id": "fixture-only-read", "config_hash": f.registration.SourceConfigHash, "binding": fleetHistoryDocument(f.registration.Binding), "collected_at": observed.Format(time.RFC3339Nano), "raw_object": rawObject, "groups": []any{model.Document{"name": "history", "arn": f.registration.ASGARN, "members": groupMembers}}}
	var persisted model.Document
	f.must("finops_ingester", func(tx *Tx) error {
		if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": revisionID, "source_id": f.registration.SourceID, "revision_hash": fleetHistoryHash(receipt), "kind": "AWS_FLEET_MEMBERSHIP", "config_hash": f.registration.SourceConfigHash, "registration_version": f.registration.SourceRegistrationVersion, "raw_object": rawObject}); e != nil {
			return e
		}
		if _, e := tx.SourceReceiptCreate(f.ctx, receipt); e != nil {
			return e
		}
		var e error
		persisted, e = tx.SourceReceiptGet(f.ctx, id)
		return e
	})
	var ref fleethistory.SourceRef
	f.must("finops_ingester", func(tx *Tx) error {
		var e error
		ref, e = tx.FleetHistorySourceReference(f.ctx, id, "AWS_FLEET_MEMBERSHIP", f.registration.ASGARN)
		return e
	})
	received, e := time.Parse(time.RFC3339Nano, model.String(persisted, "created_at"))
	if e != nil {
		f.t.Fatal(e)
	}
	return fleethistory.MembershipObservation{SchemaVersion: "1", ID: "observation-" + suffix, RegistrationID: f.registration.ID, RegistrationVersion: f.registration.Version, RegistrationHash: fleethistory.RegistrationHash(f.registration), ASGARN: f.registration.ASGARN, ObservedAt: observed, ReceivedAt: received, Source: ref, Members: observedMembers}
}

func TestFleetHistoryRestrictedRolesCASAndTenantIsolation(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.register()
	for _, role := range []string{"finops_ingester", "finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error {
			r := f.registration
			r.ID = "forged-" + role
			_, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, r)
			return e
		})
	}
	for _, role := range []string{"finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error { _, e := tx.FleetHistoryRegistrationGet(f.ctx, f.registration.ID); return e })
		f.must(role, func(tx *Tx) error {
			for _, table := range []string{"fleet_history_registrations", "fleet_demand_definitions", "fleet_history_observations", "fleet_history_scopes", "fleet_history_scope_references"} {
				var granted bool
				if e := tx.QueryRow(f.ctx, "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE')", table).Scan(&granted); e != nil {
					return e
				}
				if granted {
					return fmt.Errorf("new history privileges widened to %s on %s", role, table)
				}
			}
			return nil
		})
	}
	f.denied("finops_api", func(tx *Tx) error { _, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, f.registration); return e })
	f.must("finops_api", func(tx *Tx) error {
		rows, e := tx.FleetHistoryRegistrationPage(f.ctx, f.activity.WorkloadID, "", 1)
		if e == nil && len(rows) != 1 {
			return fmt.Errorf("registration scope page: %d rows", len(rows))
		}
		return e
	})
	if e := f.roles["finops_api"].Do(f.ctx, f.tenant+"-other", func(tx *Tx) error {
		if _, e := tx.FleetHistoryRegistrationGet(f.ctx, f.registration.ID); e == nil {
			return fmt.Errorf("foreign registration readable")
		}
		rows, e := tx.FleetHistoryRegistrationPage(f.ctx, f.activity.WorkloadID, "", 10)
		if e == nil && len(rows) != 0 {
			return fmt.Errorf("foreign registration page leaked")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"fleet_history_registrations", "fleet_demand_definitions"} {
		f.denied("finops_api", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, "UPDATE "+pgx.Identifier{table}.Sanitize()+" SET document=document WHERE tenant_id=$1", f.tenant)
			return e
		})
		f.denied("finops_api", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, "DELETE FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id=$1", f.tenant)
			return e
		})
	}
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.Create(f.ctx, "workloads", model.Document{"id": "other-workload"})
		return e
	})
	for name, change := range map[string]func(*fleethistory.Registration){"workload": func(r *fleethistory.Registration) { r.Binding.WorkloadID = "other-workload" }, "fleet": func(r *fleethistory.Registration) { r.FleetID = "other-fleet" }, "asg": func(r *fleethistory.Registration) {
		r.ASGARN = strings.Replace(r.ASGARN, "Name/history", "Name/other", 1)
	}} {
		t.Run("immutable-"+name, func(t *testing.T) {
			r := f.registration
			r.Version = 2
			change(&r)
			f.denied("finops_api", func(tx *Tx) error { _, e := tx.FleetHistoryRegistrationAppend(f.ctx, 1, r); return e })
		})
	}
	f.must("finops_api", func(tx *Tx) error {
		r := f.registration
		r.ID = "other-registration"
		_, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, r)
		return e
	})
	f.denied("finops_api", func(tx *Tx) error {
		d := f.definition
		d.Version = 2
		_, e := tx.FleetDemandDefinitionAppend(f.ctx, "other-registration", 1, d)
		return e
	})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			r := f.registration
			r.Version = 2
			r.CadenceSeconds = 120 + i
			r.MaxGapSeconds = 180
			results <- f.run("finops_api", func(tx *Tx) error { _, e := tx.FleetHistoryRegistrationAppend(f.ctx, 1, r); return e })
		}(i)
	}
	won, lost := 0, 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			won++
		} else if errors.Is(e, ErrConflict) {
			lost++
		} else {
			t.Errorf("unexpected CAS refusal: %v", e)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("concurrent expected-version writers: wins=%d conflicts=%d", won, lost)
	}
}

func TestFleetHistoryDemandDefinitionAndGuardedZeroStayIndependent(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.register()
	for name, change := range map[string]func(*fleethistory.DemandDefinition){
		"accepted-proxy": func(d *fleethistory.DemandDefinition) { d.ValueField = "ACCEPTED" },
		"native-proxy":   func(d *fleethistory.DemandDefinition) { d.Metric = "request_count" },
		"unit":           func(d *fleethistory.DemandDefinition) { d.Unit = "requests" },
		"version":        func(d *fleethistory.DemandDefinition) { v := int64(1); d.SourceRegistrationVersion = &v },
		"sourcehash":     func(d *fleethistory.DemandDefinition) { d.SourceConfigHash = strings.Repeat("f", 64) },
		"meaning":        func(d *fleethistory.DemandDefinition) { d.Meaning = "REQUEST_THROUGHPUT_PROXY" },
	} {
		t.Run(name, func(t *testing.T) {
			d := f.definition
			d.ID = "bad-" + name
			change(&d)
			f.denied("finops_api", func(tx *Tx) error { _, e := tx.FleetDemandDefinitionAppend(f.ctx, f.registration.ID, 0, d); return e })
		})
	}
	receipt := f.appendCurrentActivity(0)
	f.must("finops_api", func(tx *Tx) error {
		samples, e := tx.FleetHistoryDemandSamples(f.ctx, f.definition.ID, receipt.IntervalStart, receipt.IntervalEnd)
		if e != nil {
			return e
		}
		if len(samples) != 1 || samples[0].Value == nil || *samples[0].Value != "0" {
			return fmt.Errorf("guarded completed zero became missing: %+v", samples)
		}
		s := samples[0]
		if s.Source.StorageKind != "POSTGRES_RECEIPT" || s.Source.ReceiptID != receipt.ID || s.Source.RevisionID != "" || s.Source.Archive != nil || s.Source.SourceRegistrationVersion != nil || s.Epoch != nil || s.Source.RawSHA256 != receipt.BodySHA256 || !s.ReceivedAt.Equal(receipt.ReceivedAt) {
			return fmt.Errorf("guarded receipt provenance was synthesized: %+v", s.Source)
		}
		missing, e := tx.FleetHistoryDemandSamples(f.ctx, f.definition.ID, receipt.IntervalStart.Add(-time.Minute), receipt.IntervalStart)
		if e == nil && len(missing) != 0 {
			return fmt.Errorf("unobserved demand was backfilled with zero")
		}
		return e
	})
	f.denied("finops_api", func(tx *Tx) error {
		raw, _ := json.Marshal(receipt.ActivityInterval)
		_, _, e := tx.ActivityAppend(f.ctx, ActivitySubmission{Interval: receipt.ActivityInterval, RawBody: raw, Issuer: f.activity.Issuer, Subject: f.activity.Subject, IdempotencyKey: "forged-current"})
		return e
	})
}

func TestFleetHistoryNativeObservationReplayCorrectionsAndTampering(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.register()
	observed := time.Now().UTC().Truncate(time.Second)
	o := f.nativeObservation("original", observed, true)
	for _, role := range []string{"finops_api", "finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error { _, _, e := tx.FleetHistoryObservationAppend(f.ctx, o); return e })
	}
	var saved model.Document
	f.must("finops_ingester", func(tx *Tx) error {
		var replay bool
		var e error
		saved, replay, e = tx.FleetHistoryObservationAppend(f.ctx, o)
		if e == nil && replay {
			return fmt.Errorf("first observation was replay")
		}
		return e
	})
	f.must("finops_ingester", func(tx *Tx) error {
		again, replay, e := tx.FleetHistoryObservationAppend(f.ctx, o)
		if e == nil && (!replay || model.String(again, "id") != model.String(saved, "id")) {
			return fmt.Errorf("replay created another native observation")
		}
		return e
	})
	for name, change := range map[string]func(*fleethistory.MembershipObservation){
		"raw": func(x *fleethistory.MembershipObservation) {
			x.Source.RawSHA256 = strings.Repeat("e", 64)
			x.Source.Archive.SHA256 = x.Source.RawSHA256
		},
		"object-version": func(x *fleethistory.MembershipObservation) { x.Source.Archive.VersionID = "another-version" },
		"canonical":      func(x *fleethistory.MembershipObservation) { x.Source.CanonicalHash = strings.Repeat("f", 64) },
		"account":        func(x *fleethistory.MembershipObservation) { x.Source.Binding.AccountID = "999900001111" },
		"template":       func(x *fleethistory.MembershipObservation) { x.Members[0].LaunchTemplateVersion = 8 },
		"received":       func(x *fleethistory.MembershipObservation) { x.ReceivedAt = x.ReceivedAt.Add(time.Second) },
		"invented-launch": func(x *fleethistory.MembershipObservation) {
			v := observed.Add(-time.Hour)
			x.Members[0].LaunchTime = &v
		},
	} {
		t.Run(name, func(t *testing.T) {
			var x fleethistory.MembershipObservation
			raw, _ := json.Marshal(o)
			_ = json.Unmarshal(raw, &x)
			x.ID = "tampered-" + name
			change(&x)
			f.denied("finops_ingester", func(tx *Tx) error { _, _, e := tx.FleetHistoryObservationAppend(f.ctx, x); return e })
		})
	}
	changed := o
	changed.Members = []fleethistory.Member{}
	f.denied("finops_ingester", func(tx *Tx) error { _, _, e := tx.FleetHistoryObservationAppend(f.ctx, changed); return e })
	corrected := f.nativeObservation("corrected", observed, false)
	corrected.CorrectsID = o.ID
	f.must("finops_ingester", func(tx *Tx) error { _, _, e := tx.FleetHistoryObservationAppend(f.ctx, corrected); return e })
	wrongPoint := f.nativeObservation("wrong-point", observed.Add(-time.Second), false)
	wrongPoint.CorrectsID = o.ID
	f.denied("finops_ingester", func(tx *Tx) error { _, _, e := tx.FleetHistoryObservationAppend(f.ctx, wrongPoint); return e })
	f.must("finops_api", func(tx *Tx) error {
		rows, e := tx.FleetHistoryObservationPage(f.ctx, f.registration.ID, "", 1)
		if e != nil {
			return e
		}
		if len(rows) < 1 {
			return fmt.Errorf("native history page missing")
		}
		next, e := tx.FleetHistoryObservationPage(f.ctx, f.registration.ID, model.String(rows[0], "id"), 10)
		if e == nil && len(next) < 1 {
			return fmt.Errorf("native history cursor omitted correction")
		}
		return e
	})
	for _, table := range []string{"fleet_history_observations"} {
		f.denied("finops_ingester", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, "UPDATE "+pgx.Identifier{table}.Sanitize()+" SET document=document WHERE tenant_id=$1", f.tenant)
			return e
		})
	}
}

func TestFleetHistoryNativeReceiptCannotBeShadowedByTemporaryRelation(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.register()
	f.must("finops_api", func(tx *Tx) error {
		var functions, fixed int
		if e := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('fleet_history_json_text','fleet_history_json_hash','fleet_history_source_config','fleet_history_lock','fleet_history_source_lock','fleet_history_native_reference','guard_fleet_history','seal_fleet_history_scope')`).Scan(&functions, &fixed); e != nil {
			return e
		}
		if functions != 8 || fixed != functions {
			return fmt.Errorf("Fleet history functions do not all pin the trusted search path: %d/%d", fixed, functions)
		}
		return nil
	})
	o := f.nativeObservation("temp-shadow", time.Now().UTC().Truncate(time.Second), true)
	// The ingester can create TEMP relations, but they cannot replace the issued
	// public receipt consulted by the invoker trigger/native-reference guards.
	tx, e := f.roles["finops_ingester"].Begin(f.ctx, f.tenant)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(f.ctx, "SET LOCAL search_path=pg_temp,public"); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(f.ctx, "CREATE TEMP TABLE source_receipts (LIKE public.source_receipts INCLUDING ALL) ON COMMIT DROP"); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(f.ctx, "INSERT INTO pg_temp.source_receipts SELECT * FROM public.source_receipts WHERE tenant_id=$1 AND id=$2", f.tenant, o.Source.ReceiptID); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(f.ctx, "UPDATE pg_temp.source_receipts SET document=jsonb_set(document,'{groups,0,members,0,launch_template,version}','\"8\"'::jsonb) WHERE tenant_id=$1 AND id=$2", f.tenant, o.Source.ReceiptID); e != nil {
		t.Fatal(e)
	}
	if e = tx.QueryRow(f.ctx, "SELECT public.fleet_history_json_hash(document) FROM pg_temp.source_receipts WHERE tenant_id=$1 AND id=$2", f.tenant, o.Source.ReceiptID).Scan(&o.Source.CanonicalHash); e != nil {
		t.Fatal(e)
	}
	o.Members[0].LaunchTemplateVersion = 8
	_, _, e = tx.FleetHistoryObservationAppend(f.ctx, o)
	var refusal *pgconn.PgError
	if !errors.As(e, &refusal) || refusal.Code != "P0001" || !strings.Contains(refusal.Message, "pinned native bytes differ") {
		t.Fatalf("counterfeit temporary native receipt did not reach and fail the public pinned-byte guard: %v", e)
	}
	_ = tx.Rollback(context.Background())
	f.must("finops_api", func(read *Tx) error {
		var count int
		if e := read.QueryRow(f.ctx, "SELECT count(*) FROM public.fleet_history_observations WHERE tenant_id=$1", f.tenant).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return fmt.Errorf("temporary receipt forged an immutable observation")
		}
		return nil
	})
}

func TestFleetHistoryScopesSealCompactRootsAndHoldCurrentSource(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.register()
	f.appendCurrentActivity(0)
	var scope model.Document
	tx, e := f.roles["finops_api"].Begin(f.ctx, f.tenant)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	scope, e = tx.FleetHistoryScopeCapture(f.ctx, f.registration.ID, f.definition.ID)
	if e != nil {
		t.Fatal(e)
	}
	if model.String(scope, "status") != "BLOCKED" || model.String(scope, "membership_status") != "INTERVAL_OWNERSHIP_UNPROVEN" {
		t.Fatal("point snapshots became historical authority", scope)
	}
	if e = f.run("finops_api", func(other *Tx) error {
		if _, e := other.Exec(f.ctx, "SET LOCAL lock_timeout='150ms'"); e != nil {
			return e
		}
		d, e := other.SourceGet(f.ctx, f.registration.SourceID)
		if e != nil {
			return e
		}
		d["enabled"] = false
		_, e = other.SourceUpdate(f.ctx, f.registration.SourceID, model.Number(d, "version"), d)
		return e
	}); e == nil {
		t.Fatal("source revocation crossed a sealed-snapshot transaction")
	} else {
		var pgerr *pgconn.PgError
		if !errors.As(e, &pgerr) || pgerr.Code != "55P03" {
			t.Fatalf("source-update failure did not prove lock serialization: %v", e)
		}
	}
	if e = tx.Commit(f.ctx); e != nil {
		t.Fatal("complete immutable scope root failed to commit", e)
	}
	id := model.String(scope, "id")
	if id == "" {
		t.Fatal("scope has no immutable ID")
	}
	f.must("finops_api", func(tx *Tx) error {
		var raw []byte
		var expectedRoot, contentHash string
		var count int
		if e := tx.QueryRow(f.ctx, "SELECT raw_document,content_hash,reference_root,reference_count FROM fleet_history_scopes WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&raw, &contentHash, &expectedRoot, &count); e != nil {
			return e
		}
		actual := sha256.Sum256(raw)
		if contentHash != hex.EncodeToString(actual[:]) || len(raw) > 65536 {
			return fmt.Errorf("scope exact bytes/hash not sealed")
		}
		var doc map[string]json.RawMessage
		if e := json.Unmarshal(raw, &doc); e != nil {
			return e
		}
		for _, key := range []string{"observations", "samples", "demand_samples", "sources"} {
			if value := doc[key]; len(value) > 0 && value[0] == '[' {
				return fmt.Errorf("raw population expanded into compact scope: %s", key)
			}
		}
		rows, e := tx.Query(f.ctx, "SELECT ordinal,content_hash,raw_document FROM fleet_history_scope_references WHERE tenant_id=$1 AND scope_id=$2 ORDER BY ordinal", f.tenant, id)
		if e != nil {
			return e
		}
		defer rows.Close()
		parts := []string{}
		for rows.Next() {
			var ordinal int
			var hash string
			var body []byte
			if e = rows.Scan(&ordinal, &hash, &body); e != nil {
				return e
			}
			h := sha256.Sum256(body)
			if ordinal != len(parts)+1 || hash != hex.EncodeToString(h[:]) {
				return fmt.Errorf("immutable scope reference order/hash differs")
			}
			parts = append(parts, fmt.Sprintf("%d:%s", ordinal, hash))
		}
		if e = rows.Err(); e != nil {
			return e
		}
		h := sha256.Sum256([]byte(strings.Join(parts, ",")))
		if len(parts) != count || count < 2 || hex.EncodeToString(h[:]) != expectedRoot {
			return fmt.Errorf("compact reference root does not bind every row")
		}
		return nil
	})
	f.must("finops_api", func(tx *Tx) error {
		seen := map[string]bool{}
		cursor := ""
		for i := 0; i < int(model.Number(scope, "reference_count"))+1; i++ {
			page, e := tx.FleetHistoryScopeReferencePage(f.ctx, id, "", cursor, 1)
			if e != nil {
				return e
			}
			if len(page) == 0 {
				break
			}
			if len(page) != 1 {
				return fmt.Errorf("scope reference page exceeded requested limit")
			}
			key := model.String(page[0], "kind") + ":" + model.String(page[0], "id")
			if seen[key] {
				return fmt.Errorf("scope reference cursor repeated row")
			}
			seen[key] = true
			next := model.String(page[0], "cursor")
			if next == "" || next == cursor {
				return fmt.Errorf("scope reference has no advancing cursor")
			}
			cursor = next
		}
		if len(seen) != int(model.Number(scope, "reference_count")) {
			return fmt.Errorf("scope reference cursor lost rows")
		}
		return nil
	})
	f.must("finops_api", func(tx *Tx) error {
		got, e := tx.FleetHistoryScopeGet(f.ctx, id)
		if e == nil && model.String(got, "hash") != model.String(scope, "hash") {
			return fmt.Errorf("scope changed after commit")
		}
		return e
	})
	for _, table := range []string{"fleet_history_scopes", "fleet_history_scope_references"} {
		f.denied("finops_api", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, "DELETE FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id=$1", f.tenant)
			return e
		})
	}
	if e = f.roles["finops_api"].Do(f.ctx, f.tenant+"-other", func(tx *Tx) error {
		_, e := tx.FleetHistoryScopeGet(f.ctx, id)
		if e == nil {
			return fmt.Errorf("foreign sealed scope readable")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	f.must("finops_api", func(tx *Tx) error {
		d, e := tx.SourceGet(f.ctx, f.registration.SourceID)
		if e != nil {
			return e
		}
		d["enabled"] = false
		_, e = tx.SourceUpdate(f.ctx, f.registration.SourceID, model.Number(d, "version"), d)
		return e
	})
	f.denied("finops_api", func(tx *Tx) error {
		r := f.registration
		r.ID = "revoked-registration"
		r.SourceRegistrationVersion++
		_, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, r)
		return e
	})
	f.must("finops_api", func(tx *Tx) error { _, e := tx.FleetHistoryScopeGet(f.ctx, id); return e })
	f.must("finops_api", func(tx *Tx) error {
		fresh, e := tx.FleetHistoryScopeCapture(f.ctx, f.registration.ID, f.definition.ID)
		if e != nil {
			return e
		}
		var oldStatus, newStatus string
		q := `SELECT document->>'status' FROM fleet_history_scope_references WHERE tenant_id=$1 AND scope_id=$2 AND kind='SOURCE_STATE' AND document->>'source_system'='AWS_SOURCE_CONNECTION' AND document->>'source_id'=$3`
		if e = tx.QueryRow(f.ctx, q, f.tenant, id, f.registration.SourceID).Scan(&oldStatus); e != nil {
			return e
		}
		if e = tx.QueryRow(f.ctx, q, f.tenant, model.String(fresh, "id"), f.registration.SourceID).Scan(&newStatus); e != nil {
			return e
		}
		if oldStatus != "ACTIVE" || newStatus != "REVOKED" || model.String(fresh, "status") != "BLOCKED" {
			return fmt.Errorf("new scope reused former active source or rewrote history: %s/%s", oldStatus, newStatus)
		}
		return nil
	})
}

// Copy a legitimate compact declaration with a new identity/hash but no refs.
// The deferred seal must independently reject it at commit. This is a direct
// API-role SQL attack, not a second call through the private capture factory.
func (f *fleetHistoryDBTest) incompleteScope(tx *Tx, original string) (string, error) {
	var raw []byte
	if e := tx.QueryRow(f.ctx, "SELECT raw_document FROM fleet_history_scopes WHERE tenant_id=$1 AND id=$2", f.tenant, original).Scan(&raw); e != nil {
		return "", e
	}
	var document model.Document
	if e := json.Unmarshal(raw, &document); e != nil {
		return "", e
	}
	id := model.ID()
	document["id"] = id
	document["analysis_hash"] = fleetHistoryHash(model.Document{"nonce": id})
	body, _ := json.Marshal(document)
	h := sha256.Sum256(body)
	_, e := tx.Exec(f.ctx, `INSERT INTO fleet_history_scopes(tenant_id,id,registration_id,registration_version,definition_id,definition_version,input_hash,analysis_hash,reference_root,reference_count,content_hash,document,raw_document)
 SELECT tenant_id,$3,registration_id,registration_version,definition_id,definition_version,input_hash,$4,reference_root,reference_count,$5,$6,$7 FROM fleet_history_scopes WHERE tenant_id=$1 AND id=$2`, f.tenant, original, id, document["analysis_hash"], hex.EncodeToString(h[:]), body, body)
	return id, e
}

func TestFleetHistoryDeferredSealAndRehashedReferencesRejectForgeries(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.register()
	var scope model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		scope, e = tx.FleetHistoryScopeCapture(f.ctx, f.registration.ID, f.definition.ID)
		return e
	})
	for name, attack := range map[string]func(*Tx, string) error{
		"missing references": func(tx *Tx, id string) error { return nil },
		"rehashed registration": func(tx *Tx, id string) error {
			ref := model.Document{"id": f.registration.ID, "version": f.registration.Version, "hash": strings.Repeat("f", 64)}
			raw, _ := json.Marshal(ref)
			h := sha256.Sum256(raw)
			_, e := tx.Exec(f.ctx, "INSERT INTO fleet_history_scope_references(tenant_id,scope_id,ordinal,kind,reference_id,content_hash,document,raw_document) VALUES($1,$2,1,'REGISTRATION',$3,$4,$5,$6)", f.tenant, id, f.registration.ID, hex.EncodeToString(h[:]), raw, raw)
			return e
		},
		"rehashed source state": func(tx *Tx, id string) error {
			var body []byte
			var referenceID string
			if e := tx.QueryRow(f.ctx, `SELECT reference_id,raw_document FROM fleet_history_scope_references WHERE tenant_id=$1 AND scope_id=$2 AND kind='SOURCE_STATE' AND document->>'source_system'='AWS_SOURCE_CONNECTION'`, f.tenant, model.String(scope, "id")).Scan(&referenceID, &body); e != nil {
				return e
			}
			var ref model.Document
			if e := json.Unmarshal(body, &ref); e != nil {
				return e
			}
			ref["config_hash"] = strings.Repeat("f", 64)
			raw, _ := json.Marshal(ref)
			h := sha256.Sum256(raw)
			_, e := tx.Exec(f.ctx, "INSERT INTO fleet_history_scope_references(tenant_id,scope_id,ordinal,kind,reference_id,content_hash,document,raw_document) VALUES($1,$2,1,'SOURCE_STATE',$3,$4,$5,$6)", f.tenant, id, referenceID, hex.EncodeToString(h[:]), raw, raw)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := f.run("finops_api", func(tx *Tx) error {
				id, e := f.incompleteScope(tx, model.String(scope, "id"))
				if e != nil {
					t.Fatal("legitimate-shape forgery setup failed", e)
				}
				return attack(tx, id)
			})
			var pgerr *pgconn.PgError
			if !errors.As(e, &pgerr) || pgerr.Code != "P0001" {
				t.Fatalf("forged scope was accepted or failed outside guard: %v", e)
			}
			if name == "missing references" && !strings.Contains(pgerr.Message, "reference root incomplete") {
				t.Fatal("deferred root seal did not reject absent evidence", e)
			}
			if name == "rehashed registration" && !strings.Contains(pgerr.Message, "registration reference differs") {
				t.Fatal("rehashed foreign reference escaped binding guard", e)
			}
			if name == "rehashed source state" && !strings.Contains(pgerr.Message, "native lifecycle differs") {
				t.Fatal("rehashed source currentness escaped original registration binding", e)
			}
		})
	}
	f.must("finops_api", func(tx *Tx) error {
		var count int
		e := tx.QueryRow(f.ctx, "SELECT count(*) FROM fleet_history_scopes WHERE tenant_id=$1", f.tenant).Scan(&count)
		if e == nil && count != 1 {
			return fmt.Errorf("failed forgery left a visible scope")
		}
		return e
	})
}
