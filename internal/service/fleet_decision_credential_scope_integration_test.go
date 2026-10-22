package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecisionworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func jointCredentialLoginDSN(host string, port uint16, database, login, password string) string {
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(host, strconv.Itoa(int(port))), Path: "/" + database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	return u.String()
}

func decisionCredentialMigrate(t *testing.T, admin *store.Store, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := admin.Migrate(context.Background(), dir); e != nil {
		t.Fatal(e)
	}
}
func decisionCredentialInstall(t *testing.T, admin, runtime *store.Store, tenant string) string {
	t.Helper()
	id := model.ID()
	login := runtime.Pool.Config().ConnConfig.User
	tag, e := admin.Pool.Exec(context.Background(), `INSERT INTO public.fleet_decision_credentials(id,database_login,role_oid,tenant_id) SELECT $1,rolname,oid,$2 FROM pg_roles WHERE rolname=$3`, id, tenant, login)
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("operator credential installation", e)
	}
	return id
}
func decisionCredentialQueue(t *testing.T, f *mutationReplayFixture, ar, cr, key string) string {
	t.Helper()
	code, d, _ := f.request("workloads/fixture-workload/fleet-joint-decisions", `"1"`, key, f.token(f.tenant, "assigned-owner", "ORGANISATION_OWNER"), model.Document{"assessment_request_id": ar, "capacity_batch_request_id": cr})
	if code != 202 {
		t.Fatal("actual API decision queue", code, d)
	}
	return model.String(d, "id")
}
func decisionCredentialExpectPermission(t *testing.T, e error) {
	t.Helper()
	var p *pgconn.PgError
	if !errors.As(e, &p) || (p.Code != "42501" && (p.Code != "P0001" || !strings.HasPrefix(p.Message, "decision credential "))) {
		t.Fatal("expected DB scope/ACL refusal", e)
	}
}
func decisionCredentialRequireVisible(t *testing.T, s *store.Store, tenant, id string, want bool) {
	t.Helper()
	e := s.Do(context.Background(), tenant, func(tx *store.Tx) error { _, e := tx.FleetJointDecisionGet(context.Background(), id); return e })
	if want && e != nil {
		t.Fatal("own issued result hidden", e)
	}
	if !want && !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("foreign/disabled credential saw issued result", e)
	}
}
func decisionCredentialWaitAdvisory(t *testing.T, admin *store.Store, pid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		var waiting bool
		e := admin.Pool.QueryRow(ctx, `SELECT coalesce(wait_event_type='Lock' AND wait_event='advisory',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting)
		if e != nil {
			t.Fatal("actual credential fence waiter unavailable", e)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("credential fence was not actually contended")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Metadata transport is explicitly doubled, as in the existing037 role suite.
// Both tenants nevertheless have separately issued025/027 selectors,035/036
// children, API requests and real restricted-role analytical terminal rows.
func TestDecisionCredentialScopeBindsLoginAcrossGUCResetRoleAndRevocation(t *testing.T) {
	f, admin, evaluator, proposals := newFleetCapacityHTTPTest(t)
	ctx := context.Background()
	decisionCredentialMigrate(t, admin, "037_fleet_joint_decisions.sql", "038_fleet_decision_credential_scope.sql")
	assessor := jointRuntime(t, admin, "finops_group_assessor", "group-assessment-reader")
	writerA := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader")
	writerB := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader")
	unbound := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader")
	other, otherProposals := decisionCredentialSecondTenant(t, f)
	bindingA := decisionCredentialInstall(t, admin, writerA, f.tenant)
	bindingB := decisionCredentialInstall(t, admin, writerB, other.tenant)
	arA, crA := jointIssuedUnknownChildren(t, f, assessor, evaluator, proposals)
	arB, crB := jointIssuedUnknownChildren(t, other, assessor, evaluator, otherProposals)
	idsA := []string{}
	idsB := []string{}
	for n := 0; n < 3; n++ {
		idsA = append(idsA, decisionCredentialQueue(t, f, arA, crA, fmt.Sprintf("scope-a-%d", n)))
		idsB = append(idsB, decisionCredentialQueue(t, other, arB, crB, fmt.Sprintf("scope-b-%d", n)))
	}
	wa := &fleetdecisionworker.Worker{Store: writerA, Tenant: f.tenant}
	wb := &fleetdecisionworker.Worker{Store: writerB, Tenant: other.tenant}
	if !wa.Ready(ctx) || !wb.Ready(ctx) || (&fleetdecisionworker.Worker{Store: writerA, Tenant: other.tenant}).Ready(ctx) || (&fleetdecisionworker.Worker{Store: unbound, Tenant: f.tenant}).Ready(ctx) {
		t.Fatal("startup/readiness ignored actual LOGIN tenant mapping")
	}
	for _, v := range []struct {
		w  *fleetdecisionworker.Worker
		id string
	}{{wa, idsA[0]}, {wb, idsB[0]}} {
		if _, replay, e := v.w.Process(ctx, v.id); e != nil || replay {
			t.Fatal("own production analytical publication", e, replay)
		}
	}
	for _, v := range []struct {
		s          *store.Store
		tenant, id string
	}{{writerA, f.tenant, idsA[1]}, {writerB, other.tenant, idsB[1]}} {
		if e := v.s.Do(ctx, v.tenant, func(tx *store.Tx) error {
			_, _, e := tx.FleetJointDecisionRefuse(ctx, v.id, "JOINED_MODEL_SUMMARY_UNSUPPORTED")
			return e
		}); e != nil {
			t.Fatal("own immutable refusal", e)
		}
	}
	for _, v := range []struct {
		s      *store.Store
		tenant string
		ids    []string
	}{{writerA, f.tenant, idsA}, {writerB, other.tenant, idsB}} {
		for _, id := range v.ids {
			decisionCredentialRequireVisible(t, v.s, v.tenant, id, true)
		}
	}
	// Retain a real old transaction snapshot before the later operator revoke.
	// A stolen login may choose its isolation level even though Store.Do uses
	// READ COMMITTED. SERIALIZABLE must refuse while the credential is active too.
	retained, e := writerB.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer retained.Rollback(ctx)
	if _, e = retained.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, other.tenant); e != nil {
		t.Fatal(e)
	}
	var retainedSnapshot string
	if e = retained.QueryRow(ctx, `SELECT pg_current_snapshot()::text`).Scan(&retainedSnapshot); e != nil || retainedSnapshot == "" {
		t.Fatal("old transaction snapshot unavailable", e)
	}
	serial, e := writerA.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		t.Fatal(e)
	}
	defer serial.Rollback(ctx)
	if _, e = serial.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, f.tenant); e != nil {
		t.Fatal(e)
	}
	var serialAllowed bool
	if e = serial.QueryRow(ctx, `SELECT public.fleet_decision_credential_scope($1)`, f.tenant).Scan(&serialAllowed); e != nil || serialAllowed {
		t.Fatal("active credential accepted SERIALIZABLE authority snapshot", e)
	}
	if e = serial.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	// The normal authenticated API retains both tenants' scoped historical reads.
	for _, v := range []struct {
		f  *mutationReplayFixture
		id string
	}{{f, idsA[0]}, {other, idsB[0]}} {
		if code, d := fleetNativeHTTPGet(t, v.f, "fleet-joint-decisions/"+v.id, v.f.token(v.f.tenant, "auditor", "AUDITOR")); code != 200 || model.String(d, "status") != "ASSESSED" {
			t.Fatal("API own tenant access lost", code, d)
		}
	}
	for _, table := range []string{"fleet_joint_decision_requests", "fleet_joint_decisions", "fleet_joint_decision_refusals"} {
		t.Run("populated-foreign-"+table, func(t *testing.T) {
			var actual, visible int
			if e := admin.Pool.QueryRow(ctx, "SELECT count(*) FROM public."+table+" WHERE tenant_id=$1", other.tenant).Scan(&actual); e != nil || actual == 0 {
				t.Fatal("negative fixture is not populated", e, actual)
			}
			if e := writerA.Do(ctx, other.tenant, func(tx *store.Tx) error {
				return tx.QueryRow(ctx, "SELECT count(*) FROM public."+table+" WHERE tenant_id=$1", other.tenant).Scan(&visible)
			}); e != nil || visible != 0 {
				t.Fatal("changed GUC exposed populated foreign table", e, visible)
			}
		})
	}
	for _, id := range idsB {
		decisionCredentialRequireVisible(t, writerA, other.tenant, id, false)
	}
	decisionCredentialRequireVisible(t, unbound, f.tenant, idsA[0], false)
	for name, sql := range map[string]string{
		"public-resolver":  `SELECT public.fleet_joint_decision_inputs($1,$2,$3)`,
		"private-resolver": `SELECT public.fleet_joint_decision_inputs_v037_private($1,$2,$3)`,
	} {
		t.Run(name, func(t *testing.T) {
			e := writerA.Do(ctx, other.tenant, func(tx *store.Tx) error { _, e := tx.Exec(ctx, sql, other.tenant, arB, crB); return e })
			decisionCredentialExpectPermission(t, e)
		})
	}
	// RESET ROLE and inherited SELECT cannot select another mapped tenant. The
	// current role name is never substituted for the authenticated SESSION_USER.
	raw, e := writerA.Pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = raw.Conn().Close(context.Background()); raw.Release() }()
	if _, e = raw.Exec(ctx, "RESET ROLE"); e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec(ctx, `SELECT set_config('app.tenant_id',$1,false)`, other.tenant); e != nil {
		t.Fatal(e)
	}
	var visible int
	if e = raw.QueryRow(ctx, `SELECT count(*) FROM public.fleet_joint_decision_requests WHERE tenant_id=$1`, other.tenant).Scan(&visible); e != nil || visible != 0 {
		t.Fatal("raw LOGIN/reset-role bypass", e, visible)
	}
	_, e = raw.Exec(ctx, `SELECT public.fleet_joint_decision_inputs($1,$2,$3)`, other.tenant, arB, crB)
	decisionCredentialExpectPermission(t, e)
	// Use fully issued B rows to exercise direct INSERT scope guards, rather than
	// merely relying on a missing request, malformed digest or foreign-key error.
	var decision model.Document
	if e = writerB.Do(ctx, other.tenant, func(tx *store.Tx) error {
		d, e := tx.FleetJointDecisionGet(ctx, idsB[0])
		decision = sourceDocument(d["decision"])
		return e
	}); e != nil {
		t.Fatal(e)
	}
	bad := jointDocument(t, decision)
	bad["request_id"] = idsB[2]
	bad["observed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	bad["id"] = ""
	bad["id"] = "group-joint-decision-" + b.Hash(bad)
	encoded, e := json.Marshal(bad)
	if e != nil {
		t.Fatal(e)
	}
	positive, e := writerB.Begin(ctx, other.tenant)
	if e != nil {
		t.Fatal(e)
	}
	defer positive.Rollback(ctx)
	issuedInput, e := positive.FleetJointDecisionInputs(ctx, idsB[2])
	if e != nil {
		t.Fatal(e)
	}
	insertDecision := `INSERT INTO public.fleet_joint_decisions(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`
	if _, e = positive.Exec(ctx, insertDecision, other.tenant, bad["id"], idsB[2], b.Hash(bad), b.Hash(issuedInput), encoded, encoded); e != nil {
		t.Fatal("identical direct B decision did not qualify under B", e)
	}
	if e = positive.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	e = writerA.Do(ctx, other.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, insertDecision, other.tenant, bad["id"], idsB[2], b.Hash(bad), b.Hash(issuedInput), encoded, encoded)
		return e
	})
	decisionCredentialExpectPermission(t, e)
	e = writerA.Do(ctx, other.tenant, func(tx *store.Tx) error {
		_, _, e := tx.FleetJointDecisionRefuse(ctx, idsB[2], "JOINED_MODEL_SUMMARY_UNSUPPORTED")
		return e
	})
	if !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("foreign refusal row selected", e)
	}
	refusal := model.Document{"schema_version": "1", "id": "", "request_id": idsB[2], "reason_codes": []string{"JOINED_MODEL_SUMMARY_UNSUPPORTED"}, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "execution_authorized": false, "verified_saving": nil}
	refusal["id"] = "group-joint-refusal-" + b.Hash(refusal)
	refusalRaw, e := json.Marshal(refusal)
	if e != nil {
		t.Fatal(e)
	}
	positiveRefusal, e := writerB.Begin(ctx, other.tenant)
	if e != nil {
		t.Fatal(e)
	}
	defer positiveRefusal.Rollback(ctx)
	insertRefusal := `INSERT INTO public.fleet_joint_decision_refusals(tenant_id,id,request_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6)`
	if _, e = positiveRefusal.Exec(ctx, insertRefusal, other.tenant, refusal["id"], idsB[2], b.Hash(refusal), refusalRaw, refusalRaw); e != nil {
		t.Fatal("identical direct B refusal did not qualify under B", e)
	}
	if e = positiveRefusal.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	e = writerA.Do(ctx, other.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, insertRefusal, other.tenant, refusal["id"], idsB[2], b.Hash(refusal), refusalRaw, refusalRaw)
		return e
	})
	decisionCredentialExpectPermission(t, e)
	for _, sql := range []string{`SELECT * FROM public.fleet_decision_credentials`, `SELECT * FROM public.fleet_decision_credential_revocations`, `INSERT INTO public.fleet_decision_credential_revocations(credential_id,reason_code) VALUES('` + bindingA + `','SELF_REVOKE')`, `UPDATE public.fleet_decision_credentials SET tenant_id='foreign'`, `DELETE FROM public.fleet_decision_credentials`} {
		e = writerA.Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.Exec(ctx, sql); return e })
		decisionCredentialExpectPermission(t, e)
	}
	// Operator append-only revocation blocks readiness, current reads and both
	// terminal paths while authenticated API historical access remains intact.
	// Publication already holding the shared fence linearizes before revocation;
	// the operator's actual backend must wait until that publication commits.
	publishing, e := writerA.Begin(ctx, f.tenant)
	if e != nil {
		t.Fatal(e)
	}
	defer publishing.Rollback(ctx)
	if _, e = publishing.FleetJointDecisionInputs(ctx, idsA[2]); e != nil {
		t.Fatal(e)
	}
	revoker, e := admin.Pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer revoker.Release()
	revokeCtx, revokeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer revokeCancel()
	revokeDone := make(chan error, 1)
	go func() {
		_, e := revoker.Exec(revokeCtx, `INSERT INTO public.fleet_decision_credential_revocations(credential_id,reason_code) VALUES($1,'CREDENTIAL_RETIRED')`, bindingA)
		revokeDone <- e
	}()
	decisionCredentialWaitAdvisory(t, admin, revoker.Conn().PgConn().PID())
	if _, _, e = publishing.FleetJointDecisionRefuse(ctx, idsA[2], "JOINED_MODEL_SUMMARY_UNSUPPORTED"); e != nil {
		t.Fatal(e)
	}
	if e = publishing.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-revokeDone; e != nil {
		t.Fatal(e)
	}
	if wa.Ready(ctx) {
		t.Fatal("revoked credential ready")
	}
	decisionCredentialRequireVisible(t, writerA, f.tenant, idsA[0], false)
	if _, _, e = wa.Process(ctx, idsA[2]); e == nil {
		t.Fatal("revoked credential published")
	}
	if code, d := fleetNativeHTTPGet(t, f, "fleet-joint-decisions/"+idsA[0], f.token(f.tenant, "auditor", "AUDITOR")); code != 200 || model.String(d, "status") != "ASSESSED" {
		t.Fatal("machine revocation erased API history", code, d)
	}
	// The opposite ordering must reject a publication which initially observed
	// the old credential, then waited behind an uncommitted operator revocation.
	revoking, e := admin.Pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer revoking.Rollback(ctx)
	if _, e = revoking.Exec(ctx, `INSERT INTO public.fleet_decision_credential_revocations(credential_id,reason_code) VALUES($1,'CREDENTIAL_RETIRED')`, bindingB); e != nil {
		t.Fatal(e)
	}
	publishPID := make(chan uint32, 1)
	publishDone := make(chan error, 1)
	publishCtx, publishCancel := context.WithTimeout(ctx, 10*time.Second)
	defer publishCancel()
	go func() {
		publishDone <- writerB.Do(publishCtx, other.tenant, func(tx *store.Tx) error {
			var pid uint32
			if e := tx.QueryRow(publishCtx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
				return e
			}
			publishPID <- pid
			_, _, e := tx.FleetJointDecisionRefuse(publishCtx, idsB[2], "JOINED_MODEL_SUMMARY_UNSUPPORTED")
			return e
		})
	}()
	select {
	case pid := <-publishPID:
		decisionCredentialWaitAdvisory(t, admin, pid)
	case e := <-publishDone:
		t.Fatal("publisher did not reach actual credential fence", e)
	case <-publishCtx.Done():
		t.Fatal("publisher backend unavailable")
	}
	if e = revoking.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	decisionCredentialExpectPermission(t, <-publishDone)
	var retainedAllowed bool
	if e = retained.QueryRow(ctx, `SELECT public.fleet_decision_credential_scope($1)`, other.tenant).Scan(&retainedAllowed); e != nil || retainedAllowed {
		t.Fatal("old REPEATABLE READ snapshot retained revoked scope", e)
	}
	var retainedVisible int
	if e = retained.QueryRow(ctx, `SELECT count(*) FROM public.fleet_joint_decision_requests WHERE tenant_id=$1`, other.tenant).Scan(&retainedVisible); e != nil || retainedVisible != 0 {
		t.Fatal("old snapshot exposed revoked tenant records", e, retainedVisible)
	}
	if _, e = retained.Exec(ctx, `SAVEPOINT credential_probe`); e != nil {
		t.Fatal(e)
	}
	_, e = retained.Exec(ctx, `SELECT public.fleet_joint_decision_inputs($1,$2,$3)`, other.tenant, arB, crB)
	decisionCredentialExpectPermission(t, e)
	if _, e = retained.Exec(ctx, `ROLLBACK TO SAVEPOINT credential_probe`); e != nil {
		t.Fatal(e)
	}
	_, e = retained.Exec(ctx, insertRefusal, other.tenant, refusal["id"], idsB[2], b.Hash(refusal), refusalRaw, refusalRaw)
	decisionCredentialExpectPermission(t, e)
	if e = retained.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if code, d := fleetNativeHTTPGet(t, other, "fleet-joint-decisions/"+idsB[2], other.token(other.tenant, "auditor", "AUDITOR")); code != 200 || model.String(d, "status") != "QUEUED" {
		t.Fatal("publication escaped committed credential revocation", code, d)
	}
	for _, sql := range []string{`UPDATE public.fleet_decision_credentials SET tenant_id='foreign' WHERE id='` + bindingA + `'`, `DELETE FROM public.fleet_decision_credential_revocations WHERE credential_id='` + bindingA + `'`} {
		if _, e = admin.Pool.Exec(ctx, sql); e == nil {
			t.Fatal("operator rewrote immutable scope/revocation")
		}
	}
}

func TestDecisionCredentialRoleOIDCannotBeReplacedBySameLogin(t *testing.T) {
	_, admin, _, _ := newFleetCapacityHTTPTest(t)
	ctx := context.Background()
	decisionCredentialMigrate(t, admin, "037_fleet_joint_decisions.sql", "038_fleet_decision_credential_scope.sql")
	runtime := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader")
	decisionCredentialInstall(t, admin, runtime, "tenant-oid")
	cfg := runtime.Pool.Config()
	login := cfg.ConnConfig.User
	password := cfg.ConnConfig.Password
	var oldOID uint32
	if e := admin.Pool.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=$1`, login).Scan(&oldOID); e != nil {
		t.Fatal(e)
	}
	held, e := runtime.Pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	renamed := login + "_renamed"
	if _, e = admin.Pool.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" RENAME TO "+pgx.Identifier{renamed}.Sanitize()); e != nil {
		held.Release()
		t.Fatal(e)
	}
	_, setError := held.Exec(ctx, `SELECT set_config('app.tenant_id','tenant-oid',false)`)
	var allowed bool
	scopeError := held.QueryRow(ctx, `SELECT public.fleet_decision_credential_scope('tenant-oid')`).Scan(&allowed)
	_, renameBack := admin.Pool.Exec(ctx, "ALTER ROLE "+pgx.Identifier{renamed}.Sanitize()+" RENAME TO "+pgx.Identifier{login}.Sanitize())
	held.Release()
	if setError != nil || scopeError != nil || renameBack != nil || allowed {
		t.Fatal("renamed authenticated LOGIN retained binding", setError, scopeError, renameBack, allowed)
	}
	runtime.Pool.Close()
	if _, e := admin.Pool.Exec(ctx, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_decision"); e != nil {
		t.Fatal(e)
	}
	var nextOID uint32
	if e := admin.Pool.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=$1`, login).Scan(&nextOID); e != nil || nextOID == oldOID {
		t.Fatal("test role OID did not change", e)
	}
	next, e := store.OpenRuntime(ctx, jointCredentialLoginDSN(cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database, login, password), "group-decision-reader")
	if e != nil {
		t.Fatal(e)
	}
	defer next.Pool.Close()
	if (&fleetdecisionworker.Worker{Store: next, Tenant: "tenant-oid"}).Ready(ctx) {
		t.Fatal("recreated LOGIN inherited old OID binding")
	}
	if _, e = admin.Pool.Exec(ctx, `INSERT INTO public.fleet_decision_credentials(id,database_login,role_oid,tenant_id) VALUES($1,$2,$3,'tenant-oid')`, model.ID(), login, oldOID); e == nil {
		t.Fatal("stale inspected OID accepted")
	}
}

func decisionCredentialSecondTenant(t *testing.T, original *mutationReplayFixture) (*mutationReplayFixture, []string) {
	t.Helper()
	ctx := context.Background()
	copy := *original
	f := &copy
	f.tenant = original.tenant + "-second"
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "workloads", model.Document{"id": "fixture-workload", "name": "Independent tenant scope fixture", "owner": "assigned-owner", "environment": "NON_PRODUCTION"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	var e error
	src := source.FixtureRegistration(f.tenant, "assessment-native")
	activity := store.ActivitySource{ID: "assessment-completed", WorkloadID: "fixture-workload", ResourceID: "assessment-external-work", ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.example.invalid", Subject: "independent-completed-collector", MetricDefinition: store.ActivityMetric{ID: "orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
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
	if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, "assessment-native", "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(src), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); e != nil {
		t.Fatal(e)
	}
	platform := f.token(f.tenant, "assessment-platform", "PLATFORM_ADMIN")
	proposals := []string{}
	for n, name := range []string{"original", "candidate"} {
		arn := "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + strconv.Itoa(n+1) + ":autoScalingGroupName/assessment-" + name
		code, reg, _ := f.request("fleet-history-registrations", `"0"`, "assessment-registration-"+name, platform, model.Document{"workload_id": "fixture-workload", "fleet_id": "assessment-" + name, "asg_arn": arn, "source_connection_id": "assessment-native", "cadence_seconds": 60, "max_gap_seconds": 120})
		if code != 201 {
			t.Fatal("real group registration", code, reg)
		}
		code, definition, _ := f.request("fleet-demand-definitions", `"0"`, "assessment-definition-"+name, platform, model.Document{"registration_id": reg["id"], "activity_source_id": activity.ID, "business_operation": "committed_order", "semantic_contract_id": "reviewed-independent-orders", "semantic_contract_hash": strings.Repeat("b", 64)})
		if code != 201 {
			t.Fatal("definition", code, definition)
		}
		code, scope, _ := f.request("fleet-history-scopes", `"1"`, "assessment-scope-"+name, platform, model.Document{"registration_id": reg["id"], "definition_id": definition["id"], "definition_version": 1})
		if code != 201 {
			t.Fatal("sealed scope", code, scope)
		}
		metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://git.example.invalid/native-group.git", "ref": "refs/heads/declared", "directory": "infra"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:owner/group:ref:refs/heads/declared", "pipeline_id": "declared-native-group"}}, "terraform": model.Document{"workspace": "development", "state_lineage": "12345678-1234-1234-1234-123456789abc", "asg_address": "aws_autoscaling_group." + name, "launch_template_address": "aws_launch_template." + name, "traffic": model.Document{"listener_rule_address": "aws_lb_listener_rule.app", "target_group_addresses": []string{"aws_lb_target_group.original", "aws_lb_target_group.candidate"}}}}
		base := "fleet-history-registrations/" + model.String(reg, "id")
		code, decl, _ := f.request(base+"/configuration-authorities", `"0"`, "assessment-declare-"+name, platform, metadata)
		if code != 201 {
			t.Fatal("group declaration", code, decl)
		}
		code, proposal, _ := f.request(base+"/configuration-proposals", `"1"`, "assessment-propose-"+name, platform, model.Document{"declaration_id": decl["id"], "scope_id": scope["id"]})
		if code != 201 {
			t.Fatal("group proposal", code, proposal)
		}
		proposals = append(proposals, model.String(proposal, "id"))
	}
	profile := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000}
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.WorkloadSafetyAppend(ctx, "fixture-workload", 0, profile)
		return e
	}); e != nil {
		t.Fatal(e)
	}

	return f, proposals
}
