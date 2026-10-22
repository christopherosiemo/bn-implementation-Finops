package service

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

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacityworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func newFleetCapacityHTTPTest(t *testing.T) (*mutationReplayFixture, *store.Store, *store.Store, []string) {
	t.Helper()
	t.Setenv("DB_GROUP_CAPACITY_PASSWORD", "")
	f, admin, _, proposals := newFleetNativeHTTPTest(t)
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "036_fleet_native_capacity.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "036_fleet_native_capacity.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = admin.Migrate(context.Background(), dir); e != nil {
		t.Fatal(e)
	}
	login := "capacity_http_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	var evaluator *store.Store
	if _, e = admin.Pool.Exec(context.Background(), "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_capacity"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if evaluator != nil {
			evaluator.Pool.Close()
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	c := admin.Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))), Path: "/" + c.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	evaluator, e = store.OpenRuntime(context.Background(), dsn.String(), "group-capacity-evaluator")
	if e != nil {
		t.Fatal(e)
	}
	f.roles["capacity"] = evaluator
	return f, admin, evaluator, proposals
}

// Missing native population is published by the same production queue worker,
// with no archive, reader or Python request fabricated to fill the gap.
type fleetCapacityUnexpectedTransport struct{ calls int }

func (x *fleetCapacityUnexpectedTransport) ReadPinned(context.Context, string, model.Document) (fleetbilling.PinnedObject, error) {
	x.calls++
	return fleetbilling.PinnedObject{}, errors.New("unexpected archive read")
}
func (x *fleetCapacityUnexpectedTransport) Read(context.Context, native.CapacityInputRequest) (native.CapacityPopulation, error) {
	x.calls++
	return native.CapacityPopulation{}, errors.New("unexpected population read")
}
func (x *fleetCapacityUnexpectedTransport) Calculate(context.Context, native.CapacityModelRequest) ([]byte, error) {
	x.calls++
	return nil, errors.New("unexpected model request")
}
func TestFleetCapacityHTTPProductionWorkerPersistsUnknownWithoutInventingPopulation(t *testing.T) {
	f, _, evaluator, proposals := newFleetCapacityHTTPTest(t)
	owner := f.token(f.tenant, "assigned-owner", "APPLICATION_OWNER")
	body := model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]}
	code, queued, _ := f.request("workloads/fixture-workload/fleet-native-capacity-batches", `"1"`, "capacity-real-worker", owner, body)
	if code != 202 {
		t.Fatal("queue actual worker request", code, queued)
	}
	c := fleetcapacityworker.Config{Archive: fleetassessmentworker.Config{Enabled: true, TenantID: f.tenant, DatabaseFile: "/run/secrets/database", ArchiveMode: fleetassessmentworker.LocalArchive, ArchiveRegion: "eu-west-1", ArchiveEndpoint: "http://minio:9000", ArchiveBucket: "fixture-raw", ArchiveAccessKeyFile: "/run/secrets/access", ArchiveSecretKeyFile: "/run/secrets/secret"}, ServiceMode: fleetcapacityworker.PrivateServices, ReaderURL: "http://telemetry-reader:8095", ReaderTokenFile: "/run/secrets/reader", ModelURL: "http://economics:8000", ModelTokenFile: "/run/secrets/model"}
	x := &fleetCapacityUnexpectedTransport{}
	w, e := fleetcapacityworker.New(context.Background(), c, evaluator, x, x, x)
	if e != nil {
		t.Fatal("actual capacity identity rejected", e)
	}
	defer w.Close()
	id := model.String(queued, "id")
	result, e := w.Process(context.Background(), id)
	if e != nil || result.Existing || result.Members != 0 || result.ExecutionAuthorized || x.calls != 0 {
		t.Fatal("missing native evidence became an invented population", result, e, x.calls)
	}
	code, issued := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id, owner)
	batch := sourceDocument(issued["batch"])
	if code != 200 || model.String(issued, "status") != "ASSESSED" || model.String(batch, "coverage") != "UNAVAILABLE" || model.Bool(batch, "group_capacity_authorized") || batch["verified_saving"] != nil {
		t.Fatal("public persisted missing-evidence boundary differs", code, issued)
	}
	if replay, e := w.Process(context.Background(), id); e != nil || !replay.Existing || x.calls != 0 {
		t.Fatal("completed worker replay re-read mutable inputs", replay, e, x.calls)
	}
}

func TestFleetCapacityHTTPIDsOnlyRolesCASPaginationAndCurrentReplayScope(t *testing.T) {
	f, _, _, proposals := newFleetCapacityHTTPTest(t)
	path := "workloads/fixture-workload/fleet-native-capacity-batches"
	body := model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]}
	owner := f.token(f.tenant, "assigned-owner", "APPLICATION_OWNER")
	platform := f.token(f.tenant, "capacity-platform", "PLATFORM_ADMIN")
	auditor := f.token(f.tenant, "capacity-auditor", "AUDITOR")
	for _, role := range []string{"FINANCE", "AUDITOR", "VIEWER", "APPROVER"} {
		if code, _, _ := f.request(path, `"1"`, "capacity-denied-"+role, f.token(f.tenant, "assigned-owner", role), body); code != 403 {
			t.Fatal("capacity creation bypassedrole", role, code)
		}
	}
	if code, _, _ := f.request(path, `"1"`, "capacity-other-owner", f.token(f.tenant, "unassigned-owner", "APPLICATION_OWNER"), body); code != 403 {
		t.Fatal("unassigned owner queued batch", code)
	}
	code, request, _ := f.request(path, `"1"`, "capacity-once", owner, body)
	if code != 202 || model.String(request, "status") != "QUEUED" || request["scope"] != nil || request["batch"] != nil {
		t.Fatal("capacity request fabricated evaluation", code, request)
	}
	id := model.String(request, "id")
	if code, d, _ := f.request(path, `"0"`, "capacity-once", owner, body); code != 202 || d["id"] != id {
		t.Fatal("exact replay changed request", code)
	}
	if code, _, _ := f.request(path, `"1"`, "capacity-once", f.token(f.tenant, "assigned-owner", "VIEWER"), body); code != 403 {
		t.Fatal("cached replay bypassed currentrole", code)
	}
	for _, field := range []string{"scope", "source_id", "hardware", "candidate_template", "model_evaluation", "capacity_suitable", "execution_authorized", "estimated_saving"} {
		bad := model.Clone(body)
		bad[field] = true
		if code, _, _ := f.request(path, `"1"`, "capacity-forged-"+field, owner, bad); code != 422 {
			t.Fatal("caller supplied capacity authority", field, code)
		}
	}
	if code, _, _ := f.request(path, `"2"`, "capacity-profile-cas", owner, body); code != 409 {
		t.Fatal("current safety profile CAS ignored", code)
	}
	if code, _, _ := f.request(path, `"1"`, "capacity-second", platform, body); code != 202 {
		t.Fatal("secondcapacityrequest", code)
	}
	code, page := fleetNativeHTTPGet(t, f, path+"?limit=1", auditor)
	if code != 200 || len(page["items"].([]any)) != 1 || page["next_cursor"] == nil {
		t.Fatal("capacity native pagination absent", code, page)
	}
	cursor := url.QueryEscape(model.String(page, "next_cursor"))
	if code, next := fleetNativeHTTPGet(t, f, path+"?limit=1&cursor="+cursor, auditor); code != 200 || len(next["items"].([]any)) != 1 {
		t.Fatal("capacity secondpage", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "workloads/workload-dev/fleet-native-capacity-batches?cursor="+cursor, auditor); code != 422 {
		t.Fatal("capacitycursor escapedworkload", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id, f.token(f.tenant+"-foreign", "capacity-platform", "PLATFORM_ADMIN")); code != 404 {
		t.Fatal("foreigncapacityrecordvisible", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id+"/members?limit=1", auditor); code != 200 {
		t.Fatal("queuedcapacitymembers page unavailable", code)
	}
	if e := f.roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		w, e := tx.Get(context.Background(), "workloads", "fixture-workload")
		if e != nil {
			return e
		}
		w["owner"] = "replacement-owner"
		_, e = tx.Update(context.Background(), "workloads", "fixture-workload", model.Number(w, "version"), w)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := f.request(path, `"1"`, "capacity-once", owner, body); code != 403 {
		t.Fatal("cachedcapacityresponse ignored currentownership", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id, owner); code != 403 {
		t.Fatal("historicalcapacityread ignored currentownership", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id, auditor); code != 200 {
		t.Fatal("auditorlostreadonlyhistoricalrecord", code)
	}
}
