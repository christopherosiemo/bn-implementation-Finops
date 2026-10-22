package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

type configurationFixture struct {
	t          *testing.T
	db         *store.Store
	tenant     string
	api        *API
	identity   auth.Identity
	profile    model.Document
	connection model.Document
	assessment model.Document
}

func newConfigurationFixture(t *testing.T) *configurationFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	f := &configurationFixture{t: t, db: db, tenant: "configuration-" + model.ID()}
	f.api = &API{Store: db}
	f.identity = auth.Identity{Tenant: f.tenant, Subject: "platform-operator", Roles: map[string]bool{"PLATFORM_ADMIN": true}}
	if err = f.do(func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
		var e error
		f.profile, e = tx.WorkloadSafetyAppend(ctx, "workload-dev", 0, p)
		if e != nil {
			return e
		}
		r, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		c := telemetry.Connection{SchemaVersion: "1", ID: model.ID(), Version: 1, Kind: "PROMETHEUS", ReadBindingID: "registered-read-binding", Enabled: true, Binding: telemetry.Binding{TenantID: f.tenant, WorkloadID: "workload-dev", ResourceID: "resource-dev-api", Provider: model.String(r, "provider"), ProviderResourceID: model.String(r, "provider_resource_id"), AccountID: model.String(r, "account_id"), Region: model.String(r, "region")}, Definitions: []telemetry.Definition{{ID: "cpu", Version: "1", Metric: "cpu_utilization", Name: "cpu_utilization", Unit: "ratio", Type: "GAUGE", CadenceSeconds: 60, MaxGapSeconds: 120, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}}}}
		f.connection, e = tx.TelemetryConnectionAppend(ctx, c.ID, 0, telemetry.Document(c))
		if e != nil {
			return e
		}
		f.assessment, e = tx.CapacityAssessmentCreate(ctx, model.Document{"schema_version": "1", "workload_id": "workload-dev", "resource_id": "resource-dev-api", "connection_id": c.ID, "connection_version": int64(1), "revision_id": f.connection["revision_id"], "config_hash": f.connection["config_hash"], "safety_profile_id": f.profile["id"], "safety_profile_version": f.profile["version"], "safety_profile_hash": f.profile["hash"], "population_hash": strings.Repeat("a", 64), "receipt_ids": []string{}, "source_refs": []any{}, "status": "BLOCKED", "reason_codes": []string{"BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED", "NATIVE_PRICE_UNAVAILABLE"}, "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *configurationFixture) do(fn func(*store.Tx) error) error {
	return f.db.Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		if _, err := tx.Exec(context.Background(), "SET LOCAL ROLE finops_api"); err != nil {
			return err
		}
		return fn(tx)
	})
}
func configurationRequest() model.Document {
	d := configuration.Declaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: configuration.Repository{URL: "https://github.com/example/infrastructure.git", Ref: "main", Directory: "envs/dev"}, Pipeline: configuration.Pipeline{System: "GITHUB_ACTIONS", Identity: configuration.PipelineIdentity{Issuer: "https://token.actions.githubusercontent.com", Audience: configuration.ObserverAudience, Subject: "repo:example/infrastructure:ref:refs/heads/main", PipelineID: ".github/workflows/deploy.yml"}}, Terraform: configuration.Terraform{Workspace: "dev-eu", StateLineage: "0f5a34b0-a480-4cda-9f6a-9b205ced7937", Addresses: []string{`module.api["dev"].aws_instance.api[0]`}}}
	return configuration.DeclarationDocument(d)
}
func (f *configurationFixture) mutate(path, version string, in model.Document, who auth.Identity) (model.Document, error) {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	if version != "" {
		r.Header.Set("If-Match", version)
	}
	var out model.Document
	err := f.db.Do(context.Background(), who.Tenant, func(tx *store.Tx) error {
		if _, err := tx.Exec(context.Background(), "SET LOCAL ROLE finops_api"); err != nil {
			return err
		}
		var err error
		var status int
		var handled bool
		out, status, handled, err = f.api.configurationMutate(context.Background(), tx, who, r, in, strings.Split(strings.TrimPrefix(path, "/v1/"), "/"))
		if err == nil && (!handled || status != 201) {
			f.t.Fatal("configuration mutation not handled")
		}
		return err
	})
	return out, err
}
func (f *configurationFixture) authority() model.Document {
	f.t.Helper()
	out, err := f.mutate("/v1/resources/resource-dev-api/configuration-authorities", `"0"`, configurationRequest(), f.identity)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func TestConfigurationDeclarationsBindCurrentInventoryWithoutAttestation(t *testing.T) {
	f := newConfigurationFixture(t)
	ctx := context.Background()
	path := "/v1/resources/resource-dev-api/configuration-authorities"
	for _, field := range []string{"observed_commit", "proof_set_id", "execution_authorized", "credentials"} {
		body := configurationRequest()
		body[field] = "forbidden"
		if _, err := f.mutate(path, `"0"`, body, f.identity); err == nil {
			t.Fatalf("accepted caller %s", field)
		}
	}
	viewer := f.identity
	viewer.Roles = map[string]bool{"VIEWER": true}
	if _, err := f.mutate(path, `"0"`, configurationRequest(), viewer); err == nil {
		t.Fatal("viewer declared authority")
	}
	if _, err := f.mutate(path, "", configurationRequest(), f.identity); err == nil {
		t.Fatal("missing optimistic version accepted")
	}
	a := f.authority()
	if model.String(a, "status") != "DECLARED_NOT_ATTESTED" || model.Bool(a, "execution_authorized") || a["observed_commit"] != nil || a["observed_state_serial"] != nil {
		t.Fatal("declaration became observation", a)
	}
	if _, err := f.mutate(path, `"0"`, configurationRequest(), f.identity); !errors.Is(err, store.ErrConflict) {
		t.Fatal("concurrent stale revision accepted", err)
	}
	if err := f.do(func(tx *store.Tx) error {
		r, err := tx.Get(ctx, "resources", "resource-dev-api")
		if err != nil {
			return err
		}
		var b configuration.Binding
		raw, _ := json.Marshal(a["binding"])
		_ = json.Unmarshal(raw, &b)
		if b.TenantID != f.tenant || b.ResourceVersion != model.Number(r, "version") || b.ResourceSnapshotHash != telemetry.Hash(r) || b.AccountID != model.String(r, "account_id") {
			t.Fatal("resource identity was not server-selected")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.do(func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE configuration_authority_revisions SET document=document||'{\"execution_authorized\":true}' WHERE tenant_id=$1", f.tenant)
		return err
	}); err == nil {
		t.Fatal("immutable revision updated")
	}
	// Separate role/transaction so SQL errors cannot accidentally validate a
	// later assertion in an already-aborted transaction.
	assertDeclarationDenied := func(role, statement string) {
		t.Helper()
		err := f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			_, e := tx.Exec(ctx, statement)
			return e
		})
		var state interface{ SQLState() string }
		if !errors.As(err, &state) || state.SQLState() != "42501" {
			t.Fatalf("declaration privilege for %s was not denied with 42501: %v", role, err)
		}
	}
	for _, role := range []string{"finops_ingester", "finops_telemetry_reader"} {
		assertDeclarationDenied(role, "SELECT document FROM configuration_authority_revisions")
	}
	// Forward EC2 safety readers may inspect only the immutable declaration
	// metadata selected by migration 042; the declaration still conveys no
	// attestation, mutation or cross-tenant authority.
	for _, role := range []string{"finops_worker", "finops_signer", "finops_executor"} {
		var tenant, resource, hash string
		var version int64
		var document, snapshot []byte
		if err := f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			return tx.QueryRow(ctx, "SELECT tenant_id,resource_id,version,document,resource_snapshot,content_hash FROM configuration_authority_revisions WHERE tenant_id=$1 AND resource_id=$2", f.tenant, "resource-dev-api").Scan(&tenant, &resource, &version, &document, &snapshot, &hash)
		}); err != nil {
			t.Fatalf("permitted declaration metadata unavailable for %s: %v", role, err)
		}
		var observed, retained model.Document
		if err := json.Unmarshal(document, &observed); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(snapshot, &retained); err != nil {
			t.Fatal(err)
		}
		var binding struct {
			Binding configuration.Binding `json:"binding"`
		}
		if err := json.Unmarshal(document, &binding); err != nil {
			t.Fatal(err)
		}
		if tenant != f.tenant || resource != "resource-dev-api" || version != model.Number(a, "version") || hash != model.String(a, "hash") || telemetry.Hash(observed) != telemetry.Hash(a) || binding.Binding.TenantID != tenant || binding.Binding.ResourceID != resource || binding.Binding.ResourceVersion != model.Number(retained, "version") || binding.Binding.ResourceSnapshotHash != telemetry.Hash(retained) {
			t.Fatalf("declaration metadata binding changed for %s", role)
		}
		if err := f.db.Do(ctx, "other-tenant-"+model.ID(), func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			var count int64
			if e := tx.QueryRow(ctx, "SELECT count(document) FROM configuration_authority_revisions WHERE tenant_id=$1 AND resource_id=$2", f.tenant, resource).Scan(&count); e != nil {
				return e
			}
			if count != 0 {
				t.Fatalf("cross-tenant declaration metadata visible to %s", role)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, column := range []string{"id", "workload_id", "resource_version", "resource_snapshot_hash", "writer_role", "created_at"} {
			assertDeclarationDenied(role, "SELECT "+column+" FROM configuration_authority_revisions WHERE false")
		}
		for _, statement := range []string{
			"INSERT INTO configuration_authority_revisions (tenant_id,resource_id,version,document,resource_snapshot,content_hash) SELECT tenant_id,resource_id,version,document,resource_snapshot,content_hash FROM configuration_authority_revisions WHERE false",
			"UPDATE configuration_authority_revisions SET document=document WHERE false",
			"DELETE FROM configuration_authority_revisions WHERE false",
		} {
			assertDeclarationDenied(role, statement)
		}
	}
	if err := f.db.Do(ctx, "other-tenant-"+model.ID(), func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		rows, e := tx.ConfigurationAuthorityPage(ctx, "resource-dev-api", "", 10)
		if len(rows) != 0 {
			t.Fatal("cross-tenant authority visible")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationProposalSelectsBlockedEvidenceAndRejectsSupersededBindings(t *testing.T) {
	f := newConfigurationFixture(t)
	ctx := context.Background()
	a := f.authority()
	path := "/v1/workloads/workload-dev/configuration-proposals"
	body := model.Document{"authority_id": a["id"], "capacity_assessment_id": f.assessment["id"]}
	for _, field := range []string{"patch", "estimated_saving", "change_plan_id", "source_refs", "proof_set_id"} {
		in := model.Clone(body)
		in[field] = "forbidden"
		if _, err := f.mutate(path, `"1"`, in, f.identity); err == nil {
			t.Fatalf("accepted caller proposal %s", field)
		}
	}
	out, err := f.mutate(path, `"1"`, body, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	if model.String(out, "status") != "BLOCKED" || model.Bool(out, "execution_authorized") || out["estimated_saving"] != nil || out["verified_saving"] != nil || out["change_plan_id"] != nil || model.String(out, "capacity_assessment_hash") != model.String(f.assessment, "hash") {
		t.Fatal("blocked proposal gained authority or fabricated money", out)
	}
	readProposal := func() model.Document {
		t.Helper()
		var result any
		err := f.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
				return e
			}
			var handled bool
			var e error
			result, handled, e = f.api.configurationGet(ctx, tx, f.identity, httptest.NewRequest(http.MethodGet, path+"/"+model.String(out, "id"), nil))
			if e == nil && !handled {
				return errors.New("configuration proposal detail was not handled")
			}
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		return result.(model.Document)
	}
	current := readProposal()
	currentness := model.Doc(current["review_currentness"])
	if model.String(currentness, "status") != "CURRENT" || model.String(currentness, "repository_revision_status") != "UNBOUND" || model.String(currentness, "review_status") != "BLOCKED" || model.Bool(currentness, "execution_authorized") {
		t.Fatal("current evidence was confused with a reviewable or executable IaC proposal", currentness)
	}
	if _, err = f.mutate(path, `"0"`, body, f.identity); err == nil {
		t.Fatal("stale authority If-Match accepted")
	}
	// Resource changes invalidate a declaration even when cloud identity stays
	// unchanged; no stale proposal is silently rebound to the new resource.
	if err = f.do(func(tx *store.Tx) error {
		r, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		r["name"] = "updated-name"
		_, e = tx.Update(ctx, "resources", "resource-dev-api", model.Number(r, "version"), r)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	stale := model.Doc(readProposal()["review_currentness"])
	if model.String(stale, "status") != "STALE" || !strings.Contains(strings.Join(model.Strings(stale, "reason_codes"), ","), "RESOURCE_CONFIGURATION_CHANGED") {
		t.Fatal("changed resource configuration did not stale the review projection", stale)
	}
	if _, err = f.mutate(path, `"1"`, body, f.identity); err == nil {
		t.Fatal("stale resource declaration reused")
	}
	newAuthority, err := f.mutate("/v1/resources/resource-dev-api/configuration-authorities", `"1"`, configurationRequest(), f.identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate(path, `"1"`, body, f.identity); !errors.Is(err, store.ErrConflict) {
		t.Fatal("superseded authority ID accepted", err)
	}
	body["authority_id"] = newAuthority["id"]
	if err = f.do(func(tx *store.Tx) error {
		p, e := parseSafetyProfile(f.profile)
		if e != nil {
			return e
		}
		p.MinReplicas = 2
		_, e = tx.WorkloadSafetyAppend(ctx, "workload-dev", 1, p)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate(path, `"2"`, body, f.identity); err == nil {
		t.Fatal("assessment from superseded requirements reused")
	}
	if err = f.do(func(tx *store.Tx) error {
		rows, e := tx.ConfigurationProposalPage(ctx, "workload-dev", "", 10)
		if e == nil && len(rows) != 1 {
			t.Fatal("rejected attempts appended proposals")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationScopedReadsAndCursorsDoNotRevealOtherWorkloads(t *testing.T) {
	f := newConfigurationFixture(t)
	ctx := context.Background()
	f.authority()
	owner := auth.Identity{Tenant: f.tenant, Subject: "unrelated-owner", Email: "other@example.test", Roles: map[string]bool{"APPLICATION_OWNER": true}}
	read := func(path string, who auth.Identity) (any, error) {
		var out any
		err := f.db.Do(ctx, who.Tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
				return e
			}
			var e error
			var handled bool
			out, handled, e = f.api.configurationGet(ctx, tx, who, httptest.NewRequest(http.MethodGet, path, nil))
			if e == nil && !handled {
				t.Fatal("unhandled configuration GET")
			}
			return e
		})
		return out, err
	}
	if _, err := read("/v1/resources/resource-dev-api/configuration-authorities", owner); err == nil {
		t.Fatal("unscoped application owner read declaration")
	}
	if _, err := read("/v1/workloads/workload-dev/configuration-proposals", owner); err == nil {
		t.Fatal("unscoped application owner read proposals")
	}
	out, err := read("/v1/resources/resource-dev-api/configuration-authorities?limit=1", f.identity)
	if err != nil {
		t.Fatal(err)
	}
	page := out.(model.Document)
	if model.Number(page, "version") != 1 || page["latest"] == nil || len(page["items"].([]model.Document)) != 1 {
		t.Fatal("versioned declaration page missing", page)
	}
	if _, err := read("/v1/resources/resource-dev-api/configuration-authorities?cursor=not-a-cursor", f.identity); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}

func TestConfigurationSQLBoundaryRejectsForgedAttestationAndProposalAuthority(t *testing.T) {
	f := newConfigurationFixture(t)
	ctx := context.Background()
	a := f.authority()
	for name, mutate := range map[string]func(model.Document){
		"operator observed commit": func(d model.Document) { d["observed_commit"] = strings.Repeat("a", 40) },
		"operator observed state":  func(d model.Document) { d["observed_state_serial"] = 12 },
		"authority flag":           func(d model.Document) { d["execution_authorized"] = true },
		"arbitrary plan":           func(d model.Document) { d["change_plan_id"] = "forged" },
		"pipeline credential":      func(d model.Document) { d["pipeline"].(map[string]any)["secret"] = "not-allowed" },
		"reserved audience": func(d model.Document) {
			d["pipeline"].(map[string]any)["identity"].(map[string]any)["audience"] = "finops"
		},
		"missing system": func(d model.Document) { delete(d["pipeline"].(map[string]any), "system") },
		"data address": func(d model.Document) {
			d["terraform"].(map[string]any)["addresses"] = []string{"data.aws_instance.api"}
		},
		"missing trust blockers": func(d model.Document) { d["reason_codes"] = []string{} },
	} {
		t.Run(name, func(t *testing.T) {
			err := f.do(func(tx *store.Tx) error {
				d := model.Clone(a)
				for _, key := range []string{"tenant_id", "hash", "created_at", "writer_role"} {
					delete(d, key)
				}
				d["id"], d["version"] = model.ID(), 2
				mutate(d)
				r, err := tx.Get(ctx, "resources", "resource-dev-api")
				if err != nil {
					return err
				}
				raw, _ := json.Marshal(d)
				snapshot, _ := json.Marshal(r)
				_, err = tx.Exec(ctx, "INSERT INTO configuration_authority_revisions(tenant_id,id,resource_id,workload_id,version,resource_version,resource_snapshot_hash,resource_snapshot,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", f.tenant, d["id"], "resource-dev-api", "workload-dev", 2, model.Number(r, "version"), telemetry.Hash(r), snapshot, telemetry.Hash(d), raw)
				return err
			})
			if err == nil {
				t.Fatal("SQL boundary accepted forged declaration")
			}
		})
	}
	proposal, err := f.mutate("/v1/workloads/workload-dev/configuration-proposals", `"1"`, model.Document{"authority_id": a["id"], "capacity_assessment_id": f.assessment["id"]}, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(model.Document){
		"money":              func(d model.Document) { d["estimated_saving"] = "123.45" },
		"verification":       func(d model.Document) { d["verified_saving"] = "1" },
		"plan":               func(d model.Document) { d["change_plan_id"] = "forged" },
		"patch":              func(d model.Document) { d["patch"] = "arbitrary patch" },
		"authority":          func(d model.Document) { d["execution_authorized"] = true },
		"profile binding":    func(d model.Document) { d["safety_profile_version"] = 999 },
		"assessment binding": func(d model.Document) { d["capacity_assessment_hash"] = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			err := f.do(func(tx *store.Tx) error {
				d := model.Clone(proposal)
				for _, key := range []string{"id", "tenant_id", "hash", "created_at", "writer_role"} {
					delete(d, key)
				}
				mutate(d)
				raw, _ := json.Marshal(d)
				_, err := tx.Exec(ctx, "INSERT INTO configuration_proposals(tenant_id,id,workload_id,resource_id,authority_id,capacity_assessment_id,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", f.tenant, model.ID(), "workload-dev", "resource-dev-api", a["id"], f.assessment["id"], telemetry.Hash(d), raw)
				return err
			})
			if err == nil {
				t.Fatal("SQL boundary accepted forged proposal")
			}
		})
	}
	if err = f.do(func(tx *store.Tx) error {
		_, _, err := tx.TelemetryRevocationAppend(ctx, model.String(f.connection, "revision_id"), "source removed")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.mutate("/v1/workloads/workload-dev/configuration-proposals", `"1"`, model.Document{"authority_id": a["id"], "capacity_assessment_id": f.assessment["id"]}, f.identity); err == nil {
		t.Fatal("revoked capacity source reused")
	}
}

func TestConfigurationHistoryCursorsPreserveNewestFirstAndExactScope(t *testing.T) {
	f := newConfigurationFixture(t)
	ctx := context.Background()
	f.authority()
	for _, version := range []string{`"1"`, `"2"`} {
		if _, err := f.mutate("/v1/resources/resource-dev-api/configuration-authorities", version, configurationRequest(), f.identity); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) (model.Document, error) {
		var page model.Document
		err := f.do(func(tx *store.Tx) error {
			out, handled, err := f.api.configurationGet(ctx, tx, f.identity, httptest.NewRequest(http.MethodGet, path, nil))
			if err != nil {
				return err
			}
			if !handled {
				t.Fatal("page not handled")
			}
			page = out.(model.Document)
			return nil
		})
		return page, err
	}
	first, err := read("/v1/resources/resource-dev-api/configuration-authorities?limit=1")
	if err != nil {
		t.Fatal(err)
	}
	rows := first["items"].([]model.Document)
	if model.Number(first, "version") != 3 || len(rows) != 1 || model.Number(rows[0], "version") != 3 || first["next_cursor"] == nil {
		t.Fatal("latest revision or cursor missing", first)
	}
	cursor := first["next_cursor"].(string)
	second, err := read("/v1/resources/resource-dev-api/configuration-authorities?limit=1&cursor=" + cursor)
	if err != nil {
		t.Fatal(err)
	}
	rows = second["items"].([]model.Document)
	if model.Number(second, "version") != 3 || len(rows) != 1 || model.Number(rows[0], "version") != 2 {
		t.Fatal("history lost order or latest binding", second)
	}
	if _, err := read("/v1/workloads/workload-dev/configuration-proposals?limit=1&cursor=" + cursor); err == nil {
		t.Fatal("authority cursor accepted for proposal scope")
	}
}
