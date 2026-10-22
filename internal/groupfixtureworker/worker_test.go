package groupfixtureworker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	p "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fixtureConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{Enabled: true, Mode: g.IsolatedFixture, TenantID: "tenant-worker", ProposalID: "proposal-worker", DatabaseFile: filepath.Join(dir, "database"), InstallationFile: filepath.Join(dir, "installation"), PipelinePublicKeyFile: filepath.Join(dir, "pipeline-public"), LedgerPublicKeyFile: filepath.Join(dir, "ledger-public"), ArchiveKeyFile: filepath.Join(dir, "archive-key"), S3Endpoint: "http://minio:9000", S3Region: "eu-west-1", S3Bucket: "fixture-artifacts", S3AccessKeyFile: filepath.Join(dir, "access"), S3SecretKeyFile: filepath.Join(dir, "secret")}
}

func TestConfigIsExplicitFixtureOnlyAndPrivate(t *testing.T) {
	c := fixtureConfig(t)
	if c.Validate() != nil {
		t.Fatal("valid private configuration refused")
	}
	for name, mutate := range map[string]func(*Config){"disabled": func(c *Config) { c.Enabled = false }, "customerrealm": func(c *Config) { c.Mode = "CUSTOMER_NATIVE" }, "region": func(c *Config) { c.S3Region = "us-east-1" }, "missingtenant": func(c *Config) { c.TenantID = "" }, "pathinproposal": func(c *Config) { c.ProposalID = "../proposal" }, "relativefile": func(c *Config) { c.DatabaseFile = "relative" }, "samepublickeysfile": func(c *Config) { c.PipelinePublicKeyFile = c.LedgerPublicKeyFile }, "samesecretfile": func(c *Config) { c.ArchiveKeyFile = c.S3SecretKeyFile }, "publics3ip": func(c *Config) { c.S3Endpoint = "http://8.8.8.8:9000" }, "awsendpoint": func(c *Config) { c.S3Endpoint = "https://s3.eu-west-1.amazonaws.com:443" }, "urlcredentials": func(c *Config) { c.S3Endpoint = "http://user:secret@minio:9000" }, "urlpath": func(c *Config) { c.S3Endpoint = "http://minio:9000/bucket" }, "urlquery": func(c *Config) { c.S3Endpoint = "http://minio:9000?key=secret" }, "bucketpath": func(c *Config) { c.S3Bucket = "bucket/other" }} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	if _, err := ConfigFromEnvironment(func(string) string { return "" }); err == nil {
		t.Fatal("ambient defaults enabled process")
	}
}

func TestForbiddenAmbientAuthorityAndPrivateNetworks(t *testing.T) {
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_WEB_IDENTITY_TOKEN_FILE", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "GCP_TOKEN", "ARM_CLIENT_SECRET", "TF_VAR_instances", "TF_CLI_ARGS_plan", "TF_TOKEN_example", "DOCKER_HOST", "PGPASSWORD", "PGPASSFILE", "PGSSLKEY", "PGSERVICE", "SIGNING_KEY_FILE", "EXECUTOR_TOKEN"} {
		if checkEnvironment([]string{name + "=must-not-be-used"}) == nil {
			t.Fatalf("ambient authority accepted: %s", name)
		}
	}
	if checkEnvironment([]string{"PATH=/usr/bin", "GROUP_FIXTURE_ARCHIVE_KEY_FILE=/run/secrets/key"}) != nil {
		t.Fatal("explicit private file denied")
	}
	for _, address := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.2", "192.168.1.5"} {
		if !localAddress(net.ParseIP(address)) {
			t.Fatal("private address denied")
		}
	}
	for _, address := range []string{"8.8.8.8", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1", "2001:4860:4860::8888"} {
		if localAddress(net.ParseIP(address)) {
			t.Fatal("non-private address accepted")
		}
	}
	for _, dsn := range []string{"postgres://u:private@8.8.8.8/db?sslmode=disable", "postgres://u:private@127.0.0.1/db", "postgres://u:private@127.0.0.1/db?sslmode=require", "postgres://u:private@127.0.0.1/db?sslmode=disable&role=finops_api", "postgres://u:private@127.0.0.1/db?sslmode=disable&options=-crole%3Dfinops_api", "postgres://u@127.0.0.1/db?sslmode=disable"} {
		if _, err := privateDatabase(t.Context(), []byte(dsn)); err == nil {
			t.Fatal("unsafe DSN accepted")
		}
	}
	dsn, err := privateDatabase(t.Context(), []byte("postgres://restricted:private@127.0.0.1:5432/owned?sslmode=disable&pool_max_conns=1"))
	if err != nil || !strings.Contains(dsn, "pool_max_conns=2") {
		t.Fatal("dedicated two-connection fixture DSN unavailable")
	}
}

// This optional acceptance creates only its own marked child database/login;
// it applies no migration and never writes the administrator's database. The
// caller supplies a disposable test cluster where029's role already exists.
func TestPreparerActualDedicatedDatabaseIdentityAndJobFence(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("disposable PostgreSQL acceptance not configured")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal("disposable administrator unavailable")
	}
	t.Cleanup(admin.Close)
	var roleExists bool
	if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_group_fixture')`).Scan(&roleExists); err != nil {
		t.Fatal("cannot inspect disposable role")
	}
	if !roleExists {
		t.Skip("029 group fixture role must be commissioned in disposable cluster")
	}
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database := "group_preparer_" + suffix
	login := "preparer_login_" + suffix
	marker := "owned-group-preparer-" + suffix
	qDatabase, qLogin := pgx.Identifier{database}.Sanitize(), pgx.Identifier{login}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+qDatabase); err != nil {
		t.Fatal("cannot create isolated child database")
	}
	if _, err = admin.Exec(ctx, "COMMENT ON DATABASE "+qDatabase+" IS '"+marker+"'"); err != nil {
		t.Fatal("cannot mark isolated database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		var actual string
		if e := admin.QueryRow(cleanup, `SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1`, database).Scan(&actual); e != nil || actual != marker {
			t.Error("database cleanup ownership mismatch")
			return
		}
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+qDatabase+" WITH (FORCE)"); e != nil {
			t.Error("cannot remove owned child database")
		}
		if e := admin.QueryRow(cleanup, `SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1`, login).Scan(&actual); e == nil && actual == marker {
			if _, e = admin.Exec(cleanup, "DROP ROLE "+qLogin); e != nil {
				t.Error("cannot remove owned dedicated login")
			}
		} else if e == nil {
			t.Error("role cleanup ownership mismatch")
		}
	})
	password := model.ID() + model.ID()
	if _, err = admin.Exec(ctx, "CREATE ROLE "+qLogin+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_fixture"); err != nil {
		t.Fatal("cannot create dedicated child login")
	}
	if _, err = admin.Exec(ctx, "COMMENT ON ROLE "+qLogin+" IS '"+marker+"'"); err != nil {
		t.Fatal("cannot mark dedicated child login")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("test URL unavailable")
	}
	u.Path = "/" + database
	u.User = url.UserPassword(login, password)
	q := u.Query()
	q.Set("pool_max_conns", "2")
	u.RawQuery = q.Encode()
	db, err := store.OpenRuntime(ctx, u.String(), "group-fixture")
	if err != nil {
		t.Fatal("actual dedicated preparer identity refused")
	}
	var session, current string
	if err = db.Pool.QueryRow(ctx, `SELECT session_user,current_user`).Scan(&session, &current); err != nil || session != login || current != "finops_group_fixture" {
		db.Pool.Close()
		t.Fatal("runtime did not retain authenticated/group identity")
	}
	repository := postgresRepository{db}
	release, err := repository.lock(ctx, "tenant-isolated", "proposal-isolated")
	if err != nil {
		db.Pool.Close()
		t.Fatal("cannot acquire actual job fence")
	}
	if _, e := repository.lock(ctx, "tenant-isolated", "proposal-isolated"); !errors.Is(e, ErrBusy) {
		release()
		db.Pool.Close()
		t.Fatal("parallel same-job delivery was not refused")
	}
	release()
	release, err = repository.lock(ctx, "tenant-isolated", "proposal-isolated")
	if err != nil {
		db.Pool.Close()
		t.Fatal("committed job fence was not released")
	}
	release()
	db.Pool.Close()
	for _, extra := range []string{"finops_api", "pg_read_all_data"} {
		if _, err = admin.Exec(ctx, "GRANT "+pgx.Identifier{extra}.Sanitize()+" TO "+qLogin); err != nil {
			t.Fatal("cannot construct mixed identity negative")
		}
		bad, e := store.OpenRuntime(ctx, u.String(), "group-fixture")
		if bad != nil {
			bad.Pool.Close()
		}
		if e == nil {
			t.Fatal("mixed authenticated identity accepted")
		}
		if _, err = admin.Exec(ctx, "REVOKE "+pgx.Identifier{extra}.Sanitize()+" FROM "+qLogin); err != nil {
			t.Fatal("cannot restore owned login membership")
		}
	}
	q = u.Query()
	q.Set("options", "-c role=finops_group_fixture")
	u.RawQuery = q.Encode()
	bad, e := store.OpenRuntime(ctx, u.String(), "group-fixture")
	if bad != nil {
		bad.Pool.Close()
	}
	if e == nil {
		t.Fatal("startup identity override accepted")
	}
}

func TestPrivateFileRefusesSymlinksPermissionsAndOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("fixture-private-value"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := privateFile(path, 32); err != nil || string(raw) != "fixture-private-value" {
		t.Fatal("private file not read")
	}
	if _, err := privateFile(path, 4); err == nil {
		t.Fatal("oversize private file accepted")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err = privateFile(link, 32); err == nil {
			t.Fatal("symlink accepted")
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := privateFile(path, 32); err == nil {
		t.Fatal("world-readable credential accepted")
	}
}

type archiveDouble struct{}

func (archiveDouble) Put(context.Context, ff.Proposal, string, []byte) (ff.ArtifactReference, error) {
	return ff.ArtifactReference{}, errors.New("unit factory never archives native proof")
}

type repositoryDouble struct {
	selected                                  ff.Proposal
	mapping                                   g.ModelMapping
	doc                                       model.Document
	existing                                  bool
	busy                                      bool
	changed                                   bool
	locks, releases, reads, currents, appends int
}

func (r *repositoryDouble) lock(context.Context, string, string) (func(), error) {
	r.locks++
	if r.busy {
		return nil, ErrBusy
	}
	return func() { r.releases++ }, nil
}
func (r *repositoryDouble) prepared(context.Context, string, string) (model.Document, error) {
	r.reads++
	if r.existing {
		return r.doc, nil
	}
	return nil, pgx.ErrNoRows
}
func (r *repositoryDouble) current(context.Context, string, string) (ff.Proposal, g.ModelMapping, error) {
	r.currents++
	return r.selected, r.mapping, nil
}
func (r *repositoryDouble) append(_ context.Context, _ string, selected ff.Proposal, mapping g.ModelMapping, _ ff.Preparation) (model.Document, error) {
	r.appends++
	if r.changed || g.Digest(selected) != g.Digest(r.selected) || mapping != r.mapping {
		return nil, ff.ErrCurrent
	}
	return r.doc, nil
}

func fixtureWorker(t *testing.T) (*Worker, *repositoryDouble, *int) {
	t.Helper()
	c := fixtureConfig(t)
	hash := strings.Repeat("a", 64)
	side := func(name, uuid string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: c.TenantID, WorkloadID: "workload-worker", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: "fleet-" + name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:" + uuid + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: "registration-" + name, Version: 1, SHA256: hash}, Declaration: g.VersionedRef{ID: "declaration-" + name, Version: 1, SHA256: hash}, Scope: g.SnapshotRef{ID: "scope-" + name, SHA256: hash}, SourceID: "source-worker", SourceRegistrationVersion: 1, SourceConfigSHA256: hash}
	}
	installed := Installation{SchemaVersion: "1", ProfileID: "profile-worker", Generation: "generation-worker", ToolchainImageSHA256: hash, TerraformVersion: "1.16.0", ReceiptID: "private-installation", SourceSHA256: hash}
	selected := ff.Proposal{ID: c.ProposalID, Binding: g.Binding{Old: side("old", "11111111-1111-1111-1111-111111111111"), Candidate: side("candidate", "22222222-2222-2222-2222-222222222222")}, Realm: g.Realm{Kind: g.IsolatedFixture, FixtureID: installed.ProfileID, Generation: installed.Generation, ModelSHA256: hash}, Profile: ff.Profile{ID: installed.ProfileID, Generation: installed.Generation, Installation: ff.Installation{ToolchainImageSHA256: hash, TerraformVersion: installed.TerraformVersion, ReceiptID: installed.ReceiptID, SourceSHA256: hash}}}
	r := &repositoryDouble{selected: selected, mapping: g.ModelMapping{OldDeclaredASG: "aws_autoscaling_group.real_old", CandidateDeclaredASG: "aws_autoscaling_group.real_candidate", DeclaredListenerRule: "aws_lb_listener_rule.real"}, doc: model.Document{"id": "prepared-worker", "proposal_id": c.ProposalID, "program_hash": hash, "manifest_hash": strings.Repeat("b", 64)}}
	count := new(int)
	w := &Worker{config: c, installation: installed, pipeline: ed25519.PublicKey(bytesOf(1, 32)), ledger: ed25519.PublicKey(bytesOf(2, 32)), repository: r, archive: archiveDouble{}, prepare: func(_ context.Context, actual ff.Proposal, in p.Installation, _ p.Archive) (ff.Preparation, error) {
		*count++
		if g.Digest(actual) != g.Digest(r.selected) || in.Mapping != r.mapping || in.ImageSHA256 != installed.ToolchainImageSHA256 || len(in.PipelineKey) != 32 || len(in.LedgerKey) != 32 {
			t.Fatal("native factory did not receive server-resolved installation/mapping")
		}
		return ff.Preparation{}, nil
	}}
	return w, r, count
}
func bytesOf(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}

func TestOneJobRechecksBindingsAndReplaysWithoutNativeBootstrap(t *testing.T) {
	w, r, calls := fixtureWorker(t)
	result, err := w.Run(t.Context())
	if err != nil || result.Existing || result.CustomerExecutionAuthorized || *calls != 1 || r.currents != 1 || r.appends != 1 || r.releases != 1 {
		t.Fatalf("bad one-job sequence: %+v %v", result, err)
	}
	r.existing = true
	r.selected = ff.Proposal{} // Historical replay survives revocation.
	result, err = w.Run(t.Context())
	if err != nil || !result.Existing || *calls != 1 || r.currents != 1 || r.appends != 1 || r.releases != 2 {
		t.Fatal("replay ran native bootstrap/currentness again")
	}
}

func TestSourceChangeOrWrongCommissioningCannotPublish(t *testing.T) {
	t.Run("changed after native capture", func(t *testing.T) {
		w, r, calls := fixtureWorker(t)
		r.changed = true
		if result, err := w.Run(t.Context()); err == nil || result.PreparedProgramID != "" || *calls != 1 || r.releases != 1 {
			t.Fatal("stale native preparation published")
		}
	})
	for name, mutate := range map[string]func(*Worker, *repositoryDouble){"image": func(w *Worker, _ *repositoryDouble) { w.installation.ToolchainImageSHA256 = strings.Repeat("c", 64) }, "generation": func(w *Worker, _ *repositoryDouble) { w.installation.Generation = "another-generation" }, "sourcehash": func(w *Worker, _ *repositoryDouble) { w.installation.SourceSHA256 = strings.Repeat("c", 64) }, "tenant": func(_ *Worker, r *repositoryDouble) { r.selected.Binding.Old.Target.TenantID = "foreign-tenant" }, "realm": func(_ *Worker, r *repositoryDouble) { r.selected.Realm.Kind = "CUSTOMER_NATIVE" }, "customerexecution": func(_ *Worker, r *repositoryDouble) { r.selected.CustomerExecutionAuthorized = true }} {
		t.Run(name, func(t *testing.T) {
			w, r, calls := fixtureWorker(t)
			mutate(w, r)
			if _, err := w.Run(t.Context()); err == nil || *calls != 0 || r.appends != 0 || r.releases != 1 {
				t.Fatal("wrong bound installation reached native work")
			}
		})
	}
	t.Run("held job", func(t *testing.T) {
		w, r, calls := fixtureWorker(t)
		r.busy = true
		if _, err := w.Run(t.Context()); !errors.Is(err, ErrBusy) || *calls != 0 || r.reads != 0 {
			t.Fatal("busy job dispatched")
		}
	})
	t.Run("cross proposal replay", func(t *testing.T) {
		w, r, calls := fixtureWorker(t)
		r.existing = true
		r.doc["proposal_id"] = "foreign-proposal"
		if _, err := w.Run(t.Context()); err == nil || *calls != 0 {
			t.Fatal("cross-proposal replay accepted")
		}
	})
}
