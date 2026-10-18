package configuration

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This tool is test-only and executes inside the explicitly isolated acceptance
// container. Live Pipeline rejects it; production uses pinned Docker read tools.
type artifactFixtureProcessTools struct {
	Terraform     string
	BeforeInspect func()
}
type artifactFailPublish struct {
	ArtifactRepository
	once bool
}

func (r *artifactFailPublish) Publish(ctx context.Context, tenant, job string) (ArtifactReceipt, bool, error) {
	if !r.once {
		r.once = true
		return ArtifactReceipt{}, false, errors.New("simulated private process loss before receipt")
	}
	return r.ArtifactRepository.Publish(ctx, tenant, job)
}

type artifactRevokeOnPut struct {
	ArtifactArchive
	Revoke func() error
}

func (a *artifactRevokeOnPut) Put(ctx context.Context, tenant, job string, body []byte) (ArtifactArchiveRef, error) {
	ref, e := a.ArtifactArchive.Put(ctx, tenant, job, body)
	if e == nil {
		e = a.Revoke()
	}
	return ref, e
}

func (*artifactFixtureProcessTools) ContainerIsolated() bool { return false }
func (f *artifactFixtureProcessTools) Inspect(ctx context.Context, r ArtifactRegistration, root string, plan, state []byte) (ArtifactInspection, error) {
	var out ArtifactInspection
	if f.BeforeInspect != nil {
		f.BeforeInspect()
	}
	dir, e := os.MkdirTemp("", "artifact-fixture-sensitive-")
	if e != nil {
		return out, e
	}
	defer os.RemoveAll(dir)
	for name, body := range map[string][]byte{"plan.bin": plan, "state.raw": state} {
		if e = os.WriteFile(filepath.Join(dir, name), body, 0600); e != nil {
			return out, e
		}
	}
	run := func(args ...string) ([]byte, error) { return artifactCommand(ctx, f.Terraform, root, args...) }
	if out.VersionJSON, e = run("version", "-json"); e != nil {
		return out, e
	}
	if out.PlanJSON, e = run("show", "-json", filepath.Join(dir, "plan.bin")); e != nil {
		return out, e
	}
	if out.StateJSON, e = run("show", "-json", filepath.Join(dir, "state.raw")); e != nil {
		return out, e
	}
	workspace, e := run("workspace", "show")
	out.Workspace = strings.TrimSpace(string(workspace))
	return out, e
}

func actualArtifactFixture(t *testing.T) (ArtifactRegistration, *LocalArtifactCollector, ArtifactBundle) {
	t.Helper()
	binary := os.Getenv("TEST_ARTIFACT_TERRAFORM")
	if binary == "" {
		t.Skip("explicit isolated built-in Terraform acceptance required")
	}
	if binary != "/usr/local/bin/terraform" || os.Getenv("TEST_ARTIFACT_WORKSPACE") != "/workspace" {
		t.Fatal("actual fixture requires exact ephemeral container tool/workspace")
	}
	root := "/workspace"
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 0 {
		t.Fatal("fixture workspace must be a new empty container directory")
	}
	private := t.TempDir()
	reg := artifactTestRegistration()
	run := func(binary string, args ...string) {
		t.Helper()
		if _, e := artifactCommand(context.Background(), binary, root, args...); e != nil {
			t.Fatalf("local fixture command %s failed (output withheld)", binary)
		}
	}
	run("git", "init", "--initial-branch=main")
	run("git", "config", "user.name", "Local acceptance fixture")
	run("git", "config", "user.email", "fixture@example.invalid")
	run("git", "remote", "add", "origin", reg.Declaration.Repository.URL)
	if e = os.MkdirAll(filepath.Join(root, "modules", "local"), 0700); e != nil {
		t.Fatal(e)
	}
	for name, body := range map[string]string{".gitignore": ".terraform/\n", "main.tf": "module \"local\" { source = \"./modules/local\" }\n", "modules/local/main.tf": "resource \"terraform_data\" \"fixture\" { input = \"sensitive-fixture-state\" }\n"} {
		if e = os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	run("git", "add", ".")
	run("git", "commit", "--message", "Local committed built-in fixture")
	state := filepath.Join(private, "current.tfstate")
	plan := filepath.Join(private, "saved.tfplan")
	run(binary, "init", "-backend=false", "-input=false", "-no-color")
	// This is test setup only: terraform_data writes local state in an isolated
	// no-cloud container. The actual collector never runs init/plan/apply.
	run(binary, "apply", "-auto-approve", "-input=false", "-no-color", "-state="+state)
	run(binary, "plan", "-input=false", "-no-color", "-state="+state, "-out="+plan)
	raw, e := artifactReadFile(state)
	if e != nil {
		t.Fatal(e)
	}
	native, e := artifactDecode(raw)
	if e != nil {
		t.Fatal(e)
	}
	reg.Declaration.Terraform.StateLineage = artifactString(native, "lineage")
	collector := &LocalArtifactCollector{Sources: map[string]ArtifactLocalSource{reg.ID: {root, plan, state}}, Tools: &artifactFixtureProcessTools{Terraform: binary}}
	bundle, e := collector.Collect(context.Background(), reg)
	if e != nil {
		t.Fatal("actual Git/Terraform collection", e)
	}
	if _, e = ValidateArtifactBundle(reg, bundle); e != nil {
		z, _ := zip.NewReader(bytes.NewReader(bundle.SavedPlan), int64(len(bundle.SavedPlan)))
		actual, _ := artifactDecode(bundle.StateRaw)
		for _, f := range z.File {
			if f.Name == "tfstate" || f.Name == "tfstate-prev" {
				rd, _ := f.Open()
				raw, _ := io.ReadAll(rd)
				rd.Close()
				embedded, _ := artifactDecode(raw)
				for k := range actual {
					if artifactHash(actual[k]) != artifactHash(embedded[k]) {
						t.Logf("fixture embedded %s differs at top-level key %s", f.Name, k)
					}
				}
			}
		}
		t.Fatal("actual saved binary/source/state validation", e)
	}
	return reg, collector, bundle
}

func TestArtifactActualGitTerraformEncryptedPostgresS3(t *testing.T) {
	reg, collector, bundle := actualArtifactFixture(t)
	ctx := context.Background()
	meta, e := ValidateArtifactBundle(reg, bundle)
	if e != nil || meta.Status != "BLOCKED" || !artifactHasReason(meta, "CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED") {
		t.Fatal("fixture claimed observed cloud configuration", e)
	}
	t.Run("source-commit-and-capture-race", func(t *testing.T) {
		root := collector.Sources[reg.ID].RepositoryRoot
		name := filepath.Join(root, "main.tf")
		original, _ := os.ReadFile(name)
		os.WriteFile(name, append(original, []byte("\n# changed uncommitted source\n")...), 0600)
		if _, e := collector.Collect(ctx, reg); e == nil {
			t.Fatal("dirty source accepted")
		}
		os.WriteFile(name, original, 0600)
		tools := collector.Tools.(*artifactFixtureProcessTools)
		tools.BeforeInspect = func() {
			artifactCommand(ctx, "git", root, "commit", "--allow-empty", "--message", "concurrent fixture commit")
		}
		if _, e := collector.Collect(ctx, reg); e == nil {
			t.Fatal("changed HEAD during capture accepted")
		}
		tools.BeforeInspect = nil
		// A new committed source snapshot with an older saved no-op plan is rejected
		// even if Git is clean and the resource values happen to be unchanged.
		changed := append(original, []byte("\nlocals { extra = \"different committed configuration\" }\n")...)
		os.WriteFile(name, changed, 0600)
		artifactCommand(ctx, "git", root, "add", "main.tf")
		artifactCommand(ctx, "git", root, "commit", "--message", "changed committed configuration")
		newBundle, e := collector.Collect(ctx, reg)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ValidateArtifactBundle(reg, newBundle); e == nil {
			t.Fatal("old saved plan rebound to new committed configuration")
		}
		artifactCommand(ctx, "git", root, "reset", "--hard", bundle.Git.Commit)
	})
	t.Run("local-git-filter-cannot-run", func(t *testing.T) {
		root := collector.Sources[reg.ID].RepositoryRoot
		marker := filepath.Join(t.TempDir(), "filter-ran")
		if e := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte("main.tf filter=evil\n"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := artifactCommand(ctx, "git", root, "config", "filter.evil.clean", "sh -c 'printf executed > "+marker+"; cat'"); e != nil {
			t.Fatal(e)
		}
		if _, e := collector.Collect(ctx, reg); e == nil || e.Error() != "CONFIGURATION_ARTIFACT_GIT_CONFIG_UNSAFE" {
			t.Fatal("unsafe local filter configuration accepted", e)
		}
		if _, e := os.Stat(marker); !os.IsNotExist(e) {
			t.Fatal("Git filter side effect executed")
		}
		artifactCommand(ctx, "git", root, "config", "--unset", "filter.evil.clean")
		if _, e := collector.Collect(ctx, reg); e == nil || e.Error() != "CONFIGURATION_ARTIFACT_GIT_ATTRIBUTES_UNSUPPORTED" {
			t.Fatal("source attributes accepted", e)
		}
		os.Remove(filepath.Join(root, ".gitattributes"))
	})
	if os.Getenv("TEST_ARTIFACT_ADMIN_URL") == "" {
		t.Log("actual Git+offline Terraform capture/source-race acceptance passed; PG/S3 explicitly disabled")
		return
	}
	pg := artifactTestPostgres(t, reg)
	reg = pg.reg
	archive := artifactTestS3(t)
	key, e := NewArtifactFixtureKeys(bytes.Repeat([]byte{29}, 32))
	if e != nil {
		t.Fatal(e)
	}
	p := ArtifactPipeline{Repository: pg.repo, Collector: collector, Archive: archive, Keys: key, Fixture: true}
	principal := ArtifactPrincipal{reg.Binding.TenantID, reg.Subject, reg.Issuer, reg.Audience}
	p.Repository = &artifactFailPublish{ArtifactRepository: pg.repo}
	if _, _, e = p.Capture(ctx, principal, reg.ID, "capture-first"); e == nil {
		t.Fatal("expected injected process loss before immutable receipt")
	}
	pg.repo.Pool.Close()
	restarted, e := OpenArtifactRepository(ctx, pg.dsn, ArtifactDatabaseOptions{Fixture: true})
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Pool.Close()
	p.Repository = restarted
	receipt, replay, e := p.Capture(ctx, principal, reg.ID, "capture-first")
	if e != nil {
		t.Fatal("actual PG/encrypted versioned S3 publication", e)
	}
	if !replay || receipt.Metadata.ExecutionAuthorized || receipt.Metadata.VerifiedSaving != nil || receipt.Metadata.Status != "BLOCKED" || !receipt.ExpiresAt.Equal(receipt.ObservedAt.Add(15*time.Minute)) || receipt.ObservedAt.After(receipt.ReceivedAt) {
		t.Fatal("receipt authority invalid")
	}
	encrypted, e := archive.Read(ctx, reg.Binding.TenantID, receipt.Archive)
	if e != nil || bytes.Contains(encrypted, []byte("sensitive-fixture-state")) || bytes.Contains(encrypted, bundle.StateRaw) {
		t.Fatal("plaintext artifact persisted", e)
	}
	raw, e := artifactOpen(ctx, key, true, reg.Binding.TenantID, receipt.JobID, receipt.Metadata.BundleSHA256, encrypted)
	if e != nil {
		t.Fatal(e)
	}
	var restored ArtifactBundle
	if json.Unmarshal(raw, &restored) != nil || !bytes.Equal(restored.SavedPlan, bundle.SavedPlan) {
		t.Fatal("encrypted artifact did not preserve exact saved plan")
	}
	// Losing the process/pool after publication never refreshes or rewrites the
	// old immutable observation and never rereads the newest object version.
	pg.repo.Pool.Close()
	reopened, e := OpenArtifactRepository(ctx, pg.dsn, ArtifactDatabaseOptions{Fixture: true})
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Pool.Close()
	p.Repository = reopened
	again, replay, e := p.Capture(ctx, principal, reg.ID, "capture-first")
	if e != nil || !replay || again.ID != receipt.ID || !again.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("process replay altered receipt", e)
	}
	if _, e = archive.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(archive.Bucket), Key: aws.String(receipt.Archive.Key), Body: strings.NewReader("unrelated latest version")}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = p.Capture(ctx, principal, reg.ID, "capture-first"); e != nil {
		t.Fatal("read latest instead of pinned version", e)
	}
	if _, _, e = p.Capture(ctx, ArtifactPrincipal{"tenant-other", reg.Subject, reg.Issuer, reg.Audience}, reg.ID, "capture-other"); e == nil {
		t.Fatal("cross-tenant artifact read/publication")
	}
	if _, e = archive.Read(ctx, "tenant-other", receipt.Archive); e == nil {
		t.Fatal("cross-tenant encrypted archive read")
	}
	for _, sql := range []string{"UPDATE configuration_artifact_receipts SET document=document", "DELETE FROM configuration_artifact_archives", "INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document) VALUES('tenant-a','x','x','x','{}')", "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES('tenant-a','x','x','{}')", "INSERT INTO provider_operations(tenant_id,execution_id,resource_id) VALUES('tenant-a','x','x')", "UPDATE entities SET version=version+1"} {
		artifactExpectSQLDenied(t, reopened.Pool, "", reg.Binding.TenantID, sql)
	}
	artifactExpectSQLDenied(t, pg.admin, "finops_api", reg.Binding.TenantID, "INSERT INTO configuration_artifact_jobs SELECT * FROM configuration_artifact_jobs")
	if e = reopened.Revoke(ctx, reg.Binding.TenantID, reg.ID, reg.Version, "SOURCE_REVOKED"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = p.Capture(ctx, principal, reg.ID, "capture-after-revoke"); e == nil {
		t.Fatal("revoked machine captured")
	}
	if _, _, e = reopened.Publish(ctx, reg.Binding.TenantID, receipt.JobID); e == nil {
		t.Fatal("revoked machine replay republished")
	}
	reg2 := reg
	reg2.Version = 2
	if e = reopened.Register(ctx, reg2); e != nil {
		t.Fatal(e)
	}
	p.Archive = &artifactRevokeOnPut{ArtifactArchive: archive, Revoke: func() error {
		return reopened.Revoke(ctx, reg2.Binding.TenantID, reg2.ID, reg2.Version, "REVOKED_DURING_ARCHIVE")
	}}
	if _, _, e = p.Capture(ctx, principal, reg2.ID, "capture-revocation-race"); e == nil {
		t.Fatal("revocation race published a new receipt")
	}
	var count int
	if e = pg.admin.QueryRow(ctx, "SELECT count(*) FROM configuration_artifact_receipts").Scan(&count); e != nil || count != 1 {
		t.Fatal("revocation race changed immutable receipt history", e)
	}
	t.Log("Actual local Git + Terraform1.16.0 + restricted PostgreSQL + encrypted/versioned MinIO + process replay; cloud address unobserved, no AWS/authority/savings")
}

type artifactPGFixture struct {
	admin *pgxpool.Pool
	repo  *ArtifactPostgresRepository
	dsn   string
	reg   ArtifactRegistration
}

func artifactTestPostgres(t *testing.T, reg ArtifactRegistration) artifactPGFixture {
	t.Helper()
	ctx := context.Background()
	master, e := pgxpool.New(ctx, os.Getenv("TEST_ARTIFACT_ADMIN_URL"))
	if e != nil {
		t.Fatal(e)
	}
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	database := "artifact_acceptance_" + id
	login := "artifact_login_" + id
	password := uuid.NewString()
	if _, e = master.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(os.Getenv("TEST_ARTIFACT_ADMIN_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + database
	admin, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	var repo *ArtifactPostgresRepository
	t.Cleanup(func() {
		if repo != nil {
			repo.Pool.Close()
		}
		admin.Close()
		if _, e = master.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("owned artifact DB cleanup failed")
		}
		if _, e = master.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("owned artifact login cleanup failed")
		}
		master.Close()
	})
	files, e := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range files {
		name := filepath.Base(file)
		if name > "017_native_hardware.sql" && name != "020_configuration_artifacts.sql" {
			continue
		}
		raw, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, string(raw)); e != nil {
			t.Fatalf("isolated migration %s: %v", name, e)
		}
	}
	// Prepare the ordinary frozen016 declaration through its actual API role and
	// guard, rather than creating a synthetic attestation-only authority table.
	resource := map[string]any{"provider": "AWS", "provider_resource_id": reg.Binding.ProviderResourceID, "workload_id": reg.Binding.WorkloadID, "account_id": reg.Binding.AccountID, "region": reg.Binding.Region, "name": "fixture cloud mapping (unobserved)"}
	tx, e := admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", reg.Binding.TenantID)
	tx.Exec(ctx, "SET LOCAL ROLE finops_api")
	resourceRaw, _ := json.Marshal(resource)
	if _, e = tx.Exec(ctx, "INSERT INTO entities(tenant_id,kind,id,version,document) VALUES($1,'workloads',$2,1,'{}'),($1,'resources',$3,1,$4)", reg.Binding.TenantID, reg.Binding.WorkloadID, reg.Binding.ResourceID, resourceRaw); e != nil {
		t.Fatal(e)
	}
	snapshot := map[string]any{}
	for k, v := range resource {
		snapshot[k] = v
	}
	snapshot["id"], snapshot["version"] = reg.Binding.ResourceID, 1
	reg.Binding.ResourceSnapshotHash = artifactHash(snapshot)
	d := DeclarationDocument(reg.Declaration)
	d["id"], d["version"], d["binding"] = reg.AuthorityID, 1, reg.Binding
	d["status"], d["reason_codes"], d["execution_authorized"] = "DECLARED_NOT_ATTESTED", Reasons(reg.Binding), false
	d["observed_commit"], d["observed_state_serial"], d["declared_by"] = nil, nil, "local-fixture-admin"
	reg.AuthorityHash = artifactHash(d)
	raw, _ := json.Marshal(d)
	snap, _ := json.Marshal(snapshot)
	if _, e = tx.Exec(ctx, "INSERT INTO configuration_authority_revisions(tenant_id,id,resource_id,workload_id,version,resource_version,resource_snapshot_hash,resource_snapshot,content_hash,document) VALUES($1,$2,$3,$4,1,1,$5,$6,$7,$8)", reg.Binding.TenantID, reg.AuthorityID, reg.Binding.ResourceID, reg.Binding.WorkloadID, reg.Binding.ResourceSnapshotHash, snap, reg.AuthorityHash, raw); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", pgx.Identifier{login}.Sanitize(), password)); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Exec(ctx, "GRANT finops_configuration_attestor TO "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	u.User = url.UserPassword(login, password)
	dsn := u.String()
	repo, e = OpenArtifactRepository(ctx, dsn, ArtifactDatabaseOptions{Fixture: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.Register(ctx, reg); e != nil {
		t.Fatal("private registered machine", e)
	}
	if broad, e := OpenArtifactRepository(ctx, os.Getenv("TEST_ARTIFACT_ADMIN_URL"), ArtifactDatabaseOptions{Fixture: true}); e == nil {
		broad.Pool.Close()
		t.Fatal("accepted broad database user")
	}
	startup := *u
	q := startup.Query()
	q.Set("options", "-c role=finops_configuration_attestor")
	startup.RawQuery = q.Encode()
	if other, e := OpenArtifactRepository(ctx, startup.String(), ArtifactDatabaseOptions{Fixture: true}); e == nil {
		other.Pool.Close()
		t.Fatal("accepted startup identity override")
	}
	if _, e = OpenArtifactRepository(ctx, dsn); e == nil {
		t.Fatal("live database accepted unverified TLS")
	}
	for _, role := range []string{"pg_read_all_data", "finops_deployment_observer"} {
		if _, e = master.Exec(ctx, "GRANT "+pgx.Identifier{role}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		if bad, e := OpenArtifactRepository(ctx, dsn, ArtifactDatabaseOptions{Fixture: true}); e == nil {
			bad.Pool.Close()
			t.Fatal("accepted widened transitive database membership", role)
		}
		if _, e = master.Exec(ctx, "REVOKE "+pgx.Identifier{role}.Sanitize()+" FROM "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = master.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" REPLICATION"); e != nil {
		t.Fatal(e)
	}
	if bad, e := OpenArtifactRepository(ctx, dsn, ArtifactDatabaseOptions{Fixture: true}); e == nil {
		bad.Pool.Close()
		t.Fatal("accepted replication-capable session user")
	}
	if _, e = master.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" NOREPLICATION"); e != nil {
		t.Fatal(e)
	}
	return artifactPGFixture{admin, repo, dsn, reg}
}
func artifactExpectSQLDenied(t *testing.T, pool *pgxpool.Pool, role, tenant, sql string) {
	t.Helper()
	tx, e := pool.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if role != "" {
		if _, e = tx.Exec(context.Background(), "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	tx.Exec(context.Background(), "SELECT set_config('app.tenant_id',$1,true)", tenant)
	if _, e = tx.Exec(context.Background(), sql); e == nil {
		t.Fatal("SQL accepted forbidden artifact mutation")
	}
}
func artifactTestS3(t *testing.T) *S3ArtifactArchive {
	t.Helper()
	endpoint := os.Getenv("TEST_ARTIFACT_S3_ENDPOINT")
	if endpoint != "http://minio:9000" {
		t.Fatal("artifact S3 acceptance requires exact isolated local MinIO endpoint")
	}
	ctx := context.Background()
	client := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("TEST_ARTIFACT_S3_ACCESS_KEY"), os.Getenv("TEST_ARTIFACT_S3_SECRET_KEY"), "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	bucket := "artifact-acceptance-" + id
	owner := "owned-" + id
	if _, e := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal("owned local artifact bucket create", e)
	}
	tagged := false
	t.Cleanup(func() {
		tags, e := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if e == nil && tagged {
			for _, v := range tags.TagSet {
				if aws.ToString(v.Key) == "finops-artifact-acceptance-owner" && aws.ToString(v.Value) == owner {
					owned = true
				}
			}
		}
		if !owned {
			t.Error("artifact bucket ownership check prevented cleanup")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			page, e := pages.NextPage(ctx)
			if e != nil {
				t.Error("owned artifact version enumeration failed")
				return
			}
			objects := []types.ObjectIdentifier{}
			for _, v := range page.Versions {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range page.DeleteMarkers {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("owned artifact version cleanup failed")
					return
				}
			}
		}
		if _, e = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error("owned artifact bucket cleanup failed")
		}
	})
	if _, e := client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("finops-artifact-acceptance-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal(e)
	}
	tagged = true
	if _, e := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	return &S3ArtifactArchive{client, bucket}
}
