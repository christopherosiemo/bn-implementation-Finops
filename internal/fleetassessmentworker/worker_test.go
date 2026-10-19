package fleetassessmentworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

func configFixture(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{Enabled: true, TenantID: "tenant", DatabaseFile: filepath.Join(dir, "database"), ArchiveMode: LocalArchive, ArchiveRegion: "eu-west-1", ArchiveEndpoint: "http://127.0.0.1:9000", ArchiveBucket: "private-raw-archive", ArchiveAccessKeyFile: filepath.Join(dir, "access"), ArchiveSecretKeyFile: filepath.Join(dir, "secret")}
}
func TestCommissioningRejectsAmbientAuthorityAndAmbiguousConfiguration(t *testing.T) {
	c := configFixture(t)
	if c.Validate() != nil {
		t.Fatal("valid local commissioning rejected")
	}
	for name, mutate := range map[string]func(*Config){"disabled": func(c *Config) { c.Enabled = false }, "foreign-region": func(c *Config) { c.ArchiveRegion = "us-east-1" }, "public-ip": func(c *Config) { c.ArchiveEndpoint = "https://8.8.8.8:443" }, "userinfo": func(c *Config) { c.ArchiveEndpoint = "http://secret@127.0.0.1:9000" }, "endpoint-query": func(c *Config) { c.ArchiveEndpoint += "?key=another" }, "same-secret": func(c *Config) { c.ArchiveSecretKeyFile = c.ArchiveAccessKeyFile }, "relative-file": func(c *Config) { c.DatabaseFile = "database" }, "mixed-irsa": func(c *Config) { c.RoleARN = "arn:aws:iam::111122223333:role/archive-reader" }} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, ambient := range []string{"AWS_ACCESS_KEY_ID=unused", "AWS_PROFILE=unused", "AWS_ENDPOINT_URL=http://public", "PGPASSWORD=unused", "TF_VAR_money=1", "DOCKER_HOST=unused", "SIGNING_PRIVATE_KEY=unused"} {
		if checkEnvironment([]string{ambient}, c) == nil {
			t.Fatal("ambient authority accepted")
		}
	}
	irsa := c
	irsa.ArchiveMode = IRSAArchive
	irsa.ArchiveEndpoint = ""
	irsa.ArchiveAccessKeyFile = ""
	irsa.ArchiveSecretKeyFile = ""
	irsa.ArchiveBucketOwner = "111122223333"
	irsa.RoleARN = "arn:aws:iam::111122223333:role/archive-reader"
	irsa.WebIdentityTokenFile = filepath.Join(t.TempDir(), "token")
	if irsa.Validate() != nil || checkEnvironment([]string{"AWS_ROLE_ARN=" + irsa.RoleARN, "AWS_WEB_IDENTITY_TOKEN_FILE=" + irsa.WebIdentityTokenFile, "AWS_REGION=eu-west-1"}, irsa) != nil {
		t.Fatal("renewable explicit IRSA configuration rejected")
	}
	if checkEnvironment([]string{"AWS_ACCESS_KEY_ID=must-not-fallback"}, irsa) == nil {
		t.Fatal("IRSA accepted static credential fallback")
	}
	for _, value := range []string{"AWS_REGION=us-east-1", "AWS_ROLE_ARN=arn:aws:iam::999999999999:role/other", "AWS_WEB_IDENTITY_TOKEN_FILE=/uninstalled/token", "AWS_STS_REGIONAL_ENDPOINTS=legacy"} {
		if checkEnvironment([]string{value}, irsa) == nil {
			t.Fatal("IRSA accepted conflicting installed transport identity")
		}
	}
	values := map[string]string{"FLEET_ASSESSMENT_ENABLED": "true", "FLEET_ASSESSMENT_TENANT_ID": c.TenantID, "FLEET_ASSESSMENT_DATABASE_FILE": c.DatabaseFile, "FLEET_ASSESSMENT_ARCHIVE_MODE": c.ArchiveMode, "FLEET_ASSESSMENT_ARCHIVE_REGION": c.ArchiveRegion, "FLEET_ASSESSMENT_ARCHIVE_ENDPOINT": c.ArchiveEndpoint, "FLEET_ASSESSMENT_ARCHIVE_BUCKET": c.ArchiveBucket, "FLEET_ASSESSMENT_ARCHIVE_ACCESS_KEY_FILE": c.ArchiveAccessKeyFile, "FLEET_ASSESSMENT_ARCHIVE_SECRET_KEY_FILE": c.ArchiveSecretKeyFile}
	if from, e := ConfigFromEnvironment(func(k string) string { return values[k] }); e != nil || from != c {
		t.Fatal("deployment environment contract changed")
	}
}
func TestSecretAndDatabaseFilesDoNotFallBackToAmbientCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readonly-secret")
	if e := os.WriteFile(path, []byte("exact-private-value"), 0444); e != nil {
		t.Fatal(e)
	}
	if raw, e := secretFile(path, 64); e != nil || string(raw) != "exact-private-value" {
		t.Fatal("readonly mounted secret rejected")
	}
	if _, e := secretFile(path, 3); e == nil {
		t.Fatal("oversized secret accepted")
	}
	if e := os.Chmod(path, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := secretFile(path, 64); e == nil {
		t.Fatal("shared writable secret accepted")
	}
	_ = os.Chmod(path, 0400)
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := secretFile(link, 64); e == nil {
		t.Fatal("static secret symlink accepted")
	}
	password := "independent@escaped:/password&value"
	u := url.URL{Scheme: "postgres", User: url.UserPassword("dedicated-reader", password), Host: "127.0.0.1:5432", Path: "/owned-child", RawQuery: "sslmode=disable"}
	pinned, e := databaseURL(context.Background(), []byte(u.String()), false)
	parsed, _ := url.Parse(pinned)
	actual, ok := parsed.User.Password()
	if e != nil || !ok || actual != password || parsed.User.Username() != "dedicated-reader" || parsed.Query().Get("pool_max_conns") != "3" {
		t.Fatal("database pin changed independent identity")
	}
	for _, query := range []string{"sslmode=disable&host=other", "sslmode=disable&user=postgres", "sslmode=disable&options=-crole=postgres", "sslmode=disable&sslmode=verify-full", "sslmode=prefer", "sslmode=disable&service=outside"} {
		bad := u
		bad.RawQuery = query
		if _, e := databaseURL(context.Background(), []byte(bad.String()), false); e == nil {
			t.Fatal("ambiguous database binding accepted")
		}
	}
	// An RDS certificate authenticates its commissioned DNS name, not the
	// address returned by a preflight lookup. Never weaken verify-full to CA-only.
	secure := u
	secure.Host = "localhost:5432"
	secure.RawQuery = "sslmode=verify-full"
	verified, e := databaseURL(context.Background(), []byte(secure.String()), false)
	if e != nil {
		t.Fatal("verified TLS DSN preflight failed")
	}
	parsedConfig, e := pgxpool.ParseConfig(verified)
	if e != nil || parsedConfig.ConnConfig.Host != "localhost" || parsedConfig.ConnConfig.TLSConfig == nil || parsedConfig.ConnConfig.TLSConfig.ServerName != "localhost" || parsedConfig.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("verified TLS lost commissioned certificate hostname")
	}
	for _, query := range []string{"sslmode=disable", "sslmode=verify-full", "sslmode=verify-ca&sslrootcert=/etc/finops/rds/ca.pem", "sslmode=verify-full&sslrootcert=/tmp/uncommissioned.pem"} {
		bad := secure
		bad.RawQuery = query
		if _, e := databaseURL(context.Background(), []byte(bad.String()), true); e == nil {
			t.Fatal("hosted database accepted plaintext or missing reviewed CA")
		}
	}
	secure.RawQuery = "sslmode=verify-full&sslrootcert=/etc/finops/rds/reviewed.pem"
	if _, e := databaseURL(context.Background(), []byte(secure.String()), true); e != nil {
		t.Fatal("hosted reviewed TLS preflight rejected")
	}
}

func TestArchiveReaderAuthenticatesActualVersionAndBoundedBody(t *testing.T) {
	body := []byte("native captured bytes")
	version := "original-issued-version"
	requests := 0
	wrongVersion := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/private-raw-archive/tenant/tenant/object" || r.URL.Query().Get("versionId") != version {
			t.Error("reader changed exact archive request")
		}
		if wrongVersion {
			w.Header().Set("x-amz-version-id", "another-version")
		} else {
			w.Header().Set("x-amz-version-id", version)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client := s3.New(s3.Options{Region: "eu-west-1", BaseEndpoint: aws.String(server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("separate-readonly", "local-only", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	if _, e := NewPinnedReader(nil, "private-raw-archive", ""); e == nil {
		t.Fatal("missing SDK transport accepted")
	}
	if _, e := NewPinnedReader(client, "private-raw-archive", "invalid-owner"); e == nil {
		t.Fatal("ambiguous bucket owner accepted")
	}
	reader := archiveReader{client: client, bucket: "private-raw-archive"}
	ref := model.Document{"bucket": reader.bucket, "key": "tenant/tenant/object", "version_id": version, "body_sha256": b.BytesHash(body)}
	got, e := reader.ReadPinned(context.Background(), "tenant", ref)
	if e != nil || got.VersionID != version || string(got.Body) != string(body) {
		t.Fatal("actual version readback failed")
	}
	wrongVersion = true
	if _, e := reader.ReadPinned(context.Background(), "tenant", ref); e == nil {
		t.Fatal("requested version was echoed instead of authenticating response")
	}
	before := requests
	for _, mutate := range []func(model.Document){func(d model.Document) { d["key"] = "tenant/other/object" }, func(d model.Document) { d["bucket"] = "foreign" }, func(d model.Document) { d["version_id"] = "null" }, func(d model.Document) { d["key"] = "tenant/tenant/../escape" }} {
		bad := model.Clone(ref)
		mutate(bad)
		if _, e := reader.ReadPinned(context.Background(), "tenant", bad); e == nil {
			t.Fatal("unscoped archive ref accepted")
		}
	}
	if requests != before {
		t.Fatal("invalid archive ref caused network I/O")
	}
	tooLarge := archiveReader{client: getObjectFunction(func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{VersionId: aws.String(version), ContentLength: aws.Int64(maximumObjectBytes + 1), Body: io.NopCloser(strings.NewReader("not-read"))}, nil
	}), bucket: reader.bucket}
	if _, e := tooLarge.ReadPinned(context.Background(), "tenant", ref); e == nil {
		t.Fatal("oversized native response accepted")
	}
	unknown := &boundedGeneratedBody{remaining: maximumObjectBytes + 2}
	tooLarge.client = getObjectFunction(func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{VersionId: aws.String(version), Body: unknown}, nil
	})
	if _, e := tooLarge.ReadPinned(context.Background(), "tenant", ref); e == nil || unknown.read != maximumObjectBytes+1 || !unknown.closed {
		t.Fatal("unknown-length response exceeded bounded read or retained body")
	}
}

type boundedGeneratedBody struct {
	remaining, read int
	closed          bool
}

func (b *boundedGeneratedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	clear(p[:n])
	b.remaining -= n
	b.read += n
	return n, nil
}
func (b *boundedGeneratedBody) Close() error { b.closed = true; return nil }

type getObjectFunction func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)

func (f getObjectFunction) GetObject(c context.Context, i *s3.GetObjectInput, o ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return f(c, i, o...)
}

type fixtureRepository struct {
	requestBody                                  model.Document
	snapshotBody                                 model.Document
	requests, snapshots, appends, locks, unlocks int
	requestError, appendError                    error
	busy                                         bool
	queue                                        []model.Document
	lastAppend                                   model.Document
}

func (r *fixtureRepository) lock(context.Context, string, string) (func(), error) {
	r.locks++
	if r.busy {
		return nil, ErrBusy
	}
	return func() { r.unlocks++ }, nil
}
func (r *fixtureRepository) request(context.Context, string, string) (model.Document, error) {
	r.requests++
	return r.requestBody, r.requestError
}
func (r *fixtureRepository) pending(_ context.Context, _ string, after string, limit int) ([]model.Document, error) {
	out := []model.Document{}
	for _, d := range r.queue {
		if model.String(d, "id") > after {
			out = append(out, d)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}
func (r *fixtureRepository) snapshot(context.Context, string, string) (model.Document, error) {
	r.snapshots++
	return r.snapshotBody, nil
}
func (r *fixtureRepository) members(context.Context, string, string, model.Document) ([]model.Document, error) {
	return []model.Document{}, nil
}
func (r *fixtureRepository) append(_ context.Context, _ string, _ string, hash string, d model.Document) (model.Document, bool, error) {
	r.appends++
	if hash != b.Hash(r.snapshotBody) {
		return nil, false, ErrJob
	}
	if r.appendError != nil {
		return nil, false, r.appendError
	}
	r.lastAppend = d
	return model.Document{"assessment": d}, false, nil
}

type forbiddenArchive struct{ calls int }

func (a *forbiddenArchive) ReadPinned(context.Context, string, model.Document) (b.PinnedObject, error) {
	a.calls++
	return b.PinnedObject{}, errors.New("archive must not be read")
}
func selectionFixture() a.Selection {
	selection := func(name, suffix string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + suffix + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: strings.Repeat("a", 64)}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: strings.Repeat("b", 64)}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: strings.Repeat("c", 64)}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: strings.Repeat("d", 64)}
	}
	return a.Selection{Groups: b.GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: strings.Repeat("e", 64)}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: strings.Repeat("f", 64)}, Binding: g.Binding{Old: selection("old", "1"), Candidate: selection("candidate", "2")}}, SafetyProfile: g.VersionedRef{ID: "profile", Version: 1, SHA256: strings.Repeat("a", 64)}}
}
func workerFixture(t *testing.T) (*Worker, *fixtureRepository, *forbiddenArchive) {
	t.Helper()
	s := selectionFixture()
	snapshot := b.GroupNativeSnapshot{Selection: s.Groups, Registrations: map[string]model.Document{}, Memberships: []b.GroupNativeReceipt{}, Templates: []b.GroupNativeReceipt{}, Hardware: []b.GroupNativeReceipt{}, Commitment: model.Document{}, Billing: []b.GroupNativeBillingRevision{}}
	var body model.Document
	if decode(snapshot, &body) != nil {
		t.Fatal("fixture snapshot encode")
	}
	r := &fixtureRepository{requestBody: model.Document{"id": "request", "selection": s, "assessment": nil}, snapshotBody: body}
	archive := &forbiddenArchive{}
	return &Worker{config: configFixture(t), repository: r, archive: archive}, r, archive
}
func TestExistingAssessmentReplayPrecedesAllEvidenceReads(t *testing.T) {
	w, r, archive := workerFixture(t)
	r.requestBody["assessment"] = model.Document{"id": "immutable-assessment"}
	got, e := w.process(context.Background(), "request")
	if e != nil || !got.Existing || got.AssessmentID != "immutable-assessment" || r.snapshots != 0 || archive.calls != 0 || r.appends != 0 || r.locks != 1 || r.unlocks != 1 {
		t.Fatal("replay caused evidence resolution or publication")
	}
	r.busy = true
	if _, e := w.process(context.Background(), "request"); !errors.Is(e, ErrBusy) || r.requests != 1 {
		t.Fatal("busy job read past session fence")
	}
}
func TestMissingNativeEvidencePersistsBlockedNullScenario(t *testing.T) {
	w, r, archive := workerFixture(t)
	got, e := w.process(context.Background(), "request")
	if e != nil || got.Existing || got.AssessmentID == "" || r.appends != 1 || archive.calls != 0 || r.unlocks != 1 {
		t.Fatal("missing evidence did not produce bounded blocked assessment", e)
	}
	var assessment a.Assessment
	if decode(r.lastAppend, &assessment) != nil || assessment.Status != "BLOCKED" || assessment.ExecutionAuthorized || assessment.ChangePlanID != nil || assessment.VerifiedSaving != nil || assessment.Scenario.Status != "UNAVAILABLE" || assessment.Scenario.HourlyComputeDifference != nil || assessment.Capacity.GroupCapacityAuthorized {
		t.Fatal("missing evidence acquired authority or zero money")
	}
	r.appendError = errors.New("source changed before commit")
	if _, e := w.process(context.Background(), "request"); !errors.Is(e, ErrJob) {
		t.Fatal("publication currentness refusal ignored")
	}
}
func TestSnapshotCanonicalRoundTripRetainsNumbersAndGroupSelectors(t *testing.T) {
	w, r, _ := workerFixture(t)
	s := selectionFixture()
	r.snapshotBody["registrations"] = model.Document{"source": model.Document{"version": json.Number("9007199254740993"), "amount": "0.123456789012", "exact_big": json.Number("18446744073709551615")}}
	repo := &nativeRepository{repository: r, tenant: "tenant", id: "request", selection: s}
	got, e := repo.ResolveGroupNative(context.Background(), "tenant", "old-proposal", "candidate-proposal")
	if e != nil || repo.hash != b.Hash(r.snapshotBody) || model.Number(got.Registrations["source"], "version") != 9007199254740993 {
		t.Fatal("typed snapshot and PG map named different exact content")
	}
	if _, e := repo.ResolveGroupNative(context.Background(), "foreign", "old-proposal", "candidate-proposal"); e == nil {
		t.Fatal("foreign tenant resolved")
	}
	_ = w
}
func TestBoundedQueueAdvancesPastBusyAndFailedRequests(t *testing.T) {
	w, r, _ := workerFixture(t)
	r.queue = []model.Document{{"id": "a"}, {"id": "b"}}
	r.busy = true
	got, e := w.Poll(context.Background())
	if e != nil || got.Busy != 2 || got.Inspected != 2 || r.requests != 0 {
		t.Fatal("busy jobs blocked bounded cursor progress")
	}
	if _, e := w.Poll(context.Background()); e != nil || w.cursor != "" {
		t.Fatal("completed page did not wrap")
	}
	r.busy = false
	r.requestError = ErrJob
	got, e = w.Poll(context.Background())
	if e == nil || got.Failed != 1 || w.cursor != "a" || !w.retry["a"].After(time.Now()) {
		t.Fatal("failed request lost retry/backoff or cursor")
	}
	if _, e := w.Poll(context.Background()); e == nil || w.cursor != "b" {
		t.Fatal("one failed request starved later request")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(w.Run(cancelled, nil), context.Canceled) {
		t.Fatal("daemon ignored shutdown")
	}
}
