// Package groupfixtureworker is an explicitly commissioned, single-job local
// preparer. It has no HTTP ingress, signer, journal, delivery or cloud adapter.
package groupfixtureworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	p "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

var ErrConfiguration = errors.New("GROUP_FIXTURE_PREPARER_CONFIGURATION_INVALID")
var ErrBusy = errors.New("GROUP_FIXTURE_PREPARER_JOB_BUSY")
var ErrJob = errors.New("GROUP_FIXTURE_PREPARER_JOB_FAILED")

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// All values are private operator installation input. No browser can select a
// target, image, key, file, command, native sample, or program through this job.
type Config struct {
	Enabled               bool
	Mode                  string
	TenantID              string
	ProposalID            string
	DatabaseFile          string
	InstallationFile      string
	PipelinePublicKeyFile string
	LedgerPublicKeyFile   string
	ArchiveKeyFile        string
	S3Endpoint            string
	S3Region              string
	S3Bucket              string
	S3AccessKeyFile       string
	S3SecretKeyFile       string
}

func ConfigFromEnvironment(get func(string) string) (Config, error) {
	c := Config{Enabled: get("GROUP_FIXTURE_ENABLED") == "true", Mode: get("GROUP_FIXTURE_MODE"), TenantID: get("GROUP_FIXTURE_TENANT_ID"), ProposalID: get("GROUP_FIXTURE_PROPOSAL_ID"), DatabaseFile: get("GROUP_FIXTURE_DATABASE_FILE"), InstallationFile: get("GROUP_FIXTURE_INSTALLATION_FILE"), PipelinePublicKeyFile: get("GROUP_FIXTURE_PIPELINE_PUBLIC_KEY_FILE"), LedgerPublicKeyFile: get("GROUP_FIXTURE_LEDGER_PUBLIC_KEY_FILE"), ArchiveKeyFile: get("GROUP_FIXTURE_ARCHIVE_KEY_FILE"), S3Endpoint: get("GROUP_FIXTURE_S3_ENDPOINT"), S3Region: get("GROUP_FIXTURE_S3_REGION"), S3Bucket: get("GROUP_FIXTURE_S3_BUCKET"), S3AccessKeyFile: get("GROUP_FIXTURE_S3_ACCESS_KEY_FILE"), S3SecretKeyFile: get("GROUP_FIXTURE_S3_SECRET_KEY_FILE")}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if !c.Enabled || c.Mode != g.IsolatedFixture || !identifier.MatchString(c.TenantID) || !identifier.MatchString(c.ProposalID) || c.S3Region != "eu-west-1" || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(c.S3Bucket) {
		return ErrConfiguration
	}
	u, err := url.Parse(c.S3Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !localName(u.Hostname()) || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for _, path := range []string{c.DatabaseFile, c.InstallationFile, c.PipelinePublicKeyFile, c.LedgerPublicKeyFile, c.ArchiveKeyFile, c.S3AccessKeyFile, c.S3SecretKeyFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return ErrConfiguration
		}
		seen[path] = true
	}
	return nil
}

// Installation is a read-only commissioner's pin, not self-attestation that a
// process can inspect its own container image. Actual image inspection belongs
// to the external installer; the native producer checks its fixed CLI outputs.
type Installation struct {
	SchemaVersion        string `json:"schema_version"`
	ProfileID            string `json:"profile_id"`
	Generation           string `json:"generation"`
	ToolchainImageSHA256 string `json:"toolchain_image_sha256"`
	TerraformVersion     string `json:"terraform_version"`
	ReceiptID            string `json:"receipt_id"`
	SourceSHA256         string `json:"source_sha256"`
}

func (i Installation) valid() bool {
	return i.SchemaVersion == "1" && identifier.MatchString(i.ProfileID) && identifier.MatchString(i.Generation) && digest.MatchString(i.ToolchainImageSHA256) && digest.MatchString(i.SourceSHA256) && identifier.MatchString(i.ReceiptID) && i.TerraformVersion == "1.16.0"
}

func (i Installation) matches(selected ff.Proposal) bool {
	x := selected.Profile.Installation
	return i.valid() && i.ProfileID == selected.Profile.ID && i.Generation == selected.Profile.Generation && i.ToolchainImageSHA256 == x.ToolchainImageSHA256 && i.TerraformVersion == x.TerraformVersion && i.ReceiptID == x.ReceiptID && i.SourceSHA256 == x.SourceSHA256
}

func privateFile(path string, max int64) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return nil, ErrConfiguration
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > max {
		return nil, ErrConfiguration
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrConfiguration
	}
	return raw, nil
}

func checkEnvironment(entries []string) error {
	for _, entry := range entries {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		for _, prefix := range []string{"AWS_", "AZURE_", "GOOGLE_", "GCP_", "ARM_", "TF_VAR_", "TF_CLI_ARGS", "TF_TOKEN_", "DOCKER_", "PG"} {
			if strings.HasPrefix(key, prefix) {
				return ErrConfiguration
			}
		}
		for _, exact := range []string{"PGPASSWORD", "PGPASSFILE", "PGSERVICE", "PGSERVICEFILE", "SIGNING_KEY", "SIGNING_KEY_FILE", "EXECUTOR_TOKEN", "SIGNER_TOKEN"} {
			if key == exact {
				return ErrConfiguration
			}
		}
	}
	return nil
}

func localAddress(ip net.IP) bool {
	v4 := ip.To4()
	return ip.IsLoopback() || v4 != nil && (v4[0] == 10 || v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 || v4[0] == 192 && v4[1] == 168)
}
func localName(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return localAddress(ip)
	}
	return regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`).MatchString(host)
}

func privateHost(ctx context.Context, host string) (string, error) {
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return "", ErrConfiguration
	}
	for _, ip := range addresses {
		if !localAddress(ip) {
			return "", ErrConfiguration
		}
	}
	return addresses[0].String(), nil
}

// Pin the resolved private database address before OpenRuntime. Only explicit
// fixture-local transport is accepted; there is no environment/pgpass fallback.
func privateDatabase(ctx context.Context, raw []byte) (string, error) {
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !localName(u.Hostname()) || u.User == nil || u.User.Username() == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" {
		return "", ErrConfiguration
	}
	password, present := u.User.Password()
	if !present || password == "" {
		return "", ErrConfiguration
	}
	q := u.Query()
	if q.Get("sslmode") != "disable" && q.Get("sslmode") != "verify-full" {
		return "", ErrConfiguration
	}
	for _, key := range []string{"host", "hostaddr", "user", "password", "dbname", "service", "passfile", "options", "role", "session_authorization"} {
		if q.Has(key) {
			return "", ErrConfiguration
		}
	}
	ip, err := privateHost(ctx, u.Hostname())
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	u.Host = net.JoinHostPort(ip, port)
	// The process retains one job-lock connection and uses a second for short
	// tenant transactions. Neither connection is an administrative identity.
	q.Set("pool_max_conns", "2")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type repository interface {
	lock(context.Context, string, string) (func(), error)
	prepared(context.Context, string, string) (model.Document, error)
	current(context.Context, string, string) (ff.Proposal, g.ModelMapping, error)
	append(context.Context, string, ff.Proposal, g.ModelMapping, ff.Preparation) (model.Document, error)
}

type postgresRepository struct{ db *store.Store }

func (r postgresRepository) lock(ctx context.Context, tenant, id string) (func(), error) {
	conn, err := r.db.Pool.Acquire(ctx)
	if err != nil {
		return nil, ErrJob
	}
	key := tenant + ":group-fixture-preparation:" + id
	var held bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&held); err != nil || !held {
		conn.Release()
		return nil, ErrBusy
	}
	return func() {
		defer conn.Release()
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if conn.QueryRow(release, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key).Scan(&unlocked) != nil || !unlocked {
			_ = conn.Conn().Close(release)
		}
	}, nil
}
func (r postgresRepository) prepared(ctx context.Context, tenant, id string) (model.Document, error) {
	var out model.Document
	err := r.db.Do(ctx, tenant, func(tx *store.Tx) error { var e error; out, e = tx.FleetFixturePreparedProgramGet(ctx, id); return e })
	return out, err
}
func (r postgresRepository) current(ctx context.Context, tenant, id string) (ff.Proposal, g.ModelMapping, error) {
	var selected ff.Proposal
	var mapping g.ModelMapping
	err := r.db.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		selected, e = tx.FleetFixtureCurrent(ctx, id)
		if e != nil {
			return e
		}
		mapping, e = tx.FleetFixtureMapping(ctx, id)
		return e
	})
	return selected, mapping, err
}
func (r postgresRepository) append(ctx context.Context, tenant string, selected ff.Proposal, mapping g.ModelMapping, in ff.Preparation) (model.Document, error) {
	var out model.Document
	err := r.db.Do(ctx, tenant, func(tx *store.Tx) error {
		fresh, e := tx.FleetFixtureCurrent(ctx, selected.ID)
		if e != nil {
			return e
		}
		freshMapping, e := tx.FleetFixtureMapping(ctx, selected.ID)
		if e != nil {
			return e
		}
		if g.Digest(fresh) != g.Digest(selected) || freshMapping != mapping {
			return ff.ErrCurrent
		}
		out, e = tx.FleetFixturePreparedProgramAppend(ctx, selected.ID, in)
		return e
	})
	return out, err
}

type Result struct {
	ProposalID                  string `json:"proposal_id"`
	PreparedProgramID           string `json:"prepared_program_id"`
	ProgramSHA256               string `json:"program_sha256"`
	ManifestSHA256              string `json:"manifest_sha256"`
	Existing                    bool   `json:"existing"`
	CustomerExecutionAuthorized bool   `json:"customer_execution_authorized"`
}

type Worker struct {
	config           Config
	installation     Installation
	pipeline, ledger ed25519.PublicKey
	repository       repository
	archive          p.Archive
	prepare          func(context.Context, ff.Proposal, p.Installation, p.Archive) (ff.Preparation, error)
	close            func()
}

// Open is fixture-only. It loads no private signing keys and gives AWS SDK no
// default credential chain, proxies, public endpoint, cloud region or metadata
// access. Its fixed native subprocesses inherit the producer's clean env.
func Open(ctx context.Context, c Config) (*Worker, error) {
	if c.Validate() != nil || runtime.GOOS != "linux" || os.Getuid() == 0 || checkEnvironment(os.Environ()) != nil {
		return nil, ErrConfiguration
	}
	installationRaw, err := privateFile(c.InstallationFile, 4096)
	if err != nil {
		return nil, err
	}
	var installed Installation
	decoder := json.NewDecoder(bytes.NewReader(installationRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&installed) != nil || decoder.Decode(new(any)) != io.EOF || !installed.valid() {
		return nil, ErrConfiguration
	}
	pipeline, err := privateFile(c.PipelinePublicKeyFile, ed25519.PublicKeySize)
	if err != nil || len(pipeline) != ed25519.PublicKeySize {
		return nil, ErrConfiguration
	}
	ledger, err := privateFile(c.LedgerPublicKeyFile, ed25519.PublicKeySize)
	if err != nil || len(ledger) != ed25519.PublicKeySize || bytes.Equal(pipeline, ledger) {
		return nil, ErrConfiguration
	}
	master, err := privateFile(c.ArchiveKeyFile, 32)
	if err != nil || len(master) != 32 {
		return nil, ErrConfiguration
	}
	defer func() {
		for i := range master {
			master[i] = 0
		}
	}()
	keys, err := configuration.NewArtifactFixtureKeys(master)
	if err != nil {
		return nil, ErrConfiguration
	}
	access, err := privateFile(c.S3AccessKeyFile, 256)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range access {
			access[i] = 0
		}
	}()
	secret, err := privateFile(c.S3SecretKeyFile, 256)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	accessText, secretText := strings.TrimSpace(string(access)), strings.TrimSpace(string(secret))
	if accessText == "" || secretText == "" || strings.ContainsAny(accessText+secretText, "\x00\r\n\t ") || strings.HasPrefix(accessText, "AKIA") || strings.HasPrefix(accessText, "ASIA") {
		return nil, ErrConfiguration
	}
	u, _ := url.Parse(c.S3Endpoint)
	ip, err := privateHost(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	wantedAddress := net.JoinHostPort(u.Hostname(), u.Port())
	pinnedAddress := net.JoinHostPort(ip, u.Port())
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != wantedAddress {
			return nil, ErrConfiguration
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, pinnedAddress)
	}}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client := s3.New(s3.Options{Region: c.S3Region, BaseEndpoint: aws.String(c.S3Endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(accessText, secretText, ""), HTTPClient: httpClient, RetryMaxAttempts: 2})
	version, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(c.S3Bucket)})
	if err != nil || version == nil || version.Status != s3types.BucketVersioningStatusEnabled {
		transport.CloseIdleConnections()
		return nil, ErrConfiguration
	}
	dsn, err := privateFile(c.DatabaseFile, 8192)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	defer func() {
		for i := range dsn {
			dsn[i] = 0
		}
	}()
	pinned, err := privateDatabase(ctx, dsn)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	db, err := store.OpenRuntime(ctx, pinned, "group-fixture")
	if err != nil {
		transport.CloseIdleConnections()
		return nil, ErrConfiguration
	}
	return &Worker{config: c, installation: installed, pipeline: pipeline, ledger: ledger, repository: postgresRepository{db}, archive: &p.EncryptedArchive{Client: client, Bucket: c.S3Bucket, Keys: keys}, prepare: p.Prepare, close: func() { db.Pool.Close(); transport.CloseIdleConnections() }}, nil
}

func (w *Worker) Close() {
	if w != nil && w.close != nil {
		w.close()
	}
}

// Run performs one explicit job. A crash leaves its native files untouched for
// investigation; the preparer never cleans or overwrites an uncertain workspace.
// Audit INSERT is not granted to029's role: append issuer columns are provenance.
func (w *Worker) Run(ctx context.Context) (Result, error) {
	var result Result
	if w == nil || w.repository == nil || w.archive == nil || w.prepare == nil || w.config.Validate() != nil {
		return result, ErrConfiguration
	}
	release, err := w.repository.lock(ctx, w.config.TenantID, w.config.ProposalID)
	if err != nil {
		return result, err
	}
	defer release()
	doc, err := w.repository.prepared(ctx, w.config.TenantID, w.config.ProposalID)
	existing := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, ErrJob
	}
	if !existing {
		selected, mapping, e := w.repository.current(ctx, w.config.TenantID, w.config.ProposalID)
		if e != nil {
			return result, ErrJob
		}
		if selected.ID != w.config.ProposalID || g.ValidateBinding(selected.Binding) != nil || g.ValidateRealm(selected.Realm) != nil || selected.Binding.Old.Target.TenantID != w.config.TenantID || selected.Binding.Candidate.Target.TenantID != w.config.TenantID || selected.CustomerExecutionAuthorized || selected.EstimatedSaving != nil || selected.VerifiedSaving != nil || !w.installation.matches(selected) {
			return result, ErrConfiguration
		}
		prepared, e := w.prepare(ctx, selected, p.Installation{ImageSHA256: w.installation.ToolchainImageSHA256, Mapping: mapping, PipelineKey: w.pipeline, LedgerKey: w.ledger}, w.archive)
		if e != nil {
			return result, ErrJob
		}
		doc, e = w.repository.append(ctx, w.config.TenantID, selected, mapping, prepared)
		if e != nil {
			return result, ErrJob
		}
	}
	result = Result{ProposalID: w.config.ProposalID, PreparedProgramID: model.String(doc, "id"), ProgramSHA256: model.String(doc, "program_hash"), ManifestSHA256: model.String(doc, "manifest_hash"), Existing: existing}
	if model.String(doc, "proposal_id") != w.config.ProposalID || !identifier.MatchString(result.PreparedProgramID) || !digest.MatchString(result.ProgramSHA256) || !digest.MatchString(result.ManifestSHA256) {
		return Result{}, ErrJob
	}
	return result, nil
}
