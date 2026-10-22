// Package groupfixturecommission is an operator-only local fixture adapter.
// Its September billing reader is explicitly a deterministic test double, not
// AWS evidence. Production AWSFactory never selects it. No customer execution,
// historical ownership, native price or verified saving is established here.
package groupfixturecommission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

const ReadBinding = "DETERMINISTIC_FIXTURE_GROUP_COMMISSION"
const FixturePrefix = "DETERMINISTIC_FIXTURE_GROUP/cur/"

var ErrBoundary = errors.New("ISOLATED_GROUP_COMMISSION_BOUNDARY_INVALID")
var ErrJob = errors.New("ISOLATED_GROUP_COMMISSION_JOB_FAILED")
var id = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)
var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Config struct {
	SchemaVersion string   `json:"schema_version"`
	Mode          string   `json:"mode"`
	Fixture       bool     `json:"fixture"`
	TenantID      string   `json:"tenant_id"`
	SourceID      string   `json:"source_id,omitempty"`
	DatabaseFile  string   `json:"database_file"`
	ImageSHA256   string   `json:"image_sha256,omitempty"`
	SourceSHA256  string   `json:"source_sha256,omitempty"`
	ReceiptID     string   `json:"receipt_id,omitempty"`
	Storage       *Storage `json:"storage,omitempty"`
}

type Storage struct {
	ObjectAccessFile       string `json:"object_access_file"`
	ObjectSecretFile       string `json:"object_secret_file"`
	ClickHousePasswordFile string `json:"clickhouse_password_file"`
	EconomicsTokenFile     string `json:"economics_token_file"`
}

// NewRegistration is passed only to the existing authenticated registration
// API. It contains no raw observations, checkpoint status or credentials.
func NewRegistration(tenant, sourceID string) model.Document {
	d := source.FixtureRegistration(tenant, sourceID)
	d["read_role_binding_id"], d["prefix"] = ReadBinding, FixturePrefix
	return d
}

func RegistrationInput() model.Document {
	d := NewRegistration("tenant-demo", "not-submitted")
	for _, key := range []string{"id", "tenant_id", "version", "enabled"} {
		delete(d, key)
	}
	return d
}

func (c Config) Validate() error {
	if c.SchemaVersion != "1" || !c.Fixture || c.TenantID != "tenant-demo" || c.DatabaseFile != "/secrets/database" {
		return ErrBoundary
	}
	switch c.Mode {
	case "INSTALL_PROFILE":
		if c.SourceID != "" || c.Storage != nil || !hash.MatchString(c.ImageSHA256) || !hash.MatchString(c.SourceSHA256) || !id.MatchString(c.ReceiptID) {
			return ErrBoundary
		}
	case "SYNC_SOURCE":
		if !id.MatchString(c.SourceID) || c.ImageSHA256 != "" || c.SourceSHA256 != "" || c.ReceiptID != "" || c.Storage == nil {
			return ErrBoundary
		}
		if *c.Storage != (Storage{"/secrets/object-access", "/secrets/object-secret", "/secrets/clickhouse-password", "/secrets/economics-token"}) {
			return ErrBoundary
		}
	default:
		return ErrBoundary
	}
	return nil
}

func Decode(raw []byte) (Config, error) {
	var c Config
	if len(raw) > 8192 {
		return c, ErrBoundary
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, ErrBoundary
	}
	return c, c.Validate()
}

// PrivateInput is supplied only over the inspected local daemon's stdin to a
// fresh nonroot job. File names are fixed; no environment or host secret mount
// enters the process. It is not a public API or an artifact authority upload.
type PrivateInput struct {
	Job   json.RawMessage   `json:"job"`
	Files map[string][]byte `json:"files"`
}

func DecodePrivateInput(raw []byte) (PrivateInput, Config, error) {
	var input PrivateInput
	var c Config
	if len(raw) > 65536 {
		return input, c, ErrBoundary
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		return input, c, ErrBoundary
	}
	c, e := Decode(input.Job)
	if e != nil {
		return input, c, e
	}
	wanted := []string{"database"}
	if c.Mode == "SYNC_SOURCE" {
		wanted = append(wanted, "object-access", "object-secret", "clickhouse-password", "economics-token")
	}
	if len(input.Files) != len(wanted) {
		return input, c, ErrBoundary
	}
	for _, name := range wanted {
		if len(input.Files[name]) < 1 || len(input.Files[name]) > 8192 {
			return input, c, ErrBoundary
		}
	}
	return input, c, nil
}
func StagePrivateInput(reader io.Reader) error {
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		return ErrBoundary
	}
	raw, e := io.ReadAll(io.LimitReader(reader, 65537))
	if e != nil {
		return ErrBoundary
	}
	input, c, e := DecodePrivateInput(raw)
	if e != nil {
		return e
	}
	i, e := os.Lstat("/secrets")
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 {
		return ErrBoundary
	}
	entries, e := os.ReadDir("/secrets")
	if e != nil || len(entries) != 0 {
		return ErrBoundary
	}
	job, _ := json.Marshal(c)
	input.Files["job.json"] = job
	for name, body := range input.Files {
		f, e := os.OpenFile("/secrets/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrBoundary
		}
		_, e = f.Write(body)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return ErrBoundary
		}
	}
	return nil
}

func secret(path string) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() < 1 || i.Size() > 8192 {
		return nil, ErrBoundary
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrBoundary
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) {
		return nil, ErrBoundary
	}
	raw, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || int64(len(raw)) != i.Size() {
		return nil, ErrBoundary
	}
	return raw, nil
}

func environment(entries []string) error {
	for _, entry := range entries {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		for _, prefix := range []string{"AWS_", "AZURE_", "GOOGLE_", "GCP_", "ARM_", "TF_VAR_", "TF_CLI_ARGS", "TF_TOKEN_", "DOCKER_", "PG", "SIGNING_", "SIGNER_", "EXECUTOR_", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
			if strings.HasPrefix(key, prefix) {
				return ErrBoundary
			}
		}
	}
	return nil
}

func native(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary != "/usr/bin/git" && binary != "/usr/local/bin/terraform" {
		return nil, ErrBoundary
	}
	c := exec.CommandContext(ctx, binary, args...)
	c.Dir = "/tmp"
	c.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C", "LC_ALL=C", "CHECKPOINT_DISABLE=1"}
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = io.Discard
	if c.Run() != nil || out.Len() > 65536 {
		return nil, ErrJob
	}
	return out.Bytes(), nil
}

type Result struct {
	Status                      string      `json:"status"`
	Mode                        string      `json:"mode"`
	Fixture                     bool        `json:"fixture"`
	ProviderAdapter             string      `json:"provider_adapter,omitempty"`
	Profile                     *ff.Profile `json:"profile,omitempty"`
	SourceID                    string      `json:"source_id,omitempty"`
	ConfigSHA256                string      `json:"config_sha256,omitempty"`
	LastSyncAt                  string      `json:"last_sync_at,omitempty"`
	ActualGitVersion            string      `json:"actual_git_version,omitempty"`
	ActualTerraformVersion      string      `json:"actual_terraform_version,omitempty"`
	ActualPlatform              string      `json:"actual_platform,omitempty"`
	ImageSHA256                 string      `json:"image_sha256,omitempty"`
	SourceSHA256                string      `json:"source_sha256,omitempty"`
	ReceiptID                   string      `json:"receipt_id,omitempty"`
	CustomerExecutionAuthorized bool        `json:"customer_execution_authorized"`
	VerifiedSaving              any         `json:"verified_saving"`
}

func Run(ctx context.Context, c Config) (Result, error) {
	result := Result{Mode: c.Mode, Fixture: true}
	if c.Validate() != nil || runtime.GOOS != "linux" || os.Getuid() == 0 || environment(os.Environ()) != nil {
		return result, ErrBoundary
	}
	dsn, e := secret(c.DatabaseFile)
	if e != nil {
		return result, e
	}
	u, e := url.Parse(strings.TrimSpace(string(dsn)))
	if e != nil || u.Scheme != "postgres" || u.Host != "postgres:5432" || u.Path != "/finops" || u.User == nil || u.User.Username() == "" || u.RawQuery != "sslmode=disable" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || u.ForceQuery {
		return result, ErrBoundary
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return result, ErrBoundary
	}
	role := "ingester"
	if c.Mode == "INSTALL_PROFILE" {
		role = "group-fixture"
	}
	db, e := store.OpenRuntime(ctx, u.String(), role)
	if e != nil {
		return result, ErrBoundary
	}
	defer db.Pool.Close()
	if e = fixtureOrganization(ctx, db); e != nil {
		return result, ErrBoundary
	}
	if c.Mode == "INSTALL_PROFILE" {
		gitRaw, e := native(ctx, "/usr/bin/git", "--version")
		if e != nil {
			return result, e
		}
		gitVersion := strings.TrimSpace(string(gitRaw))
		if !regexp.MustCompile(`^git version [0-9]+\.[0-9]+\.[0-9]+$`).MatchString(gitVersion) {
			return result, ErrBoundary
		}
		tfRaw, e := native(ctx, "/usr/local/bin/terraform", "version", "-json")
		if e != nil {
			return result, e
		}
		var tf struct {
			Version  string `json:"terraform_version"`
			Platform string `json:"platform"`
		}
		if json.Unmarshal(tfRaw, &tf) != nil || tf.Version != "1.16.0" || tf.Platform != "linux_"+runtime.GOARCH {
			return result, ErrBoundary
		}
		var installed ff.Profile
		e = db.Do(ctx, c.TenantID, func(tx *store.Tx) error {
			var e error
			installed, e = tx.FleetFixtureProfileInstall(ctx, ff.Installation{TemplateID: "builtin-group-fixture-v1", ToolchainImageSHA256: c.ImageSHA256, TerraformVersion: tf.Version, ReceiptID: c.ReceiptID, SourceSHA256: c.SourceSHA256})
			return e
		})
		if e != nil {
			return result, ErrJob
		}
		result.Status = "INSTALLED"
		result.Profile = &installed
		result.ActualGitVersion = gitVersion
		result.ActualTerraformVersion = tf.Version
		result.ActualPlatform = tf.Platform
		result.ImageSHA256 = c.ImageSHA256
		result.SourceSHA256 = c.SourceSHA256
		result.ReceiptID = c.ReceiptID
		return result, nil
	}
	for variable, path := range map[string]string{"OBJECT_ACCESS_KEY": c.Storage.ObjectAccessFile, "OBJECT_SECRET_KEY": c.Storage.ObjectSecretFile, "CLICKHOUSE_PASSWORD": c.Storage.ClickHousePasswordFile, "ECONOMICS_TOKEN": c.Storage.EconomicsTokenFile} {
		raw, e := secret(path)
		if e != nil {
			return result, e
		}
		value := strings.TrimSpace(string(raw))
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return result, ErrBoundary
		}
		if e = os.Setenv(variable, value); e != nil {
			return result, ErrBoundary
		}
		defer os.Unsetenv(variable)
	}
	for k, v := range map[string]string{"OBJECT_ENDPOINT": "http://minio:9000", "OBJECT_BUCKET_RAW": "finops-raw", "OBJECT_REGION": "eu-west-1", "CLICKHOUSE_URL": "http://clickhouse:8123", "CLICKHOUSE_DATABASE": "finops", "CLICKHOUSE_USER": "finops"} {
		if e = os.Setenv(k, v); e != nil {
			return result, ErrBoundary
		}
		defer os.Unsetenv(k)
	}
	var registration model.Document
	e = db.Do(ctx, c.TenantID, func(tx *store.Tx) error { var e error; registration, e = tx.SourceGet(ctx, c.SourceID); return e })
	if e != nil {
		return result, ErrJob
	}
	wanted := NewRegistration(c.TenantID, c.SourceID)
	if source.ConfigurationHash(registration) != source.ConfigurationHash(wanted) || !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") {
		return result, ErrBoundary
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	api := &service.API{Config: service.Config{Fixture: true, EconomicsURL: "http://economics:8000", EconomicsToken: os.Getenv("ECONOMICS_TOKEN")}, Client: client}
	pipeline := source.Pipeline{Store: db, Normalize: api.NormalizeTrustedSource, Persist: service.PersistEvidence, ArchiveObject: service.ArchiveSourceObject, ProviderFactory: func(_ context.Context, r source.Registration) (source.Reader, error) {
		if r.ID != c.SourceID || r.TenantID != c.TenantID {
			return nil, ErrBoundary
		}
		wanted, e := source.ParseRegistration(NewRegistration(c.TenantID, c.SourceID))
		if e != nil {
			return nil, ErrBoundary
		}
		wanted.Version = r.Version
		if g.Digest(wanted) != g.Digest(r) {
			return nil, ErrBoundary
		}
		return source.NewFixtureReader(r, nil)
	}}
	if e = pipeline.Sync(ctx, c.TenantID, c.SourceID); e != nil {
		return result, ErrJob
	}
	e = db.Do(ctx, c.TenantID, func(tx *store.Tx) error { var e error; registration, e = tx.SourceGet(ctx, c.SourceID); return e })
	if e != nil || model.String(registration, "status") != "HEALTHY" || model.String(registration, "config_hash") != source.ConfigurationHash(wanted) {
		return result, ErrJob
	}
	last, e := time.Parse(time.RFC3339Nano, model.String(registration, "last_sync_at"))
	if e != nil || time.Since(last) < 0 || time.Since(last) > time.Minute {
		return result, ErrJob
	}
	result.Status = "HEALTHY"
	result.ProviderAdapter = "DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026"
	result.SourceID = c.SourceID
	result.ConfigSHA256 = source.ConfigurationHash(wanted)
	result.LastSyncAt = last.UTC().Format(time.RFC3339Nano)
	return result, nil
}

// The private job's assertion never substitutes for the persisted tenant
// boundary. A missing or live organization is refused before native commands,
// profile reads/writes, source reads, storage or provider-shaped I/O.
func fixtureOrganization(ctx context.Context, db *store.Store) error {
	return db.Do(ctx, "tenant-demo", func(tx *store.Tx) error {
		org, err := tx.Get(ctx, "org", "tenant-demo")
		if err != nil || org["fixture"] != true {
			return ErrBoundary
		}
		return nil
	})
}
