package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
)

const ArtifactAudience = "finops-configuration-attestor"
const ArtifactMaxBytes = 64 << 20

var artifactID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var artifactSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var artifactCommit = regexp.MustCompile(`^[a-f0-9]{40}$|^[a-f0-9]{64}$`)
var ErrArtifactInactive = errors.New("CONFIGURATION_ARTIFACT_REGISTRATION_INACTIVE")
var ErrArtifactConflict = errors.New("CONFIGURATION_ARTIFACT_REPLAY_CONFLICT")

func artifactHash(v any) string {
	raw, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	return artifactBytesHash(raw)
}
func artifactBytesHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// ArtifactRegistration is installed by a private operator-owned registry. The
// declaration remains unchanged: this registry never makes it executable.
type ArtifactRegistration struct {
	SchemaVersion    string            `json:"schema_version"`
	ID               string            `json:"id"`
	Version          int64             `json:"version"`
	Binding          Binding           `json:"binding"`
	AuthorityID      string            `json:"authority_id"`
	AuthorityVersion int64             `json:"authority_version"`
	AuthorityHash    string            `json:"authority_hash"`
	Declaration      Declaration       `json:"declaration"`
	Issuer           string            `json:"issuer"`
	Audience         string            `json:"audience"`
	Subject          string            `json:"subject"`
	PipelineID       string            `json:"pipeline_id"`
	Toolchain        ArtifactToolchain `json:"toolchain"`
}
type ArtifactToolchain struct {
	TerraformVersion string `json:"terraform_version"`
	Image            string `json:"image"`
	OS               string `json:"os"`
	Architecture     string `json:"architecture"`
	WorkingDirectory string `json:"working_directory"`
}

func ValidateArtifactRegistration(r ArtifactRegistration) error {
	b := r.Binding
	if r.SchemaVersion != "1" || !artifactID.MatchString(r.ID) || r.Version < 1 || !artifactID.MatchString(b.TenantID) || !artifactID.MatchString(b.ResourceID) || !artifactID.MatchString(b.WorkloadID) || b.ResourceVersion < 1 || !artifactSHA.MatchString(b.ResourceSnapshotHash) || !artifactID.MatchString(r.AuthorityID) || r.AuthorityVersion < 1 || !artifactSHA.MatchString(r.AuthorityHash) {
		return errors.New("CONFIGURATION_ARTIFACT_REGISTRATION_INVALID")
	}
	if e := ValidateBinding(r.Declaration, b); e != nil {
		return e
	}
	i := r.Declaration.Pipeline.Identity
	if r.Issuer != i.Issuer || !HTTPSMetadata(r.Issuer) || r.Audience != ArtifactAudience || r.Subject != i.Subject || r.PipelineID != i.PipelineID {
		return errors.New("CONFIGURATION_ARTIFACT_MACHINE_BINDING_INVALID")
	}
	t := r.Toolchain
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(t.TerraformVersion) || !regexp.MustCompile(`^[a-z0-9./:_-]+@sha256:[a-f0-9]{64}$`).MatchString(t.Image) || t.OS != "linux" || (t.Architecture != "amd64" && t.Architecture != "arm64") || t.WorkingDirectory != path.Join("/workspace", r.Declaration.Repository.Directory) {
		return errors.New("CONFIGURATION_ARTIFACT_TOOLCHAIN_INVALID")
	}
	return nil
}

// Principal can only be produced through the configured OIDC verifier. It is
// deliberately not JSON-decodable and contains no caller-selected tenant.
type ArtifactPrincipal struct{ tenant, subject, issuer, audience string }
type artifactTokenValidator interface {
	Validate(*http.Request) (auth.Identity, error)
}
type ArtifactAuthenticator struct {
	validator        artifactTokenValidator
	issuer, audience string
}

func NewArtifactAuthenticator(ctx context.Context, issuer, audience, jwks string, fixture bool) (*ArtifactAuthenticator, error) {
	valid := func(raw string) bool {
		u, e := url.Parse(raw)
		return e == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Scheme == "https" || fixture && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))
	}
	if !valid(issuer) || jwks != "" && !valid(jwks) || audience != ArtifactAudience {
		return nil, errors.New("CONFIGURATION_ARTIFACT_OIDC_INVALID")
	}
	v, e := auth.New(ctx, issuer, audience, jwks)
	if e != nil {
		return nil, errors.New("CONFIGURATION_ARTIFACT_OIDC_INVALID")
	}
	return &ArtifactAuthenticator{v, issuer, audience}, nil
}
func (a *ArtifactAuthenticator) Authenticate(r *http.Request) (ArtifactPrincipal, error) {
	if a == nil || a.validator == nil {
		return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_MACHINE_REQUIRED")
	}
	i, e := a.validator.Validate(r)
	if e != nil || !artifactID.MatchString(i.Tenant) || i.Subject == "" {
		return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_MACHINE_REQUIRED")
	}
	// The shared verifier checks signature/issuer/expiry and target audience.
	// Require that audience alone, so a multi-purpose console/activity token
	// cannot double as this dedicated artifact machine credential.
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	var claims struct {
		Audience json.RawMessage `json:"aud"`
	}
	if len(parts) != 3 || len(parts[1]) > 32768 {
		return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_MACHINE_REQUIRED")
	}
	payload, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decodeErr != nil || json.Unmarshal(payload, &claims) != nil {
		return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_MACHINE_REQUIRED")
	}
	var aud string
	var audiences []string
	if json.Unmarshal(claims.Audience, &aud) != nil {
		if json.Unmarshal(claims.Audience, &audiences) != nil || len(audiences) != 1 {
			return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_DEDICATED_AUDIENCE_REQUIRED")
		}
		aud = audiences[0]
	}
	if aud != a.audience {
		return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_DEDICATED_AUDIENCE_REQUIRED")
	}
	for _, role := range []string{"ORGANISATION_OWNER", "FINOPS_ADMIN", "PLATFORM_ADMIN", "FINANCE", "APPLICATION_OWNER", "APPROVER", "VIEWER", "AUDITOR", "FLEET_APPROVER"} {
		if i.Roles[role] {
			return ArtifactPrincipal{}, errors.New("CONFIGURATION_ARTIFACT_MACHINE_REQUIRED")
		}
	}
	return ArtifactPrincipal{i.Tenant, i.Subject, a.issuer, a.audience}, nil
}
func artifactPrincipalMatches(p ArtifactPrincipal, r ArtifactRegistration) bool {
	return p.tenant == r.Binding.TenantID && p.subject == r.Subject && p.issuer == r.Issuer && p.audience == r.Audience && p.subject != ""
}

type ArtifactFile struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
	Body   []byte `json:"body"`
}
type ArtifactGit struct {
	Commit              string `json:"commit"`
	Tree                string `json:"tree"`
	Ref                 string `json:"ref"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
	DependencySHA256    string `json:"dependency_sha256"`
}
type ArtifactState struct {
	Lineage   string `json:"lineage"`
	Serial    uint64 `json:"serial"`
	Workspace string `json:"workspace"`
}

// Bundle is sensitive. It has no public route, log formatter or workflow input.
type ArtifactBundle struct {
	SchemaVersion  string            `json:"schema_version"`
	Git            ArtifactGit       `json:"git"`
	Toolchain      ArtifactToolchain `json:"toolchain"`
	State          ArtifactState     `json:"state"`
	Files          []ArtifactFile    `json:"files"`
	SavedPlan      []byte            `json:"saved_plan"`
	PlanJSON       []byte            `json:"plan_json"`
	StateRaw       []byte            `json:"state_raw"`
	StateJSON      []byte            `json:"state_json"`
	VersionJSON    []byte            `json:"version_json"`
	ModuleManifest []byte            `json:"module_manifest"`
}
type ArtifactMetadata struct {
	SchemaVersion       string            `json:"schema_version"`
	RegistrationID      string            `json:"registration_id"`
	RegistrationVersion int64             `json:"registration_version"`
	RegistrationHash    string            `json:"registration_hash"`
	Binding             Binding           `json:"binding"`
	AuthorityID         string            `json:"authority_id"`
	AuthorityVersion    int64             `json:"authority_version"`
	AuthorityHash       string            `json:"authority_hash"`
	Git                 ArtifactGit       `json:"git"`
	Toolchain           ArtifactToolchain `json:"toolchain"`
	State               ArtifactState     `json:"state"`
	BundleSHA256        string            `json:"bundle_sha256"`
	SavedPlanSHA256     string            `json:"saved_plan_sha256"`
	PlanJSONSHA256      string            `json:"plan_json_sha256"`
	StateSHA256         string            `json:"state_sha256"`
	Status              string            `json:"status"`
	ReasonCodes         []string          `json:"reason_codes"`
	ExecutionAuthorized bool              `json:"execution_authorized"`
	VerifiedSaving      *string           `json:"verified_saving"`
}
type ArtifactArchiveRef struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}
type ArtifactJob struct {
	ID        string           `json:"id"`
	Key       string           `json:"key"`
	Metadata  ArtifactMetadata `json:"metadata"`
	CreatedAt time.Time        `json:"created_at"`
}
type ArtifactReceipt struct {
	ID         string             `json:"id"`
	JobID      string             `json:"job_id"`
	Metadata   ArtifactMetadata   `json:"metadata"`
	Archive    ArtifactArchiveRef `json:"archive"`
	ObservedAt time.Time          `json:"observed_at"`
	ReceivedAt time.Time          `json:"received_at"`
	ExpiresAt  time.Time          `json:"expires_at"`
}

// PublicProjection never returns file names, state/config values or object URLs.
func (r ArtifactReceipt) PublicProjection() map[string]any {
	return map[string]any{"id": r.ID, "job_id": r.JobID, "registration_id": r.Metadata.RegistrationID, "authority_id": r.Metadata.AuthorityID, "binding": r.Metadata.Binding, "bundle_sha256": r.Metadata.BundleSHA256, "saved_plan_sha256": r.Metadata.SavedPlanSHA256, "plan_json_sha256": r.Metadata.PlanJSONSHA256, "status": r.Metadata.Status, "reason_codes": r.Metadata.ReasonCodes, "observed_at": r.ObservedAt, "received_at": r.ReceivedAt, "expires_at": r.ExpiresAt, "execution_authorized": false, "verified_saving": nil}
}

type ArtifactRepository interface {
	Current(context.Context, string, string) (ArtifactRegistration, error)
	Prepare(context.Context, ArtifactRegistration, string, ArtifactMetadata) (ArtifactJob, bool, error)
	JobByKey(context.Context, string, string, string) (ArtifactJob, error)
	Checkpoint(context.Context, string, string, ArtifactArchiveRef) error
	Archive(context.Context, string, string) (ArtifactArchiveRef, error)
	Publish(context.Context, string, string) (ArtifactReceipt, bool, error)
}
type ArtifactCollector interface {
	Collect(context.Context, ArtifactRegistration) (ArtifactBundle, error)
}
type ArtifactArchive interface {
	Put(context.Context, string, string, []byte) (ArtifactArchiveRef, error)
	Read(context.Context, string, ArtifactArchiveRef) ([]byte, error)
}

func artifactSafeReason(e error) string {
	if e == nil {
		return ""
	}
	s := e.Error()
	if regexp.MustCompile(`^CONFIGURATION_[A-Z0-9_]{1,110}$`).MatchString(s) {
		return s
	}
	return "CONFIGURATION_ARTIFACT_UNAVAILABLE"
}
func artifactUnique(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func artifactHTTPS(s string) bool { return HTTPSMetadata(strings.TrimSuffix(s, "/")) }
