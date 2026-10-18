// Package configuration records operator declarations, never deployment proof.
// Repository and issuer URLs are metadata; this package does not fetch them.
package configuration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

const ObserverAudience = "finops-deployment-observer"

type Repository struct {
	URL       string `json:"url"`
	Ref       string `json:"ref"`
	Directory string `json:"directory"`
}
type PipelineIdentity struct {
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	Subject    string `json:"subject"`
	PipelineID string `json:"pipeline_id"`
}
type Pipeline struct {
	System   string           `json:"system"`
	Identity PipelineIdentity `json:"identity"`
}
type Terraform struct {
	Workspace    string   `json:"workspace"`
	StateLineage string   `json:"state_lineage"`
	Addresses    []string `json:"addresses"`
}

// Declaration contains no observed commit, state serial, credentials, proof,
// plan or execution permission. Such fields are rejected by Decode.
type Declaration struct {
	SchemaVersion string     `json:"schema_version"`
	Authority     string     `json:"authority"`
	Repository    Repository `json:"repository"`
	Pipeline      Pipeline   `json:"pipeline"`
	Terraform     Terraform  `json:"terraform"`
}

type Binding struct {
	telemetry.Binding
	ResourceVersion      int64  `json:"resource_version"`
	ResourceSnapshotHash string `json:"resource_snapshot_hash"`
}

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	namePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	// Restrict the initial declaration grammar to managed provider resources.
	// Module paths and explicit count/for_each indices are retained exactly.
	addressPattern = regexp.MustCompile(`^(module\.[A-Za-z_][A-Za-z0-9_-]*(\[(0|[1-9][0-9]*)\]|\["[A-Za-z0-9_-]+"\])?\.)*(aws|azurerm|google)_[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_-]*(\[(0|[1-9][0-9]*)\]|\["[A-Za-z0-9_-]+"\])?$`)
)

func invalid(code string) error { return errors.New(code) }
func scalar(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.IsSpace(c) || c == '*' {
			return false
		}
	}
	return true
}
func HTTPSMetadata(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(s, "\\\r\n\t ")
}
func ValidRef(s string) bool {
	if !scalar(s, 255) || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || strings.Contains(s, "@{") || strings.ContainsAny(s, "~^:?[]\\") || strings.HasSuffix(s, "/") || strings.HasPrefix(s, "/") || strings.Contains(s, "//") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
func ValidDirectory(s string) bool {
	if s == "." {
		return true
	}
	return scalar(s, 512) && !strings.ContainsAny(s, "\\:") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../")
}
func Decode(raw []byte) (Declaration, error) {
	var d Declaration
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 32<<10 || decoder.Decode(&d) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return d, invalid("CONFIGURATION_DECLARATION_FIELDS_INVALID")
	}
	if err := Validate(d); err != nil {
		return d, err
	}
	// Deterministic set order does not change canonical address spelling.
	sort.Strings(d.Terraform.Addresses)
	return d, nil
}
func Validate(d Declaration) error {
	if d.SchemaVersion != "1" || d.Authority != "TERRAFORM" {
		return invalid("CONFIGURATION_AUTHORITY_UNSUPPORTED")
	}
	if !HTTPSMetadata(d.Repository.URL) || !ValidRef(d.Repository.Ref) || !ValidDirectory(d.Repository.Directory) {
		return invalid("CONFIGURATION_REPOSITORY_INVALID")
	}
	switch d.Pipeline.System {
	case "GITHUB_ACTIONS", "GITLAB_CI", "BITBUCKET_PIPELINES", "OTHER":
	default:
		return invalid("CONFIGURATION_PIPELINE_INVALID")
	}
	i := d.Pipeline.Identity
	if !HTTPSMetadata(i.Issuer) || i.Audience != ObserverAudience || !scalar(i.Subject, 512) || !scalar(i.PipelineID, 256) {
		return invalid("CONFIGURATION_PIPELINE_IDENTITY_INVALID")
	}
	if !namePattern.MatchString(d.Terraform.Workspace) || !uuidPattern.MatchString(d.Terraform.StateLineage) || len(d.Terraform.Addresses) < 1 || len(d.Terraform.Addresses) > 32 {
		return invalid("CONFIGURATION_TERRAFORM_STATE_INVALID")
	}
	seen := map[string]bool{}
	for _, address := range d.Terraform.Addresses {
		if len(address) > 512 || !addressPattern.MatchString(address) || seen[address] {
			return invalid("CONFIGURATION_TERRAFORM_ADDRESS_INVALID")
		}
		seen[address] = true
	}
	return nil
}

func NewBinding(tenant string, r model.Document) (Binding, error) {
	b := Binding{Binding: telemetry.Binding{TenantID: tenant, ResourceID: model.String(r, "id"), WorkloadID: model.String(r, "workload_id"), Provider: model.String(r, "provider"), ProviderResourceID: model.String(r, "provider_resource_id"), AccountID: model.String(r, "account_id"), Region: model.String(r, "region")}, ResourceVersion: model.Number(r, "version"), ResourceSnapshotHash: telemetry.Hash(r)}
	if tenant == "" || b.ResourceID == "" || b.WorkloadID == "" || b.ProviderResourceID == "" || b.AccountID == "" || b.Region == "" || b.ResourceVersion < 1 {
		return b, invalid("CONFIGURATION_RESOURCE_BINDING_REQUIRED")
	}
	switch b.Provider {
	case "AWS", "AZURE", "GCP":
	default:
		return b, invalid("CONFIGURATION_PROVIDER_UNSUPPORTED")
	}
	return b, nil
}

func Reasons(b Binding) []string {
	reasons := []string{"PIPELINE_ATTESTATION_REQUIRED", "CONFIGURATION_STATE_UNOBSERVED"}
	if b.Provider != "AWS" || b.Region != "eu-west-1" {
		reasons = append(reasons, "PROVIDER_ACTION_NOT_ENABLED")
	}
	return reasons
}

func ValidateBinding(d Declaration, b Binding) error {
	if err := Validate(d); err != nil {
		return err
	}
	prefix := map[string]string{"AWS": "aws_", "AZURE": "azurerm_", "GCP": "google_"}[b.Provider]
	for _, address := range d.Terraform.Addresses {
		// Strip module pairs, preserving the final managed resource pair.
		parts := strings.Split(address, ".")
		if prefix == "" || len(parts) < 2 || !strings.HasPrefix(parts[len(parts)-2], prefix) {
			return invalid("CONFIGURATION_ADDRESS_PROVIDER_MISMATCH")
		}
	}
	return nil
}

func DeclarationDocument(d Declaration) model.Document {
	raw, _ := json.Marshal(d)
	var out model.Document
	_ = json.Unmarshal(raw, &out)
	return out
}
