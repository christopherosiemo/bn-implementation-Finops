// Package fleetfixture connects real group selectors to an isolated fixture
// proposal. Customer evidence remains blocked; a selection is not a program,
// artifact attestation, execution permission or financial claim.
package fleetfixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

var ErrSelection = errors.New("FLEET_FIXTURE_SELECTION_INVALID")
var ErrCurrent = errors.New("FLEET_FIXTURE_CURRENT_BINDING_REQUIRED")
var ErrMapping = errors.New("FLEET_FIXTURE_MAPPING_CONFLICT")
var ErrProgram = errors.New("PROGRAM_NOT_PREPARED")
var ErrPreparation = errors.New("FLEET_FIXTURE_PREPARATION_INVALID")
var ErrSelfApproval = errors.New("FLEET_FIXTURE_INDEPENDENT_APPROVER_REQUIRED")

type SelectionRequest struct {
	OldConfigurationProposalID       string `json:"old_configuration_proposal_id"`
	CandidateConfigurationProposalID string `json:"candidate_configuration_proposal_id"`
	FixtureProfileID                 string `json:"fixture_profile_id"`
}

type Profile struct {
	SchemaVersion    string       `json:"schema_version"`
	ID               string       `json:"id"`
	Generation       string       `json:"generation"`
	Name             string       `json:"name"`
	RealmKind        string       `json:"realm_kind"`
	ModelKind        string       `json:"model_kind"`
	ModelVersion     string       `json:"model_version"`
	ModelSHA256      string       `json:"model_sha256"`
	RuntimeAvailable bool         `json:"runtime_available"`
	Model            Model        `json:"model"`
	Installation     Installation `json:"installation"`
}

type Installation struct {
	TemplateID           string `json:"template_id"`
	ToolchainImageSHA256 string `json:"toolchain_image_sha256"`
	TerraformVersion     string `json:"terraform_version"`
	ReceiptID            string `json:"receipt_id"`
	SourceSHA256         string `json:"source_sha256"`
}

// All prices/capacities here are an explicitly installed fixture model. They
// do not describe the selected AWS groups, contracted rates or customer money.
type Model struct {
	OldTemplate       fleetgroup.Template    `json:"old_template"`
	CandidateTemplate fleetgroup.Template    `json:"candidate_template"`
	Budget            fleetgroup.ModelBudget `json:"budget"`
	Policy            fleetgroup.Policy      `json:"policy"`
}

type ConfigurationRef struct {
	ID                 string   `json:"id"`
	SHA256             string   `json:"sha256"`
	ScopeReferenceRoot string   `json:"scope_reference_root"`
	CustomerStatus     string   `json:"customer_status"`
	CustomerReasons    []string `json:"customer_reasons"`
}

type Proposal struct {
	SchemaVersion               string             `json:"schema_version"`
	ID                          string             `json:"id"`
	Purpose                     string             `json:"purpose"`
	CreatorID                   string             `json:"creator_id"`
	WorkloadID                  string             `json:"workload_id"`
	Profile                     Profile            `json:"profile"`
	Realm                       fleetgroup.Realm   `json:"realm"`
	Binding                     fleetgroup.Binding `json:"binding"`
	Old                         ConfigurationRef   `json:"old_configuration_proposal"`
	Candidate                   ConfigurationRef   `json:"candidate_configuration_proposal"`
	CustomerExecutionAuthorized bool               `json:"customer_execution_authorized"`
	EstimatedSaving             *string            `json:"estimated_saving"`
	VerifiedSaving              *string            `json:"verified_saving"`
}

func ID(v string) bool {
	if len(v) < 1 || len(v) > 256 {
		return false
	}
	for _, c := range v {
		if c < 33 || c > 126 || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}

func DecodeSelection(raw []byte) (SelectionRequest, error) {
	var r SelectionRequest
	if len(raw) > 2048 {
		return r, ErrSelection
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !ID(r.OldConfigurationProposalID) || !ID(r.CandidateConfigurationProposalID) || !ID(r.FixtureProfileID) || r.OldConfigurationProposalID == r.CandidateConfigurationProposalID {
		return r, ErrSelection
	}
	return r, nil
}

func Actor(s string) bool { return strings.TrimSpace(s) == s && ID(s) }
