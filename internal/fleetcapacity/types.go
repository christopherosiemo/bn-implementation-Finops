// Package fleetcapacity evaluates each real member of a server-selected group
// pair. Its observations grant neither group capacity nor execution authority.
package fleetcapacity

import (
	"context"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

const MaximumMembers = 256

// Scope is selected and revalidated by the private repository. CurrentMemberIDs
// is the complete authenticated original membership point, including unmapped
// members; a missing inventory or telemetry mapping must not shrink it.
type Scope struct {
	Selection        fleetassessment.Selection     `json:"selection"`
	SnapshotSHA256   string                        `json:"snapshot_sha256"`
	PopulationStatus string                        `json:"population_status"`
	ObservedAt       time.Time                     `json:"observed_at"`
	MembershipPins   []fleetbilling.GroupNativePin `json:"membership_pins"`
	CurrentMemberIDs []string                      `json:"current_member_ids"`
}

// CandidateTemplate is decoded from exact issued launch-template response
// bytes. It is deliberately not a public input or a hypothetical type catalog.
type CandidateTemplate struct {
	ID               string                      `json:"id"`
	Version          string                      `json:"version"`
	InstanceType     string                      `json:"instance_type"`
	ImageID          string                      `json:"image_id"`
	SourcePin        fleetbilling.GroupNativePin `json:"source_pin"`
	DefinitionSHA256 string                      `json:"definition_sha256"`
	ReasonCodes      []string                    `json:"reason_codes"`
	definition       candidateDefinition
}

type NativeEvidence struct {
	Receipt     model.Document
	Revision    model.Document
	Raw         []byte
	RevisionRaw []byte
}

type ScopeInput struct {
	RequestID           string
	Selection           fleetassessment.Selection
	OldMembership       *NativeEvidence
	CandidateMembership *NativeEvidence
	Templates           []NativeEvidence
}

type ScopeCapture struct {
	SchemaVersion       string                        `json:"schema_version"`
	RequestID           string                        `json:"request_id"`
	Scope               Scope                         `json:"scope"`
	CandidateTemplate   *CandidateTemplate            `json:"candidate_template"`
	SourcePins          []fleetbilling.GroupNativePin `json:"source_pins"`
	ReasonCodes         []string                      `json:"reason_codes"`
	ExecutionAuthorized bool                          `json:"execution_authorized"`
	VerifiedSaving      *string                       `json:"verified_saving"`
}

type TelemetryPin struct {
	ConnectionID      string                      `json:"connection_id"`
	ConnectionVersion int64                       `json:"connection_version"`
	RevisionID        string                      `json:"revision_id"`
	ConfigHash        string                      `json:"config_hash"`
	PopulationHash    string                      `json:"population_hash"`
	ReceiptIDs        []string                    `json:"receipt_ids"`
	SourceRefs        []native.CapacityReceiptRef `json:"source_refs"`
}

type HardwarePin struct {
	SourcePin            fleetbilling.GroupNativePin `json:"source_pin"`
	ReceiptID            string                      `json:"receipt_id"`
	SourceID             string                      `json:"source_id"`
	RevisionID           string                      `json:"revision_id"`
	RegistrationVersion  int64                       `json:"registration_version"`
	ConfigHash           string                      `json:"config_hash"`
	RawSHA256            string                      `json:"raw_sha256"`
	ResourceSnapshotHash string                      `json:"resource_snapshot_hash"`
	ResourceVersion      int64                       `json:"resource_version"`
}

// MemberInput contains private, current repository/reader selections. The
// repository authenticates original issued rows and raw versions, and repeats
// those checks under publication locks. This library cannot authenticate a DB
// issuer merely because a document contains its name.
type MemberInput struct {
	BatchID          string
	Scope            Scope
	InstanceID       string
	Resource         model.Document
	Connection       model.Document
	Profile          workload.Profile
	Population       *native.CapacityPopulation
	Hardware         model.Document
	HardwareEvidence *NativeEvidence
	Candidate        *CandidateTemplate
}

type MemberResult struct {
	SchemaVersion                  string                      `json:"schema_version"`
	ID                             string                      `json:"id"`
	BatchID                        string                      `json:"batch_id"`
	Scope                          Scope                       `json:"scope"`
	InstanceID                     string                      `json:"instance_id"`
	ResourceID                     string                      `json:"resource_id"`
	Binding                        *telemetry.Binding          `json:"binding"`
	ObservedAt                     time.Time                   `json:"observed_at"`
	Telemetry                      *TelemetryPin               `json:"telemetry"`
	Hardware                       *HardwarePin                `json:"hardware"`
	CandidateTemplate              *CandidateTemplate          `json:"candidate_template"`
	InputKind                      string                      `json:"input_kind"`
	InputHash                      string                      `json:"input_hash"`
	HardwareMapping                *native.CapacityMapping     `json:"hardware_mapping"`
	ModelRequested                 bool                        `json:"model_requested"`
	ModelEvaluated                 bool                        `json:"model_evaluated"`
	ModelEvaluation                *native.CapacityModelResult `json:"model_evaluation"`
	CapacitySuitable               *bool                       `json:"capacity_suitable"`
	Status                         string                      `json:"status"`
	ReasonCodes                    []string                    `json:"reason_codes"`
	DemandMeaning                  string                      `json:"demand_meaning"`
	GroupCapacityAuthorized        bool                        `json:"group_capacity_authorized"`
	CompletedBusinessWorkPreserved *bool                       `json:"completed_business_work_preserved"`
	ExecutionAuthorized            bool                        `json:"execution_authorized"`
	EstimatedSaving                *string                     `json:"estimated_saving"`
	VerifiedSaving                 *string                     `json:"verified_saving"`
	ChangePlanID                   *string                     `json:"change_plan_id"`
}

// Calculator returns the actual /v4/capacity response bytes. Evaluate verifies
// the independent response hash, exact inputs and no-price/authority contract
// through the existing native decoder before publishing its bounded summary.
type Calculator interface {
	Calculate(context.Context, native.CapacityModelRequest) ([]byte, error)
}

type Plan struct {
	Result  MemberResult
	Request *native.CapacityModelRequest
}

type BatchResult struct {
	SchemaVersion                  string            `json:"schema_version"`
	Scope                          Scope             `json:"scope"`
	Members                        []MemberReference `json:"members"`
	Coverage                       string            `json:"coverage"`
	Status                         string            `json:"status"`
	ReasonCodes                    []string          `json:"reason_codes"`
	GroupCapacityAuthorized        bool              `json:"group_capacity_authorized"`
	CompletedBusinessWorkPreserved *bool             `json:"completed_business_work_preserved"`
	ExecutionAuthorized            bool              `json:"execution_authorized"`
	VerifiedSaving                 *string           `json:"verified_saving"`
}

type MemberReference struct {
	InstanceID       string `json:"instance_id"`
	ResultID         string `json:"result_id"`
	SHA256           string `json:"sha256"`
	Status           string `json:"status"`
	ModelEvaluated   bool   `json:"model_evaluated"`
	CapacitySuitable *bool  `json:"capacity_suitable"`
}
