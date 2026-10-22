// Package fleet defines an offline R2 contract. A valid/signed plan is not a
// customer-pipeline apply receipt, execution lease or financial verification.
// Existing standalone v3 stop/start plans are deliberately separate.
package fleet

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "4"
const Kind = "STATELESS_FLEET_RIGHTSIZING"
const ApproverRole = "fleet_approver"
const (
	Prepare   = "PREPARE_CANDIDATE"
	Canary10  = "CANARY_10"
	Expand25  = "EXPAND_25"
	Expand50  = "EXPAND_50"
	Expand100 = "EXPAND_100"
	DrainOld  = "DRAIN_OLD"
)

type Binding struct {
	TenantID           string `json:"tenant_id"`
	ResourceID         string `json:"resource_id"`
	WorkloadID         string `json:"workload_id"`
	Provider           string `json:"provider"`
	ProviderResourceID string `json:"provider_resource_id"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
}
type ProofRef struct {
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	Version    string    `json:"version"`
	SHA256     string    `json:"sha256"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type IaCBinding struct {
	Authority           string `json:"authority"`
	Repository          string `json:"repository"`
	GitCommit           string `json:"git_commit"`
	Workspace           string `json:"workspace"`
	StateLineage        string `json:"state_lineage"`
	StateSerial         uint64 `json:"state_serial"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
	TerraformVersion    string `json:"terraform_version"`
	PipelineID          string `json:"pipeline_id"`
}
type Governance struct {
	RiskClass     string `json:"risk_class"`
	Enabled       bool   `json:"enabled"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion int64  `json:"policy_version"`
	PolicySHA256  string `json:"policy_sha256"`
	ApproverRole  string `json:"approver_role"`
}
type Cohort struct {
	ID                    string `json:"id"`
	ASGAddress            string `json:"asg_address"`
	LaunchTemplateAddress string `json:"launch_template_address"`
	LaunchTemplateVersion uint64 `json:"launch_template_version"`
	InstanceType          string `json:"instance_type"`
	DesiredCount          int    `json:"desired_count"`
	Stateless             bool   `json:"stateless"`
	DataVolumes           bool   `json:"data_volumes"`
	IndependentScaling    bool   `json:"independent_scaling"`
}
type TrafficControl struct {
	Authority               string `json:"authority"`
	Address                 string `json:"address"`
	OldTargetGroupARN       string `json:"old_target_group_arn"`
	CandidateTargetGroupARN string `json:"candidate_target_group_arn"`
}
type Budget struct {
	BaselineCount               int    `json:"baseline_count"`
	MaxInFlight                 int    `json:"max_in_flight"`
	MaxUnavailable              int    `json:"max_unavailable"`
	MaxBlastRadiusPPM           int    `json:"max_blast_radius_ppm"`
	MaxSurgeCount               int    `json:"max_surge_count"`
	Currency                    string `json:"currency"`
	MaximumCost                 string `json:"maximum_cost"`
	OldInstanceHourlyCost       string `json:"old_instance_hourly_cost"`
	CandidateInstanceHourlyCost string `json:"candidate_instance_hourly_cost"`
	MaximumDurationSeconds      int64  `json:"maximum_duration_seconds"`
}
type Stage struct {
	ID                          string       `json:"id"`
	Kind                        string       `json:"kind"`
	DependsOn                   []string     `json:"depends_on"`
	TargetCandidateCount        int          `json:"target_candidate_count"`
	TargetTrafficPercent        int          `json:"target_traffic_percent"`
	MinimumObservationSeconds   int64        `json:"minimum_observation_seconds"`
	ConfigurationSHA256         string       `json:"configuration_sha256"`
	CleanupReviewed             bool         `json:"cleanup_reviewed"`
	Permissions                 []Permission `json:"permissions"`
	IntermediateCandidateCounts []int        `json:"intermediate_candidate_counts"`
}
type Permission struct {
	Address       string   `json:"address"`
	Type          string   `json:"type"`
	Actions       []string `json:"actions"`
	Paths         []string `json:"paths"`
	ComputedPaths []string `json:"computed_paths"`
}
type FleetPlanV4 struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	Binding       Binding        `json:"binding"`
	CreatorID     string         `json:"creator_id"`
	Environment   string         `json:"environment"`
	IaC           IaCBinding     `json:"iac"`
	Governance    Governance     `json:"governance"`
	Old           Cohort         `json:"old"`
	Candidate     Cohort         `json:"candidate"`
	Traffic       TrafficControl `json:"traffic"`
	Budget        Budget         `json:"budget"`
	Proofs        []ProofRef     `json:"proofs"`
	Stages        []Stage        `json:"stages"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Nonce         string         `json:"nonce"`
}
type Plan = FleetPlanV4
type Approval struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ActorID    string    `json:"actor_id"`
	Role       string    `json:"role"`
	PlanSHA256 string    `json:"plan_sha256"`
	ApprovedAt time.Time `json:"approved_at"`
}
type Envelope struct {
	Plan      FleetPlanV4 `json:"plan"`
	Approvals []Approval  `json:"approvals"`
	Algorithm string      `json:"algorithm"`
	Signature string      `json:"signature"`
}
type Transition struct {
	OldBefore       int `json:"old_before"`
	OldAfter        int `json:"old_after"`
	CandidateBefore int `json:"candidate_before"`
	CandidateAfter  int `json:"candidate_after"`
	TrafficBefore   int `json:"traffic_before"`
	TrafficAfter    int `json:"traffic_after"`
	InFlight        int `json:"in_flight"`
	Unavailable     int `json:"unavailable"`
}

// FieldChange pins exact leaf input values; paths are RFC6901 JSON pointers.
// Computed provider outputs can be unknown only when explicitly listed below.
type FieldChange struct {
	Path   string          `json:"path"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}
type AllowedChange struct {
	Address       string        `json:"address"`
	Type          string        `json:"type"`
	Action        string        `json:"action"`
	Fields        []FieldChange `json:"fields"`
	ComputedPaths []string      `json:"computed_paths"`
}
type ChildPlan struct {
	SchemaVersion             string          `json:"schema_version"`
	ID                        string          `json:"id"`
	ParentID                  string          `json:"parent_id"`
	ParentSHA256              string          `json:"parent_sha256"`
	StageID                   string          `json:"stage_id"`
	StageSHA256               string          `json:"stage_sha256"`
	Sequence                  uint64          `json:"sequence"`
	Binding                   Binding         `json:"binding"`
	IaC                       IaCBinding      `json:"iac"`
	SavedPlanSHA256           string          `json:"saved_plan_sha256"`
	PlanJSONSHA256            string          `json:"plan_json_sha256"`
	Changes                   []AllowedChange `json:"changes"`
	Transition                Transition      `json:"transition"`
	Proofs                    []ProofRef      `json:"proofs"`
	CompensationFor           string          `json:"compensation_for,omitempty"`
	CompensationReceiptSHA256 string          `json:"compensation_receipt_sha256,omitempty"`
	CreatedAt                 time.Time       `json:"created_at"`
	ExpiresAt                 time.Time       `json:"expires_at"`
	Nonce                     string          `json:"nonce"`
}
type ChildEnvelope struct {
	Plan      ChildPlan `json:"plan"`
	Algorithm string    `json:"algorithm"`
	Signature string    `json:"signature"`
}
type StageObservation struct {
	StageID       string    `json:"stage_id"`
	ChildID       string    `json:"child_id"`
	Outcome       string    `json:"outcome"`
	CompletedAt   time.Time `json:"completed_at"`
	ObservedUntil time.Time `json:"observed_until"`
	ReceiptSHA256 string    `json:"receipt_sha256"`
}
type Flight struct {
	ID          string
	TenantID    string
	WorkloadID  string
	InFlight    int
	Unavailable int
}
type DispatchEvidence struct {
	IntentRecorded bool
	Dispatched     bool
	OutcomeKnown   bool
	Owned          bool
	Restored       bool
	ReceiptID      string
	ReceiptSHA256  string
}

// OwnedReceipt is selected from an authenticated immutable deployment callback,
// never accepted as a console request assertion. The store owns its authority.
type OwnedReceipt struct {
	ID                string    `json:"id"`
	ParentID          string    `json:"parent_id"`
	ChildID           string    `json:"child_id"`
	ChildSHA256       string    `json:"child_sha256"`
	Binding           Binding   `json:"binding"`
	PipelineID        string    `json:"pipeline_id"`
	SavedPlanSHA256   string    `json:"saved_plan_sha256"`
	Status            string    `json:"status"`
	BeforeStateSerial uint64    `json:"before_state_serial"`
	AfterStateSerial  uint64    `json:"after_state_serial"`
	ObservedAt        time.Time `json:"observed_at"`
}
type RecoveryDecision struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}
