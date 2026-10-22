// Package fleetgroup defines the separate group-bound v5 contract for an
// isolated fixture operating loop. Validation or a signature is not a native
// provider attestation, runtime enablement, historical ownership or savings.
// No v4 type, serialized payload or Temporal command is converted by this package.
package fleetgroup

import "time"

const (
	SchemaVersion          = "5"
	Kind                   = "STATELESS_GROUP_RIGHTSIZING"
	IsolatedFixture        = "ISOLATED_FIXTURE"
	BuiltinFixtureArtifact = "TERRAFORM_BUILTIN_FIXTURE"
	BuiltinProvider        = "terraform.io/builtin/terraform"
	FixtureModelCost       = "FIXTURE_MODEL_COST"
	ApproverRole           = "fleet_approver"
	Forward                = "FORWARD"
	OwnedRecovery          = "OWNED_RECOVERY"
	Prepare                = "PREPARE_CANDIDATE"
	Canary10               = "CANARY_10"
	Expand25               = "EXPAND_25"
	Expand50               = "EXPAND_50"
	Expand100              = "EXPAND_100"
	DrainOld               = "DRAIN_OLD"
)

// Realm is server-resolved. FixtureID identifies an isolated service registry,
// never a caller URL. Generation and model hash prevent cross-run evidence use.
// CUSTOMER_NATIVE is deliberately not an accepted realm in this version.
type Realm struct {
	Kind        string `json:"kind"`
	FixtureID   string `json:"fixture_id"`
	Generation  string `json:"generation"`
	ModelSHA256 string `json:"model_sha256"`
}

// GroupTarget uses actual registration identity, not a representative instance
// or an invented inventory resource for the ASG.
type GroupTarget struct {
	TenantID   string `json:"tenant_id"`
	WorkloadID string `json:"workload_id"`
	Provider   string `json:"provider"`
	AccountID  string `json:"account_id"`
	Region     string `json:"region"`
	FleetID    string `json:"fleet_id"`
	ASGARN     string `json:"asg_arn"`
}

type VersionedRef struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	SHA256  string `json:"sha256"`
}

type SnapshotRef struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

// Selection pins existing 025/027 records. Their hashes do not promote the
// declared ASG or point history to native interval/configuration authority.
// A future repository must resolve every ID, hash, binding and current source.
type Selection struct {
	Target                    GroupTarget  `json:"target"`
	Registration              VersionedRef `json:"registration"`
	Declaration               VersionedRef `json:"declaration"`
	Scope                     SnapshotRef  `json:"scope"`
	SourceID                  string       `json:"source_id"`
	SourceRegistrationVersion int64        `json:"source_registration_version"`
	SourceConfigSHA256        string       `json:"source_config_sha256"`
}

type Binding struct {
	Old       Selection `json:"old"`
	Candidate Selection `json:"candidate"`
}

type Expected struct {
	Binding Binding
	Realm   Realm
}

// ModelMapping is an explicit lab mapping. A terraform_data address never
// attests that the declared aws_* address maps to a customer native resource.
type ModelMapping struct {
	OldDeclaredASG       string `json:"old_declared_asg"`
	CandidateDeclaredASG string `json:"candidate_declared_asg"`
	DeclaredListenerRule string `json:"declared_listener_rule"`
	OldModel             string `json:"old_model"`
	CandidateModel       string `json:"candidate_model"`
	TrafficModel         string `json:"traffic_model"`
}

type ArtifactContext struct {
	Kind                 string       `json:"kind"`
	ProviderSource       string       `json:"provider_source"`
	RepositoryID         string       `json:"repository_id"`
	GitCommit            string       `json:"git_commit"`
	GitTree              string       `json:"git_tree"`
	ConfigurationSHA256  string       `json:"configuration_sha256"`
	ToolchainImageSHA256 string       `json:"toolchain_image_sha256"`
	TerraformVersion     string       `json:"terraform_version"`
	PipelineID           string       `json:"pipeline_id"`
	Workspace            string       `json:"workspace"`
	StateLineage         string       `json:"state_lineage"`
	InitialStateSerial   uint64       `json:"initial_state_serial"`
	Mapping              ModelMapping `json:"mapping"`
}

type Template struct {
	ID           string `json:"id"`
	Version      uint64 `json:"version"`
	InstanceType string `json:"instance_type"`
	SHA256       string `json:"sha256"`
}

type Policy struct {
	ID           string `json:"id"`
	Version      int64  `json:"version"`
	SHA256       string `json:"sha256"`
	ApproverRole string `json:"approver_role"`
}

// ModelBudget bounds only the declared fixture model. It is not an AWS spend
// cap, native contracted rate, future-price guarantee or financial claim.
type ModelBudget struct {
	CostBasis              string `json:"cost_basis"`
	Currency               string `json:"currency"`
	BaselineCount          int    `json:"baseline_count"`
	MaxInFlight            int    `json:"max_in_flight"`
	MaxUnavailable         int    `json:"max_unavailable"`
	MaxBlastRadiusPPM      int    `json:"max_blast_radius_ppm"`
	MaxSurgeCount          int    `json:"max_surge_count"`
	OldHourlyCost          string `json:"old_hourly_cost"`
	CandidateHourlyCost    string `json:"candidate_hourly_cost"`
	MaximumModelCost       string `json:"maximum_model_cost"`
	MaximumDurationSeconds int64  `json:"maximum_duration_seconds"`
}

type Stage struct {
	ID                        string `json:"id"`
	Kind                      string `json:"kind"`
	TargetCandidateCount      int    `json:"target_candidate_count"`
	TargetTrafficPercent      int    `json:"target_traffic_percent"`
	MinimumObservationSeconds int64  `json:"minimum_observation_seconds"`
}

// EvidenceRef is a repository-selected lab receipt. Coverage/completeness is
// not a caller boolean. The signed realm hash must match every selected receipt.
type EvidenceRef struct {
	Kind          string    `json:"kind"`
	ID            string    `json:"id"`
	SHA256        string    `json:"sha256"`
	BindingSHA256 string    `json:"binding_sha256"`
	RealmSHA256   string    `json:"realm_sha256"`
	ObservedAt    time.Time `json:"observed_at"`
	ValidUntil    time.Time `json:"valid_until"`
}

type Program struct {
	SchemaVersion     string          `json:"schema_version"`
	Kind              string          `json:"kind"`
	ID                string          `json:"id"`
	Binding           Binding         `json:"binding"`
	Realm             Realm           `json:"realm"`
	CreatorID         string          `json:"creator_id"`
	Environment       string          `json:"environment"`
	Policy            Policy          `json:"policy"`
	ArtifactContext   ArtifactContext `json:"artifact_context"`
	OldTemplate       Template        `json:"old_template"`
	CandidateTemplate Template        `json:"candidate_template"`
	Budget            ModelBudget     `json:"budget"`
	Stages            []Stage         `json:"stages"`
	Evidence          []EvidenceRef   `json:"evidence"`
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	Nonce             string          `json:"nonce"`
}

type Approval struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ActorID       string    `json:"actor_id"`
	Role          string    `json:"role"`
	ProgramSHA256 string    `json:"program_sha256"`
	RealmSHA256   string    `json:"realm_sha256"`
	ApprovedAt    time.Time `json:"approved_at"`
}

type Envelope struct {
	Program   Program    `json:"program"`
	Approvals []Approval `json:"approvals"`
	Algorithm string     `json:"algorithm"`
	Signature string     `json:"signature"`
}

// ModelState is the typed input of the three built-in Terraform fixture
// resources. Its hash pins group and realm independently of display names.
type ModelState struct {
	BindingSHA256           string `json:"binding_sha256"`
	RealmSHA256             string `json:"realm_sha256"`
	OldCount                int    `json:"old_count"`
	CandidateCount          int    `json:"candidate_count"`
	CandidateTrafficPercent int    `json:"candidate_traffic_percent"`
}

// Artifact pins bytes and the expected model effect. It does not prove that a
// Terraform CLI actually produced them: an independent artifact producer must
// check saved-plan/show/state semantics before publishing the referenced receipt.
type Artifact struct {
	Kind              string      `json:"kind"`
	Receipt           SnapshotRef `json:"receipt"`
	ContextSHA256     string      `json:"context_sha256"`
	BeforeStateSerial uint64      `json:"before_state_serial"`
	BeforeStateSHA256 string      `json:"before_state_sha256"`
	SavedPlanSHA256   string      `json:"saved_plan_sha256"`
	PlanJSONSHA256    string      `json:"plan_json_sha256"`
	Before            ModelState  `json:"before"`
	After             ModelState  `json:"after"`
}

type Child struct {
	SchemaVersion             string        `json:"schema_version"`
	ID                        string        `json:"id"`
	ParentID                  string        `json:"parent_id"`
	ParentSHA256              string        `json:"parent_sha256"`
	BindingSHA256             string        `json:"binding_sha256"`
	RealmSHA256               string        `json:"realm_sha256"`
	Mode                      string        `json:"mode"`
	StageID                   string        `json:"stage_id"`
	StageSHA256               string        `json:"stage_sha256"`
	Sequence                  uint64        `json:"sequence"`
	Artifact                  Artifact      `json:"artifact"`
	MinimumObservationSeconds int64         `json:"minimum_observation_seconds"`
	Evidence                  []EvidenceRef `json:"evidence"`
	CompensationFor           string        `json:"compensation_for,omitempty"`
	OwnedReceiptSHA256        string        `json:"owned_receipt_sha256,omitempty"`
	CreatedAt                 time.Time     `json:"created_at"`
	ExpiresAt                 time.Time     `json:"expires_at"`
	Nonce                     string        `json:"nonce"`
}

type ChildEnvelope struct {
	Child     Child  `json:"child"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// OwnedReceipt must come from the authenticated exact-artifact pipeline and
// immutable store, not a request payload. APPLIED proves a fixture effect only.
type OwnedReceipt struct {
	SchemaVersion     string    `json:"schema_version"`
	ID                string    `json:"id"`
	CommandID         string    `json:"command_id"`
	ParentID          string    `json:"parent_id"`
	ParentSHA256      string    `json:"parent_sha256"`
	ChildID           string    `json:"child_id"`
	ChildSHA256       string    `json:"child_sha256"`
	BindingSHA256     string    `json:"binding_sha256"`
	RealmSHA256       string    `json:"realm_sha256"`
	ArtifactSHA256    string    `json:"artifact_sha256"`
	SavedPlanSHA256   string    `json:"saved_plan_sha256"`
	PipelineID        string    `json:"pipeline_id"`
	Outcome           string    `json:"outcome"`
	BeforeStateSerial uint64    `json:"before_state_serial"`
	AfterStateSerial  uint64    `json:"after_state_serial"`
	AfterModelSHA256  string    `json:"after_model_sha256"`
	ReceivedAt        time.Time `json:"received_at"`
}

// Capability is deliberately constant for this domain-only fixture family.
// Neither a valid signature nor an APPLIED callback changes these values.
type Capability struct {
	CustomerNativeExecution bool `json:"customer_native_execution"`
	CustomerVerifiedSavings bool `json:"customer_verified_savings"`
}

func Capabilities() Capability { return Capability{} }
