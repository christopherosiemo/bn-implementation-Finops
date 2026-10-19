// Package fleethistory describes captured Fleet observations, not historical
// ownership, business-work authenticity, financial attribution or action authority.
// Inputs must be resolved by a trusted repository/collector; these structs are
// deliberately not a public evidence-upload contract. Hashes bind content but do
// not authenticate an asserted source, native timestamp or completed-work meaning.
package fleethistory

import "time"

const SchemaVersion = "1"

// Binding identifies an independently registered fleet, not an invented ASG
// inventory resource or one EC2 resource shared by every member.
type Binding struct {
	TenantID   string `json:"tenant_id"`
	WorkloadID string `json:"workload_id"`
	Provider   string `json:"provider"`
	AccountID  string `json:"account_id"`
	Region     string `json:"region"`
}

type Registration struct {
	SchemaVersion             string  `json:"schema_version"`
	ID                        string  `json:"id"`
	Version                   int64   `json:"version"`
	FleetID                   string  `json:"fleet_id"`
	Binding                   Binding `json:"binding"`
	ASGARN                    string  `json:"asg_arn"`
	SourceID                  string  `json:"source_id"`
	SourceSystem              string  `json:"source_system"`
	SourceRegistrationVersion int64   `json:"source_registration_version"`
	SourceConfigHash          string  `json:"source_config_hash"`
	CadenceSeconds            int     `json:"cadence_seconds"`
	MaxGapSeconds             int     `json:"max_gap_seconds"`
}

type ArchiveRef struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
}

// SourceRef is capture provenance: pinned native object/readback or an immutable
// guarded PostgreSQL receipt. Neither proves that a historical interval is covered.
// RevisionID identifies immutable native DATA, not a configuration revision.
// SourceRegistrationVersion/ConfigHash bind configuration independently. Target
// is the exact ASG ARN, instance ID or workload ID.
type SourceRef struct {
	Kind                      string      `json:"kind"`
	Binding                   Binding     `json:"binding"`
	SourceID                  string      `json:"source_id"`
	SourceSystem              string      `json:"source_system"`
	RevisionID                string      `json:"revision_id"`
	SourceRegistrationVersion *int64      `json:"source_registration_version,omitempty"`
	ConfigHash                string      `json:"config_hash"`
	ReceiptID                 string      `json:"receipt_id"`
	Target                    string      `json:"target"`
	RawSHA256                 string      `json:"raw_sha256"`
	CanonicalHash             string      `json:"canonical_hash"`
	CapturedAt                time.Time   `json:"captured_at"`
	StorageKind               string      `json:"storage_kind"`
	Archive                   *ArchiveRef `json:"archive,omitempty"`
}

// SourceState is a server-resolved current lifecycle projection. It is not
// accepted from an observation body. CheckedAt is the immutable snapshot time;
// a new analysis is required after source correction/configuration/revocation.
type SourceState struct {
	SourceID                  string    `json:"source_id"`
	SourceSystem              string    `json:"source_system"`
	SourceRegistrationVersion *int64    `json:"source_registration_version,omitempty"`
	ConfigHash                string    `json:"config_hash"`
	Binding                   Binding   `json:"binding"`
	Status                    string    `json:"status"` // ACTIVE, REVOKED, SUPERSEDED, DEGRADED
	CheckedAt                 time.Time `json:"checked_at"`
}

type Member struct {
	InstanceID            string     `json:"instance_id"`
	LaunchTime            *time.Time `json:"launch_time"`
	LaunchTemplateID      string     `json:"launch_template_id"`
	LaunchTemplateVersion uint64     `json:"launch_template_version"`
	ResourceID            string     `json:"resource_id,omitempty"`
	Hardware              *SourceRef `json:"hardware"`
}

type MembershipObservation struct {
	SchemaVersion       string    `json:"schema_version"`
	ID                  string    `json:"id"`
	RegistrationID      string    `json:"registration_id"`
	RegistrationVersion int64     `json:"registration_version"`
	RegistrationHash    string    `json:"registration_hash"`
	ASGARN              string    `json:"asg_arn"`
	ObservedAt          time.Time `json:"observed_at"`
	ReceivedAt          time.Time `json:"received_at"`
	Source              SourceRef `json:"source"`
	Members             []Member  `json:"members"`
	CorrectsID          string    `json:"corrects_id,omitempty"`
}

// DemandDefinition is an explicit semantic declaration, not proof of causal
// workload preservation. It cannot automatically relabel a request metric.
// The first supported scope is one independently collected external total.
type DemandDefinition struct {
	SchemaVersion             string  `json:"schema_version"`
	ID                        string  `json:"id"`
	Version                   int64   `json:"version"`
	Binding                   Binding `json:"binding"`
	Aggregation               string  `json:"aggregation"`
	Meaning                   string  `json:"meaning"`
	BusinessOperation         string  `json:"business_operation"`
	Unit                      string  `json:"unit"`
	Metric                    string  `json:"metric"`
	MetricDefinitionID        string  `json:"metric_definition_id"`
	MetricDefinitionVersion   string  `json:"metric_definition_version"`
	ValueField                string  `json:"value_field"`
	Origin                    string  `json:"origin"`
	SemanticContractID        string  `json:"semantic_contract_id"`
	SemanticContractHash      string  `json:"semantic_contract_hash"`
	SourceID                  string  `json:"source_id"`
	SourceSystem              string  `json:"source_system"`
	SourceRegistrationVersion *int64  `json:"source_registration_version,omitempty"`
	SourceConfigHash          string  `json:"source_config_hash"`
	Temporality               string  `json:"temporality"` // DELTA or CUMULATIVE
	CadenceSeconds            int     `json:"cadence_seconds"`
	MaxGapSeconds             int     `json:"max_gap_seconds"`
}

// DemandSample preserves integer counts as native decimal text. Nil is missing;
// "0" is observed zero. Start is a DELTA interval start, or the actual cumulative
// epoch/start timestamp. Time is the actual observed point/end, never a held or
// extrapolated query timestamp. DELTA activity intervals have no invented counter
// epoch. Partitioned streams are presently unsupported.
type DemandSample struct {
	SchemaVersion           string     `json:"schema_version"`
	ID                      string     `json:"id"`
	DefinitionID            string     `json:"definition_id"`
	DefinitionVersion       int64      `json:"definition_version"`
	DefinitionHash          string     `json:"definition_hash"`
	MetricDefinitionID      string     `json:"metric_definition_id"`
	MetricDefinitionVersion string     `json:"metric_definition_version"`
	Start                   time.Time  `json:"start"`
	Time                    time.Time  `json:"time"`
	Epoch                   *time.Time `json:"epoch"`
	ReceivedAt              time.Time  `json:"received_at"`
	Value                   *string    `json:"value"`
	Partition               string     `json:"partition,omitempty"`
	Source                  SourceRef  `json:"source"`
	CorrectsID              string     `json:"corrects_id,omitempty"`
}

type Input struct {
	Registration Registration            `json:"registration"`
	Definition   DemandDefinition        `json:"definition"`
	Sources      []SourceState           `json:"sources"`
	Observations []MembershipObservation `json:"observations"`
	Demand       []DemandSample          `json:"demand"`
	Start        time.Time               `json:"start"`
	End          time.Time               `json:"end"`
	AsOf         time.Time               `json:"as_of"`
}

type Gap struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	ReasonCode string    `json:"reason_code"`
}

type DemandSegment struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Status     string    `json:"status"`
	Units      *string   `json:"units"`
	SampleIDs  []string  `json:"sample_ids"`
	ReasonCode string    `json:"reason_code"`
}

type Issue struct {
	RecordID   string `json:"record_id"`
	ReasonCode string `json:"reason_code"`
}

type DemandAnalysis struct {
	Status        string          `json:"status"`
	MeaningBasis  string          `json:"meaning_basis"`
	Unit          string          `json:"unit"`
	ObservedUnits *string         `json:"observed_units"`
	WindowUnits   *string         `json:"window_units"`
	Segments      []DemandSegment `json:"segments"`
	Gaps          []Gap           `json:"gaps"`
	ReasonCodes   []string        `json:"reason_codes"`
}

// Analysis contains no money, normalized savings, verified business-work,
// completeness attestation or execution permission. Even equal point snapshots
// leave every historical membership interval unproved.
type Analysis struct {
	SchemaVersion       string                  `json:"schema_version"`
	Purpose             string                  `json:"purpose"`
	Status              string                  `json:"status"`
	Binding             Binding                 `json:"binding"`
	FleetID             string                  `json:"fleet_id"`
	ASGARN              string                  `json:"asg_arn"`
	RegistrationID      string                  `json:"registration_id"`
	RegistrationVersion int64                   `json:"registration_version"`
	RegistrationHash    string                  `json:"registration_hash"`
	DefinitionID        string                  `json:"definition_id"`
	DefinitionVersion   int64                   `json:"definition_version"`
	DefinitionHash      string                  `json:"definition_hash"`
	InputHash           string                  `json:"input_hash"`
	Start               time.Time               `json:"start"`
	End                 time.Time               `json:"end"`
	AsOf                time.Time               `json:"as_of"`
	MembershipStatus    string                  `json:"membership_status"`
	Observations        []MembershipObservation `json:"observations"`
	SupersededIDs       []string                `json:"superseded_ids"`
	MembershipGaps      []Gap                   `json:"membership_gaps"`
	ObservationGaps     []Gap                   `json:"observation_gaps"`
	Sources             []SourceState           `json:"sources"`
	Demand              DemandAnalysis          `json:"demand"`
	Issues              []Issue                 `json:"issues"`
	ReasonCodes         []string                `json:"reason_codes"`
	Hash                string                  `json:"hash"`
}
