package multicloud

import (
	"context"
	"errors"
	"time"
)

var ErrPublicationConflict = errors.New("MULTICLOUD_PUBLICATION_CONFLICT")
var ErrPublicationInactive = errors.New("MULTICLOUD_REGISTRATION_INACTIVE")

type RegistrationSnapshot struct {
	Registration Registration           `json:"registration"`
	ReadBinding  PublicationReadBinding `json:"read_binding"`
	ConfigHash   string                 `json:"config_hash"`
	ScopeHash    string                 `json:"scope_hash"`
	BindingHash  string                 `json:"binding_hash"`
}
type PublicationReadBinding struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	Provider          string `json:"provider"`
	DirectoryTenantID string `json:"directory_tenant_id,omitempty"`
	BillingAccountID  string `json:"billing_account_id,omitempty"`
	DatasetProjectID  string `json:"dataset_project_id,omitempty"`
	ScopeHash         string `json:"scope_hash"`
}

// PrivateRegistration is called only by an explicit server credential registry,
// never an upload route. The snapshot contains no token or credential material.
func PrivateRegistration(r Registration, b ReadBinding) (RegistrationSnapshot, error) {
	if e := Validate(r); e != nil {
		return RegistrationSnapshot{}, e
	}
	provider := "GCP"
	if r.Azure != nil {
		provider = "AZURE"
	}
	if b.ID != r.ReadBindingID || b.TenantID != r.TenantID || b.Provider != provider || b.ScopeHash != ScopeHash(r) {
		return RegistrationSnapshot{}, errors.New("MULTICLOUD_PRIVATE_REGISTRATION_BINDING_INVALID")
	}
	if r.Azure != nil && b.DirectoryTenantID != r.Azure.DirectoryTenantID || r.GCP != nil && (b.BillingAccountID != r.GCP.BillingAccountID || b.DatasetProjectID != r.GCP.DatasetProjectID) {
		return RegistrationSnapshot{}, errors.New("MULTICLOUD_PRIVATE_NATIVE_SCOPE_MISMATCH")
	}
	bound := PublicationReadBinding{b.ID, b.TenantID, b.Provider, b.DirectoryTenantID, b.BillingAccountID, b.DatasetProjectID, b.ScopeHash}
	return RegistrationSnapshot{Registration: r, ReadBinding: bound, ConfigHash: Hash(r), ScopeHash: ScopeHash(r), BindingHash: Hash(bound)}, nil
}

type ArchiveRef struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}
type PublicationArchive interface {
	Put(context.Context, string, string, string, []byte) (ArchiveRef, error)
	Read(context.Context, string, ArchiveRef) ([]byte, error)
}
type EconomicRow struct {
	Hash             string   `json:"hash"`
	Multiplicity     int64    `json:"multiplicity"`
	Native           Record   `json:"native"`
	BilledDecimal    *string  `json:"billed_decimal"`
	EffectiveDecimal *string  `json:"effective_decimal"`
	ListDecimal      *string  `json:"list_decimal"`
	ProjectionGaps   []string `json:"projection_gaps"`
}
type FactPopulation struct {
	SchemaVersion  string        `json:"schema_version"`
	TenantID       string        `json:"tenant_id"`
	RegistrationID string        `json:"registration_id"`
	ScopeHash      string        `json:"scope_hash"`
	Kind           Kind          `json:"kind"`
	Period         Period        `json:"period"`
	EconomicHash   string        `json:"economic_hash"`
	Rows           []EconomicRow `json:"rows"`
	RecordCount    int64         `json:"record_count"`
}
type FactAck struct {
	TenantID     string `json:"tenant_id"`
	PopulationID string `json:"population_id"`
	FactHash     string `json:"fact_hash"`
	EconomicHash string `json:"economic_hash"`
	DistinctRows int64  `json:"distinct_rows"`
	RecordCount  int64  `json:"record_count"`
	Database     string `json:"database"`
	Table        string `json:"table"`
}
type PublicationFactSink interface {
	Write(context.Context, FactPopulation) (FactAck, error)
	Readback(context.Context, FactAck) (FactAck, error)
}
type PublicationManifest struct {
	SchemaVersion       string    `json:"schema_version"`
	TenantID            string    `json:"tenant_id"`
	RegistrationID      string    `json:"registration_id"`
	RegistrationVersion int64     `json:"registration_version"`
	ConfigHash          string    `json:"config_hash"`
	ScopeHash           string    `json:"scope_hash"`
	BindingHash         string    `json:"binding_hash"`
	Kind                Kind      `json:"kind"`
	Period              Period    `json:"period"`
	NativeRevision      string    `json:"native_revision"`
	NativeReference     string    `json:"native_reference"`
	NativeObservedAt    time.Time `json:"native_observed_at"`
	SourceReasonCodes   []string  `json:"source_reason_codes"`
	RawObjects          []Object  `json:"raw_objects"`
	RawManifestHash     string    `json:"raw_manifest_hash"`
	CanonicalSHA256     string    `json:"canonical_sha256"`
	FactHash            string    `json:"fact_hash"`
	PopulationID        string    `json:"population_id"`
	EconomicHash        string    `json:"economic_hash"`
	NativeRowCount      int64     `json:"native_row_count"`
	RecordCount         int64     `json:"record_count"`
	DistinctRows        int64     `json:"distinct_rows"`
	Status              string    `json:"status"`
	ReasonCodes         []string  `json:"reason_codes"`
}
type PublicationJob struct {
	ID        string              `json:"id"`
	Key       string              `json:"key"`
	Manifest  PublicationManifest `json:"manifest"`
	CreatedAt time.Time           `json:"created_at"`
}
type PublicationCheckpoint struct {
	Stage     string       `json:"stage"`
	Raw       []ArchiveRef `json:"raw,omitempty"`
	Canonical *ArchiveRef  `json:"canonical,omitempty"`
	Facts     *FactAck     `json:"facts,omitempty"`
}
type PublicationReceipt struct {
	ID                  string              `json:"id"`
	JobID               string              `json:"job_id"`
	Manifest            PublicationManifest `json:"manifest"`
	Sequence            int64               `json:"sequence"`
	CreatedAt           time.Time           `json:"created_at"`
	ActiveSource        bool                `json:"active_source"`
	IsCurrent           bool                `json:"is_current"`
	HeadReasonCode      string              `json:"head_reason_code,omitempty"`
	ExecutionAuthorized bool                `json:"execution_authorized"`
	VerifiedSaving      *string             `json:"verified_saving"`
}
type PublicationRepository interface {
	Register(context.Context, RegistrationSnapshot) error
	Current(context.Context, string, string) (RegistrationSnapshot, error)
	Prepare(context.Context, RegistrationSnapshot, string, PublicationManifest) (PublicationJob, bool, error)
	Job(context.Context, string, string) (PublicationJob, error)
	Checkpoints(context.Context, string, string) ([]PublicationCheckpoint, error)
	Checkpoint(context.Context, string, string, PublicationCheckpoint) error
	Publish(context.Context, string, string) (PublicationReceipt, bool, error)
	Revoke(context.Context, string, string, int64, string) error
}
type PublicationPipeline struct {
	Repository PublicationRepository
	Archive    PublicationArchive
	Facts      PublicationFactSink
}
