package fleetgroup

import (
	"context"
	"time"
)

const ContinuationSchemaVersion = "1"

// The draft review window permits actual independent human review of an
// immutable body. It never renews evidence, forward authority or command time.
const ContinuationPolicy = "OWNED_RECOVERY_ONLY_SEGMENTS_30M_DRAFT_REVIEW"
const ContinuationDraftReviewWindow = 30 * time.Minute
const (
	ContinuationOriginal           = "ORIGINAL_JOURNAL"
	ContinuationSegment            = "RECOVERY_SEGMENT"
	ContinuationInverse            = "OWNED_INVERSE"
	ContinuationRepair             = "GIT_ONLY_REPAIR"
	ContinuationPreparing          = "PREPARING"
	ContinuationFinalized          = "FINALIZED"
	ContinuationGitAdvanced        = "GIT_ADVANCED"
	ContinuationReady              = "READY_TO_APPLY"
	ContinuationIntent             = "APPLY_INTENT"
	ContinuationApplied            = "APPLIED"
	ContinuationUnknown            = "UNKNOWN"
	ContinuationNoApply            = "NO_APPLY_CONFIRMED"
	ContinuationRepaired           = "GIT_REPAIRED"
	ContinuationLegacy             = "ORIGINAL_OUTCOME"
	ContinuationLegacyRepairFenced = "ORIGINAL_REPAIR_FENCED_NOT_DISPATCHED"
)

// Authority is an injected, commissioned server repository, never request data.
// Current and LookupIdentity must resolve the same committed head/root under a
// writer fence. A false membership result is a database absence check under
// that fence, not an assertion supplied by a machine or browser caller.
type ContinuationAuthority interface {
	Current(context.Context, string) (ContinuationCursor, error)
	LookupIdentity(context.Context, string, ContinuationIdentityAnchor, ContinuationIdentityKey) (ContinuationIdentity, bool, error)
}
type ContinuationIdentityKey struct {
	Namespace string `json:"namespace"`
	ID        string `json:"id"`
}
type ContinuationIdentity struct {
	Key    ContinuationIdentityKey `json:"key"`
	SHA256 string                  `json:"sha256"`
}
type ContinuationIdentityAnchor struct {
	ChainID string `json:"chain_id"`
	Count   uint64 `json:"count"`
	SHA256  string `json:"sha256"`
}
type ContinuationCursor struct {
	ChainID          string                     `json:"chain_id"`
	Kind             string                     `json:"kind"`
	Segment          uint64                     `json:"segment"`
	RecordCount      int                        `json:"record_count"`
	GlobalCount      uint64                     `json:"global_count"`
	HeadSHA256       string                     `json:"head_sha256"`
	CheckpointSHA256 string                     `json:"checkpoint_sha256"`
	ProjectionSHA256 string                     `json:"projection_sha256"`
	Identities       ContinuationIdentityAnchor `json:"identities"`
}
type ContinuationOrigin struct {
	Parent        GitEnvelope     `json:"parent"`
	Authorization JournalEnvelope `json:"authorization"`
}
type ContinuationAuthorization struct {
	SchemaVersion              string              `json:"schema_version"`
	ID                         string              `json:"id"`
	ChainID                    string              `json:"chain_id"`
	Policy                     string              `json:"policy"`
	ParentEnvelopeSHA256       string              `json:"parent_envelope_sha256"`
	JournalAuthorizationSHA256 string              `json:"journal_authorization_sha256"`
	BindingSHA256              string              `json:"binding_sha256"`
	RealmSHA256                string              `json:"realm_sha256"`
	SignerKeySHA256            string              `json:"signer_key_sha256"`
	PipelineKeySHA256          string              `json:"pipeline_key_sha256"`
	LedgerKeySHA256            string              `json:"ledger_key_sha256"`
	BootstrapHead              JournalHeadEnvelope `json:"bootstrap_head"`
	RecordLimit                int                 `json:"record_limit"`
	ByteLimit                  int                 `json:"byte_limit"`
	CreatedAt                  time.Time           `json:"created_at"`
	ForwardExpiresAt           time.Time           `json:"forward_expires_at"`
	Nonce                      string              `json:"nonce"`
}
type ContinuationApproval struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	ActorID             string    `json:"actor_id"`
	Role                string    `json:"role"`
	AuthorizationSHA256 string    `json:"authorization_sha256"`
	ApprovedAt          time.Time `json:"approved_at"`
}
type ContinuationEnvelope struct {
	Authorization ContinuationAuthorization `json:"authorization"`
	Approvals     []ContinuationApproval    `json:"approvals"`
	Algorithm     string                    `json:"algorithm"`
	Signature     string                    `json:"signature"`
}

// A checkpoint carries the actual prior issued projection, not just a hash or
// opaque assertion. Issuance first replays its bounded source under Current.
// Seed state is derived from this one-of source; Authorization.Base is untouched.
type ContinuationCheckpoint struct {
	SchemaVersion      string                     `json:"schema_version"`
	ChainSHA256        string                     `json:"chain_sha256"`
	Segment            uint64                     `json:"segment"`
	GlobalCount        uint64                     `json:"global_count"`
	SourceKind         string                     `json:"source_kind"`
	SourceHeadSHA256   string                     `json:"source_head_sha256"`
	OriginalHead       *JournalHeadEnvelope       `json:"original_head,omitempty"`
	OriginalProjection *JournalProjection         `json:"original_projection,omitempty"`
	PriorHead          *ContinuationHeadEnvelope  `json:"prior_head,omitempty"`
	PriorProjection    *ContinuationProjection    `json:"prior_projection,omitempty"`
	ImportedIdentities []ContinuationIdentity     `json:"imported_identities,omitempty"`
	Identities         ContinuationIdentityAnchor `json:"identities"`
	CreatedAt          time.Time                  `json:"created_at"`
	Nonce              string                     `json:"nonce"`
}
type ContinuationCheckpointEnvelope struct {
	Checkpoint ContinuationCheckpoint `json:"checkpoint"`
	Algorithm  string                 `json:"algorithm"`
	Signature  string                 `json:"signature"`
}
type ContinuationHead struct {
	ChainSHA256      string                     `json:"chain_sha256"`
	Segment          uint64                     `json:"segment"`
	CheckpointSHA256 string                     `json:"checkpoint_sha256"`
	RecordCount      int                        `json:"record_count"`
	GlobalCount      uint64                     `json:"global_count"`
	LastRecordSHA256 string                     `json:"last_record_sha256"`
	ProjectionSHA256 string                     `json:"projection_sha256"`
	Identities       ContinuationIdentityAnchor `json:"identities"`
	ObservedAt       time.Time                  `json:"observed_at"`
	ValidUntil       time.Time                  `json:"valid_until"`
}
type ContinuationHeadEnvelope struct {
	Head      ContinuationHead `json:"head"`
	Algorithm string           `json:"algorithm"`
	Signature string           `json:"signature"`
}

type ContinuationGitDuty struct {
	CommandID            string       `json:"command_id"`
	CommandSHA256        string       `json:"command_sha256"`
	OperationID          string       `json:"operation_id"`
	Fence                uint64       `json:"fence"`
	NativeBefore         JournalState `json:"native_before"`
	Current              JournalState `json:"current"`
	NoApplyReceiptSHA256 string       `json:"no_apply_receipt_sha256"`
}
type ContinuationCommand struct {
	ID               string                   `json:"id"`
	OperationID      string                   `json:"operation_id"`
	IdempotencyKey   string                   `json:"idempotency_key"`
	Nonce            string                   `json:"nonce"`
	Fence            uint64                   `json:"fence"`
	Mode             string                   `json:"mode"`
	ObligationSHA256 string                   `json:"obligation_sha256"`
	Head             ContinuationHeadEnvelope `json:"head"`
	Before           JournalState             `json:"before"`
	Revision         GitRevision              `json:"revision"`
	After            ModelState               `json:"after"`
	CreatedAt        time.Time                `json:"created_at"`
}
type ContinuationFinalization struct {
	SchemaVersion     string        `json:"schema_version"`
	ID                string        `json:"id"`
	ChainSHA256       string        `json:"chain_sha256"`
	CommandSHA256     string        `json:"command_sha256"`
	SigningHeadSHA256 string        `json:"signing_head_sha256"`
	Artifact          GitArtifact   `json:"artifact"`
	Evidence          []EvidenceRef `json:"evidence"`
	CreatedAt         time.Time     `json:"created_at"`
	ExpiresAt         time.Time     `json:"expires_at"`
	Nonce             string        `json:"nonce"`
}
type ContinuationFinalizationEnvelope struct {
	Finalization ContinuationFinalization `json:"finalization"`
	Head         ContinuationHeadEnvelope `json:"head"`
	Algorithm    string                   `json:"algorithm"`
	Signature    string                   `json:"signature"`
}
type ContinuationReceipt struct {
	SchemaVersion      string       `json:"schema_version"`
	ID                 string       `json:"id"`
	IdempotencyKey     string       `json:"idempotency_key"`
	ChainSHA256        string       `json:"chain_sha256"`
	CommandID          string       `json:"command_id"`
	OperationID        string       `json:"operation_id"`
	Fence              uint64       `json:"fence"`
	Kind               string       `json:"kind"`
	CommandSHA256      string       `json:"command_sha256"`
	FinalizationSHA256 string       `json:"finalization_sha256"`
	Before             JournalState `json:"before"`
	After              JournalState `json:"after"`
	ReceivedAt         time.Time    `json:"received_at"`
	ValidUntil         time.Time    `json:"valid_until,omitempty"`
}
type ContinuationReceiptEnvelope struct {
	Receipt   ContinuationReceipt `json:"receipt"`
	Algorithm string              `json:"algorithm"`
	Signature string              `json:"signature"`
}
type ContinuationPending struct {
	Command     ContinuationCommand               `json:"command"`
	Phase       string                            `json:"phase"`
	GitAdvanced bool                              `json:"git_advanced"`
	ApplyIntent bool                              `json:"apply_intent"`
	Finalized   *ContinuationFinalizationEnvelope `json:"finalized,omitempty"`
	ReadyUntil  time.Time                         `json:"ready_until"`
	IntentAt    time.Time                         `json:"intent_at"`
}
type ContinuationProjection struct {
	RecoveryOnly     bool                       `json:"recovery_only"`
	Current          JournalState               `json:"current"`
	Stack            []JournalEffect            `json:"stack"`
	Consumed         []string                   `json:"consumed"`
	OriginalPending  *JournalPending            `json:"original_pending,omitempty"`
	Pending          *ContinuationPending       `json:"pending,omitempty"`
	GitDuty          *ContinuationGitDuty       `json:"git_duty,omitempty"`
	LastFence        uint64                     `json:"last_fence"`
	RepairCount      uint64                     `json:"repair_count"`
	RepairRootSHA256 string                     `json:"repair_root_sha256"`
	Identities       ContinuationIdentityAnchor `json:"identities"`
}
type ContinuationRecord struct {
	Sequence        uint64                            `json:"sequence"`
	PreviousSHA256  string                            `json:"previous_sha256"`
	Kind            string                            `json:"kind"`
	Command         *ContinuationCommand              `json:"command,omitempty"`
	Finalization    *ContinuationFinalizationEnvelope `json:"finalization,omitempty"`
	Receipt         *ContinuationReceiptEnvelope      `json:"receipt,omitempty"`
	OriginalReceipt *JournalReceiptEnvelope           `json:"original_receipt,omitempty"`
	RecordedAt      time.Time                         `json:"recorded_at"`
}
type ContinuationView struct {
	Origin        ContinuationOrigin             `json:"origin"`
	Authorization ContinuationEnvelope           `json:"authorization"`
	Checkpoint    ContinuationCheckpointEnvelope `json:"checkpoint"`
	Records       []ContinuationRecord           `json:"records"`
	Head          ContinuationHeadEnvelope       `json:"head"`
}

// Future storage commits this entire result atomically under its writer fence:
// exact Expected cursor, immutable event/checkpoint, identities and Next cursor.
// A pure helper neither persists nor proves that such a commit happened.
type ContinuationTransition struct {
	Expected   ContinuationCursor
	Next       ContinuationCursor
	View       ContinuationView
	Projection ContinuationProjection
	Identities []ContinuationIdentity
	Replayed   bool
}
type ContinuationPermit struct {
	Cursor        ContinuationCursor
	CommandSHA256 string
	OperationID   string
	Fence         uint64
	Mode          string
	ValidUntil    time.Time
}

const ContinuationIntegrationBoundary = "PURE_RECOVERY_ONLY_SEGMENTS_TRUSTED_REPOSITORY_REQUIRED_NO_RUNTIME_OR_CUSTOMER_AUTHORITY"
