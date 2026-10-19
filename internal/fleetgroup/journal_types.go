package fleetgroup

import (
	"crypto/ed25519"
	"time"
)

const JournalSchemaVersion = "1"
const JournalKind = "ISOLATED_GROUP_TRANSITION_JOURNAL"
const JournalPolicy = "STRICT_LIFO_OWNED_INVERSE"
const (
	JournalPreparing       = "PREPARING"
	JournalReserved        = "RESERVED"
	JournalGitAdvanced     = "GIT_ADVANCED"
	JournalReadyToApply    = "READY_TO_APPLY"
	JournalApplyIntent     = "APPLY_INTENT"
	JournalUnknown         = "UNKNOWN"
	JournalApplied         = "APPLIED"
	JournalNoApply         = "NO_APPLY_CONFIRMED"
	JournalGitRepairIntent = "GIT_REPAIR_INTENT"
	JournalGitRepaired     = "GIT_REPAIRED"
	JournalRecoveryMode    = "JOURNAL_OWNED_RECOVERY"
)

type JournalState struct {
	Revision     GitRevision `json:"revision"`
	StateLineage string      `json:"state_lineage"`
	StateSerial  uint64      `json:"state_serial"`
	StateSHA256  string      `json:"state_sha256"`
	Model        ModelState  `json:"model"`
}

// This new opt-in authorization is approved BEFORE any journal command. The
// unchanged5.1 parent/envelope alone cannot authorize composable recovery.
type JournalAuthorization struct {
	SchemaVersion        string       `json:"schema_version"`
	Kind                 string       `json:"kind"`
	ID                   string       `json:"id"`
	JournalID            string       `json:"journal_id"`
	ParentEnvelopeSHA256 string       `json:"parent_envelope_sha256"`
	ParentSHA256         string       `json:"parent_sha256"`
	BindingSHA256        string       `json:"binding_sha256"`
	RealmSHA256          string       `json:"realm_sha256"`
	PipelineID           string       `json:"pipeline_id"`
	Ref                  string       `json:"ref"`
	Policy               string       `json:"policy"`
	Base                 JournalState `json:"base"`
	PipelineKeySHA256    string       `json:"pipeline_key_sha256"`
	LedgerKeySHA256      string       `json:"ledger_key_sha256"`
	MaximumEffects       int          `json:"maximum_effects"`
	MaximumRecords       int          `json:"maximum_records"`
	CreatedAt            time.Time    `json:"created_at"`
	ExpiresAt            time.Time    `json:"expires_at"`
	Nonce                string       `json:"nonce"`
}

type JournalApproval struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	ActorID             string    `json:"actor_id"`
	Role                string    `json:"role"`
	AuthorizationSHA256 string    `json:"authorization_sha256"`
	ApprovedAt          time.Time `json:"approved_at"`
}
type JournalEnvelope struct {
	Authorization JournalAuthorization `json:"authorization"`
	Approvals     []JournalApproval    `json:"approvals"`
	Algorithm     string               `json:"algorithm"`
	Signature     string               `json:"signature"`
}

// Keys and ExpectedHead are server-resolved trust/currentness inputs. Accepting
// these values from a caller would defeat the boundary, even with valid hashes.
type JournalKeys struct{ Signer, Pipeline, Ledger ed25519.PublicKey }
type JournalHeadRef struct {
	Version          uint64 `json:"version"`
	RecordCount      int    `json:"record_count"`
	LastRecordSHA256 string `json:"last_record_sha256"`
}
type JournalHead struct {
	JournalID           string         `json:"journal_id"`
	AuthorizationSHA256 string         `json:"authorization_sha256"`
	Ref                 JournalHeadRef `json:"ref"`
	ProjectionSHA256    string         `json:"projection_sha256"`
	ObservedAt          time.Time      `json:"observed_at"`
	ValidUntil          time.Time      `json:"valid_until"`
}
type JournalHeadEnvelope struct {
	Head      JournalHead `json:"head"`
	Algorithm string      `json:"algorithm"`
	Signature string      `json:"signature"`
}

// Recovery is its own signed type/domain. It is not a converted5.1 child.
type JournalRecovery struct {
	SchemaVersion             string        `json:"schema_version"`
	ID                        string        `json:"id"`
	CommandID                 string        `json:"command_id"`
	JournalID                 string        `json:"journal_id"`
	AuthorizationSHA256       string        `json:"authorization_sha256"`
	ParentEnvelopeSHA256      string        `json:"parent_envelope_sha256"`
	PreparationHeadSHA256     string        `json:"preparation_head_sha256"`
	SigningHeadSHA256         string        `json:"signing_head_sha256"`
	EffectID                  string        `json:"effect_id"`
	OriginalChildSHA256       string        `json:"original_child_sha256"`
	OriginalReceiptSHA256     string        `json:"original_receipt_sha256"`
	Artifact                  GitArtifact   `json:"artifact"`
	MinimumObservationSeconds int64         `json:"minimum_observation_seconds"`
	Evidence                  []EvidenceRef `json:"evidence"`
	CreatedAt                 time.Time     `json:"created_at"`
	ExpiresAt                 time.Time     `json:"expires_at"`
	Nonce                     string        `json:"nonce"`
}
type JournalRecoveryEnvelope struct {
	Recovery  JournalRecovery     `json:"recovery"`
	Head      JournalHeadEnvelope `json:"head"`
	Algorithm string              `json:"algorithm"`
	Signature string              `json:"signature"`
}

type JournalCommand struct {
	ID             string                   `json:"id"`
	OperationID    string                   `json:"operation_id"`
	IdempotencyKey string                   `json:"idempotency_key"`
	Fence          uint64                   `json:"fence"`
	Head           JournalHeadEnvelope      `json:"head"`
	Before         JournalState             `json:"before"`
	Preparation    JournalPreparation       `json:"preparation"`
	Forward        *GitChildEnvelope        `json:"forward,omitempty"`
	Recovery       *JournalRecoveryEnvelope `json:"recovery,omitempty"`
	CreatedAt      time.Time                `json:"created_at"`
}

// A reservation exists before Git CAS and plan creation. Exact signed artifact
// envelopes finalize the SAME command later; no invented artifact hash is used.
type JournalPreparation struct {
	Mode                string      `json:"mode"`
	Sequence            uint64      `json:"sequence"`
	ManifestEntrySHA256 string      `json:"manifest_entry_sha256,omitempty"`
	EffectID            string      `json:"effect_id,omitempty"`
	Revision            GitRevision `json:"revision"`
	Before              ModelState  `json:"before"`
	After               ModelState  `json:"after"`
}

// A receipt is issued by the pinned independent pipeline observer after it
// checks the actual stable operation/fencing state, not a browser assertion.
// READY_TO_APPLY positively certifies NOT_DISPATCHED; missing callbacks cannot.
type JournalReceipt struct {
	SchemaVersion       string       `json:"schema_version"`
	ID                  string       `json:"id"`
	IdempotencyKey      string       `json:"idempotency_key"`
	JournalID           string       `json:"journal_id"`
	AuthorizationSHA256 string       `json:"authorization_sha256"`
	CommandID           string       `json:"command_id"`
	OperationID         string       `json:"operation_id"`
	Fence               uint64       `json:"fence"`
	PipelineID          string       `json:"pipeline_id"`
	Kind                string       `json:"kind"`
	PreparationSHA256   string       `json:"preparation_sha256"`
	ArtifactSHA256      string       `json:"artifact_sha256"`
	SavedPlanSHA256     string       `json:"saved_plan_sha256"`
	Before              JournalState `json:"before"`
	After               JournalState `json:"after"`
	ReceivedAt          time.Time    `json:"received_at"`
	ValidUntil          time.Time    `json:"valid_until,omitempty"`
}
type JournalReceiptEnvelope struct {
	Receipt   JournalReceipt `json:"receipt"`
	Algorithm string         `json:"algorithm"`
	Signature string         `json:"signature"`
}

type JournalRecord struct {
	Sequence       uint64                    `json:"sequence"`
	PreviousSHA256 string                    `json:"previous_sha256"`
	Kind           string                    `json:"kind"`
	Command        *JournalCommand           `json:"command,omitempty"`
	Receipt        *JournalReceiptEnvelope   `json:"receipt,omitempty"`
	GitRepair      *JournalGitRepairEnvelope `json:"git_repair,omitempty"`
	RecordedAt     time.Time                 `json:"recorded_at"`
}
type JournalEffect struct {
	ID      string                 `json:"id"`
	Forward GitChildEnvelope       `json:"forward"`
	Applied JournalReceiptEnvelope `json:"applied"`
}
type JournalPending struct {
	Command        JournalCommand            `json:"command"`
	Phase          string                    `json:"phase"`
	GitAdvanced    bool                      `json:"git_advanced"`
	ApplyIntent    bool                      `json:"apply_intent"`
	ReadyUntil     time.Time                 `json:"ready_until"`
	IntentAt       time.Time                 `json:"intent_at"`
	RepairIntentAt time.Time                 `json:"repair_intent_at"`
	NoApply        *JournalReceiptEnvelope   `json:"no_apply,omitempty"`
	GitRepair      *JournalGitRepairEnvelope `json:"git_repair,omitempty"`
}

// A dispatch permit is an immediate, local validation result, not a signed or
// reusable capability. The trusted producer must keep its current-head/operation
// fence locked, compare actual Git/state and atomically mark DISPATCHING before
// I/O. Renewing a ledger head cannot renew an old intent or READY receipt.
type JournalDispatchPermit struct {
	JournalID      string         `json:"journal_id"`
	CommandID      string         `json:"command_id"`
	OperationID    string         `json:"operation_id"`
	Fence          uint64         `json:"fence"`
	CommandSHA256  string         `json:"command_sha256"`
	ArtifactSHA256 string         `json:"artifact_sha256"`
	Head           JournalHeadRef `json:"head"`
	ValidUntil     time.Time      `json:"valid_until"`
}
type JournalProjection struct {
	Current             JournalState    `json:"current"`
	Stack               []JournalEffect `json:"stack"`
	Consumed            []string        `json:"consumed"`
	Pending             *JournalPending `json:"pending,omitempty"`
	LastForwardSequence uint64          `json:"last_forward_sequence"`
	LastFence           uint64          `json:"last_fence"`
	ForwardAborted      bool            `json:"forward_aborted"`
	GitRepairs          []string        `json:"git_repairs"`
}

type JournalGitRepair struct {
	SchemaVersion        string       `json:"schema_version"`
	ID                   string       `json:"id"`
	CommandID            string       `json:"command_id"`
	AuthorizationSHA256  string       `json:"authorization_sha256"`
	HeadSHA256           string       `json:"head_sha256"`
	PreparationSHA256    string       `json:"preparation_sha256"`
	NoApplyReceiptSHA256 string       `json:"no_apply_receipt_sha256"`
	Before               JournalState `json:"before"`
	Revision             GitRevision  `json:"revision"`
	CreatedAt            time.Time    `json:"created_at"`
	ExpiresAt            time.Time    `json:"expires_at"`
	Nonce                string       `json:"nonce"`
}
type JournalGitRepairEnvelope struct {
	Repair    JournalGitRepair    `json:"repair"`
	Head      JournalHeadEnvelope `json:"head"`
	Algorithm string              `json:"algorithm"`
	Signature string              `json:"signature"`
}
type JournalView struct {
	Parent        GitEnvelope
	Authorization JournalEnvelope
	Records       []JournalRecord
	Head          JournalHeadEnvelope
}

// This component validates journal algebra, not operational health or permission
// to advance. APPLIED does NOT release operational reservations or attest full
// observation windows. Future store/runtime must independently impose those.
// Producer keys, current head, complete history and writer fencing come from
// commissioned trusted services. No public caller may install keys/roots.
// Unknown CLI effects remain held until an authenticated terminal operation
// receipt resolves them. Git-only repair is a separate signed no-CLI effect and
// permanently aborts forward progress; it cannot consume prior APPLIED duties.
const JournalIntegrationBoundary = "PURE_ISSUED_JOURNAL_ALGEBRA_NOT_RUNTIME_HEALTH_OR_AUTHORITY"
