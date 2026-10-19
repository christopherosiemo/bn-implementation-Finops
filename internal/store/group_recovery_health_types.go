package store

// These private fixture contracts do not authorize deployments or customer
// finance. An independently commissioned observer signs measured receipt
// bindings; the ledger can select an issued result but cannot manufacture one.
import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
)

var ErrGroupRecoveryHealth = errors.New("GROUP_RECOVERY_HEALTH_INVALID")
var ErrGroupRecoveryHealthConflict = errors.New("GROUP_RECOVERY_HEALTH_CONFLICT")

const GroupRecoveryHealthAlgorithm = "Ed25519/group-recovery-health/v1"
const groupRecoveryObservationDomain = "finops/group-fixture/recovery-health-observation/v1\x00"
const groupRecoveryOutcomeDomain = "finops/group-fixture/recovery-health-outcome/v1\x00"

type GroupRecoveryHealthIdentity struct {
	SourceID string `json:"source_id"`
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Audience string `json:"audience"`
}

// Installation is operator-only, immutable, and scoped to the actual issued
// chain. DatabaseLogin is the authenticated session identity, not SET ROLE.
type GroupRecoveryHealthObserver struct {
	ID            string                      `json:"id"`
	TenantID      string                      `json:"tenant_id"`
	ChainID       string                      `json:"chain_id"`
	DatabaseLogin string                      `json:"database_login"`
	Identity      GroupRecoveryHealthIdentity `json:"identity"`
	PublicKey     ed25519.PublicKey           `json:"public_key"`
	Limits        native.HealthLimits         `json:"limits"`
}

type GroupRecoveryHealthObservation struct {
	SchemaVersion string                 `json:"schema_version"`
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	ChainID       string                 `json:"chain_id"`
	ObserverID    string                 `json:"observer_id"`
	Workspace     native.NativeWorkspace `json:"workspace"`
	Phase         string                 `json:"phase"` // BASELINE or RESTORATION
	AttemptID     string                 `json:"attempt_id"`
	CommandID     string                 `json:"command_id"`
	Receipt       native.HealthReceipt   `json:"receipt"`
	Reference     ff.ArtifactReference   `json:"reference"`
	SignedAt      time.Time              `json:"signed_at"`
}
type GroupRecoveryHealthObservationEnvelope struct {
	Observation GroupRecoveryHealthObservation `json:"observation"`
	Algorithm   string                         `json:"algorithm"`
	Signature   string                         `json:"signature"`
}

type GroupRecoveryHealthBaseline struct {
	SchemaVersion   string                              `json:"schema_version"`
	ID              string                              `json:"id"`
	TenantID        string                              `json:"tenant_id"`
	ChainID         string                              `json:"chain_id"`
	Anchor          native.HealthBaselineAnchorEnvelope `json:"anchor"`
	AnchorReference ff.ArtifactReference                `json:"anchor_reference"`
	ObservationIDs  []string                            `json:"observation_ids"`
}

// StartedAt is the server-selected PostgreSQL clock immediately before insert.
// Positive coverage must also begin after the row's actual created_at clock.
// A retry is a NEW attempt; earlier receipts cannot contribute elapsed time.
type GroupRecoveryHealthAttempt struct {
	SchemaVersion     string                 `json:"schema_version"`
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	ChainID           string                 `json:"chain_id"`
	ObserverID        string                 `json:"observer_id"`
	BaselineID        string                 `json:"baseline_id"`
	PreviousOutcomeID string                 `json:"previous_outcome_id"`
	Workspace         native.NativeWorkspace `json:"workspace"`
	CommandID         string                 `json:"command_id"`
	OperationID       string                 `json:"operation_id"`
	Fence             uint64                 `json:"fence"`
	TerminalID        string                 `json:"terminal_id"`
	StateSHA256       string                 `json:"state_sha256"`
	Head              g.JournalHeadRef       `json:"head"`
	StartedAt         time.Time              `json:"started_at"`
}

type GroupRecoveryHealthOutcome struct {
	SchemaVersion  string              `json:"schema_version"`
	ID             string              `json:"id"`
	TenantID       string              `json:"tenant_id"`
	ChainID        string              `json:"chain_id"`
	AttemptID      string              `json:"attempt_id"`
	ObserverID     string              `json:"observer_id"`
	Status         string              `json:"status"` // OBSERVED, BREACH, INVALID or ABANDONED
	ObservationIDs []string            `json:"observation_ids"`
	Window         native.HealthWindow `json:"window"`
	SignedAt       time.Time           `json:"signed_at"`
}
type GroupRecoveryHealthOutcomeEnvelope struct {
	Outcome   GroupRecoveryHealthOutcome `json:"outcome"`
	Algorithm string                     `json:"algorithm"`
	Signature string                     `json:"signature"`
}

type GroupRecoveryHealthSnapshot struct {
	Observer   GroupRecoveryHealthObserver
	View       g.JournalView
	Keys       g.JournalKeys
	Workspace  native.NativeWorkspace
	Command    g.JournalCommand
	TerminalID string
	Baseline   *GroupRecoveryHealthBaseline
	Released   bool
	Now        time.Time
}

func groupRecoveryHealthMessage(domain string, body any) []byte {
	raw, _ := json.Marshal(body)
	return append([]byte(domain), raw...)
}
func SignGroupRecoveryHealthObservation(body GroupRecoveryHealthObservation, key ed25519.PrivateKey) (GroupRecoveryHealthObservationEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return GroupRecoveryHealthObservationEnvelope{}, ErrGroupRecoveryHealth
	}
	return GroupRecoveryHealthObservationEnvelope{body, GroupRecoveryHealthAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, groupRecoveryHealthMessage(groupRecoveryObservationDomain, body)))}, nil
}
func SignGroupRecoveryHealthOutcome(body GroupRecoveryHealthOutcome, key ed25519.PrivateKey) (GroupRecoveryHealthOutcomeEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return GroupRecoveryHealthOutcomeEnvelope{}, ErrGroupRecoveryHealth
	}
	return GroupRecoveryHealthOutcomeEnvelope{body, GroupRecoveryHealthAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, groupRecoveryHealthMessage(groupRecoveryOutcomeDomain, body)))}, nil
}
func groupRecoveryHealthVerify(domain string, body any, algorithm, signature string, key ed25519.PublicKey) bool {
	sig, e := base64.StdEncoding.DecodeString(signature)
	return e == nil && algorithm == GroupRecoveryHealthAlgorithm && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, groupRecoveryHealthMessage(domain, body), sig)
}
