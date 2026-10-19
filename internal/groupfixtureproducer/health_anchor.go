package groupfixtureproducer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

const healthAnchorDomain = "finops/group-fixture/activated-health-baseline/v1\x00"
const healthAnchorAlgorithm = "Ed25519/group-fixture-activated-health/v1"
const HealthManifestObservation = "MANIFEST_FORWARD"
const HealthRestorationObservation = "TERMINAL_RESTORATION"

// IssuedAt is the immutable032 database publication time, resolved privately
// by the ledger. It is not a caller timestamp or object-store LastModified.
type HealthBaselineArtifact struct {
	Reference ff.ArtifactReference `json:"reference"`
	IssuedAt  time.Time            `json:"issued_at"`
}

// Deployment is distinct from the stable instrumented observer operation. Its IDs must be server-resolved from the actual issued APPLIED command.
type ActivatedHealthDeployment struct {
	CommandID   string `json:"command_id"`
	OperationID string `json:"operation_id"`
	Fence       uint64 `json:"fence"`
	Kind        string `json:"kind"`
}
type HealthBaselineAnchor struct {
	SchemaVersion            string                   `json:"schema_version"`
	ProgramSHA256            string                   `json:"program_sha256"`
	AuthorizationSHA256      string                   `json:"authorization_sha256"`
	Observer                 HealthBinding            `json:"observer"`
	MeasurementRevision      string                   `json:"measurement_revision"`
	ActivationRecordSHA256   string                   `json:"activation_record_sha256"`
	ActivationRecordSequence uint64                   `json:"activation_record_sequence"`
	ActivatedAt              time.Time                `json:"activated_at"`
	ReceiptSHA256s           []string                 `json:"receipt_sha256s"`
	Artifacts                []HealthBaselineArtifact `json:"artifacts"`
	IssuedAt                 time.Time                `json:"issued_at"`
}
type HealthBaselineAnchorEnvelope struct {
	Anchor    HealthBaselineAnchor `json:"anchor"`
	Algorithm string               `json:"algorithm"`
	Signature string               `json:"signature"`
}

func healthCommandArtifact(c g.JournalCommand) (g.GitArtifact, bool) {
	if c.Forward != nil && c.Recovery == nil {
		return c.Forward.Child.Artifact, true
	}
	if c.Recovery != nil && c.Forward == nil {
		return c.Recovery.Recovery.Artifact, true
	}
	return g.GitArtifact{}, false
}
func healthBaselineReference(p ff.Proposal, r ff.ArtifactReference) bool {
	b, e := bindingFor(p, r.ID, "HEALTH_BASELINE", r.SHA256, r.SizeBytes)
	return e == nil && archiveID.MatchString(r.Bucket) && r.Key == archiveObjectKey(b) && r.VersionID != "" && r.VersionID != "null" && len(r.VersionID) <= 1024
}

func healthActivation(v g.JournalView) (g.JournalRecord, bool) {
	commands := map[string]g.JournalCommand{}
	for _, record := range v.Records {
		if record.Command != nil && record.Kind == g.JournalReserved {
			commands[record.Command.ID] = *record.Command
		}
		if record.Kind == g.JournalApplyIntent && record.Receipt != nil {
			c, ok := commands[record.Receipt.Receipt.CommandID]
			if ok && c.Forward != nil && c.Recovery == nil {
				return record, true
			}
		}
	}
	return g.JournalRecord{}, false
}
func baselineObserver(b []HealthReceipt) HealthBinding {
	if len(b) == 0 {
		return HealthBinding{}
	}
	return b[0].Binding
}
func healthAnchorMessage(a HealthBaselineAnchor) []byte {
	raw, _ := json.Marshal(a)
	return append([]byte(healthAnchorDomain), raw...)
}

func validateHealthAnchor(a HealthBaselineAnchor, v g.JournalView, binding HealthBinding, baseline []HealthReceipt, now time.Time) error {
	activation, ok := healthActivation(v)
	if !ok || a.SchemaVersion != "1" || a.ProgramSHA256 != g.Digest(v.Parent.Program) || a.AuthorizationSHA256 != g.Digest(v.Authorization) || len(baseline) == 0 || a.Observer != baseline[0].Binding || binding.ProgramSHA256 != g.Digest(v.Parent.Program) || binding.Binding != v.Parent.Program.Binding || binding.Realm != v.Parent.Program.Realm || a.Observer.ProgramSHA256 != binding.ProgramSHA256 || a.Observer.Binding != binding.Binding || a.Observer.Realm != binding.Realm || a.MeasurementRevision != healthMeasurementV2 || a.ActivationRecordSHA256 != g.Digest(activation) || a.ActivationRecordSequence != activation.Sequence || !a.ActivatedAt.Equal(activation.RecordedAt) || a.IssuedAt.Before(a.ActivatedAt) || a.IssuedAt.After(a.ActivatedAt.Add(5*time.Minute)) || a.IssuedAt.After(now.Add(5*time.Second)) || len(a.Artifacts) != len(baseline) || len(a.ReceiptSHA256s) != len(baseline) {
		return ErrHealth
	}
	p, err := population(baseline, binding, true)
	if err != nil || !p.complete || p.schema != "2" || p.last.Sub(p.first) < 2*time.Minute || p.monotonicNS < int64(2*time.Minute) || p.last.After(a.ActivatedAt) || a.ActivatedAt.Sub(p.last) > 5*time.Minute {
		return ErrHealth
	}
	pseudo := ff.Proposal{ID: v.Parent.Program.ArtifactContext.RepositoryID, Binding: binding.Binding, Realm: binding.Realm, Profile: ff.Profile{ID: binding.Realm.FixtureID, Generation: binding.Realm.Generation, ModelSHA256: binding.Realm.ModelSHA256, Installation: ff.Installation{ToolchainImageSHA256: v.Parent.Program.ArtifactContext.ToolchainImageSHA256}}}
	seen := map[string]bool{}
	for i, r := range baseline {
		ref := a.Artifacts[i]
		raw, _ := json.Marshal(r)
		if r.Binding != a.Observer || seen[ref.Reference.ID] || a.ReceiptSHA256s[i] != r.SHA256 || ref.Reference.SHA256 != g.BytesDigest(raw) || ref.Reference.SizeBytes != int64(len(raw)) || !healthBaselineReference(pseudo, ref.Reference) || ref.IssuedAt.IsZero() || ref.IssuedAt.Before(r.After.CapturedAt) || ref.IssuedAt.After(a.ActivatedAt) {
			return ErrHealth
		}
		seen[ref.Reference.ID] = true
	}
	return nil
}

// SignHealthBaselineAnchor is a private ledger operation after actual initial
// activation. The trusted repository must resolve the exact032 baseline refs,
// their actual database issue times, archived bodies and immutable selection.
// No HTTP endpoint accepts an anchor or the signing key. A hash is not origin
// authority. This must be persisted once per program before later observations.
func SignHealthBaselineAnchor(v g.JournalView, keys g.JournalKeys, expected g.JournalHeadRef, binding HealthBinding, baseline []HealthReceipt, refs []HealthBaselineArtifact, key ed25519.PrivateKey, now time.Time) (HealthBaselineAnchorEnvelope, error) {
	var out HealthBaselineAnchorEnvelope
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Ledger) {
		return out, ErrHealth
	}
	if _, err := g.VerifyJournal(v, keys, expected, now); err != nil {
		return out, err
	}
	activation, ok := healthActivation(v)
	if !ok {
		return out, ErrHealth
	}
	a := HealthBaselineAnchor{SchemaVersion: "1", ProgramSHA256: g.Digest(v.Parent.Program), AuthorizationSHA256: g.Digest(v.Authorization), Observer: baselineObserver(baseline), MeasurementRevision: healthMeasurementV2, ActivationRecordSHA256: g.Digest(activation), ActivationRecordSequence: activation.Sequence, ActivatedAt: activation.RecordedAt, Artifacts: append([]HealthBaselineArtifact{}, refs...), IssuedAt: now}
	for _, r := range baseline {
		a.ReceiptSHA256s = append(a.ReceiptSHA256s, r.SHA256)
	}
	if err := validateHealthAnchor(a, v, binding, baseline, now); err != nil {
		return out, err
	}
	return HealthBaselineAnchorEnvelope{a, healthAnchorAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, healthAnchorMessage(a)))}, nil
}

// EvaluateActivatedHealthWindow uses original baseline evidence, never renewed
// or relearned after a failure. Freshness is checked at the authenticated first
// dispatch activation. Current head/stage/receipts remain independently checked.
// Keys/current view and the selected immutable anchor are server-owned inputs.
// This does not change source freshness, dispatch permissions or financial gates.
func EvaluateActivatedHealthWindow(v g.JournalView, keys g.JournalKeys, expected g.JournalHeadRef, anchor HealthBaselineAnchorEnvelope, deployment ActivatedHealthDeployment, binding HealthBinding, baseline, current []HealthReceipt, limits HealthLimits, now time.Time) HealthWindow {
	commandID, kind := deployment.CommandID, deployment.Kind
	blocked := func(code string) HealthWindow {
		return HealthWindow{Status: "BLOCKED", ReasonCodes: []string{code}, Binding: binding, Definition: HealthCompletedOperation, AvailabilityBasis: "OBSERVED_HTTP_REQUEST_SUCCESS"}
	}
	p, err := g.VerifyJournal(v, keys, expected, now)
	if err != nil {
		return blocked("HEALTH_CURRENT_JOURNAL_UNAVAILABLE")
	}
	sig, err := base64.StdEncoding.DecodeString(anchor.Signature)
	if err != nil || anchor.Algorithm != healthAnchorAlgorithm || len(keys.Ledger) != ed25519.PublicKeySize || !ed25519.Verify(keys.Ledger, healthAnchorMessage(anchor.Anchor), sig) || validateHealthAnchor(anchor.Anchor, v, binding, baseline, now) != nil {
		return blocked("HEALTH_ACTIVATION_ANCHOR_INVALID")
	}
	if len(current) == 0 {
		return blocked("HEALTH_SAMPLES_INSUFFICIENT")
	}
	if now.Sub(current[len(current)-1].After.CapturedAt) > time.Minute {
		return blocked("HEALTH_CURRENT_RECEIPTS_STALE")
	}
	var command g.JournalCommand
	var applied *g.JournalReceiptEnvelope
	for _, r := range v.Records {
		if r.Kind == g.JournalReserved && r.Command != nil && r.Command.ID == commandID {
			command = *r.Command
		}
		if r.Kind == g.JournalApplied && r.Receipt != nil {
			applied = r.Receipt
		}
	}
	artifact, ok := healthCommandArtifact(command)
	if !ok || deployment.OperationID != command.OperationID || deployment.Fence != command.Fence || p.Pending != nil || applied == nil || applied.Receipt.CommandID != commandID || applied.Receipt.ArtifactSHA256 != g.Digest(artifact) || applied.Receipt.After != p.Current || p.Current.Model != artifact.After || p.Current.Revision != artifact.Revision || current[0].Before.CapturedAt.Before(applied.Receipt.ReceivedAt) {
		return blocked("HEALTH_STAGE_OWNERSHIP_UNAVAILABLE")
	}
	start := current[0].Before.CapturedAt
	var stage g.Stage
	if kind == HealthManifestObservation && command.Forward != nil && command.Recovery == nil {
		if start.Sub(applied.Receipt.ReceivedAt) > time.Minute {
			return blocked("HEALTH_STAGE_INITIAL_COVERAGE_UNKNOWN")
		}
		c := command.Forward.Child
		if c.Sequence < 1 || c.Sequence > uint64(len(v.Parent.Program.Manifest.Entries)) {
			return blocked("MANIFEST_ENTRY_HEALTH_BINDING_INVALID")
		}
		entry := v.Parent.Program.Manifest.Entries[c.Sequence-1]
		if c.Artifact.ManifestEntrySHA256 != g.Digest(entry) || c.MinimumObservationSeconds != entry.MinimumObservationSeconds || entry.MinimumObservationSeconds < 120 {
			return blocked("MANIFEST_ENTRY_HEALTH_BINDING_INVALID")
		}
		for _, s := range v.Parent.Program.Stages {
			if s.ID == entry.StageID && g.Digest(s) == entry.StageSHA256 {
				stage = s
				stage.MinimumObservationSeconds = entry.MinimumObservationSeconds
			}
		}
	} else if kind == HealthRestorationObservation && command.Recovery != nil && command.Forward == nil && len(p.Stack) == 0 && p.Current.Model == v.Authorization.Authorization.Base.Model {
		// This is one full observation window after restoration. Repeated
		// attempts require a repository-owned incident/attempt history; this
		// observational function never certifies absence of earlier failures.
		stage = g.DefaultStages(20)[5]
	} else {
		return blocked("HEALTH_STAGE_OWNERSHIP_UNAVAILABLE")
	}
	return evaluateHealthWindowBaselineAt(binding, stage, start, baseline, current, limits, now, kind == HealthManifestObservation, anchor.Anchor.ActivatedAt)
}
