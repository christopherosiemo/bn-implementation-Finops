package fleetgroup

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

const (
	parentDomain      = "finops/fleet-group/v5/isolated-fixture/parent\x00"
	childDomain       = "finops/fleet-group/v5/isolated-fixture/child\x00"
	recoveryDomain    = "finops/fleet-group/v5/isolated-fixture/owned-recovery\x00"
	parentAlgorithm   = "Ed25519-FleetGroup-v5-fixture"
	childAlgorithm    = "Ed25519-FleetGroup-v5-fixture-child"
	recoveryAlgorithm = "Ed25519-FleetGroup-v5-fixture-owned-recovery"
)

func parentMessage(p Program, a []Approval) []byte {
	raw, _ := json.Marshal(struct {
		Program   Program    `json:"program"`
		Approvals []Approval `json:"approvals"`
	}{p, a})
	return append([]byte(parentDomain), raw...)
}
func childMessage(c Child, domain string) []byte {
	raw, _ := json.Marshal(c)
	return append([]byte(domain), raw...)
}

func ValidateApprovals(p Program, approvals []Approval, now time.Time) error {
	if len(approvals) < 1 || len(approvals) > 16 {
		return invalid("GROUP_INDEPENDENT_APPROVAL_REQUIRED")
	}
	ids, actors := map[string]bool{}, map[string]bool{}
	for _, a := range approvals {
		if !idPattern.MatchString(a.ID) || ids[a.ID] || !idPattern.MatchString(a.ActorID) || actors[a.ActorID] || a.ActorID == p.CreatorID || a.TenantID != p.Binding.Old.Target.TenantID || a.Role != ApproverRole || a.ProgramSHA256 != Digest(p) || a.RealmSHA256 != Digest(p.Realm) || !canonicalTime(a.ApprovedAt) || a.ApprovedAt.Before(p.CreatedAt) || a.ApprovedAt.After(now.Add(5*time.Second)) || !a.ApprovedAt.Before(p.ExpiresAt) {
			return invalid("GROUP_APPROVAL_INVALID")
		}
		ids[a.ID], actors[a.ActorID] = true, true
	}
	return nil
}

func Sign(p Program, a []Approval, key ed25519.PrivateKey, now time.Time) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, invalid("GROUP_SIGNING_KEY_INVALID")
	}
	if err := ValidateProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		return Envelope{}, err
	}
	if err := ValidateApprovals(p, a, now); err != nil {
		return Envelope{}, err
	}
	return Envelope{p, a, parentAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, parentMessage(p, a)))}, nil
}

func Verify(e Envelope, key ed25519.PublicKey, expected Expected, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || e.Algorithm != parentAlgorithm {
		return invalid("GROUP_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, parentMessage(e.Program, e.Approvals), sig) {
		return invalid("GROUP_SIGNATURE_INVALID")
	}
	if err = ValidateProgram(e.Program, expected, now); err != nil {
		return err
	}
	return ValidateApprovals(e.Program, e.Approvals, now)
}

func SignChild(c Child, parent Envelope, key ed25519.PrivateKey, now time.Time) (ChildEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ChildEnvelope{}, invalid("GROUP_SIGNING_KEY_INVALID")
	}
	if err := Verify(parent, key.Public().(ed25519.PublicKey), Expected{parent.Program.Binding, parent.Program.Realm}, now); err != nil {
		return ChildEnvelope{}, err
	}
	if err := ValidateChild(c, parent.Program, now); err != nil {
		return ChildEnvelope{}, err
	}
	return ChildEnvelope{c, childAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, childMessage(c, childDomain)))}, nil
}

func VerifyChild(e ChildEnvelope, parent Envelope, key ed25519.PublicKey, expected Expected, now time.Time) error {
	if err := Verify(parent, key, expected, now); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || e.Algorithm != childAlgorithm {
		return invalid("GROUP_CHILD_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, childMessage(e.Child, childDomain), sig) {
		return invalid("GROUP_CHILD_SIGNATURE_INVALID")
	}
	return ValidateChild(e.Child, parent.Program, now)
}

// ValidateRecovery checks the exact inverse of one immutable APPLIED effect.
// The current parent expiry, failed canary or revoked forward evidence does not
// erase that obligation. Current state/artifact/receipt authentication and fresh
// recovery health must still be established by independent future factories.
// In particular, a historical APPLIED receipt is not proof that its capability
// remains unconsumed; the store must serialize and check current ownership.
func ValidateRecovery(c Child, original Child, p Program, owned OwnedReceipt, now time.Time) error {
	if err := ValidateChild(original, p, original.CreatedAt); err != nil {
		return err
	}
	_, _, err := childBinding(c, p, now)
	if err != nil {
		return err
	}
	if owned.SchemaVersion != SchemaVersion || !idPattern.MatchString(owned.ID) || !idPattern.MatchString(owned.CommandID) || owned.ParentID != p.ID || owned.ParentSHA256 != Digest(p) || owned.ChildID != original.ID || owned.ChildSHA256 != Digest(original) || owned.BindingSHA256 != Digest(p.Binding) || owned.RealmSHA256 != Digest(p.Realm) || owned.ArtifactSHA256 != Digest(original.Artifact) || owned.SavedPlanSHA256 != original.Artifact.SavedPlanSHA256 || owned.PipelineID != p.ArtifactContext.PipelineID || owned.Outcome != "APPLIED" || owned.BeforeStateSerial != original.Artifact.BeforeStateSerial || owned.AfterStateSerial <= owned.BeforeStateSerial || owned.AfterModelSHA256 != Digest(original.Artifact.After) || !canonicalTime(owned.ReceivedAt) || owned.ReceivedAt.Before(original.CreatedAt) || owned.ReceivedAt.After(now.Add(5*time.Second)) || original.Artifact.Before == original.Artifact.After {
		return invalid("GROUP_OWNED_RECEIPT_INVALID")
	}
	if c.Mode != OwnedRecovery || c.ID == original.ID || c.Nonce == original.Nonce || c.Sequence <= original.Sequence || c.StageID != original.StageID || c.StageSHA256 != original.StageSHA256 || c.CompensationFor != original.ID || c.OwnedReceiptSHA256 != Digest(owned) || c.CreatedAt.Before(owned.ReceivedAt) || c.Artifact.BeforeStateSerial < owned.AfterStateSerial || c.Artifact.Before != original.Artifact.After || c.Artifact.After != original.Artifact.Before {
		return invalid("GROUP_RECOVERY_NOT_EXACT_OWNED_INVERSE")
	}
	if c.MinimumObservationSeconds < 120 || c.MinimumObservationSeconds > 3600 {
		return invalid("GROUP_RECOVERY_HEALTH_WINDOW_INVALID")
	}
	return evidence(c.Evidence, []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"}, p.Binding, p.Realm, now, c.ExpiresAt, true)
}

func SignRecovery(c Child, original ChildEnvelope, parent Envelope, owned OwnedReceipt, key ed25519.PrivateKey, now time.Time) (ChildEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ChildEnvelope{}, invalid("GROUP_SIGNING_KEY_INVALID")
	}
	expected := Expected{parent.Program.Binding, parent.Program.Realm}
	if err := VerifyChild(original, parent, key.Public().(ed25519.PublicKey), expected, original.Child.CreatedAt); err != nil {
		return ChildEnvelope{}, err
	}
	if err := ValidateRecovery(c, original.Child, parent.Program, owned, now); err != nil {
		return ChildEnvelope{}, err
	}
	return ChildEnvelope{c, recoveryAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, childMessage(c, recoveryDomain)))}, nil
}

func VerifyRecovery(e ChildEnvelope, original ChildEnvelope, parent Envelope, owned OwnedReceipt, key ed25519.PublicKey, expected Expected, now time.Time) error {
	if err := VerifyChild(original, parent, key, expected, original.Child.CreatedAt); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || e.Algorithm != recoveryAlgorithm {
		return invalid("GROUP_RECOVERY_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, childMessage(e.Child, recoveryDomain), sig) {
		return invalid("GROUP_RECOVERY_SIGNATURE_INVALID")
	}
	return ValidateRecovery(e.Child, original.Child, parent.Program, owned, now)
}
