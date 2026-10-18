package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

const recoveryDomain = "finops/fleet/v4/owned-recovery\x00"

func recoveryMessage(c ChildPlan) []byte { return append([]byte(recoveryDomain), CanonicalJSON(c)...) }

// ValidateRecoveryChild uses an authenticated, store-selected immutable receipt.
// Forward expiry, paused policy and revoked telemetry do not abandon ownership.
// Recovery still needs a fresh saved plan/current state and exact inverse fields.
func ValidateRecoveryChild(c, original ChildPlan, p FleetPlanV4, owned OwnedReceipt, now time.Time) error {
	if owned.ID == "" || owned.Status != "APPLIED" || owned.ParentID != p.ID || owned.ChildID != original.ID || owned.ChildSHA256 != Digest(original) || owned.Binding != p.Binding || owned.PipelineID != p.IaC.PipelineID || owned.SavedPlanSHA256 != original.SavedPlanSHA256 || owned.BeforeStateSerial != original.IaC.StateSerial || owned.AfterStateSerial <= owned.BeforeStateSerial || owned.ObservedAt.Before(original.CreatedAt) || owned.ObservedAt.After(now.Add(5*time.Second)) {
		return invalid("FLEET_OWNED_RECEIPT_INVALID")
	}
	if c.SchemaVersion != "4" || c.ID == "" || c.Binding != p.Binding || c.ParentID != p.ID || c.ParentSHA256 != Digest(p) || c.StageID != original.StageID || c.StageSHA256 != original.StageSHA256 || c.CompensationFor != original.ID || c.CompensationReceiptSHA256 != Digest(owned) || c.Nonce == "" || c.Nonce == original.Nonce || !hashPattern.MatchString(c.SavedPlanSHA256) || !hashPattern.MatchString(c.PlanJSONSHA256) {
		return invalid("FLEET_RECOVERY_BINDING_INVALID")
	}
	if c.CreatedAt.After(now.Add(5*time.Second)) || now.Sub(c.CreatedAt) > 5*time.Minute || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.Sub(c.CreatedAt) > 15*time.Minute {
		return invalid("FLEET_RECOVERY_PLAN_STALE")
	}
	if e := validateIaC(c.IaC); e != nil {
		return e
	}
	if c.IaC.Repository != p.IaC.Repository || c.IaC.GitCommit != p.IaC.GitCommit || c.IaC.Workspace != p.IaC.Workspace || c.IaC.StateLineage != p.IaC.StateLineage || c.IaC.StateSerial < owned.AfterStateSerial || c.IaC.ConfigurationSHA256 != original.IaC.ConfigurationSHA256 || c.IaC.PipelineID != p.IaC.PipelineID || c.IaC.TerraformVersion != p.IaC.TerraformVersion {
		return invalid("FLEET_RECOVERY_IAC_BINDING_INVALID")
	}
	originalFields := map[string]AllowedChange{}
	for _, a := range original.Changes {
		originalFields[a.Address] = a
	}
	if len(c.Changes) != len(original.Changes) {
		return invalid("FLEET_RECOVERY_MUST_INVERT_OWNED_FIELDS")
	}
	for _, a := range c.Changes {
		old, ok := originalFields[a.Address]
		if !ok || a.Type != old.Type || a.Action != "update" || len(a.Fields) != len(old.Fields) {
			return invalid("FLEET_RECOVERY_MUST_INVERT_OWNED_FIELDS")
		}
		fields := map[string]FieldChange{}
		for _, f := range old.Fields {
			fields[f.Path] = f
		}
		for _, f := range a.Fields {
			prior, exists := fields[f.Path]
			if !exists || !sameJSONValue(f.Before, prior.After) || !sameJSONValue(f.After, prior.Before) {
				return invalid("FLEET_RECOVERY_MUST_INVERT_OWNED_FIELDS")
			}
			delete(fields, f.Path)
		}
		for _, path := range a.ComputedPaths {
			if !contains(old.ComputedPaths, path) {
				return invalid("FLEET_RECOVERY_UNKNOWN_UNDELEGATED")
			}
		}
		delete(originalFields, a.Address)
	}
	t, o := c.Transition, original.Transition
	if t.OldBefore != o.OldAfter || t.OldAfter != o.OldBefore || t.CandidateBefore != o.CandidateAfter || t.CandidateAfter != o.CandidateBefore || t.TrafficBefore != o.TrafficAfter || t.TrafficAfter != o.TrafficBefore {
		return invalid("FLEET_RECOVERY_TRANSITION_NOT_INVERSE")
	}
	stage, e := stageFor(p, c.StageID)
	if e != nil {
		return e
	}
	return validateTransition(p, stage, t, true)
}
func sameJSONValue(a, b []byte) bool {
	x, e := jsonValue(a)
	y, f := jsonValue(b)
	return e == nil && f == nil && sameJSON(x, y)
}
func verifyOriginalForRecovery(original ChildEnvelope, parent Envelope, key ed25519.PublicKey, expected Binding) error {
	// Verify the original signed authority at dispatch time, not at recovery time.
	return VerifyChild(original, parent, key, expected, original.Plan.CreatedAt)
}
func SignRecovery(c ChildPlan, original ChildEnvelope, parent Envelope, owned OwnedReceipt, key ed25519.PrivateKey, now time.Time) (ChildEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ChildEnvelope{}, invalid("FLEET_SIGNING_KEY_INVALID")
	}
	if e := verifyOriginalForRecovery(original, parent, key.Public().(ed25519.PublicKey), c.Binding); e != nil {
		return ChildEnvelope{}, e
	}
	if e := ValidateRecoveryChild(c, original.Plan, parent.Plan, owned, now); e != nil {
		return ChildEnvelope{}, e
	}
	return ChildEnvelope{c, "Ed25519-Fleet-v4-owned-recovery", base64.StdEncoding.EncodeToString(ed25519.Sign(key, recoveryMessage(c)))}, nil
}
func VerifyRecovery(c ChildEnvelope, original ChildEnvelope, parent Envelope, owned OwnedReceipt, key ed25519.PublicKey, expected Binding, now time.Time) error {
	if e := verifyOriginalForRecovery(original, parent, key, expected); e != nil {
		return e
	}
	if c.Plan.Binding != expected || c.Algorithm != "Ed25519-Fleet-v4-owned-recovery" {
		return invalid("FLEET_RECOVERY_SIGNATURE_INVALID")
	}
	sig, e := base64.StdEncoding.DecodeString(c.Signature)
	if e != nil || !ed25519.Verify(key, recoveryMessage(c.Plan), sig) {
		return invalid("FLEET_RECOVERY_SIGNATURE_INVALID")
	}
	return ValidateRecoveryChild(c.Plan, original.Plan, parent.Plan, owned, now)
}
func ValidateRecoveryTerraformPlan(raw, binary []byte, c ChildPlan, original ChildPlan, p FleetPlanV4, owned OwnedReceipt, provenance IaCBinding, now time.Time) (PlanReview, error) {
	if e := ValidateRecoveryChild(c, original, p, owned, now); e != nil {
		return PlanReview{}, e
	}
	return validateTerraformPlan(raw, binary, c, p, provenance, now)
}
