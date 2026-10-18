package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

const parentDomain = "finops/fleet/v4/parent\x00"
const childDomain = "finops/fleet/v4/child\x00"

func parentMessage(p FleetPlanV4, a []Approval) []byte {
	raw, _ := json.Marshal(struct {
		Plan      FleetPlanV4 `json:"plan"`
		Approvals []Approval  `json:"approvals"`
	}{p, a})
	return append([]byte(parentDomain), raw...)
}
func childMessage(p ChildPlan) []byte {
	raw, _ := json.Marshal(p)
	return append([]byte(childDomain), raw...)
}
func ValidateApprovals(p FleetPlanV4, a []Approval, now time.Time) error {
	if len(a) < 1 {
		return invalid("FLEET_R2_APPROVAL_REQUIRED")
	}
	seen := map[string]bool{}
	for _, v := range a {
		if v.ID == "" || seen[v.ID] || v.TenantID != p.Binding.TenantID || v.ActorID == "" || v.ActorID == p.CreatorID || v.Role != ApproverRole || v.PlanSHA256 != Digest(p) || v.ApprovedAt.Before(p.CreatedAt) || v.ApprovedAt.After(now.Add(5*time.Second)) || v.ApprovedAt.After(p.ExpiresAt) {
			return invalid("FLEET_R2_APPROVAL_INVALID")
		}
		seen[v.ID] = true
	}
	return nil
}
func Sign(p FleetPlanV4, a []Approval, key ed25519.PrivateKey, now time.Time) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, invalid("FLEET_SIGNING_KEY_INVALID")
	}
	if e := ValidatePlan(p, p.Binding, now); e != nil {
		return Envelope{}, e
	}
	if e := ValidateApprovals(p, a, now); e != nil {
		return Envelope{}, e
	}
	return Envelope{Plan: p, Approvals: a, Algorithm: "Ed25519-Fleet-v4", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, parentMessage(p, a)))}, nil
}
func Verify(e Envelope, key ed25519.PublicKey, expected Binding, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || e.Algorithm != "Ed25519-Fleet-v4" {
		return invalid("FLEET_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, parentMessage(e.Plan, e.Approvals), sig) {
		return invalid("FLEET_SIGNATURE_INVALID")
	}
	if err = ValidatePlan(e.Plan, expected, now); err != nil {
		return err
	}
	return ValidateApprovals(e.Plan, e.Approvals, now)
}
func SignChild(p ChildPlan, parent Envelope, key ed25519.PrivateKey, now time.Time) (ChildEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ChildEnvelope{}, invalid("FLEET_SIGNING_KEY_INVALID")
	}
	if e := Verify(parent, key.Public().(ed25519.PublicKey), p.Binding, now); e != nil {
		return ChildEnvelope{}, e
	}
	if e := ValidateChild(p, parent.Plan, now); e != nil {
		return ChildEnvelope{}, e
	}
	return ChildEnvelope{Plan: p, Algorithm: "Ed25519-Fleet-v4-child", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, childMessage(p)))}, nil
}
func VerifyChild(e ChildEnvelope, parent Envelope, key ed25519.PublicKey, expected Binding, now time.Time) error {
	if err := Verify(parent, key, expected, now); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || e.Algorithm != "Ed25519-Fleet-v4-child" {
		return invalid("FLEET_CHILD_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, childMessage(e.Plan), sig) {
		return invalid("FLEET_CHILD_SIGNATURE_INVALID")
	}
	return ValidateChild(e.Plan, parent.Plan, now)
}
