package safety

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func Eligibility(r, w, p model.Document, now time.Time) []string {
	blocked := []string{}
	checks := []struct {
		ok     bool
		reason string
	}{
		{model.String(w, "environment") == "NON_PRODUCTION", "BLOCKED_PRODUCTION"},
		{model.String(r, "environment") == "NON_PRODUCTION", "BLOCKED_PRODUCTION_RESOURCE"},
		{model.String(w, "owner") != "", "BLOCKED_OWNER_UNKNOWN"},
		{model.Bool(r, "runtime_stop_start_delegated"), "BLOCKED_CONFIGURATION_AUTHORITY_UNKNOWN"},
		{knownAuthority(model.String(r, "configuration_authority")), "BLOCKED_CONFIGURATION_AUTHORITY_UNKNOWN"},
		{model.String(r, "root_device_type") == "ebs", "BLOCKED_ROOT_DEVICE"},
		{!model.Bool(r, "instance_store"), "BLOCKED_EPHEMERAL_STORAGE"},
		{!model.Bool(r, "fleet_managed"), "BLOCKED_MANAGED_FLEET"},
		{!model.Bool(r, "spot"), "BLOCKED_SPOT"},
		{!model.Bool(r, "stop_protection"), "BLOCKED_STOP_PROTECTION"},
		{model.Bool(r, "commitment_known") && model.Bool(r, "uncovered_on_demand"), "BLOCKED_COMMITMENT_EXPOSURE"},
		{!model.Bool(r, "unknown_drift"), "BLOCKED_CONFIGURATION_DRIFT"},
		{model.Bool(r, "stable_network"), "BLOCKED_NETWORK_IDENTITY"},
		{!model.Bool(r, "blocking_dependencies"), "BLOCKED_DEPENDENCY"},
		{model.Number(r, "observation_days") >= 14, "INSUFFICIENT_OBSERVATION"},
		{!model.Bool(p, "paused"), "BLOCKED_POLICY_PAUSED"},
	}
	for _, c := range checks {
		if !c.ok {
			blocked = append(blocked, c.reason)
		}
	}
	for _, s := range []string{"incident", "deployment", "job"} {
		if model.String(w, s) != "CLEAR" {
			blocked = append(blocked, "BLOCKED_"+map[string]string{"incident": "ACTIVE_INCIDENT", "deployment": "ACTIVE_DEPLOYMENT", "job": "ACTIVE_OR_UNKNOWN_JOB"}[s])
		}
	}
	t, e := time.Parse(time.RFC3339Nano, model.String(w, "signals_at"))
	if e != nil || now.Sub(t) > 5*time.Minute || t.After(now.Add(time.Minute)) {
		blocked = append(blocked, "BLOCKED_STALE_SIGNALS")
	}
	return blocked
}
func knownAuthority(s string) bool {
	switch s {
	case "TERRAFORM", "CLOUDFORMATION", "BICEP", "ARM", "PULUMI", "KUBERNETES", "HELM", "ARGOCD", "FLUX", "CLOUD_API", "MANUAL":
		return true
	}
	return false
}
func SnapshotHash(r model.Document) string {
	snapshot := model.Document{}
	for _, field := range []string{"provider", "provider_resource_id", "account_id", "region", "instance_type", "root_device_type", "environment", "workload_id", "state", "configuration_authority", "runtime_stop_start_delegated", "instance_store", "fleet_managed", "spot", "stop_protection", "commitment_known", "uncovered_on_demand", "unknown_drift", "stable_network", "blocking_dependencies", "billing_source_version", "hourly_effective_cost", "currency"} {
		snapshot[field] = r[field]
	}
	b, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func Sign(p model.Plan, key ed25519.PrivateKey) (model.Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return model.Envelope{}, errors.New("invalid signing key")
	}
	b, e := json.Marshal(p)
	if e != nil {
		return model.Envelope{}, e
	}
	return model.Envelope{Plan: p, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, b)), Algorithm: "Ed25519"}, nil
}
func Verify(e model.Envelope, key ed25519.PublicKey, tenant string, now time.Time, restoring bool) error {
	if e.Algorithm != "Ed25519" || e.Plan.TenantID != tenant || e.Plan.Nonce == "" {
		return errors.New("invalid signed plan binding")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(e.Plan)
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, b, sig) {
		return errors.New("invalid plan signature")
	}
	if !restoring && (!now.Before(e.Plan.ExpiresAt) || now.Before(e.Plan.CreatedAt.Add(-time.Minute))) {
		return errors.New("plan expired or not yet valid")
	}
	if len(e.Plan.Operations) != 2 || e.Plan.Operations[0].Type != "EC2_STOP" || e.Plan.Operations[1].Type != "EC2_START" || e.Plan.Operations[0].ResourceID != e.Plan.Operations[1].ResourceID || e.Plan.Operations[0].ProviderResourceID != e.Plan.Operations[1].ProviderResourceID || e.Plan.Operations[0].AccountID != e.Plan.Operations[1].AccountID || e.Plan.Operations[0].Region != e.Plan.Operations[1].Region {
		return errors.New("invalid stop/start operation pair")
	}
	if !restoring && (e.Plan.StopAt.IsZero() || now.Before(e.Plan.StopAt) || !now.Before(e.Plan.StopAt.Add(15*time.Minute))) {
		return errors.New("outside signed stop window")
	}
	return nil
}
func PrivateKey(encoded string) (ed25519.PrivateKey, error) {
	b, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		return nil, e
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("Ed25519 private key must be 32-byte seed or 64-byte key")
}
func PublicKey(encoded string) (ed25519.PublicKey, error) {
	b, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		return nil, e
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("Ed25519 public key must be 32 bytes")
	}
	return ed25519.PublicKey(b), nil
}

// NextWindow returns an occurrence anchored to its stop day. Ambiguous local times
// resolve once; nonexistent stop times are rejected rather than caught up.
func NextWindow(now time.Time, zone, stop, ready string, days []int) (time.Time, time.Time, error) {
	loc, e := time.LoadLocation(zone)
	if e != nil {
		return time.Time{}, time.Time{}, errors.New("invalid IANA timezone")
	}
	st, e := time.Parse("15:04", stop)
	if e != nil {
		return time.Time{}, time.Time{}, errors.New("stop_time must be HH:MM")
	}
	rt, e := time.Parse("15:04", ready)
	if e != nil || ready == stop {
		return time.Time{}, time.Time{}, errors.New("ready_time must differ from stop_time")
	}
	if len(days) == 0 {
		return time.Time{}, time.Time{}, errors.New("days must contain ISO weekdays 1-7")
	}
	allowed := map[int]bool{}
	for _, d := range days {
		if d < 1 || d > 7 {
			return time.Time{}, time.Time{}, errors.New("invalid weekday")
		}
		allowed[d] = true
	}
	n := now.In(loc)
	for d := 0; d < 9; d++ {
		day := n.AddDate(0, 0, d)
		iso := int(day.Weekday())
		if iso == 0 {
			iso = 7
		}
		if !allowed[iso] {
			continue
		}
		s := time.Date(day.Year(), day.Month(), day.Day(), st.Hour(), st.Minute(), 0, 0, loc)
		if s.Format("15:04") != stop || s.Before(now.Add(-15*time.Minute)) {
			continue
		}
		r := time.Date(day.Year(), day.Month(), day.Day(), rt.Hour(), rt.Minute(), 0, 0, loc)
		if !r.After(s) {
			r = r.AddDate(0, 0, 1)
		}
		start := r.Add(-15 * time.Minute)
		if !start.After(s) || start.Sub(s) > 23*time.Hour {
			return time.Time{}, time.Time{}, errors.New("off window must be positive and below 23 hours")
		}
		return s.UTC(), start.UTC(), nil
	}
	return time.Time{}, time.Time{}, errors.New("no valid occurrence")
}
