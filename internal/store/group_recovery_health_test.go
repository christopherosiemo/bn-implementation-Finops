package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
)

func TestGroupRecoveryHealthSignatureDomainsAndWireVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, 32))
	at, _ := time.Parse(time.RFC3339Nano, "2026-10-19T10:20:30.123456789Z")
	body := GroupRecoveryHealthOutcome{SchemaVersion: "1", ID: "unit-outcome", TenantID: "unit-tenant", ChainID: "unit-chain", AttemptID: "unit-attempt", ObserverID: "unit-observer", Status: "ABANDONED", ObservationIDs: []string{}, Window: native.HealthWindow{Status: "BLOCKED", ReasonCodes: []string{"UNIT_<CLOCK>&"}}, SignedAt: at}
	envelope, e := SignGroupRecoveryHealthOutcome(body, key)
	if e != nil {
		t.Fatal(e)
	}
	if !groupRecoveryHealthVerify(groupRecoveryOutcomeDomain, body, envelope.Algorithm, envelope.Signature, key.Public().(ed25519.PublicKey)) {
		t.Fatal("genuine observer signature rejected")
	}
	if groupRecoveryHealthVerify(groupRecoveryObservationDomain, body, envelope.Algorithm, envelope.Signature, key.Public().(ed25519.PublicKey)) {
		t.Fatal("cross-purpose signature accepted")
	}
	changed := body
	changed.AttemptID += "-different"
	if groupRecoveryHealthVerify(groupRecoveryOutcomeDomain, changed, envelope.Algorithm, envelope.Signature, key.Public().(ed25519.PublicKey)) {
		t.Fatal("attempt identity mutation accepted")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))
	if groupRecoveryHealthVerify(groupRecoveryOutcomeDomain, body, envelope.Algorithm, envelope.Signature, other.Public().(ed25519.PublicKey)) {
		t.Fatal("uncommissioned key accepted")
	}
	if _, e = SignGroupRecoveryHealthOutcome(body, nil); e == nil {
		t.Fatal("missing key accepted")
	}
	if os.Getenv("GROUP_RECOVERY_HEALTH_WRITE_UNIT_VECTOR") == "1" {
		raw, _ := json.Marshal(body)
		vector := struct {
			PublicKey string `json:"public_key"`
			RawBody   string `json:"raw_body"`
			Algorithm string `json:"algorithm"`
			Signature string `json:"signature"`
		}{base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), string(raw), envelope.Algorithm, envelope.Signature}
		encoded, _ := json.Marshal(vector)
		if e = os.WriteFile(filepath.Join("..", "..", "work", "group-recovery-health-unit-vector.json"), encoded, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
