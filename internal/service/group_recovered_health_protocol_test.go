package service

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// The original033 result is a sorted top-level Document containing typed
// nested structs. Decoding the whole document into map[string]any changes
// those nested field orders, even when every value is exact and valid.
type recoveredReconstruction struct {
	TerminalHealthPending                 bool                   `json:"terminal_health_pending"`
	ReservationHeld                       bool                   `json:"reservation_held"`
	RestoredStateSHA256                   string                 `json:"restored_state_sha256"`
	FreshOwnedInverseCommandID            string                 `json:"fresh_owned_inverse_command_id"`
	ReconstructionArtifactIndexSHA256     string                 `json:"reconstruction_artifact_index_sha256"`
	PostReconstructionRecoveryInvocations native.InvocationAudit `json:"post_reconstruction_recovery_invocations"`
}

func recoveredCanonicalFragment(raw []byte, out any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, e := json.Marshal(out)
	return e == nil && bytes.Equal(raw, canonical)
}
func readRecoveredReconstruction(file string) (recoveredReconstruction, []byte) {
	var out recoveredReconstruction
	var fields map[string]json.RawMessage
	raw := workspaceRead(file, 16<<10, &fields)
	if raw == nil {
		return out, nil
	}
	for name, body := range fields {
		var valid bool
		switch name {
		case "inverse_terminal_ref":
			var v ff.ArtifactReference
			valid = recoveredCanonicalFragment(body, &v)
		case "old_workspace", "new_workspace":
			var v native.NativeWorkspace
			valid = recoveredCanonicalFragment(body, &v)
		case "post_reconstruction_recovery_invocations":
			var v native.InvocationAudit
			valid = recoveredCanonicalFragment(body, &v)
		default:
			// All other original033 fields are scalars. Reject unexpected
			// containers rather than silently accepting nested duplicate keys.
			var v any
			valid = recoveredCanonicalFragment(body, &v)
			switch v.(type) {
			case map[string]any, []any:
				valid = false
			}
		}
		if !valid {
			return out, nil
		}
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, nil
	}
	return out, raw
}

func TestRecoveredHealthReadsOriginalTypedReconstructionWithoutReencoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original.json")
	audit := native.InvocationAudit{Counts: map[string]uint64{"apply": 1, "plan": 1, "show": 1}, Total: 3, SHA256: strings.Repeat("a", 64)}
	doc := model.Document{"schema_version": "1", "status": "PASS", "terminal_health_pending": true, "reservation_held": true, "restored_state_sha256": strings.Repeat("b", 64), "fresh_owned_inverse_command_id": "actual-inverse", "reconstruction_artifact_index_sha256": strings.Repeat("c", 64), "post_reconstruction_recovery_invocations": audit, "inverse_terminal_ref": ff.ArtifactReference{ID: "archive", Bucket: "private", Key: "tenant/exact", VersionID: "immutable-version", SHA256: strings.Repeat("d", 64), SizeBytes: 4524}, "new_workspace": native.NativeWorkspace{Generation: "generation", RuntimeID: strings.Repeat("e", 64), ImageSHA256: strings.Repeat("f", 64)}}
	raw, _ := json.Marshal(doc)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	// Reproduce the failed bridge interop, without changing accepted033 bytes.
	var generic model.Document
	if workspaceRead(path, 16<<10, &generic) != nil {
		t.Fatal("fixture failed to exercise nested typed order")
	}
	got, exact := readRecoveredReconstruction(path)
	if !bytes.Equal(exact, raw) || !got.TerminalHealthPending || !got.ReservationHeld || got.RestoredStateSHA256 != strings.Repeat("b", 64) || g.Digest(got.PostReconstructionRecoveryInvocations) != g.Digest(audit) {
		t.Fatal("typed original033 result did not retain exact bytes and audit")
	}
	for name, body := range map[string][]byte{"trailing": append(append([]byte{}, raw...), []byte("{}")...), "duplicate-top": bytes.Replace(raw, []byte(`"reservation_held":true`), []byte(`"reservation_held":true,"reservation_held":false`), 1), "duplicate-nested": bytes.Replace(raw, []byte(`"total":3`), []byte(`"total":3,"total":3`), 1), "unknown-nested": bytes.Replace(raw, []byte(`"total":3`), []byte(`"total":3,"foreign":true`), 1)} {
		t.Run(name, func(t *testing.T) {
			if e := os.WriteFile(path, body, 0600); e != nil {
				t.Fatal(e)
			}
			if _, accepted := readRecoveredReconstruction(path); accepted != nil {
				t.Fatal("ambiguous original reconstruction accepted")
			}
		})
	}
}

func TestRecoveredHealthDefaultWorkspaceWireRemainsUnextended(t *testing.T) {
	raw, e := json.Marshal(workspaceBundle{SchemaVersion: "1"})
	if e != nil || bytes.Contains(raw, []byte("health_activation_sha256")) || bytes.Contains(raw, []byte("health_private_sha256")) {
		t.Fatal("default033 immutable bundle wire was extended")
	}
	var defaultBody map[string]json.RawMessage
	if json.Unmarshal(raw, &defaultBody) != nil {
		t.Fatal("default bundle invalid")
	}
	var extended workspaceBundle
	if json.Unmarshal(raw, &extended) != nil {
		t.Fatal("existing bundle no longer decodes")
	}
	extended.HealthActivationSHA256 = strings.Repeat("a", 64)
	extended.HealthPrivateSHA256 = strings.Repeat("b", 64)
	raw, e = json.Marshal(extended)
	if e != nil {
		t.Fatal(e)
	}
	var newBody map[string]json.RawMessage
	_ = json.Unmarshal(raw, &newBody)
	delete(newBody, "health_activation_sha256")
	delete(newBody, "health_private_sha256")
	left, _ := json.Marshal(defaultBody)
	right, _ := json.Marshal(newBody)
	if !bytes.Equal(left, right) {
		t.Fatal("opt-in health metadata changed original033 fields")
	}
}

func TestRecoveredHealthObserverEnvironmentCarriesNoAmbientAuthority(t *testing.T) {
	for _, key := range []string{"TEST_DATABASE_URL", "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DOCKER_HOST", "FLEET_CONNECTED_S3_SECRET", "SIGNING_PRIVATE_KEY"} {
		t.Setenv(key, "must-not-be-inherited")
	}
	environment := recoveredObserverEnvironment("/tmp/recovered-observer-test/observer-config.json")
	if len(environment) != 5 {
		t.Fatal("observer environment widened")
	}
	for _, entry := range environment {
		if strings.Contains(entry, "must-not-be-inherited") || strings.Contains(entry, "PRIVATE_KEY=") || strings.Contains(entry, "DATABASE_URL=") || strings.Contains(entry, "AWS_") {
			t.Fatal("observer inherited unrelated authority")
		}
	}
	// The helper does not mutate the coordinator's environment as a side effect.
	if os.Getenv("TEST_DATABASE_URL") != "must-not-be-inherited" {
		t.Fatal("coordinator environment changed")
	}
}

func TestRecoveredHealthOutcomeTransportKeepsExactSignatureAndDistinctArchiveHash(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	body := store.GroupRecoveryHealthOutcome{SchemaVersion: "1", ID: "outcome", TenantID: "tenant", ChainID: "chain", AttemptID: "attempt", ObserverID: "observer", Status: "ABANDONED", ObservationIDs: []string{"measured-observation"}}
	envelope, e := store.SignGroupRecoveryHealthOutcome(body, key)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(envelope)
	reference := ff.ArtifactReference{ID: "archive", SHA256: g.BytesDigest(raw), SizeBytes: int64(len(raw))}
	result := recoveredAttemptResult(store.GroupRecoveryHealthAttempt{ID: "attempt"}, recoveredObserverRun{Envelope: envelope, OutcomeReference: reference}, nil)
	sig, e := base64.StdEncoding.DecodeString(result.Signature)
	message := append([]byte("finops/group-fixture/recovery-health-outcome/v1\x00"), []byte(result.OutcomeCanonicalJSON)...)
	if e != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), message, sig) {
		t.Fatal("public outcome transport changed signed canonical bytes")
	}
	if result.OutcomeReference.SHA256 == g.BytesDigest([]byte(result.OutcomeCanonicalJSON)) || result.OutcomeReference.SHA256 != g.BytesDigest(raw) {
		t.Fatal("outcome body was confused with archived signed envelope")
	}
	if ed25519.Verify(key.Public().(ed25519.PublicKey), append(message, ' '), sig) {
		t.Fatal("altered canonical bytes retained signature")
	}
}
