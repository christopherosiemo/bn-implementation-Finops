package groupfixtureproducer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

// Signature/provenance algebra only. There is no native CLI, PG authority or
// physical worker-retirement claim in this synthetic typed-terminal fixture.
func reconstructionTerminalUnit(t *testing.T) (*reconstructionUnit, *healthAnchorUnit, NativeTerminalEnvelope) {
	t.Helper()
	h := newReconstructionUnit(t)
	q := &healthAnchorUnit{now: h.now, a: h.a, signer: h.signer, pipeline: h.pipeline, ledger: h.ledger, controller: h.controller, view: h.s.View, prepared: h.s.Prepared, keys: h.s.Keys, selected: h.s.Selected}
	q.forward(t, 1)
	c := q.forward(t, 2)
	applied := q.view.Records[len(q.view.Records)-1].Receipt.Receipt
	var e error
	full := q.view
	q.view, _, e = g.SealJournalView(q.view.Parent, q.view.Authorization, q.view.Records[:len(q.view.Records)-1], q.keys, q.ledger, q.now)
	if e != nil {
		t.Fatal(e)
	}
	h.s.Mode = ReconstructionObservation
	h.s.View = q.view
	h.s.ExpectedHead = q.view.Head.Head.Ref
	h.s.CurrentHeadSHA256 = g.Digest(q.view.Head)
	h.s.CommandID = c.ID
	reference := func(kind, id, sha string) ff.ArtifactReference {
		b, e := bindingFor(h.s.Selected, id, kind, sha, 1)
		if e != nil {
			t.Fatal(e)
		}
		return ff.ArtifactReference{ID: id, Bucket: "fixture-artifacts", Key: archiveObjectKey(b), VersionID: "pinned-version", SHA256: sha, SizeBytes: 1}
	}
	a := c.Forward.Child.Artifact
	h.s.References = NativeReconstructionRefs{Review: reference("NATIVE_ARTIFACT_REVIEW", a.Receipt.ID, a.Receipt.SHA256), Capture: reference("NATIVE_CAPTURE", "capture-unit", strings.Repeat("b", 64)), After: reference("AFTER_NATIVE_STATE", "after-unit", applied.After.StateSHA256)}
	terminal := NativeTerminal{SchemaVersion: "1", ID: "positive-terminal-unit", TenantID: h.s.Selected.Binding.Old.Target.TenantID, ChainID: h.s.ChainID, ProgramSHA256: g.Digest(full.Parent.Program), AuthorizationSHA256: g.Digest(full.Authorization), CommandSHA256: g.Digest(c), OperationID: c.OperationID, Fence: c.Fence, ArtifactSHA256: g.Digest(a), PreparationSHA256: g.Digest(c.Preparation), Workspace: h.s.Workspace, References: h.s.References, Before: c.Before, After: applied.After, Head: q.view.Head, ObservedAt: q.now}
	envelope := NativeTerminalEnvelope{Terminal: terminal, Algorithm: nativeReconstructionAlgorithm}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(h.pipeline, reconstructionMessage(nativeTerminalDomain, terminal)))
	h.now = q.now
	if e = ValidateNativeTerminal(h.s, envelope, h.now); e != nil {
		t.Fatal("positive issued-intent terminal", e)
	}
	q.view = full
	return h, q, envelope
}
func signTerminalUnit(e NativeTerminalEnvelope, key ed25519.PrivateKey) NativeTerminalEnvelope {
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, reconstructionMessage(nativeTerminalDomain, e.Terminal)))
	return e
}

func TestNativeTerminalPositiveUnknownAndHistoricalAppliedFacts(t *testing.T) {
	h, q, terminal := reconstructionTerminalUnit(t)
	// UNKNOWN is retained duty. Only an independently issued positive terminal
	// can reconcile it; missing terminal never implies NOT_APPLIED.
	pending := q.view
	last := pending.Records[len(pending.Records)-1]
	pending.Records = pending.Records[:len(pending.Records)-1]
	q.view = pending
	q.renew(t, h.now)
	c := q.projection(t).Pending.Command
	q.receipt(t, g.JournalUnknown, c.Before, c.Before)
	h.s.View = q.view
	h.s.ExpectedHead = q.view.Head.Head.Ref
	h.s.CurrentHeadSHA256 = g.Digest(q.view.Head)
	if e := ValidateNativeTerminal(h.s, terminal, q.now); e != nil {
		t.Fatal("positive terminal could not reconcile UNKNOWN", e)
	}
	if e := ValidateNativeTerminal(h.s, NativeTerminalEnvelope{}, q.now); e == nil {
		t.Fatal("missing positive terminal became success")
	}
	fact := last.Receipt.Receipt
	fact.ID += "-positive-terminal"
	fact.IdempotencyKey += "-positive-terminal"
	factual, e := g.SignJournalReceipt(fact, h.pipeline)
	if e != nil {
		t.Fatal(e)
	}
	q.append(t, g.JournalRecord{Kind: g.JournalApplied, Receipt: &factual})
	q.renew(t, q.view.Parent.Program.ExpiresAt.Add(time.Hour))
	h.s.View = q.view
	h.s.ExpectedHead = q.view.Head.Head.Ref
	h.s.CurrentHeadSHA256 = g.Digest(q.view.Head)
	h.s.Mode = ReconstructionTerminal
	old := h.s.Workspace
	h.s.Workspace = NativeWorkspace{Generation: "replacement-generation", RuntimeID: strings.Repeat("f", 64), ImageSHA256: old.ImageSHA256}
	retirement, e := SignNativeRetirement(NativeWorkspaceRetirement{SchemaVersion: "1", ID: "removed-original-unit", TenantID: h.s.Selected.Binding.Old.Target.TenantID, ChainID: h.s.ChainID, ProgramSHA256: g.Digest(q.view.Parent.Program), Method: "OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED", Old: old, New: h.s.Workspace, ObservedAt: h.now.Add(time.Second)}, h.controller)
	if e != nil {
		t.Fatal(e)
	}
	h.s.Retirement = &retirement
	raw, _ := json.Marshal(terminal)
	h.s.TerminalRef, e = h.a.Put(t.Context(), h.s.Selected, "NATIVE_OPERATION_PROOF", raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateNativeTerminal(h.s, terminal, q.now); e != nil {
		t.Fatal("historical owned fact erased by forward expiry", e)
	}
	// A second loss has no positive terminal from generation1. Never reuse
	// generation0's native fact by weakening exact retirement.Old equality.
	repeated := h.s
	repeated.Workspace.Generation = "second-replacement"
	repeated.Workspace.RuntimeID = strings.Repeat("e", 64)
	second, e := SignNativeRetirement(NativeWorkspaceRetirement{SchemaVersion: "1", ID: "removed-replacement-unit", TenantID: h.s.Selected.Binding.Old.Target.TenantID, ChainID: h.s.ChainID, ProgramSHA256: g.Digest(q.view.Parent.Program), Method: "OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED", Old: h.s.Workspace, New: repeated.Workspace, ObservedAt: q.now}, h.controller)
	if e != nil {
		t.Fatal(e)
	}
	repeated.Retirement = &second
	if ValidateNativeTerminal(repeated, terminal, q.now) == nil {
		t.Fatal("old terminal silently renewed across repeated workspace loss")
	}
}

func TestNativeTerminalResignedBindingAndAncestryForgeriesFail(t *testing.T) {
	h, _, terminal := reconstructionTerminalUnit(t)
	for name, mutate := range map[string]func(*NativeTerminal){
		"tenant": func(t *NativeTerminal) { t.TenantID = "foreign" }, "operation": func(t *NativeTerminal) { t.OperationID = "foreign" }, "fence": func(t *NativeTerminal) { t.Fence++ }, "artifact": func(t *NativeTerminal) { t.ArtifactSHA256 = strings.Repeat("e", 64) }, "captureversion": func(t *NativeTerminal) { t.References.Capture.VersionID = "other-version" }, "review": func(t *NativeTerminal) { t.References.Review.ID = "other-review" }, "state": func(t *NativeTerminal) { t.After.StateSHA256 = strings.Repeat("e", 64) }, "lineage": func(t *NativeTerminal) { t.After.StateLineage = "foreign" }, "before": func(t *NativeTerminal) { t.Before.StateSerial++ }, "head": func(t *NativeTerminal) { t.Head.Head.Ref.RecordCount-- }, "observed": func(t *NativeTerminal) { t.ObservedAt = t.ObservedAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := terminal
			mutate(&bad.Terminal)
			bad = signTerminalUnit(bad, h.pipeline)
			if ValidateNativeTerminal(h.s, bad, h.now) == nil {
				t.Fatal("validly signed foreign terminal accepted")
			}
		})
	}
	for _, key := range []ed25519.PrivateKey{h.signer, h.ledger, h.controller} {
		if ValidateNativeTerminal(h.s, signTerminalUnit(terminal, key), h.now) == nil {
			t.Fatal("wrong issuer key accepted")
		}
	}
}

func TestNativeRetirementNodeWireSignatureMatchesGoCanonicalDTO(t *testing.T) {
	// Produced by the reviewed Node host controller using an explicit UNIT-only
	// seed0x44. The production host generates an independent random privatekey.
	raw := []byte(`{"retirement":{"schema_version":"1","id":"111700da-3e4b-4617-b00e-009c29276ee1","tenant_id":"fixture-tenant","chain_id":"connected-chain-21111111-2222-3333-4444-555555555555","program_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","method":"OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED","old":{"generation":"31111111-2222-3333-4444-555555555555","runtime_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","image_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"new":{"generation":"41111111-2222-3333-4444-555555555555","runtime_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","image_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"observed_at":"2026-10-19T06:00:00.12Z"},"algorithm":"Ed25519/group-fixture-native/v1","signature":"r5S9ySguCoLjrfoO+rG8eDQv+WY7fB5eoqRN+7BaCFaipa0VCuv8c/oYhwRiapUCReoe2JDhathRYm3yJ9WpDw=="}`)
	var envelope NativeRetirementEnvelope
	if decodeReconstruction(raw, &envelope) != nil {
		t.Fatal("native controller wire body cannot decode")
	}
	pub, _ := base64.StdEncoding.DecodeString("11l5O7wTooGagnx2rbb7qKSa7gB/SfLQmS2ZuCWtLEg=")
	sig, _ := base64.StdEncoding.DecodeString(envelope.Signature)
	if !ed25519.Verify(ed25519.PublicKey(pub), reconstructionMessage(nativeRetirementDomain, envelope.Retirement), sig) {
		t.Fatal("Node/Go signing domains, JSON order or UTC fractions differ")
	}
	envelope.Retirement.Old.RuntimeID = strings.Repeat("e", 64)
	if ed25519.Verify(ed25519.PublicKey(pub), reconstructionMessage(nativeRetirementDomain, envelope.Retirement), sig) {
		t.Fatal("controller signature failed to pin exact old runtime")
	}
}
