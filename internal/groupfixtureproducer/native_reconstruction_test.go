package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

// This is explicitly synthetic domain/AEAD fixture evidence. It is not the
// separate actual Git/TF/PG/container-removal acceptance.
type reconstructionUnit struct {
	s                                    NativeReconstructionSnapshot
	a                                    *EncryptedArchive
	now                                  time.Time
	signer, pipeline, ledger, controller ed25519.PrivateKey
}

func reconstructionUnitProof(source, desired []byte, parent string, sequence int) ff.GitProof {
	tree := []byte{}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{g.GitDesiredPath, desired}, {g.GitMainPath, source}} {
		oid, _ := hex.DecodeString(reconstructionOID("blob", file.raw, 40))
		tree = append(tree, []byte("100644 "+file.name+"\x00")...)
		tree = append(tree, oid...)
	}
	head := "tree " + reconstructionOID("tree", tree, 40) + "\n"
	if parent != "" {
		head += "parent " + parent + "\n"
	}
	head += "author Unit <unit@example.invalid> 1792411200 +0000\ncommitter Unit <unit@example.invalid> 1792411200 +0000\n\nSynthetic reconstruction unit " + fmt.Sprint(sequence) + "\n"
	commit := []byte(head)
	r := g.GitRevision{Commit: reconstructionOID("commit", commit, 40), Tree: reconstructionOID("tree", tree, 40), ConfigurationSHA256: g.BytesDigest(source), DesiredSHA256: g.BytesDigest(desired)}
	return ff.GitProof{Revision: r, CommitObject: commit, TreeObject: tree, Configuration: source, DesiredVariables: desired}
}
func newReconstructionUnit(t *testing.T) *reconstructionUnit {
	t.Helper()
	h := &reconstructionUnit{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	h.a, _ = newArchiveTest(t)
	key := func(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
	h.signer, h.pipeline, h.ledger, h.controller = key(31), key(32), key(33), key(34)
	selected := archiveSelection()
	selected.CreatorID = "unit-creator"
	selected.Profile.Installation.TerraformVersion = "1.16.0"
	model := ff.Model{OldTemplate: g.Template{ID: "lt-12345678", Version: 1, InstanceType: "m6i.large", SHA256: strings.Repeat("a", 64)}, CandidateTemplate: g.Template{ID: "lt-87654321", Version: 1, InstanceType: "m6i.medium", SHA256: strings.Repeat("b", 64)}, Budget: g.ModelBudget{CostBasis: g.FixtureModelCost, Currency: "USD", BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 0, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, OldHourlyCost: "0.5", CandidateHourlyCost: "0.3", MaximumModelCost: "100", MaximumDurationSeconds: 6 * 3600}, Policy: g.Policy{ID: "unit-policy", Version: 1, SHA256: strings.Repeat("c", 64), ApproverRole: g.ApproverRole}}
	selected.Profile.Model = model
	p := g.GitProgram{SchemaVersion: g.GitSchemaVersion, Kind: g.Kind, ID: "unit-reconstruction", Binding: selected.Binding, Realm: selected.Realm, CreatorID: selected.CreatorID, Environment: "NON_PRODUCTION", Policy: model.Policy, OldTemplate: model.OldTemplate, CandidateTemplate: model.CandidateTemplate, Budget: model.Budget, Stages: g.DefaultStages(20), CreatedAt: h.now, ExpiresAt: h.now.Add(8 * time.Hour), Nonce: "unit-parent-nonce"}
	p.ArtifactContext = g.ArtifactContext{Kind: g.BuiltinFixtureArtifact, ProviderSource: g.BuiltinProvider, RepositoryID: selected.ID, GitCommit: strings.Repeat("a", 40), GitTree: strings.Repeat("b", 40), ConfigurationSHA256: strings.Repeat("c", 64), ToolchainImageSHA256: selected.Profile.Installation.ToolchainImageSHA256, TerraformVersion: "1.16.0", PipelineID: "unit-pipeline", Workspace: "default", StateLineage: "11111111-2222-3333-4444-555555555555", InitialStateSerial: 1, Mapping: g.ModelMapping{OldDeclaredASG: "aws_autoscaling_group.old", CandidateDeclaredASG: "aws_autoscaling_group.candidate", DeclaredListenerRule: "aws_lb_listener_rule.workload", OldModel: "terraform_data.old", CandidateModel: "terraform_data.candidate", TrafficModel: "terraform_data.traffic"}}
	steps, e := g.GitStageSpecifications(p)
	if e != nil {
		t.Fatal(e)
	}
	source, e := g.GitFixtureConfiguration(p)
	if e != nil {
		t.Fatal(e)
	}
	desired, _ := g.GitFixtureDesired(p, steps[0].Before)
	base := reconstructionUnitProof(source, desired, "", 0)
	p.ArtifactContext.GitCommit, p.ArtifactContext.GitTree, p.ArtifactContext.ConfigurationSHA256 = base.Revision.Commit, base.Revision.Tree, base.Revision.ConfigurationSHA256
	p.Manifest = g.GitManifest{SchemaVersion: "1", Ref: executionRef, Base: base.Revision}
	proofs := []ff.GitProof{}
	prior := base.Revision
	for i, step := range steps {
		step.PredecessorCommit = prior.Commit
		proof := base
		if i > 0 {
			desired, _ := g.GitFixtureDesired(p, step.After)
			proof = reconstructionUnitProof(source, desired, prior.Commit, i)
		}
		step.Revision = proof.Revision
		p.Manifest.Entries = append(p.Manifest.Entries, step)
		proofs = append(proofs, proof)
		prior = proof.Revision
	}
	p.ManifestSHA256 = g.Digest(p.Manifest)
	refs := []ff.ArtifactReference{}
	put := func(kind string, raw []byte) ff.ArtifactReference {
		r, e := h.a.Put(context.Background(), selected, kind, raw)
		if e != nil {
			t.Fatal(e)
		}
		refs = append(refs, r)
		return r
	}
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		r := put(kind, []byte("synthetic unit "+kind))
		p.Evidence = append(p.Evidence, g.EvidenceRef{Kind: kind, ID: r.ID, SHA256: r.SHA256, BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: h.now, ValidUntil: p.ExpiresAt})
	}
	inputs, e := g.GitFixtureInputs(p, steps[0].Before)
	if e != nil {
		t.Fatal(e)
	}
	resources := []any{}
	for _, name := range []string{"old", "candidate", "traffic"} {
		resources = append(resources, map[string]any{"mode": "managed", "type": "terraform_data", "name": name, "instances": []any{map[string]any{"attributes": map[string]any{"id": "unit-" + name, "input": map[string]any{"value": inputs["terraform_data."+name]}}}}})
	}
	stateRaw, _ := json.Marshal(map[string]any{"version": 4, "terraform_version": "1.16.0", "serial": 1, "lineage": p.ArtifactContext.StateLineage, "resources": resources})
	baseState, e := baseState(stateRaw, p, steps[0].Before)
	if e != nil {
		t.Fatal(e)
	}
	proofRaw, _ := ff.ProofBytes(proofs)
	put("GIT_PROOF_SET", proofRaw)
	put("BASE_NATIVE_STATE", stateRaw)
	keys := g.JournalKeys{Signer: h.signer.Public().(ed25519.PublicKey), Pipeline: h.pipeline.Public().(ed25519.PublicKey), Ledger: h.ledger.Public().(ed25519.PublicKey)}
	prepared := ff.Preparation{Program: p, GitProofs: proofs, Artifacts: refs, JournalReview: ff.JournalReview{SchemaVersion: "1", Policy: p.Policy, Ref: p.Manifest.Ref, PipelineID: p.ArtifactContext.PipelineID, PipelineKeySHA256: g.BytesDigest(keys.Pipeline), LedgerKeySHA256: g.BytesDigest(keys.Ledger), Base: baseState, MaxEffects: 32, MaxRecords: 512, ExpiresAt: p.ExpiresAt}}
	parent, e := g.SignGitProgram(p, []g.Approval{{ID: "unit-parent-approval", TenantID: p.Binding.Old.Target.TenantID, ActorID: "unit-approver", Role: g.ApproverRole, ProgramSHA256: g.Digest(p), RealmSHA256: g.Digest(p.Realm), ApprovedAt: h.now}}, h.signer, h.now)
	if e != nil {
		t.Fatal(e)
	}
	auth := g.JournalAuthorization{SchemaVersion: g.JournalSchemaVersion, Kind: g.JournalKind, ID: "unit-journal-auth", JournalID: "unit-journal", ParentEnvelopeSHA256: g.Digest(parent), ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), PipelineID: p.ArtifactContext.PipelineID, Ref: p.Manifest.Ref, Policy: g.JournalPolicy, Base: baseState, PipelineKeySHA256: g.BytesDigest(keys.Pipeline), LedgerKeySHA256: g.BytesDigest(keys.Ledger), MaximumEffects: 32, MaximumRecords: 512, CreatedAt: h.now, ExpiresAt: p.ExpiresAt, Nonce: "unit-auth-nonce"}
	env, e := g.SignJournalAuthorization(auth, []g.JournalApproval{{ID: "unit-journal-approval", TenantID: p.Binding.Old.Target.TenantID, ActorID: "unit-independent", Role: g.ApproverRole, AuthorizationSHA256: g.Digest(auth), ApprovedAt: h.now}}, parent, keys, h.signer, h.now)
	if e != nil {
		t.Fatal(e)
	}
	view, _, e := g.SealJournalView(parent, env, nil, keys, h.ledger, h.now)
	if e != nil {
		t.Fatal(e)
	}
	h.s = NativeReconstructionSnapshot{Kind: ReconstructionOriginal, Mode: ReconstructionInitial, ChainID: "unit-chain", Selected: selected, Prepared: prepared, View: view, Keys: keys, ExpectedHead: view.Head.Head.Ref, CurrentHeadSHA256: g.Digest(view.Head), Workspace: NativeWorkspace{Generation: "new-workspace", RuntimeID: strings.Repeat("d", 64), ImageSHA256: selected.Profile.Installation.ToolchainImageSHA256}, RetirementKey: h.controller.Public().(ed25519.PublicKey)}
	return h
}

func TestNativeReconstructionInitialIsActualZeroHeadNotUnknownFallback(t *testing.T) {
	h := newReconstructionUnit(t)
	m, e := reconstructionMaterializeInput(t.Context(), h.a, h.s, h.now)
	if e != nil || m.current != h.s.Prepared.JournalReview.Base || len(m.state) == 0 || len(m.objects) < 26 {
		t.Fatal("exact initial material unavailable", e)
	}
	for _, mutate := range []func(*NativeReconstructionSnapshot){func(s *NativeReconstructionSnapshot) { s.Kind = ReconstructionRecoverySegment }, func(s *NativeReconstructionSnapshot) { s.CurrentHeadSHA256 = strings.Repeat("a", 64) }, func(s *NativeReconstructionSnapshot) { s.Workspace.ImageSHA256 = strings.Repeat("f", 64) }, func(s *NativeReconstructionSnapshot) { s.ExpectedHead.Version++ }, func(s *NativeReconstructionSnapshot) { s.TerminalRef.ID = "caller-terminal" }} {
		s := h.s
		mutate(&s)
		if _, e := reconstructionMaterializeInput(t.Context(), h.a, s, h.now); e == nil {
			t.Fatal("changed boundary materialized")
		}
	}
	s := h.s
	s.Mode = ReconstructionTerminal
	s.CommandID = "unknown-command"
	if _, e := reconstructionMaterializeInput(t.Context(), h.a, s, h.now); !errors.Is(e, ErrUncertain) {
		t.Fatal("missing terminal became historical Before", e)
	}
	s = h.s
	s.Prepared.Artifacts = append([]ff.ArtifactReference{}, s.Prepared.Artifacts...)
	s.Prepared.Artifacts[0].VersionID = "wrong-version"
	if _, e := reconstructionMaterializeInput(t.Context(), h.a, s, h.now); e == nil {
		t.Fatal("wrong archived version materialized")
	}
}

func TestNativeWorkspaceRetirementRequiresSeparateExactControllerProof(t *testing.T) {
	h := newReconstructionUnit(t)
	old := NativeWorkspace{Generation: "old-generation", RuntimeID: strings.Repeat("e", 64), ImageSHA256: h.s.Workspace.ImageSHA256}
	terminal := NativeTerminal{Workspace: old, ObservedAt: h.now}
	r := NativeWorkspaceRetirement{SchemaVersion: "1", ID: "unit-removal", TenantID: h.s.Selected.Binding.Old.Target.TenantID, ChainID: h.s.ChainID, ProgramSHA256: g.Digest(h.s.View.Parent.Program), Method: "OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED", Old: old, New: h.s.Workspace, ObservedAt: h.now.Add(time.Second)}
	envelope, e := SignNativeRetirement(r, h.controller)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifyNativeRetirement(envelope, h.s.RetirementKey, h.s, terminal, h.now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*NativeRetirementEnvelope){func(e *NativeRetirementEnvelope) { e.Retirement.Old.RuntimeID = strings.Repeat("a", 64) }, func(e *NativeRetirementEnvelope) { e.Retirement.New.Generation = "other" }, func(e *NativeRetirementEnvelope) { e.Retirement.TenantID = "other-tenant" }, func(e *NativeRetirementEnvelope) { e.Retirement.Method = "LEASE_EXPIRED" }, func(e *NativeRetirementEnvelope) { e.Retirement.ObservedAt = h.now.Add(-time.Second) }, func(e *NativeRetirementEnvelope) { e.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) }} {
		bad := envelope
		mutate(&bad)
		if verifyNativeRetirement(bad, h.s.RetirementKey, h.s, terminal, h.now.Add(2*time.Second)) == nil {
			t.Fatal("unrelated retirement proof accepted")
		}
	}
	for _, key := range []ed25519.PublicKey{h.s.Keys.Pipeline, h.s.Keys.Signer, h.s.Keys.Ledger, nil} {
		if verifyNativeRetirement(envelope, key, h.s, terminal, h.now.Add(2*time.Second)) == nil {
			t.Fatal("pipeline or missing key became retirement controller")
		}
	}
}

func TestNativeReconstructionStrictDecodeAndAncestry(t *testing.T) {
	var out NativeTerminalEnvelope
	for _, raw := range []string{`{"terminal":{},"terminal":{}}`, `{"terminal":{},"unexpected":true}`, `{} {}`, `{"terminal":{"schema_version":"1","schema_version":"1"}}`} {
		if decodeReconstruction([]byte(raw), &out) == nil {
			t.Fatal("ambiguous terminal body accepted")
		}
	}
	h := newReconstructionUnit(t)
	m, e := reconstructionMaterializeInput(t.Context(), h.a, h.s, h.now)
	if e != nil {
		t.Fatal(e)
	}
	base := h.s.Prepared.Program.Manifest.Base.Commit
	m.current.Revision = h.s.Prepared.Program.Manifest.Entries[2].Revision
	if e = m.ancestry(base); e != nil {
		t.Fatal("complete approved ancestry unavailable", e)
	}
	delete(m.objects, h.s.Prepared.Program.Manifest.Entries[1].Revision.Commit)
	if e = m.ancestry(base); !errors.Is(e, ErrUncertain) {
		t.Fatal("missing ancestor silently bridged", e)
	}
}
