package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"strings"
	"testing"
	"time"
)

// Pure signed-domain algebra and encrypted object doubles, never native CLI or elapsed-time evidence.
type healthAnchorUnit struct {
	now                                  time.Time
	a                                    *EncryptedArchive
	signer, pipeline, ledger, controller ed25519.PrivateKey
	view                                 g.JournalView
	prepared                             ff.Preparation
	keys                                 g.JournalKeys
	selected                             ff.Proposal
}

func healthUnitProof(source, desired []byte, parent string, sequence int) ff.GitProof {
	return ff.GitProof{Revision: g.GitRevision{Commit: fmt.Sprintf("%040x", sequence+100), Tree: fmt.Sprintf("%040x", sequence+200), ConfigurationSHA256: g.BytesDigest(source), DesiredSHA256: g.BytesDigest(desired)}, Configuration: source, DesiredVariables: desired}
}
func newHealthAnchorUnit(t *testing.T) *healthAnchorUnit {
	t.Helper()
	h := &healthAnchorUnit{now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
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
	base := healthUnitProof(source, desired, "", 0)
	p.ArtifactContext.GitCommit, p.ArtifactContext.GitTree, p.ArtifactContext.ConfigurationSHA256 = base.Revision.Commit, base.Revision.Tree, base.Revision.ConfigurationSHA256
	p.Manifest = g.GitManifest{SchemaVersion: "1", Ref: executionRef, Base: base.Revision}
	proofs := []ff.GitProof{}
	prior := base.Revision
	for i, step := range steps {
		step.PredecessorCommit = prior.Commit
		proof := base
		if i > 0 {
			desired, _ := g.GitFixtureDesired(p, step.After)
			proof = healthUnitProof(source, desired, prior.Commit, i)
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
	h.view, h.prepared, h.keys, h.selected = view, prepared, keys, selected
	return h
}

func (h *healthAnchorUnit) append(t *testing.T, r g.JournalRecord) {
	t.Helper()
	// Model immutable persisted bytes, not a pointer to a mutable local command.
	raw, _ := json.Marshal(r)
	var immutable g.JournalRecord
	_ = json.Unmarshal(raw, &immutable)
	r = immutable
	h.now = h.now.Add(time.Second)
	r.Sequence = uint64(len(h.view.Records) + 1)
	r.PreviousSHA256 = h.view.Head.Head.Ref.LastRecordSHA256
	r.RecordedAt = h.now
	records, _, e := g.AppendJournalRecord(h.view, h.keys, h.view.Head.Head.Ref, r, h.now)
	if e != nil {
		t.Fatal(r.Kind, e)
	}
	h.view, _, e = g.SealJournalView(h.view.Parent, h.view.Authorization, records, h.keys, h.ledger, h.now)
	if e != nil {
		t.Fatal(e)
	}
}
func (h *healthAnchorUnit) projection(t *testing.T) g.JournalProjection {
	t.Helper()
	p, e := g.VerifyJournal(h.view, h.keys, h.view.Head.Head.Ref, h.now)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func (h *healthAnchorUnit) receipt(t *testing.T, kind string, before, after g.JournalState) {
	t.Helper()
	p := h.projection(t)
	c := p.Pending.Command
	r := g.JournalReceipt{SchemaVersion: "1", ID: fmt.Sprintf("receipt-%d", len(h.view.Records)+1), IdempotencyKey: fmt.Sprintf("key-%d", len(h.view.Records)+1), JournalID: h.view.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(h.view.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: h.view.Authorization.Authorization.PipelineID, Kind: kind, PreparationSHA256: g.Digest(c.Preparation), Before: before, After: after, ReceivedAt: h.now}
	if a, ok := healthCommandArtifact(c); ok {
		r.ArtifactSHA256 = g.Digest(a)
		r.SavedPlanSHA256 = a.SavedPlanSHA256
	}
	if kind == g.JournalReadyToApply {
		r.ValidUntil = h.now.Add(30 * time.Second)
	}
	env, e := g.SignJournalReceipt(r, h.pipeline)
	if e != nil {
		t.Fatal(e)
	}
	h.append(t, g.JournalRecord{Kind: kind, Receipt: &env})
}
func (h *healthAnchorUnit) complete(t *testing.T, c g.JournalCommand) g.JournalCommand {
	t.Helper()
	h.append(t, g.JournalRecord{Kind: g.JournalReserved, Command: &c})
	gitState := c.Before
	gitState.Revision = c.Preparation.Revision
	h.receipt(t, g.JournalReadyToApply, gitState, gitState)
	h.receipt(t, g.JournalApplyIntent, gitState, gitState)
	a, _ := healthCommandArtifact(c)
	after := gitState
	after.Model = a.After
	if a.Before != a.After {
		after.StateSerial++
		after.StateSHA256 = g.Digest(after.Model)
	}
	h.receipt(t, g.JournalApplied, c.Before, after)
	return c
}
func (h *healthAnchorUnit) forward(t *testing.T, seq uint64) g.JournalCommand {
	t.Helper()
	p := h.projection(t)
	e := h.view.Parent.Program.Manifest.Entries[seq-1]
	id := fmt.Sprintf("command-%d", p.LastFence+1)
	c := g.JournalCommand{ID: id, OperationID: "operation-" + id, IdempotencyKey: "key-" + id, Fence: p.LastFence + 1, Head: h.view.Head, Before: p.Current, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: seq, ManifestEntrySHA256: g.Digest(e), Revision: e.Revision, Before: e.Before, After: e.After}, CreatedAt: h.now}
	h.append(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &c})
	gitState := c.Before
	gitState.Revision = e.Revision
	h.receipt(t, g.JournalGitAdvanced, c.Before, gitState)
	p0 := h.view.Parent.Program
	child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: "child-" + id, ParentID: p0.ID, ParentSHA256: g.Digest(p0), BindingSHA256: g.Digest(p0.Binding), RealmSHA256: g.Digest(p0.Realm), Mode: g.Forward, StageID: e.StageID, StageSHA256: e.StageSHA256, Sequence: seq, Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "artifact-" + id, SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(p0.ArtifactContext), ManifestSHA256: p0.ManifestSHA256, ManifestEntrySHA256: g.Digest(e), PreviousRevision: c.Before.Revision, Revision: e.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: e.Before, After: e.After}, MinimumObservationSeconds: e.MinimumObservationSeconds, CreatedAt: h.now, ExpiresAt: h.now.Add(10 * time.Minute), Nonce: "nonce-" + id}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
		child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: kind + id, SHA256: strings.Repeat("a", 64), BindingSHA256: g.Digest(p0.Binding), RealmSHA256: g.Digest(p0.Realm), ObservedAt: h.now, ValidUntil: h.now.Add(15 * time.Minute)})
	}
	signed, err := g.SignGitChild(child, h.view.Parent, h.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	c.Forward = &signed
	return h.complete(t, c)
}
func (h *healthAnchorUnit) renew(t *testing.T, now time.Time) {
	t.Helper()
	h.now = now
	var e error
	h.view, _, e = g.SealJournalView(h.view.Parent, h.view.Authorization, h.view.Records, h.keys, h.ledger, h.now)
	if e != nil {
		t.Fatal(e)
	}
}
func healthAnchorRows(b HealthBinding, start time.Time, n int) []HealthReceipt {
	out := []HealthReceipt{}
	for i := 0; i < n; i++ {
		r := syntheticHealthReceipt(b, start.Add(time.Duration(i)*time.Minute), time.Minute, 10*time.Millisecond, uint64(i+1), "", uint64(i*40))
		if i > 0 {
			r.Before = out[i-1].After
			r.After.PeakSinceSequence = r.Before.Sequence
			r.PreviousSHA256 = out[i-1].SHA256
		}
		out = append(out, v2HealthReceipt(r, time.Minute))
	}
	return out
}
func (h *healthAnchorUnit) anchor(t *testing.T, b HealthBinding, baseline []HealthReceipt) HealthBaselineAnchorEnvelope {
	t.Helper()
	refs := []HealthBaselineArtifact{}
	for _, r := range baseline {
		raw, _ := json.Marshal(r)
		ref, e := h.a.Put(t.Context(), h.selected, "HEALTH_BASELINE", raw)
		if e != nil {
			t.Fatal(e)
		}
		refs = append(refs, HealthBaselineArtifact{ref, r.After.CapturedAt.Add(time.Nanosecond)})
	}
	a, e := SignHealthBaselineAnchor(h.view, h.keys, h.view.Head.Head.Ref, b, baseline, refs, h.ledger, h.now)
	if e != nil {
		t.Fatal("anchor", e)
	}
	first := a.Anchor.Artifacts[0]
	refs[0].Reference.ID = "mutated-caller-slice"
	if a.Anchor.Artifacts[0] != first {
		t.Fatal("signed anchor aliases mutable caller references")
	}
	return a
}
func TestHealthAnchorRetainsOriginalBaselineAcrossLaterStages(t *testing.T) {
	h := newHealthAnchorUnit(t)
	b := HealthBinding{Binding: h.view.Parent.Program.Binding, Realm: h.view.Parent.Program.Realm, ProgramSHA256: g.Digest(h.view.Parent.Program), CommandID: "stable-health-observer", OperationID: "observer-operation", Fence: 1}
	baseline := healthAnchorRows(b, h.now.Add(-2*time.Minute-time.Second), 2)
	h.forward(t, 1)
	a := h.anchor(t, b, baseline)
	h.forward(t, 2)
	h.renew(t, h.now.Add(time.Hour)) // A genuinely later issued stage, not a refreshed baseline.
	c := h.forward(t, 3)
	start := h.now.Add(time.Second)
	current := healthAnchorRows(b, start, 60)
	h.renew(t, start.Add(time.Hour))
	deployment := ActivatedHealthDeployment{c.ID, c.OperationID, c.Fence, HealthManifestObservation}
	result := EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, a, deployment, b, baseline, current, healthLimits(), h.now)
	if result.Status != "OBSERVED" || !result.RequiredEnd.Equal(start.Add(time.Hour)) {
		t.Fatal("anchored later canary", result.ReasonCodes)
	}
	old := EvaluateManifestHealthWindow(h.view.Parent.Program, h.view.Parent.Program.Manifest.Entries[2], b, start, baseline, current, healthLimits(), h.now)
	if !hasHealthReason(old, "BASELINE_OBSERVATION_STALE") {
		t.Fatal("legacy semantics changed")
	}
	// Raw observer IDs remain stable and are never relabelled to deployment.
	if result.Binding.CommandID == c.ID || a.Anchor.Observer != baseline[0].Binding {
		t.Fatal("observer/deployment authority conflated")
	}
	for name, mutate := range map[string]func(*HealthBaselineAnchorEnvelope, *ActivatedHealthDeployment, *HealthBinding){
		"activation": func(a *HealthBaselineAnchorEnvelope, _ *ActivatedHealthDeployment, _ *HealthBinding) {
			a.Anchor.ActivatedAt = a.Anchor.ActivatedAt.Add(time.Hour)
		},
		"program": func(_ *HealthBaselineAnchorEnvelope, _ *ActivatedHealthDeployment, b *HealthBinding) {
			b.ProgramSHA256 = strings.Repeat("a", 64)
		},
		"realm": func(_ *HealthBaselineAnchorEnvelope, _ *ActivatedHealthDeployment, b *HealthBinding) {
			b.Realm.Generation = "other-generation"
		},
		"deployment": func(_ *HealthBaselineAnchorEnvelope, d *ActivatedHealthDeployment, _ *HealthBinding) {
			d.OperationID = "foreign-operation"
		},
		"fence": func(_ *HealthBaselineAnchorEnvelope, d *ActivatedHealthDeployment, _ *HealthBinding) { d.Fence++ },
		"missing": func(a *HealthBaselineAnchorEnvelope, _ *ActivatedHealthDeployment, _ *HealthBinding) {
			*a = HealthBaselineAnchorEnvelope{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad, dep, bind := a, deployment, b
			mutate(&bad, &dep, &bind)
			if EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, bad, dep, bind, baseline, current, healthLimits(), h.now).Status == "OBSERVED" {
				t.Fatal("forged anchor/stage accepted")
			}
		})
	}
	stale := h.view
	stale.Head.Head.Ref.Version++
	if EvaluateActivatedHealthWindow(stale, h.keys, stale.Head.Head.Ref, a, deployment, b, baseline, current, healthLimits(), h.now).Status != "BLOCKED" {
		t.Fatal("forged current head")
	}
	late := healthAnchorRows(b, start.Add(2*time.Minute), 60)
	h.renew(t, start.Add(62*time.Minute))
	if !hasHealthReason(EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, a, deployment, b, baseline, late, healthLimits(), h.now), "HEALTH_STAGE_INITIAL_COVERAGE_UNKNOWN") {
		t.Fatal("unobserved initial deployment gap accepted")
	}
}

func (h *healthAnchorUnit) inverse(t *testing.T) g.JournalCommand {
	t.Helper()
	p := h.projection(t)
	top := p.Stack[len(p.Stack)-1]
	program := h.view.Parent.Program
	before := p.Current
	desired, _ := g.GitFixtureDesired(program, top.Forward.Child.Artifact.Before)
	rev := g.GitRevision{Commit: fmt.Sprintf("%040x", p.LastFence+500), Tree: fmt.Sprintf("%040x", p.LastFence+600), ConfigurationSHA256: before.Revision.ConfigurationSHA256, DesiredSHA256: g.BytesDigest(desired)}
	id := fmt.Sprintf("inverse-%d", p.LastFence+1)
	c := g.JournalCommand{ID: id, OperationID: "operation-" + id, IdempotencyKey: "key-" + id, Fence: p.LastFence + 1, Head: h.view.Head, Before: before, Preparation: g.JournalPreparation{Mode: g.JournalRecoveryMode, EffectID: top.ID, Revision: rev, Before: before.Model, After: top.Forward.Child.Artifact.Before}, CreatedAt: h.now}
	h.append(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &c})
	gitState := before
	gitState.Revision = rev
	h.receipt(t, g.JournalGitAdvanced, before, gitState)
	r := g.JournalRecovery{SchemaVersion: "1", ID: "recovery-" + id, CommandID: id, JournalID: h.view.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(h.view.Authorization), ParentEnvelopeSHA256: g.Digest(h.view.Parent), PreparationHeadSHA256: g.Digest(c.Head), SigningHeadSHA256: g.Digest(h.view.Head), EffectID: top.ID, OriginalChildSHA256: g.Digest(top.Forward.Child), OriginalReceiptSHA256: g.Digest(top.Applied), Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "artifact-" + id, SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(program.ArtifactContext), ManifestSHA256: program.ManifestSHA256, PreviousRevision: before.Revision, Revision: rev, BeforeStateSerial: before.StateSerial, BeforeStateSHA256: before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: before.Model, After: c.Preparation.After}, MinimumObservationSeconds: 120, CreatedAt: h.now, ExpiresAt: h.now.Add(10 * time.Minute), Nonce: "nonce-" + id}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
		r.Evidence = append(r.Evidence, g.EvidenceRef{Kind: kind, ID: kind + id, SHA256: strings.Repeat("a", 64), BindingSHA256: g.Digest(program.Binding), RealmSHA256: g.Digest(program.Realm), ObservedAt: h.now, ValidUntil: h.now.Add(15 * time.Minute)})
	}
	signed, e := g.SignJournalRecovery(r, h.view, h.keys, h.view.Head.Head.Ref, h.signer, h.now)
	if e != nil {
		t.Fatal(e)
	}
	c.Recovery = &signed
	return h.complete(t, c)
}
func TestHealthAnchorOwnedRecoveryAfterParentExpiryKeepsFrozenBaseline(t *testing.T) {
	h := newHealthAnchorUnit(t)
	b := HealthBinding{Binding: h.view.Parent.Program.Binding, Realm: h.view.Parent.Program.Realm, ProgramSHA256: g.Digest(h.view.Parent.Program), CommandID: "observer", OperationID: "observer-op", Fence: 1}
	baseline := healthAnchorRows(b, h.now.Add(-2*time.Minute-time.Second), 2)
	h.forward(t, 1)
	a := h.anchor(t, b, baseline)
	h.forward(t, 2)
	h.renew(t, h.view.Parent.Program.ExpiresAt.Add(time.Hour))
	c := h.inverse(t)
	start := h.now.Add(time.Second)
	current := healthAnchorRows(b, start, 15)
	h.renew(t, start.Add(15*time.Minute))
	d := ActivatedHealthDeployment{c.ID, c.OperationID, c.Fence, HealthRestorationObservation}
	result := EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, a, d, b, baseline, current, healthLimits(), h.now)
	if result.Status != "OBSERVED" || result.RequiredEnd.Sub(result.Start) != 15*time.Minute {
		t.Fatal("owned terminal after expiry", result.ReasonCodes)
	}
	// A new retry is a distinct full900s population, never a tail subset.
	short := current[1:]
	if EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, a, d, b, baseline, short, healthLimits(), h.now).Status == "OBSERVED" {
		t.Fatal("discarded failed tail shortened terminal")
	}
	raw, _ := json.Marshal(baseline)
	var changed []HealthReceipt
	_ = json.Unmarshal(raw, &changed)
	changed[0].Observations[0].ElapsedNS++
	changed[0].SHA256 = HealthReceiptSHA256(changed[0])
	if EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, a, d, b, changed, current, healthLimits(), h.now).Status != "BLOCKED" {
		t.Fatal("baseline relearned")
	}
	if EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, a, d, b, baseline, current, healthLimits(), h.now.Add(2*time.Minute)).Status != "BLOCKED" {
		t.Fatal("stale current observations revived")
	}
}

func TestHealthAnchorRefusesResignedFalseActivationAndForeignReceiptScope(t *testing.T) {
	h := newHealthAnchorUnit(t)
	b := HealthBinding{Binding: h.view.Parent.Program.Binding, Realm: h.view.Parent.Program.Realm, ProgramSHA256: g.Digest(h.view.Parent.Program), CommandID: "observer", OperationID: "observer-op", Fence: 1}
	baseline := healthAnchorRows(b, h.now.Add(-2*time.Minute-time.Second), 2)
	if _, e := SignHealthBaselineAnchor(h.view, h.keys, h.view.Head.Head.Ref, b, baseline, nil, h.ledger, h.now); e == nil {
		t.Fatal("caller activation without actual dispatch")
	}
	h.forward(t, 1)
	a := h.anchor(t, b, baseline)
	c := h.forward(t, 2)
	start := h.now.Add(time.Second)
	current := healthAnchorRows(b, start, 2)
	h.renew(t, start.Add(2*time.Minute))
	d := ActivatedHealthDeployment{c.ID, c.OperationID, c.Fence, HealthManifestObservation}
	bad := a
	bad.Anchor.ActivatedAt = bad.Anchor.ActivatedAt.Add(time.Second)
	bad.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(h.ledger, healthAnchorMessage(bad.Anchor)))
	if EvaluateActivatedHealthWindow(h.view, h.keys, h.view.Head.Head.Ref, bad, d, b, baseline, current, healthLimits(), h.now).Status != "BLOCKED" {
		t.Fatal("valid signature blessed caller activation time")
	}
	for _, bind := range []HealthBinding{func() HealthBinding { x := b; x.ProgramSHA256 = strings.Repeat("f", 64); return x }(), func() HealthBinding { x := b; x.Realm.Generation = "foreign"; return x }(), func() HealthBinding { x := b; x.Binding.Old.Target.WorkloadID = "foreign"; return x }()} {
		rows := healthAnchorRows(bind, baseline[0].Before.CapturedAt, 2)
		if _, e := SignHealthBaselineAnchor(h.view, h.keys, h.view.Head.Head.Ref, bind, rows, a.Anchor.Artifacts, h.ledger, h.now); e == nil {
			t.Fatal("ledger blessed foreign program/realm/workload receipts")
		}
	}
	refs := append([]HealthBaselineArtifact{}, a.Anchor.Artifacts...)
	refs[0].IssuedAt = a.Anchor.ActivatedAt.Add(time.Second)
	if _, e := SignHealthBaselineAnchor(h.view, h.keys, h.view.Head.Head.Ref, b, baseline, refs, h.ledger, h.now); e == nil {
		t.Fatal("post-activation receipt publication accepted as frozen baseline")
	}
}
