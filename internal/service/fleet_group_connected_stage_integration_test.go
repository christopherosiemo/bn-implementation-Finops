package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// These private references are observations, never approvals. Every selected
// ref is persisted by the commissioned pipeline before the ledger uses it.
type connectedStageArtifacts struct {
	h        *connectedJournal
	selected ff.Proposal
	archive  *groupfixtureproducer.EncryptedArchive
	prepared ff.Preparation
	metadata []model.Document
}

func (a *connectedStageArtifacts) retain(t *testing.T, ctx context.Context, command, kind string, ref ff.ArtifactReference) {
	t.Helper()
	plain, err := a.archive.Read(ctx, a.selected, kind, ref)
	if err != nil || g.BytesDigest(plain) != ref.SHA256 {
		t.Fatal("native immutable artifact readback", err)
	}
	if err = a.h.pipeline.Do(ctx, a.h.f.tenant, func(tx *store.Tx) error {
		_, _, e := tx.GroupArtifactAppend(ctx, a.h.bootstrap.ChainID, command, kind, store.FleetGroupPipelineIdentity{SourceID: "connected-machine", Issuer: "https://connected-machine.invalid", Subject: "connected-pipeline", Audience: "finops-group-pipeline"}, ref)
		return e
	}); err != nil {
		t.Fatal("pipeline artifact pin", kind, err)
	}
	object, err := a.archive.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(ref.Bucket), Key: aws.String(ref.Key), VersionId: aws.String(ref.VersionID)})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := io.ReadAll(io.LimitReader(object.Body, (24<<20)+1))
	_ = object.Body.Close()
	if err != nil || len(cipher) > 24<<20 || bytes.Contains(cipher, plain) {
		t.Fatal("native ciphertext retention invalid")
	}
	for _, d := range a.metadata {
		if model.String(d, "id") == ref.ID {
			if model.String(d, "plain_sha256") != ref.SHA256 {
				t.Fatal("artifact identity changed")
			}
			return
		}
	}
	name := ref.ID + ".ciphertext.json"
	if err = os.WriteFile(filepath.Join("/results", name), cipher, 0600); err != nil {
		t.Fatal(err)
	}
	a.metadata = append(a.metadata, model.Document{"id": ref.ID, "kind": kind, "plain_sha256": ref.SHA256, "plain_size": ref.SizeBytes, "cipher_sha256": g.BytesDigest(cipher), "cipher_size": len(cipher), "file": name, "version_id": ref.VersionID})
}

func (a *connectedStageArtifacts) put(t *testing.T, ctx context.Context, command, kind string, body any) ff.ArtifactReference {
	t.Helper()
	raw, ok := body.([]byte)
	if !ok {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	ref, err := a.archive.Put(ctx, a.selected, kind, raw)
	if err != nil {
		t.Fatal("native archive publication", kind, err)
	}
	a.retain(t, ctx, command, kind, ref)
	return ref
}

func (a *connectedStageArtifacts) evidence(t *testing.T, ctx context.Context, native *groupfixtureproducer.NativeStage, slo any) []g.EvidenceRef {
	t.Helper()
	p := a.h.refresh(t, ctx)
	if p.Pending == nil {
		t.Fatal("current evidence command missing")
	}
	c := p.Pending.Command
	expected := c.Before
	expected.Revision = c.Preparation.Revision
	actual, err := native.Inspect(ctx, expected.Revision, expected.Model)
	if err != nil || actual != expected {
		t.Fatal("current native evidence", err)
	}
	now := time.Now().UTC()
	current := a.put(t, ctx, c.ID, "FIXTURE_CURRENT", model.Document{"schema_version": "1", "realm": "ISOLATED_FIXTURE", "observed_at": now, "command_id": c.ID, "operation_id": c.OperationID, "fence": c.Fence, "cursor": a.h.cursor, "native": actual, "customer_interval_authority": false})
	kinds := []string{"FIXTURE_CURRENT"}
	refs := []ff.ArtifactReference{current}
	if c.Preparation.Mode == g.Forward {
		// The exact current selection/source guard is rechecked under the
		// repository fence. Declared customer topology stays unproved.
		if err = a.h.nativeFence(ctx, func(g.JournalView, g.JournalKeys) error { return nil }); err != nil {
			t.Fatal("current dependency selection", err)
		}
		dep := a.put(t, ctx, c.ID, "FIXTURE_DEPENDENCY", model.Document{"schema_version": "1", "observed_at": now, "proposal_id": a.selected.ID, "binding": a.selected.Binding, "mapping": a.h.view.Parent.Program.ArtifactContext.Mapping, "source_guard": "CURRENT_UNDER_REPOSITORY_FENCE", "customer_graph_complete": false})
		kinds = append(kinds, "FIXTURE_DEPENDENCY")
		refs = append(refs, dep)
	}
	// Recovery uses the same immutable SLO archive kind but the explicitly
	// distinct recovery evidence kind in the signed contract.
	sloRef := a.put(t, ctx, c.ID, "FIXTURE_SLO", model.Document{"schema_version": "1", "observed_at": now, "command_id": c.ID, "operation_id": c.OperationID, "fence": c.Fence, "observation": slo, "customer_work_preservation_authority": false})
	sloKind := "FIXTURE_SLO"
	if c.Preparation.Mode != g.Forward {
		sloKind = "FIXTURE_RECOVERY_SLO"
	}
	kinds = append(kinds, sloKind)
	refs = append(refs, sloRef)
	out := []g.EvidenceRef{}
	for i, ref := range refs {
		out = append(out, g.EvidenceRef{Kind: kinds[i], ID: ref.ID, SHA256: ref.SHA256, BindingSHA256: g.Digest(a.h.view.Parent.Program.Binding), RealmSHA256: g.Digest(a.h.view.Parent.Program.Realm), ObservedAt: now, ValidUntil: now.Add(12 * time.Minute)})
	}
	return out
}

func (a *connectedStageArtifacts) finalize(t *testing.T, ctx context.Context, capture g.GitTerraformArtifactCapture, evidence []g.EvidenceRef) (g.JournalCommand, map[string]string) {
	t.Helper()
	h := a.h
	p := h.refresh(t, ctx)
	if p.Pending == nil || !p.Pending.GitAdvanced {
		t.Fatal("owned captured preparation required")
	}
	c := p.Pending.Command
	program := h.view.Parent.Program
	refs := map[string]string{}
	a.put(t, ctx, c.ID, "NATIVE_CAPTURE", capture)
	for kind, raw := range map[string][]byte{"SAVED_PLAN": capture.SavedPlan, "PLAN_JSON": capture.PlanJSON, "BEFORE_NATIVE_STATE": capture.BeforeState} {
		ref := a.put(t, ctx, c.ID, kind, raw)
		refs[kind] = ref.ID
	}
	artifact := g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: model.ID(), SHA256: g.Digest(capture)}, BaseContextSHA256: g.Digest(program.ArtifactContext), ManifestSHA256: program.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Preparation.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: g.BytesDigest(capture.SavedPlan), PlanJSONSHA256: g.BytesDigest(capture.PlanJSON), Before: c.Preparation.Before, After: c.Preparation.After}
	now := time.Now().UTC()
	child := g.GitChild{}
	recovery := g.JournalRecovery{}
	var review g.ArtifactReview
	var err error
	if c.Preparation.Mode == g.Forward {
		entry := program.Manifest.Entries[c.Preparation.Sequence-1]
		artifact.ManifestEntrySHA256 = g.Digest(entry)
		child = g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: model.ID(), ParentID: program.ID, ParentSHA256: g.Digest(program), BindingSHA256: g.Digest(program.Binding), RealmSHA256: g.Digest(program.Realm), Mode: g.Forward, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: entry.Sequence, Artifact: artifact, MinimumObservationSeconds: entry.MinimumObservationSeconds, Evidence: evidence, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: model.ID()}
		review, err = g.ValidateGitTerraformArtifact(program, child, capture, now)
	} else {
		if len(p.Stack) == 0 {
			t.Fatal("owned inverse top missing")
		}
		top := p.Stack[len(p.Stack)-1]
		recovery = g.JournalRecovery{SchemaVersion: g.JournalSchemaVersion, ID: model.ID(), CommandID: c.ID, JournalID: h.view.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(h.view.Authorization), ParentEnvelopeSHA256: g.Digest(h.view.Parent), PreparationHeadSHA256: g.Digest(c.Head), SigningHeadSHA256: g.Digest(h.view.Head), EffectID: top.ID, OriginalChildSHA256: g.Digest(top.Forward.Child), OriginalReceiptSHA256: g.Digest(top.Applied), Artifact: artifact, MinimumObservationSeconds: 120, Evidence: evidence, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: model.ID()}
		review, err = g.ValidateJournalTerraformArtifact(h.view, h.bootstrap.Keys.Core(), h.view.Head.Head.Ref, recovery, capture, now)
	}
	if err != nil {
		t.Fatal("actual saved-plan semantic review", err)
	}
	// Receipt hashes cannot recursively contain themselves. These two digest
	// fields are omitted from the archived input/results statement; the final
	// exact artifact is independently revalidated and signed below.
	review.ChildSHA256 = ""
	review.ArtifactSHA256 = ""
	reviewRef := a.put(t, ctx, c.ID, "NATIVE_ARTIFACT_REVIEW", model.Document{"schema_version": "1", "command_id": c.ID, "preparation_sha256": g.Digest(c.Preparation), "capture_sha256": g.Digest(capture), "review": review, "self_referential_envelope_digests_omitted": true})
	artifact.Receipt = g.SnapshotRef{ID: reviewRef.ID, SHA256: reviewRef.SHA256}
	refs["NATIVE_ARTIFACT_REVIEW"] = reviewRef.ID
	// Keep the retained signing head exact across finalization. Registry writes
	// do not advance the journal's issued head.
	h.appendNativeRecord(t, ctx, func(v g.JournalView, current g.JournalProjection) (g.JournalRecord, error) {
		if current.Pending == nil || g.Digest(current.Pending.Command) != g.Digest(c) {
			return g.JournalRecord{}, errors.New("current finalization command changed")
		}
		if c.Preparation.Mode == g.Forward {
			child.Artifact = artifact
			if _, e := g.ValidateGitTerraformArtifact(program, child, capture, now); e != nil {
				return g.JournalRecord{}, e
			}
			signed, e := g.SignGitChild(child, v.Parent, h.signerKey, now)
			if e != nil {
				return g.JournalRecord{}, e
			}
			c.Forward = &signed
		} else {
			recovery.Artifact = artifact
			if _, e := g.ValidateJournalTerraformArtifact(v, h.bootstrap.Keys.Core(), v.Head.Head.Ref, recovery, capture, now); e != nil {
				return g.JournalRecord{}, e
			}
			signed, e := g.SignJournalRecovery(recovery, v, h.bootstrap.Keys.Core(), v.Head.Head.Ref, h.signerKey, now)
			if e != nil {
				return g.JournalRecord{}, e
			}
			c.Recovery = &signed
		}
		return g.JournalRecord{Kind: g.JournalReserved, Command: &c}, nil
	})
	return c, refs
}

func connectedCommandArtifact(c g.JournalCommand) g.GitArtifact {
	if c.Forward != nil {
		return c.Forward.Child.Artifact
	}
	return c.Recovery.Recovery.Artifact
}

// execute commits distinct one-shot Git and apply claims before actual I/O.
// Unknown is an uncertainty record, followed by positive terminal readback;
// reopening never infers NO_APPLY and never redispatches the old operation.
func (a *connectedStageArtifacts) execute(t *testing.T, ctx context.Context, native *groupfixtureproducer.NativeStage, c g.JournalCommand, slo any, reconcile bool) (g.JournalCommand, g.JournalState) {
	t.Helper()
	h := a.h
	gitDelivery, gitPermit, gitAttempt := h.claim(t, ctx, c.ID, "GIT_ADVANCE")
	h.assertReconcileDeliveryRefused(t, ctx, gitDelivery, gitPermit, gitAttempt)
	var capture g.GitTerraformArtifactCapture
	if err := h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		var e error
		capture, e = native.Capture(ctx, v, k, gitPermit)
		return e
	}, h.deliveryFence(ctx, gitDelivery, gitPermit, gitAttempt)); err != nil {
		t.Fatal("actual claimed Git CAS and fresh saved plan", err)
	}
	beforeCounts, err := groupfixtureproducer.TerraformInvocations()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error { _, e := native.Capture(ctx, v, k, gitPermit); return e }, h.deliveryFence(ctx, gitDelivery, gitPermit, gitAttempt)); !errors.Is(err, groupfixtureproducer.ErrUncertain) {
		t.Fatal("repeat capture must retain one-shot uncertainty", err)
	}
	if counts, e := groupfixtureproducer.TerraformInvocations(); e != nil || g.Digest(counts.Counts) != g.Digest(beforeCounts.Counts) {
		t.Fatal("repeat capture launched Terraform", e)
	}
	gitAfter := c.Before
	gitAfter.Revision = c.Preparation.Revision
	h.receipt(t, ctx, g.JournalGitAdvanced, c.Before, gitAfter)
	c, refs := a.finalize(t, ctx, capture, a.evidence(t, ctx, native, slo))
	if err = h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		var proof groupfixtureproducer.NotDispatchedProof
		var e error
		proof, e = native.VerifyNotDispatched(ctx, v, k, capture)
		if e != nil {
			return e
		}
		// The positive fixed native operation proof is archived outside this
		// lock below; no private absence inference is used as READY.
		if proof.CommandSHA256 != g.Digest(c) || !proof.ValidUntil.After(time.Now().UTC()) {
			return errors.New("native positive not-dispatched proof mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal("positive native not-dispatched proof", err)
	}
	// Repeat under a fresh issued current fence and retain the exact proof.
	var proof groupfixtureproducer.NotDispatchedProof
	if err = h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		var e error
		proof, e = native.VerifyNotDispatched(ctx, v, k, capture)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	a.put(t, ctx, c.ID, "NATIVE_OPERATION_PROOF", proof)
	h.receipt(t, ctx, g.JournalReadyToApply, gitAfter, gitAfter, proof)
	h.receipt(t, ctx, g.JournalApplyIntent, gitAfter, gitAfter)
	applyDelivery, applyPermit, applyAttempt := h.claim(t, ctx, c.ID, "APPLY")
	h.assertReconcileDeliveryRefused(t, ctx, applyDelivery, applyPermit, applyAttempt)
	var after g.JournalState
	// Rehashed public metadata cannot substitute different native saved bytes,
	// and actual native-state drift is refused before any CLI attempt.
	probeCounts, err := groupfixtureproducer.TerraformInvocations()
	if err != nil {
		t.Fatal(err)
	}
	badCapture := capture
	badCapture.SavedPlan = append(append([]byte(nil), capture.SavedPlan...), 0)
	if err = h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		_, e := native.Apply(ctx, v, k, applyPermit, badCapture)
		return e
	}); err == nil {
		t.Fatal("tampered native plan accepted")
	}
	originalState, err := os.ReadFile(g.GitFixtureStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(g.GitFixtureStatePath, append(append([]byte(nil), originalState...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	driftErr := h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		_, e := native.Apply(ctx, v, k, applyPermit, capture)
		return e
	})
	if err = os.WriteFile(g.GitFixtureStatePath, originalState, 0600); err != nil {
		t.Fatal(err)
	}
	if driftErr == nil {
		t.Fatal("actual native state byte drift accepted")
	}
	if counts, e := groupfixtureproducer.TerraformInvocations(); e != nil || g.Digest(counts.Counts) != g.Digest(probeCounts.Counts) {
		t.Fatal("negative drift/plan probe dispatched Terraform", e)
	}
	if err = h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		if reconcile {
			if e := connectedApplyProcess(ctx, connectedProcessDispatch{a.selected, a.prepared, v, k, applyPermit, capture}); e != nil {
				return e
			}
			return nil
		}
		var e error
		after, e = native.Apply(ctx, v, k, applyPermit, capture)
		return e
	}, h.deliveryFence(ctx, applyDelivery, applyPermit, applyAttempt), func(tx *store.Tx) error {
		return tx.GroupArtifactRequireFinalized(ctx, h.bootstrap.ChainID, c.ID, connectedCommandArtifact(c), refs)
	}); err != nil {
		t.Fatal("actual exact saved-plan apply", err)
	}
	afterCounts, err := groupfixtureproducer.TerraformInvocations()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.nativeFence(ctx, func(v g.JournalView, k g.JournalKeys) error {
		_, e := native.Apply(ctx, v, k, applyPermit, capture)
		return e
	}, h.deliveryFence(ctx, applyDelivery, applyPermit, applyAttempt)); !errors.Is(err, groupfixtureproducer.ErrUncertain) {
		t.Fatal("repeat apply uncertainty", err)
	}
	if counts, e := groupfixtureproducer.TerraformInvocations(); e != nil || g.Digest(counts.Counts) != g.Digest(afterCounts.Counts) {
		t.Fatal("repeat apply launched Terraform", e)
	}
	if reconcile {
		h.receipt(t, ctx, g.JournalUnknown, c.Before, c.Before)
		h.reopen(t, ctx)
		held := h.refresh(t, ctx)
		if held.Pending == nil || held.Pending.Phase != g.JournalUnknown || !held.Pending.ApplyIntent {
			t.Fatal("database reopen lost the unresolved dispatched obligation")
		}
	}
	// Reopen actual producer state and fresh authenticated database pools. The
	// terminal is positive encrypted readback, not a second CLI invocation.
	reopened, err := groupfixtureproducer.OpenNativeStage(ctx, a.selected, a.prepared, a.archive)
	if err != nil {
		t.Fatal("native stage process-state reopen", err)
	}
	outcome, err := reopened.Outcome(ctx, c)
	if reconcile && err == nil {
		after = outcome.After
	}
	if err != nil || outcome.CommandSHA256 != g.Digest(c) || outcome.Before != c.Before || outcome.After != after {
		t.Fatal("positive durable terminal reconciliation", err)
	}
	if after.Model != c.Preparation.After || after.Revision != c.Preparation.Revision {
		t.Fatal("terminal native after-state differs from exact approved effect")
	}
	a.retain(t, ctx, c.ID, "AFTER_NATIVE_STATE", outcome.Artifact)
	if counts, e := groupfixtureproducer.TerraformInvocations(); e != nil || g.Digest(counts.Counts) != g.Digest(afterCounts.Counts) {
		t.Fatal("terminal reconciliation launched Terraform", e)
	}
	h.receipt(t, ctx, g.JournalApplied, c.Before, after)
	return c, after
}
