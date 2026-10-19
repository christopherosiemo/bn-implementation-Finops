package service

import (
	"context"
	"errors"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"os"
	"testing"
	"time"
)

// Dedicated rehearsal preserves the original UNKNOWN until033 terminal
// publication/selection and independent runtime retirement are proven.
func (a *connectedStageArtifacts) workspacePendingEffect(t *testing.T, ctx context.Context, native *groupfixtureproducer.NativeStage, c g.JournalCommand, slo any, reconcile bool) workspacePending {
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
	return workspacePending{Command: c, Capture: capture, Delivery: applyDelivery, AttemptID: applyAttempt, Permit: applyPermit, Outcome: outcome, SelectedRefs: refs}
}
