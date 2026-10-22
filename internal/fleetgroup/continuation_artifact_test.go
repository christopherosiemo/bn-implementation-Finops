package fleetgroup

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Synthetic native-shaped bytes exercise the decoder boundary only. Actual
// Terraform dispatch and persistence are independent acceptance gates.
func continuationArtifactFixture(t *testing.T) (*continuationFixture, ContinuationFinalization, GitTerraformArtifactCapture) {
	t.Helper()
	h := newContinuationFixture(t)
	h.old.forward(1)
	h.old.forward(2)
	h.old.forward(3)
	h.open()
	h.prepare(ContinuationInverse)
	c := h.p.Pending.Command
	p := h.view.Origin.Parent.Program
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, c.After)
	rev, commit, tree := unitGitRevision(source, desired, c.Before.Revision.Commit, 40, fmt.Sprintf("NEW continuation inverse-%d", c.Fence))
	if rev != c.Revision {
		t.Fatal("unit Git proof differs")
	}
	h.issue(ContinuationGitAdvanced, c.Before, journalAtRevision(c.Before, c.Revision))
	_, _, raw, _ := unitCaptureForChild(t, gitModelView(p), Child{Artifact: Artifact{BeforeStateSerial: c.Before.StateSerial, Before: c.Before.Model, After: c.After}}, source, h.now)
	// This decoder fixture represents a plan captured after this new command,
	// rather than the older generic builder's pre-command timestamp.
	plan, _ := fixtureObject(raw.PlanJSON, fixtureArtifactLimit)
	plan["timestamp"] = h.now.Format(time.RFC3339Nano)
	raw.PlanJSON, _ = json.Marshal(plan)
	before := journalNativeState(t, p, c.Before.Model, c.Before.StateSerial)
	capture := GitTerraformArtifactCapture{Context: p.ArtifactContext, Revision: c.Revision, Configuration: source, DesiredVariables: desired, SavedPlan: unitFixtureContainer(t, source, before, nil), PlanJSON: raw.PlanJSON, BeforeState: before, GitCommitObject: commit, GitTreeObject: tree, Ref: p.Manifest.Ref, RefBefore: c.Before.Revision.Commit, RefAfter: c.Revision.Commit, Invocation: gitInvocationFixture()}
	f := ContinuationFinalization{SchemaVersion: ContinuationSchemaVersion, ID: "native-continuation-finalization", ChainSHA256: Digest(h.chain), CommandSHA256: Digest(c), SigningHeadSHA256: Digest(h.view.Head), CreatedAt: h.now, ExpiresAt: h.now.Add(time.Minute), Nonce: "native-continuation-finalization-nonce", Artifact: GitArtifact{Kind: BuiltinFixtureArtifact, Receipt: SnapshotRef{"unit-native-continuation-capture", sha("a")}, BaseContextSHA256: Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: BytesDigest(capture.SavedPlan), PlanJSONSHA256: BytesDigest(capture.PlanJSON), Before: c.Before.Model, After: c.After}}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
		f.Evidence = append(f.Evidence, EvidenceRef{kind, "unit-artifact-" + kind, sha("d"), Digest(p.Binding), Digest(p.Realm), h.now, h.now.Add(5 * time.Minute)})
	}
	return h, f, capture
}

func TestContinuationArtifactUsesOwnTypedAuthorityBeforeAndAtDispatch(t *testing.T) {
	h, f, capture := continuationArtifactFixture(t)
	review, err := ValidateContinuationTerraformArtifact(h.ctx, h.view, h.old.keys, h.memory, f, capture, h.now)
	if err != nil {
		t.Fatal(err)
	}
	if review.Status != "FIXTURE_CONTINUATION_RECOVERY_SEMANTICS_MATCHED" || review.ChildSHA256 != Digest(f) || review.CustomerNativeExecution || review.CustomerVerifiedSaving != nil {
		t.Fatal("wrong authority or financial projection")
	}
	signed, err := SignContinuationFinalization(h.ctx, f, h.view, h.old.keys, h.memory, h.old.signer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	h.must(ContinuationRecord{Kind: ContinuationFinalized, Finalization: &signed})
	h.issue(ContinuationReady, h.p.Current, h.p.Current)
	h.issue(ContinuationIntent, h.p.Current, h.p.Current)
	if _, err = ValidateContinuationTerraformArtifact(h.ctx, h.view, h.old.keys, h.memory, f, capture, h.now); err != nil {
		t.Fatal("current dispatch could not recheck exact finalized inverse", err)
	}
}

func TestContinuationArtifactRejectsRehashedOverridesAndOldAuthorityAdapters(t *testing.T) {
	h, f, capture := continuationArtifactFixture(t)
	cases := map[string]func(*ContinuationFinalization, *GitTerraformArtifactCapture){
		"old recovery adapter": func(_ *ContinuationFinalization, x *GitTerraformArtifactCapture) {
			x.Recovery = &GitTerraformRecoveryAuthority{}
		},
		"wrong ref": func(_ *ContinuationFinalization, x *GitTerraformArtifactCapture) { x.Ref = "refs/heads/unapproved" },
		"wrong state": func(f *ContinuationFinalization, x *GitTerraformArtifactCapture) {
			x.BeforeState = append(append([]byte{}, x.BeforeState...), ' ')
			f.Artifact.BeforeStateSHA256 = BytesDigest(x.BeforeState)
		},
		"unrelated variables": func(f *ContinuationFinalization, x *GitTerraformArtifactCapture) {
			plan, _ := fixtureObject(x.PlanJSON, fixtureArtifactLimit)
			tfObject(tfObject(plan["variables"])["candidate_traffic_percent"])["value"] = json.Number("99")
			x.PlanJSON, _ = json.Marshal(plan)
			f.Artifact.PlanJSONSHA256 = BytesDigest(x.PlanJSON)
		},
		"future plan": func(f *ContinuationFinalization, x *GitTerraformArtifactCapture) {
			plan, _ := fixtureObject(x.PlanJSON, fixtureArtifactLimit)
			plan["timestamp"] = h.now.Add(time.Hour).Format(time.RFC3339Nano)
			x.PlanJSON, _ = json.Marshal(plan)
			f.Artifact.PlanJSONSHA256 = BytesDigest(x.PlanJSON)
		},
		"new unapproved head": func(f *ContinuationFinalization, _ *GitTerraformArtifactCapture) { f.SigningHeadSHA256 = sha("f") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad, changed := f, capture
			mutate(&bad, &changed)
			if _, err := ValidateContinuationTerraformArtifact(h.ctx, h.view, h.old.keys, h.memory, bad, changed, h.now); err == nil {
				t.Fatal("invalid independent native proof admitted")
			}
		})
	}
}
