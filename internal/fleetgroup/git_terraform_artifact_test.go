package fleetgroup

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func gitInvocationFixture() GitPlanInvocation {
	return GitPlanInvocation{[]string{"plan", "-input=false", "-no-color", "-refresh=false", "-state=" + GitFixtureStatePath, "-out=" + GitFixturePlanPath}, []string{"PATH", "HOME", "TMPDIR", "TF_IN_AUTOMATION"}}
}

func unitGitArtifactCapture(t *testing.T, sequence uint64) (GitProgram, GitChild, GitTerraformArtifactCapture, time.Time) {
	t.Helper()
	p, now, commits, trees := gitProgramFixture(t)
	c := gitChildFixture(p, now, sequence)
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, c.Artifact.After)
	// Share only synthetic native-schema builders. No v5 validator/signature is
	// used to attest a5.1 artifact, and opaque unit bytes remain labelled as such.
	oldModel := gitModelView(p)
	oldChild := Child{Artifact: Artifact{BeforeStateSerial: c.Artifact.BeforeStateSerial, Before: c.Artifact.Before, After: c.Artifact.After}}
	_, _, raw, _ := unitCaptureForChild(t, oldModel, oldChild, source, now)
	capture := GitTerraformArtifactCapture{Context: p.ArtifactContext, Revision: c.Artifact.Revision, Configuration: source, DesiredVariables: desired, SavedPlan: raw.SavedPlan, PlanJSON: raw.PlanJSON, BeforeState: raw.BeforeState, GitCommitObject: commits[c.Artifact.Revision.Commit], GitTreeObject: trees[c.Artifact.Revision.Tree], Ref: p.Manifest.Ref, RefBefore: c.Artifact.PreviousRevision.Commit, RefAfter: c.Artifact.Revision.Commit, Invocation: gitInvocationFixture()}
	bindGitBytes(&c, capture)
	return p, c, capture, now
}

func bindGitBytes(c *GitChild, capture GitTerraformArtifactCapture) {
	c.Artifact.BeforeStateSHA256 = BytesDigest(capture.BeforeState)
	c.Artifact.SavedPlanSHA256 = BytesDigest(capture.SavedPlan)
	c.Artifact.PlanJSONSHA256 = BytesDigest(capture.PlanJSON)
}

func TestGitTerraformArtifactRequiresTwoCommittedFilesAndNativeExactPlan(t *testing.T) {
	for _, seq := range []uint64{1, 2, 3, 26} {
		t.Run(string(rune('a'+seq)), func(t *testing.T) {
			p, c, capture, now := unitGitArtifactCapture(t, seq)
			review, err := ValidateGitTerraformArtifact(p, c, capture, now)
			if err != nil {
				t.Fatal(err)
			}
			if review.Status != "FIXTURE_GIT_SEMANTICS_MATCHED" || review.ProgramSHA256 != Digest(p) || review.ChildSHA256 != Digest(c) || review.ArtifactSHA256 != Digest(c.Artifact) || review.NoOp != (seq == 1) || review.CustomerNativeExecution || review.CustomerVerifiedSaving != nil {
				t.Fatalf("incorrect review %+v", review)
			}
		})
	}
	p, c, capture, now := unitGitArtifactCapture(t, 2)
	cases := map[string]func(*GitChild, *GitTerraformArtifactCapture){
		"desired bytes": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.DesiredVariables = append(append([]byte{}, x.DesiredVariables...), ' ')
		},
		"source bytes": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.Configuration = append(append([]byte{}, x.Configuration...), ' ')
		},
		"saved bytes": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.SavedPlan = append(append([]byte{}, x.SavedPlan...), ' ')
		},
		"before state": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.BeforeState = append(append([]byte{}, x.BeforeState...), ' ')
		},
		"raw commit": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.GitCommitObject = append(append([]byte{}, x.GitCommitObject...), ' ')
		},
		"raw tree": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.GitTreeObject = append(append([]byte{}, x.GitTreeObject...), ' ')
		},
		"manual ref changed":       func(_ *GitChild, x *GitTerraformArtifactCapture) { x.RefBefore = p.Manifest.Entries[2].Revision.Commit },
		"wrong target ref":         func(_ *GitChild, x *GitTerraformArtifactCapture) { x.RefAfter = p.Manifest.Base.Commit },
		"wrong ref":                func(_ *GitChild, x *GitTerraformArtifactCapture) { x.Ref = "refs/heads/other" },
		"different base authority": func(_ *GitChild, x *GitTerraformArtifactCapture) { x.Context.PipelineID = "other" },
		"CLI variable": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.Invocation.Arguments = append(x.Invocation.Arguments, "-var=old_count=20")
		},
		"CLI varfile": func(_ *GitChild, x *GitTerraformArtifactCapture) { x.Invocation.Arguments[2] = "-var-file=other.json" },
		"TF_VAR": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.Invocation.EnvironmentKeys = append(x.Invocation.EnvironmentKeys, "TF_VAR_old_count")
		},
		"TF_CLI_ARGS": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.Invocation.EnvironmentKeys = append(x.Invocation.EnvironmentKeys, "TF_CLI_ARGS_plan")
		},
		"ambient AWS": func(_ *GitChild, x *GitTerraformArtifactCapture) {
			x.Invocation.EnvironmentKeys = append(x.Invocation.EnvironmentKeys, "AWS_ACCESS_KEY_ID")
		},
		"rehashed native count": func(c *GitChild, x *GitTerraformArtifactCapture) {
			plan, _ := fixtureObject(x.PlanJSON, fixtureArtifactLimit)
			tfObject(tfObject(plan["variables"])["candidate_count"])["value"] = json.Number("3")
			x.PlanJSON, _ = json.Marshal(plan)
			bindGitBytes(c, *x)
		},
		"rehashed native planned effect": func(c *GitChild, x *GitTerraformArtifactCapture) {
			plan, _ := fixtureObject(x.PlanJSON, fixtureArtifactLimit)
			for _, raw := range tfArray(tfObject(tfObject(plan["planned_values"])["root_module"])["resources"]) {
				r := tfObject(raw)
				if r["address"] == "terraform_data.candidate" {
					tfObject(tfObject(r["values"])["input"])["desired_count"] = json.Number("3")
				}
			}
			x.PlanJSON, _ = json.Marshal(plan)
			bindGitBytes(c, *x)
		},
		"rehashed native state": func(c *GitChild, x *GitTerraformArtifactCapture) {
			state, _ := fixtureObject(x.BeforeState, fixtureArtifactLimit)
			state["serial"] = json.Number("999")
			x.BeforeState, _ = json.Marshal(state)
			bindGitBytes(c, *x)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cc, xx := c, capture
			xx.Invocation.Arguments = append([]string{}, capture.Invocation.Arguments...)
			xx.Invocation.EnvironmentKeys = append([]string{}, capture.Invocation.EnvironmentKeys...)
			mutate(&cc, &xx)
			if _, err := ValidateGitTerraformArtifact(p, cc, xx, now); err == nil {
				t.Fatal("accepted modified capture")
			}
		})
	}
}

// Rehashing a fake manifest cannot make native commit ancestry or the exact
// two-file tree valid. Use last entry so there is no later metadata to repair.
func rebindGitLastCapture(p *GitProgram, c *GitChild, x *GitTerraformArtifactCapture) {
	x.Revision.Commit = gitObjectOID("commit", x.GitCommitObject, len(x.Revision.Commit))
	x.Revision.Tree = gitObjectOID("tree", x.GitTreeObject, len(x.Revision.Tree))
	i := len(p.Manifest.Entries) - 1
	p.Manifest.Entries[i].Revision = x.Revision
	p.ManifestSHA256 = Digest(p.Manifest)
	c.ParentSHA256 = Digest(*p)
	c.Artifact.ManifestSHA256 = p.ManifestSHA256
	c.Artifact.ManifestEntrySHA256 = Digest(p.Manifest.Entries[i])
	c.Artifact.Revision = x.Revision
	x.RefAfter = x.Revision.Commit
}

func TestGitTerraformRawCommitMustAppendExactOwnedPredecessorWithoutMergeOrExtraFiles(t *testing.T) {
	for name, mutate := range map[string]func(*GitProgram, *GitChild, *GitTerraformArtifactCapture){
		"wrong parent": func(p *GitProgram, c *GitChild, x *GitTerraformArtifactCapture) {
			x.GitCommitObject = []byte(strings.Replace(string(x.GitCommitObject), "parent "+c.Artifact.PreviousRevision.Commit, "parent "+p.Manifest.Base.Commit, 1))
		},
		"merge": func(p *GitProgram, c *GitChild, x *GitTerraformArtifactCapture) {
			x.GitCommitObject = []byte(strings.Replace(string(x.GitCommitObject), "parent "+c.Artifact.PreviousRevision.Commit, "parent "+c.Artifact.PreviousRevision.Commit+"\nparent "+p.Manifest.Base.Commit, 1))
		},
		"extra file": func(_ *GitProgram, _ *GitChild, x *GitTerraformArtifactCapture) {
			x.GitTreeObject = append(append([]byte{}, x.GitTreeObject...), []byte("100644 extra.txt\x00extra-opaque-object")...)
			tree := gitObjectOID("tree", x.GitTreeObject, len(x.Revision.Tree))
			x.GitCommitObject = []byte(strings.Replace(string(x.GitCommitObject), "tree "+x.Revision.Tree, "tree "+tree, 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c, x, now := unitGitArtifactCapture(t, 26)
			mutate(&p, &c, &x)
			rebindGitLastCapture(&p, &c, &x)
			if err := ValidateGitChild(c, p, now); err != nil {
				t.Fatal("test failed before raw closure gate:", err)
			}
			if _, err := ValidateGitTerraformArtifact(p, c, x, now); err == nil {
				t.Fatal("accepted forged native Git closure")
			}
		})
	}
}

func TestGitRecoveryRejectsSameModelNewerHeadUntilCompleteOwnedJournalExists(t *testing.T) {
	p, now, _, _ := gitProgramFixture(t)
	original := gitChildFixture(p, now, 26)
	at := now.Add(time.Minute)
	r, applied, ownership := gitRecoveryFixture(t, p, original, at)
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, ownership.Model)
	newHead, _, _ := unitGitRevision(source, desired, ownership.Revision.Commit, 40, "same model but unrelated/manual source revision")
	ownership.Revision = newHead
	r.Artifact.PreviousRevision = newHead
	r.OwnershipSHA256 = Digest(ownership)
	if ValidateGitRecovery(r, original, p, applied, ownership, at) == nil {
		t.Fatal("same-model new Git head bypassed missing owned transition journal")
	}
	if !strings.Contains(GitRecoveryLimitation, "SINGLE_APPLIED_CHILD") {
		t.Fatal("single child limitation missing")
	}
}
