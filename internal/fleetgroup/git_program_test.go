package fleetgroup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Unit Git objects and opaque saved-plan members are synthetic test inputs.
// They are not the separate actual Git/Terraform process acceptance.
func unitGitRevision(source, desired []byte, parent string, width int, message string) (GitRevision, []byte, []byte) {
	tree := []byte{}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{GitDesiredPath, desired}, {GitMainPath, source}} {
		oid, _ := hex.DecodeString(gitObjectOID("blob", file.raw, width))
		tree = append(tree, []byte("100644 "+file.name+"\x00")...)
		tree = append(tree, oid...)
	}
	treeOID := gitObjectOID("tree", tree, width)
	headers := "tree " + treeOID + "\n"
	if parent != "" {
		headers += "parent " + parent + "\n"
	}
	headers += "author Unit fixture <fixture@example.invalid> 1792411200 +0000\ncommitter Unit fixture <fixture@example.invalid> 1792411200 +0000\n\n" + message + "\n"
	commit := []byte(headers)
	return GitRevision{gitObjectOID("commit", commit, width), treeOID, BytesDigest(source), BytesDigest(desired)}, commit, tree
}

func gitProgramFixture(t *testing.T) (GitProgram, time.Time, map[string][]byte, map[string][]byte) {
	t.Helper()
	old, now := programFixture()
	p := GitProgram{SchemaVersion: GitSchemaVersion, Kind: old.Kind, ID: "git-program-a", Binding: old.Binding, Realm: old.Realm, CreatorID: old.CreatorID, Environment: old.Environment, Policy: old.Policy, ArtifactContext: old.ArtifactContext, OldTemplate: old.OldTemplate, CandidateTemplate: old.CandidateTemplate, Budget: old.Budget, Stages: old.Stages, Evidence: old.Evidence, CreatedAt: old.CreatedAt, ExpiresAt: old.ExpiresAt, Nonce: "git-parent-nonce"}
	p.ArtifactContext.StateLineage = "11111111-2222-3333-4444-555555555555"
	steps, err := GitStageSpecifications(p)
	if err != nil {
		t.Fatal(err)
	}
	source, err := GitFixtureConfiguration(p)
	if err != nil {
		t.Fatal(err)
	}
	desired, _ := GitFixtureDesired(p, steps[0].Before)
	base, commit, tree := unitGitRevision(source, desired, "", 40, "Unit initial two-file tree")
	p.ArtifactContext.ConfigurationSHA256 = base.ConfigurationSHA256
	p.ArtifactContext.GitCommit, p.ArtifactContext.GitTree = base.Commit, base.Tree
	commits, trees := map[string][]byte{base.Commit: commit}, map[string][]byte{base.Tree: tree}
	p.Manifest = GitManifest{SchemaVersion: "1", Ref: "refs/heads/finops-fixture", Base: base}
	previous := base
	for i, step := range steps {
		step.PredecessorCommit = previous.Commit
		if i == 0 {
			step.Revision = base
		} else {
			desired, _ = GitFixtureDesired(p, step.After)
			r, c, tr := unitGitRevision(source, desired, previous.Commit, 40, fmt.Sprintf("Unit approved step%d", i+1))
			step.Revision = r
			commits[r.Commit], trees[r.Tree] = c, tr
		}
		p.Manifest.Entries = append(p.Manifest.Entries, step)
		previous = step.Revision
	}
	p.ManifestSHA256 = Digest(p.Manifest)
	return p, now, commits, trees
}

func gitChildFixture(p GitProgram, now time.Time, sequence uint64) GitChild {
	e := p.Manifest.Entries[sequence-1]
	previous := p.Manifest.Base
	if sequence > 1 {
		previous = p.Manifest.Entries[sequence-2].Revision
	}
	c := GitChild{SchemaVersion: GitSchemaVersion, ID: fmt.Sprintf("git-child-%d", sequence), ParentID: p.ID, ParentSHA256: Digest(p), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), Mode: Forward, StageID: e.StageID, StageSHA256: e.StageSHA256, Sequence: sequence, Artifact: GitArtifact{Kind: BuiltinFixtureArtifact, Receipt: SnapshotRef{fmt.Sprintf("git-artifact-%d", sequence), sha("a")}, BaseContextSHA256: Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, ManifestEntrySHA256: Digest(e), PreviousRevision: previous, Revision: e.Revision, BeforeStateSerial: p.ArtifactContext.InitialStateSerial + sequence, BeforeStateSHA256: sha("b"), SavedPlanSHA256: sha("c"), PlanJSONSHA256: sha("d"), Before: e.Before, After: e.After}, MinimumObservationSeconds: e.MinimumObservationSeconds, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: fmt.Sprintf("git-child-nonce-%d", sequence)}
	for _, kind := range childEvidence {
		c.Evidence = append(c.Evidence, EvidenceRef{kind, "git-" + strings.ToLower(kind), sha("b"), Digest(p.Binding), Digest(p.Realm), now, now.Add(15 * time.Minute)})
	}
	return c
}

func copyGitProgram(p GitProgram) GitProgram {
	raw, _ := json.Marshal(p)
	var out GitProgram
	_ = json.Unmarshal(raw, &out)
	return out
}
func gitApprovalsFixture(p GitProgram, now time.Time) []Approval {
	return []Approval{{"git-approval", p.Binding.Old.Target.TenantID, "independent-approver", ApproverRole, Digest(p), Digest(p.Realm), now}}
}

func TestGitProgramManifestPinsCompleteRealStageSequenceAndCommittedDesiredStates(t *testing.T) {
	p, now, _, _ := gitProgramFixture(t)
	if err := ValidateGitProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.Manifest.Entries) != 26 || GitMinimumProgramDuration(p) != 17400 {
		t.Fatal("stage population or feasibility changed")
	}
	for _, e := range p.Manifest.Entries {
		c := gitChildFixture(p, now, e.Sequence)
		if err := ValidateGitChild(c, p, now); err != nil {
			t.Fatalf("sequence%d: %v", e.Sequence, err)
		}
	}
	mutations := map[string]func(*GitProgram){
		"v5 schema":     func(p *GitProgram) { p.SchemaVersion = SchemaVersion },
		"native realm":  func(p *GitProgram) { p.Realm.Kind = "CUSTOMER_NATIVE" },
		"manifest root": func(p *GitProgram) { p.ManifestSHA256 = sha("f") },
		"missing child": func(p *GitProgram) { p.Manifest.Entries = p.Manifest.Entries[:25] },
		"extra child":   func(p *GitProgram) { p.Manifest.Entries = append(p.Manifest.Entries, p.Manifest.Entries[25]) },
		"reordered child": func(p *GitProgram) {
			p.Manifest.Entries[1], p.Manifest.Entries[2] = p.Manifest.Entries[2], p.Manifest.Entries[1]
		},
		"bad predecessor":       func(p *GitProgram) { p.Manifest.Entries[2].PredecessorCommit = p.Manifest.Base.Commit },
		"large blast":           func(p *GitProgram) { p.Manifest.Entries[1].After.CandidateCount = 3 },
		"early drain":           func(p *GitProgram) { p.Manifest.Entries[1].After.OldCount = 19 },
		"short canary":          func(p *GitProgram) { p.Manifest.Entries[2].MinimumObservationSeconds = 120 },
		"tree reused":           func(p *GitProgram) { p.Manifest.Entries[1].Revision.Tree = p.Manifest.Base.Tree },
		"commit reused":         func(p *GitProgram) { p.Manifest.Entries[2].Revision.Commit = p.Manifest.Entries[1].Revision.Commit },
		"static source changed": func(p *GitProgram) { p.Manifest.Entries[1].Revision.ConfigurationSHA256 = sha("a") },
		"desired state changed": func(p *GitProgram) { p.Manifest.Entries[1].Revision.DesiredSHA256 = sha("a") },
		"base desired changed":  func(p *GitProgram) { p.Manifest.Base.DesiredSHA256 = sha("a") },
		"ref escape":            func(p *GitProgram) { p.Manifest.Ref = "refs/heads/a/../b" },
		"short duration":        func(p *GitProgram) { p.Budget.MaximumDurationSeconds = 17400 - 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := copyGitProgram(p)
			mutate(&x)
			if name != "manifest root" {
				x.ManifestSHA256 = Digest(x.Manifest)
			}
			if err := ValidateGitProgram(x, Expected{x.Binding, x.Realm}, now); err == nil {
				t.Fatal("accepted mutated/rehashed manifest")
			}
		})
	}
}

func TestGitChildRequiresExactApprovedEntryAndDistinctFamilySignatures(t *testing.T) {
	p, now, _, _ := gitProgramFixture(t)
	pub, key := keyFixture()
	env, err := SignGitProgram(p, gitApprovalsFixture(p, now), key, now)
	if err != nil {
		t.Fatal(err)
	}
	c := gitChildFixture(p, now, 2)
	signed, err := SignGitChild(c, env, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyGitChild(signed, env, pub, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal(err)
	}
	old, _ := programFixture()
	oldEnv, err := Sign(old, approvals(old, now), key, now)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = oldEnv.Signature
	env.Algorithm = gitParentAlgorithm
	if VerifyGitProgram(env, pub, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("v5 signature accepted as5.1")
	}
	env, _ = SignGitProgram(p, gitApprovalsFixture(p, now), key, now)
	for name, mutate := range map[string]func(*GitChild){"entry": func(c *GitChild) { c.Artifact.ManifestEntrySHA256 = sha("f") }, "revision": func(c *GitChild) { c.Artifact.Revision = p.Manifest.Base }, "ref predecessor": func(c *GitChild) { c.Artifact.PreviousRevision = p.Manifest.Entries[2].Revision }, "state": func(c *GitChild) { c.Artifact.After.CandidateCount = 3 }, "stage": func(c *GitChild) { c.StageID = p.Stages[2].ID }, "serial": func(c *GitChild) { c.Artifact.BeforeStateSerial = 0 }, "schema": func(c *GitChild) { c.SchemaVersion = "5" }, "ownership on forward": func(c *GitChild) { c.OwnershipSHA256 = sha("a") }} {
		t.Run(name, func(t *testing.T) {
			x := c
			mutate(&x)
			if ValidateGitChild(x, p, now) == nil {
				t.Fatal("accepted changed stage context")
			}
		})
	}
	signed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, gitChildMessage(c, gitRecoveryDomain)))
	if VerifyGitChild(signed, env, pub, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("recovery signature accepted as forward")
	}
	raw, _ := json.Marshal(p)
	if _, err = DecodeGitProgram(raw); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeGitProgram(append(raw, []byte(" {}")...)); err == nil {
		t.Fatal("trailing program accepted")
	}
	if _, err = DecodeGitChild([]byte(`{"schema_version":"5.1","schema_version":"5.1"}`)); err == nil {
		t.Fatal("duplicate child accepted")
	}
}

func gitRecoveryFixture(t *testing.T, p GitProgram, original GitChild, at time.Time) (GitChild, GitOwnedReceipt, GitOwnership) {
	t.Helper()
	applied := GitOwnedReceipt{GitSchemaVersion, "applied-a", "command-a", Digest(p), Digest(original), Digest(original.Artifact), original.Artifact.SavedPlanSHA256, original.Artifact.PreviousRevision.Commit, original.Artifact.Revision.Commit, original.Artifact.BeforeStateSerial, original.Artifact.BeforeStateSerial + 1, sha("e"), Digest(original.Artifact.After), p.ArtifactContext.PipelineID, "APPLIED", original.CreatedAt.Add(time.Second)}
	ownership := GitOwnership{ID: "ownership-a", Version: 2, Status: "OWNED", CommandID: applied.CommandID, ParentSHA256: Digest(p), ChildSHA256: Digest(original), ReceiptSHA256: Digest(applied), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), Revision: original.Artifact.Revision, StateLineage: p.ArtifactContext.StateLineage, StateSerial: applied.AfterStateSerial, StateSHA256: sha("e"), Model: original.Artifact.After, ObservedAt: at, ValidUntil: at.Add(15 * time.Minute)}
	source, _ := GitFixtureConfiguration(p)
	desired, _ := GitFixtureDesired(p, original.Artifact.Before)
	revision, _, _ := unitGitRevision(source, desired, ownership.Revision.Commit, 40, "Unit NEW inverse commit, not history reset")
	c := original
	c.ID, c.Nonce = "recovery-a", "recovery-nonce"
	c.Mode = OwnedRecovery
	c.Sequence = 27
	c.CompensationFor = original.ID
	c.OwnedReceiptSHA256 = Digest(applied)
	c.OwnershipSHA256 = Digest(ownership)
	c.CreatedAt, c.ExpiresAt = at, at.Add(10*time.Minute)
	c.MinimumObservationSeconds = 120
	c.Artifact.ManifestEntrySHA256 = ""
	c.Artifact.PreviousRevision = ownership.Revision
	c.Artifact.Revision = revision
	c.Artifact.Before, c.Artifact.After = original.Artifact.After, original.Artifact.Before
	c.Artifact.BeforeStateSerial = ownership.StateSerial
	c.Artifact.BeforeStateSHA256 = ownership.StateSHA256
	c.Evidence = nil
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
		c.Evidence = append(c.Evidence, EvidenceRef{kind, "recovery-" + kind, sha("b"), Digest(p.Binding), Digest(p.Realm), at, at.Add(15 * time.Minute)})
	}
	return c, applied, ownership
}

func TestGitRecoveryRequiresCurrentDurableOwnershipAndAppendOnlyInverseAfterExpiry(t *testing.T) {
	p, now, _, _ := gitProgramFixture(t)
	c := gitChildFixture(p, now, 2)
	at := now.Add(8 * time.Hour)
	r, applied, ownership := gitRecoveryFixture(t, p, c, at)
	if ValidateGitProgram(p, Expected{p.Binding, p.Realm}, at) == nil {
		t.Fatal("parent still live")
	}
	if err := ValidateGitRecovery(r, c, p, applied, ownership, at); err != nil {
		t.Fatal("expired parent erased owned recovery:", err)
	}
	pub, key := keyFixture()
	parent, err := SignGitProgram(p, gitApprovalsFixture(p, now), key, now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SignGitChild(c, parent, key, now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignGitRecovery(r, original, parent, applied, ownership, key, at)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyGitRecovery(signed, original, parent, applied, ownership, pub, Expected{p.Binding, p.Realm}, at); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*GitChild, *GitOwnedReceipt, *GitOwnership){
		"consumed":           func(_ *GitChild, _ *GitOwnedReceipt, o *GitOwnership) { o.Status = "CONSUMED" },
		"no durable version": func(_ *GitChild, _ *GitOwnedReceipt, o *GitOwnership) { o.Version = 0 },
		"stale state":        func(_ *GitChild, _ *GitOwnedReceipt, o *GitOwnership) { o.StateSHA256 = sha("a") },
		"rehashed same-model state replacement": func(r *GitChild, _ *GitOwnedReceipt, o *GitOwnership) {
			o.StateSHA256 = sha("a")
			r.Artifact.BeforeStateSHA256 = o.StateSHA256
		},
		"changed current Git": func(_ *GitChild, _ *GitOwnedReceipt, o *GitOwnership) { o.Revision = p.Manifest.Base },
		"stale observation":   func(_ *GitChild, _ *GitOwnedReceipt, o *GitOwnership) { o.ObservedAt = at.Add(-6 * time.Minute) },
		"unapplied":           func(_ *GitChild, a *GitOwnedReceipt, _ *GitOwnership) { a.Outcome = "UNKNOWN" },
		"old tree reset":      func(r *GitChild, _ *GitOwnedReceipt, _ *GitOwnership) { r.Artifact.Revision = p.Manifest.Base },
		"unchanged commit":    func(r *GitChild, _ *GitOwnedReceipt, _ *GitOwnership) { r.Artifact.Revision = ownership.Revision },
		"wrong inverse":       func(r *GitChild, _ *GitOwnedReceipt, _ *GitOwnership) { r.Artifact.After.CandidateCount = 1 },
		"forward entry borrowed": func(r *GitChild, _ *GitOwnedReceipt, _ *GitOwnership) {
			r.Artifact.ManifestEntrySHA256 = Digest(p.Manifest.Entries[1])
		},
	} {
		t.Run(name, func(t *testing.T) {
			rr, aa, oo := r, applied, ownership
			mutate(&rr, &aa, &oo)
			rr.OwnedReceiptSHA256 = Digest(aa)
			rr.OwnershipSHA256 = Digest(oo)
			if ValidateGitRecovery(rr, c, p, aa, oo, at) == nil {
				t.Fatal("accepted stale/unowned/non-inverse recovery")
			}
		})
	}
	if bytes.Equal(gitChildMessage(c, gitChildDomain), gitChildMessage(c, gitRecoveryDomain)) {
		t.Fatal("domains merged")
	}
}

func TestGitConcurrentBudgetAndStrictBoundedProgramDecoder(t *testing.T) {
	p, now, _, _ := gitProgramFixture(t)
	c := gitChildFixture(p, now, 2)
	if err := CheckGitConcurrentBudget(p, c, nil); err != nil {
		t.Fatal(err)
	}
	r := Reservation{Digest(p.Realm), p.Binding.Old.Target.TenantID, p.Binding.Old.Target.WorkloadID, "other-command", 1, 0}
	if CheckGitConcurrentBudget(p, c, []Reservation{r}) == nil {
		t.Fatal("concurrent capacity exceeded bound")
	}
	r.InFlight = 0
	r.Unavailable = 1
	if CheckGitConcurrentBudget(p, c, []Reservation{r}) == nil {
		t.Fatal("unavailable member ignored")
	}
	r.Unavailable = 0
	r.RealmSHA256 = sha("a")
	if CheckGitConcurrentBudget(p, c, []Reservation{r}) == nil {
		t.Fatal("foreign population accepted")
	}
	raw, _ := json.Marshal(p)
	if _, err := DecodeGitProgram(bytes.Repeat([]byte(" "), (256<<10)+1)); err == nil {
		t.Fatal("program bound ignored")
	}
	unknown := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unregistered_authority":true}`)...)
	if _, err := DecodeGitProgram(unknown); err == nil {
		t.Fatal("unknown program field accepted")
	}
}
