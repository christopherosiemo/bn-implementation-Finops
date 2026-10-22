package fleetgroup

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sha(letter string) string { return strings.Repeat(letter, 64) }

func programFixture() (Program, time.Time) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	realm := Realm{IsolatedFixture, "lab-service", "generation-a", sha("a")}
	selection := func(name, uuid string) Selection {
		return Selection{
			Target:       GroupTarget{"tenant-a", "workload-a", "AWS", "123456789012", "eu-west-1", "fleet-" + name, "arn:aws:autoscaling:eu-west-1:123456789012:autoScalingGroup:" + uuid + ":autoScalingGroupName/" + name},
			Registration: VersionedRef{"registration-" + name, 2, sha("b")}, Declaration: VersionedRef{"declaration-" + name, 3, sha("c")}, Scope: SnapshotRef{"scope-" + name, sha("d")},
			SourceID: "native-source", SourceRegistrationVersion: 4, SourceConfigSHA256: sha("e"),
		}
	}
	p := Program{
		SchemaVersion: SchemaVersion, Kind: Kind, ID: "program-a", Binding: Binding{selection("old", "11111111-1111-1111-1111-111111111111"), selection("candidate", "22222222-2222-2222-2222-222222222222")}, Realm: realm,
		CreatorID: "creator-a", Environment: "NON_PRODUCTION", Policy: Policy{"policy-a", 1, sha("f"), ApproverRole},
		ArtifactContext: ArtifactContext{Kind: BuiltinFixtureArtifact, ProviderSource: BuiltinProvider, RepositoryID: "repo-a", GitCommit: strings.Repeat("a", 40), GitTree: strings.Repeat("b", 40), ConfigurationSHA256: sha("c"), ToolchainImageSHA256: sha("d"), TerraformVersion: "1.16.0", PipelineID: "pipeline-a", Workspace: "lab", StateLineage: "lineage-a", InitialStateSerial: 7,
			Mapping: ModelMapping{"aws_autoscaling_group.old", "aws_autoscaling_group.candidate", "aws_lb_listener_rule.workload", "terraform_data.old", "terraform_data.candidate", "terraform_data.traffic"}},
		OldTemplate: Template{"lt-12345678", 2, "m6i.large", sha("e")}, CandidateTemplate: Template{"lt-87654321", 3, "m6i.medium", sha("f")},
		Budget: ModelBudget{CostBasis: FixtureModelCost, Currency: "USD", BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 0, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, OldHourlyCost: "0.5", CandidateHourlyCost: "0.3", MaximumModelCost: "100", MaximumDurationSeconds: 6 * 3600},
		Stages: DefaultStages(20), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(6 * time.Hour), Nonce: "parent-nonce-a",
	}
	for _, kind := range parentEvidence {
		p.Evidence = append(p.Evidence, EvidenceRef{kind, "receipt-" + strings.ToLower(kind), sha("a"), Digest(p.Binding), Digest(realm), now.Add(-time.Minute), now.Add(6 * time.Hour)})
	}
	return p, now
}

func copyProgram(p Program) Program {
	raw, _ := json.Marshal(p)
	var out Program
	_ = json.Unmarshal(raw, &out)
	return out
}

func childFixture(p Program, now time.Time) Child {
	before := ModelState{Digest(p.Binding), Digest(p.Realm), 20, 0, 0}
	after := before
	after.CandidateCount = 2
	c := Child{SchemaVersion: SchemaVersion, ID: "child-a", ParentID: p.ID, ParentSHA256: Digest(p), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), Mode: Forward,
		StageID: p.Stages[1].ID, StageSHA256: Digest(p.Stages[1]), Sequence: 2,
		Artifact: Artifact{Kind: BuiltinFixtureArtifact, Receipt: SnapshotRef{"artifact-a", sha("b")}, ContextSHA256: Digest(p.ArtifactContext), BeforeStateSerial: 7,
			BeforeStateSHA256: BytesDigest([]byte("unit-only-state")), SavedPlanSHA256: BytesDigest([]byte("unit-only-saved-plan")), PlanJSONSHA256: BytesDigest([]byte(`{"unit_only_plan":true}`)), Before: before, After: after},
		MinimumObservationSeconds: 120, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "child-nonce-a",
	}
	for _, kind := range childEvidence {
		c.Evidence = append(c.Evidence, EvidenceRef{kind, "receipt-" + strings.ToLower(kind), sha("b"), Digest(p.Binding), Digest(p.Realm), now, now.Add(15 * time.Minute)})
	}
	return c
}

func approvals(p Program, now time.Time) []Approval {
	return []Approval{{"approval-a", p.Binding.Old.Target.TenantID, "independent-approver", ApproverRole, Digest(p), Digest(p.Realm), now}}
}

func keyFixture() (ed25519.PublicKey, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	return key.Public().(ed25519.PublicKey), key
}

func TestGroupProgramUsesTwoPinnedGroupsAndRejectsCrossRealmOrInstanceBridge(t *testing.T) {
	p, now := programFixture()
	if err := ValidateProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal(err)
	}
	if n := MinimumProgramObservationSeconds(p); n != 9600 {
		t.Fatalf("default observation seconds=%d, want160minutes", n)
	}
	if n := MinimumProgramDuration(p); n != 17400 {
		t.Fatalf("default feasibility seconds=%d, want290minutes", n)
	}
	if Capabilities().CustomerNativeExecution || Capabilities().CustomerVerifiedSavings {
		t.Fatal("pure fixture family gained customer authority")
	}
	cases := map[string]func(*Program){
		"legacy schema":                 func(v *Program) { v.SchemaVersion = "4" },
		"customer realm":                func(v *Program) { v.Realm.Kind = "CUSTOMER_NATIVE" },
		"production":                    func(v *Program) { v.Environment = "PRODUCTION" },
		"foreign workload":              func(v *Program) { v.Binding.Candidate.Target.WorkloadID = "another" },
		"foreign account ARN":           func(v *Program) { v.Binding.Candidate.Target.AccountID = "999999999999" },
		"other region":                  func(v *Program) { v.Binding.Old.Target.Region = "us-east-1" },
		"same ASG":                      func(v *Program) { v.Binding.Candidate.Target.ASGARN = v.Binding.Old.Target.ASGARN },
		"same registration":             func(v *Program) { v.Binding.Candidate.Registration.ID = v.Binding.Old.Registration.ID },
		"unversioned declaration":       func(v *Program) { v.Binding.Candidate.Declaration.Version = 0 },
		"missing source config":         func(v *Program) { v.Binding.Old.SourceConfigSHA256 = "" },
		"missing scope":                 func(v *Program) { v.Binding.Old.Scope.ID = "" },
		"AWS provider masquerade":       func(v *Program) { v.ArtifactContext.ProviderSource = "registry.terraform.io/hashicorp/aws" },
		"AWS model address":             func(v *Program) { v.ArtifactContext.Mapping.OldModel = "aws_autoscaling_group.old" },
		"duplicate model address":       func(v *Program) { v.ArtifactContext.Mapping.TrafficModel = v.ArtifactContext.Mapping.CandidateModel },
		"unsafe address prefix":         func(v *Program) { v.ArtifactContext.Mapping.OldDeclaredASG = "garbage.aws_autoscaling_group.old" },
		"missing template hash":         func(v *Program) { v.CandidateTemplate.SHA256 = "" },
		"forged fixture evidence realm": func(v *Program) { v.Evidence[0].RealmSHA256 = sha("f") },
		"borrowed evidence group pair":  func(v *Program) { v.Evidence[0].BindingSHA256 = sha("f") },
		"unknown authority receipt":     func(v *Program) { v.Evidence[0].Kind = "NATIVE_HISTORY" },
		"missing evidence":              func(v *Program) { v.Evidence = v.Evidence[:len(v.Evidence)-1] },
		"short-lived evidence":          func(v *Program) { v.Evidence[0].ValidUntil = now.Add(5 * time.Minute) },
		"shortened canary":              func(v *Program) { v.Stages[1].MinimumObservationSeconds = 120 },
		"shortened terminal":            func(v *Program) { v.Stages[4].MinimumObservationSeconds = 120 },
		"duration omits intermediates":  func(v *Program) { v.Budget.MaximumDurationSeconds = 7200 },
		"oversized initial blast":       func(v *Program) { v.Budget.MaxInFlight = 3 },
		"integer overflow blast":        func(v *Program) { v.Budget.MaxInFlight = int(^uint(0) >> 1) },
		"fake model spend cap":          func(v *Program) { v.Budget.CostBasis = "AWS_SPEND_CAP" },
		"rounded native rate":           func(v *Program) { v.Budget.CandidateHourlyCost = "0.1234567890123" },
		"underfunded model envelope":    func(v *Program) { v.Budget.MaximumModelCost = "95.999999999999" },
		"expired":                       func(v *Program) { v.ExpiresAt = now },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v := copyProgram(p)
			change(&v)
			if err := ValidateProgram(v, Expected{v.Binding, v.Realm}, now); err == nil {
				t.Fatal("accepted invalid program")
			}
		})
	}
	expected := Expected{p.Binding, p.Realm}
	expected.Realm.Generation = "generation-b"
	if ValidateProgram(p, expected, now) == nil {
		t.Fatal("accepted another configured generation")
	}
	raw, _ := json.Marshal(p)
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"tenant_id":"tenant-a"`, `"resource_id":"representative-ec2","tenant_id":"tenant-a"`, 1)), []byte(strings.Replace(string(raw), `"schema_version":"5"`, `"schema_version":"5","schema_version":"4"`, 1)), append(append([]byte{}, raw...), []byte(` {}`)...), bytesOf(256<<10 + 1)} {
		if _, err := DecodeProgram(bad); err == nil {
			t.Fatal("accepted instance field, duplicate, trailing or oversized JSON")
		}
	}
	decoded, err := DecodeProgram(raw)
	if err != nil || Digest(decoded) != Digest(p) {
		t.Fatalf("typed exact JSON changed: %v", err)
	}
}

func bytesOf(n int) []byte { return []byte(strings.Repeat(" ", n)) }

func TestGroupExactDecimalsAndSignedLifetimeCoverFullDefaultProgram(t *testing.T) {
	p, now := programFixture()
	p.Budget.MaximumModelCost = "96"
	if err := ValidateProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal(err)
	}
	p.Budget.MaximumModelCost = "95.999999999999"
	if ValidateProgram(p, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("rounded fractional model deficit")
	}
	p, now = programFixture()
	p.Budget.MaximumDurationSeconds = 9600
	if ValidateProgram(p, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("no processing time allowed beyond mandatory observations")
	}
	p.Budget.MaximumDurationSeconds++
	if ValidateProgram(p, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("one second margin accepted for26 independently authorized commands")
	}
	p.Budget.MaximumDurationSeconds = MinimumProgramDuration(p)
	if err := ValidateProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal("exact conservative feasibility floor:", err)
	}
	p, now = programFixture()
	p.ExpiresAt = ForwardDeadline(p).Add(-time.Nanosecond)
	if ValidateProgram(p, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("accepted expiry before program end")
	}
	p, now = programFixture()
	p.Evidence[0].ValidUntil = ForwardDeadline(p)
	if err := ValidateProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal("exact inclusive immutable evidence horizon:", err)
	}
}

func TestGroupChildSeparatesCapacityTrafficAndFullWindowAndBindsExactBytes(t *testing.T) {
	p, now := programFixture()
	c := childFixture(p, now)
	if err := ValidateChild(c, p, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactBytes(c.Artifact, []byte("unit-only-saved-plan"), []byte(`{"unit_only_plan":true}`), []byte("unit-only-state")); err != nil {
		t.Fatal(err)
	}
	if VerifyArtifactBytes(c.Artifact, []byte("another-saved-plan"), []byte(`{"unit_only_plan":true}`), []byte("unit-only-state")) == nil {
		t.Fatal("accepted different exact artifact")
	}
	cases := map[string]func(*Child){
		"cross generation":               func(v *Child) { v.RealmSHA256 = sha("f") },
		"foreign parent":                 func(v *Child) { v.ParentID = "other" },
		"borrowed declaration":           func(v *Child) { v.BindingSHA256 = sha("f") },
		"reused parent nonce":            func(v *Child) { v.Nonce = p.Nonce },
		"past child":                     func(v *Child) { v.CreatedAt = now.Add(-6 * time.Minute) },
		"expiry before creation":         func(v *Child) { v.CreatedAt = now.Add(4 * time.Second); v.ExpiresAt = now.Add(3 * time.Second) },
		"stale source":                   func(v *Child) { v.Evidence[0].ObservedAt = now.Add(-5*time.Minute - time.Nanosecond) },
		"short receipt horizon":          func(v *Child) { v.Evidence[0].ValidUntil = v.ExpiresAt.Add(-time.Nanosecond) },
		"unversioned artifact":           func(v *Child) { v.Artifact.Receipt.SHA256 = "" },
		"different toolchain":            func(v *Child) { v.Artifact.ContextSHA256 = sha("f") },
		"old state serial":               func(v *Child) { v.Artifact.BeforeStateSerial = 6 },
		"oversized child":                func(v *Child) { v.Artifact.After.CandidateCount = 3 },
		"traffic during capacity change": func(v *Child) { v.Artifact.After.CandidateTrafficPercent = 10 },
		"early old drain":                func(v *Child) { v.Artifact.After.OldCount = 19 },
		"undersized intermediate window": func(v *Child) { v.MinimumObservationSeconds = 119 },
		"recovery masquerading forward":  func(v *Child) { v.Mode = OwnedRecovery },
		"undeclared compensation":        func(v *Child) { v.CompensationFor = "other" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var v Child
			_ = json.Unmarshal(raw, &v)
			change(&v)
			if ValidateChild(v, p, now) == nil {
				t.Fatal("accepted unsafe child")
			}
		})
	}
	terminal := c
	terminal.Artifact.Before = c.Artifact.After
	terminal.Artifact.After = terminal.Artifact.Before
	terminal.Artifact.After.CandidateTrafficPercent = 10
	if ValidateChild(terminal, p, now) == nil {
		t.Fatal("canary accepted intermediate120s window")
	}
	terminal.MinimumObservationSeconds = 3600
	if err := ValidateChild(terminal, p, now); err != nil {
		t.Fatal(err)
	}
	drain := c
	drain.StageID = p.Stages[5].ID
	drain.StageSHA256 = Digest(p.Stages[5])
	drain.Artifact.Before = ModelState{Digest(p.Binding), Digest(p.Realm), 2, 20, 100}
	drain.Artifact.After = drain.Artifact.Before
	drain.Artifact.After.OldCount = 0
	if ValidateChild(drain, p, now) == nil {
		t.Fatal("final drain lost signed terminal window")
	}
	drain.MinimumObservationSeconds = 900
	if err := ValidateChild(drain, p, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckConcurrentBudget(p, c, nil); err != nil {
		t.Fatal(err)
	}
	r := Reservation{Digest(p.Realm), p.Binding.Old.Target.TenantID, p.Binding.Old.Target.WorkloadID, "other-command", 1, 0}
	if CheckConcurrentBudget(p, c, []Reservation{r}) == nil {
		t.Fatal("ignored concurrent workload reservation")
	}
	r.InFlight = 0
	r.RealmSHA256 = sha("f")
	if CheckConcurrentBudget(p, c, []Reservation{r}) == nil {
		t.Fatal("accepted cross-realm reservation population")
	}
}

func TestGroupParentAndChildSignatureDomainsRejectLegacyReplayAndApprovalChanges(t *testing.T) {
	p, now := programFixture()
	pub, key := keyFixture()
	a := approvals(p, now)
	e, err := Sign(p, a, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(e, pub, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal(err)
	}
	c := childFixture(p, now)
	signed, err := SignChild(c, e, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyChild(signed, e, pub, Expected{p.Binding, p.Realm}, now); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"finops/fleet/v4/parent\x00", "finops/fleet/v4/child\x00", "finops/fleet/v4/owned-recovery\x00", recoveryDomain} {
		bad := e
		raw := parentMessage(p, a)[len(parentDomain):]
		bad.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), raw...)))
		if Verify(bad, pub, Expected{p.Binding, p.Realm}, now) == nil {
			t.Fatal("accepted another signature domain")
		}
	}
	badChild := signed
	badChild.Algorithm = recoveryAlgorithm
	if VerifyChild(badChild, e, pub, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("accepted recovery as a new forward signature")
	}
	badParent := e
	badParent.Approvals = append([]Approval{}, e.Approvals...)
	badParent.Approvals[0].ActorID = "another"
	if Verify(badParent, pub, Expected{p.Binding, p.Realm}, now) == nil {
		t.Fatal("approval not signed")
	}
	for _, change := range []func([]Approval){func(a []Approval) { a[0].ActorID = p.CreatorID }, func(a []Approval) { a[0].TenantID = "foreign" }, func(a []Approval) { a[0].RealmSHA256 = sha("f") }, func(a []Approval) { a[0].ApprovedAt = p.CreatedAt.Add(-time.Nanosecond) }} {
		v := approvals(p, now)
		change(v)
		if _, err = Sign(p, v, key, now); err == nil {
			t.Fatal("accepted invalid independent approval")
		}
	}
	duplicateActor := append(approvals(p, now), approvals(p, now)[0])
	duplicateActor[1].ID = "approval-b"
	if _, err = Sign(p, duplicateActor, key, now); err == nil {
		t.Fatal("counted same approver twice")
	}
	if _, err = Sign(p, a, nil, now); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestGroupOwnedInverseSurvivesForwardExpiryButCannotAuthorizeAnotherForwardChild(t *testing.T) {
	p, now := programFixture()
	pub, key := keyFixture()
	parent, err := Sign(p, approvals(p, now), key, now)
	if err != nil {
		t.Fatal(err)
	}
	original := childFixture(p, now)
	signed, err := SignChild(original, parent, key, now)
	if err != nil {
		t.Fatal(err)
	}
	owned := OwnedReceipt{SchemaVersion: SchemaVersion, ID: "owned-a", CommandID: "command-a", ParentID: p.ID, ParentSHA256: Digest(p), ChildID: original.ID, ChildSHA256: Digest(original), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), ArtifactSHA256: Digest(original.Artifact), SavedPlanSHA256: original.Artifact.SavedPlanSHA256, PipelineID: p.ArtifactContext.PipelineID, Outcome: "APPLIED", BeforeStateSerial: 7, AfterStateSerial: 8, AfterModelSHA256: Digest(original.Artifact.After), ReceivedAt: now.Add(time.Second)}
	later := now.Add(7 * time.Hour)
	recovery := original
	recovery.ID = "recovery-a"
	recovery.Mode = OwnedRecovery
	recovery.Sequence++
	recovery.Nonce = "recovery-nonce-a"
	recovery.CompensationFor = original.ID
	recovery.OwnedReceiptSHA256 = Digest(owned)
	recovery.CreatedAt = later
	recovery.ExpiresAt = later.Add(10 * time.Minute)
	recovery.Artifact.BeforeStateSerial = 8
	recovery.Artifact.BeforeStateSHA256 = sha("d")
	recovery.Artifact.Receipt = SnapshotRef{"recovery-artifact", sha("c")}
	recovery.Artifact.SavedPlanSHA256 = sha("d")
	recovery.Artifact.PlanJSONSHA256 = sha("e")
	recovery.Artifact.Before = original.Artifact.After
	recovery.Artifact.After = original.Artifact.Before
	recovery.Evidence = nil
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
		recovery.Evidence = append(recovery.Evidence, EvidenceRef{kind, "current-" + strings.ToLower(kind), sha("a"), Digest(p.Binding), Digest(p.Realm), later, later.Add(15 * time.Minute)})
	}
	if _, err = SignChild(original, parent, key, later); err == nil {
		t.Fatal("expired parent authorized forward")
	}
	result, err := SignRecovery(recovery, signed, parent, owned, key, later)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyRecovery(result, signed, parent, owned, pub, Expected{p.Binding, p.Realm}, later); err != nil {
		t.Fatal(err)
	}
	if VerifyChild(result, parent, pub, Expected{p.Binding, p.Realm}, later) == nil {
		t.Fatal("owned inverse became forward authority")
	}
	for name, change := range map[string]func(*Child, *OwnedReceipt){
		"not exact inverse":     func(c *Child, o *OwnedReceipt) { c.Artifact.After.CandidateCount = 1 },
		"different owned child": func(c *Child, o *OwnedReceipt) { o.ChildID = "other" },
		"unknown apply":         func(c *Child, o *OwnedReceipt) { o.Outcome = "UNKNOWN" },
		"no state movement":     func(c *Child, o *OwnedReceipt) { o.AfterStateSerial = o.BeforeStateSerial },
		"different pipeline":    func(c *Child, o *OwnedReceipt) { o.PipelineID = "other" },
		"different artifact":    func(c *Child, o *OwnedReceipt) { o.SavedPlanSHA256 = sha("f") },
		"different generation":  func(c *Child, o *OwnedReceipt) { o.RealmSHA256 = sha("f") },
		"old state serial":      func(c *Child, o *OwnedReceipt) { c.Artifact.BeforeStateSerial = 7 },
		"stale recovery source": func(c *Child, o *OwnedReceipt) { c.Evidence[0].ObservedAt = later.Add(-6 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(recovery)
			var c Child
			_ = json.Unmarshal(raw, &c)
			o := owned
			change(&c, &o)
			if ValidateRecovery(c, original, p, o, later) == nil {
				t.Fatal("unsafe owned inverse accepted")
			}
		})
	}
}

// This is a pure transition-algebra test. It does not wait for health, issue
// receipts, run a pipeline or claim the separate real-clock3h acceptance gate.
func TestGroupDefaultTransitionAlgebraRetains26BoundedChildrenAnd160Minutes(t *testing.T) {
	p, now := programFixture()
	state := ModelState{Digest(p.Binding), Digest(p.Realm), 20, 0, 0}
	sequence, seconds := 0, int64(0)
	apply := func(stageIndex, old, candidate, traffic int, observation int64) {
		t.Helper()
		sequence++
		c := childFixture(p, now)
		c.ID = "child-" + strings.Repeat("x", sequence)
		c.Nonce = "nonce-" + c.ID
		c.Sequence = uint64(sequence)
		c.StageID = p.Stages[stageIndex].ID
		c.StageSHA256 = Digest(p.Stages[stageIndex])
		c.Artifact.Before = state
		c.Artifact.After = ModelState{Digest(p.Binding), Digest(p.Realm), old, candidate, traffic}
		c.Artifact.BeforeStateSerial = uint64(6 + sequence)
		c.MinimumObservationSeconds = observation
		if err := ValidateChild(c, p, now); err != nil {
			t.Fatalf("child%d stage%s: %v", sequence, c.StageID, err)
		}
		state = c.Artifact.After
		seconds += observation
	}
	apply(0, 20, 0, 0, 0)
	for i := 1; i < 5; i++ {
		for state.CandidateCount < p.Stages[i].TargetCandidateCount {
			apply(i, state.OldCount, min(state.CandidateCount+2, p.Stages[i].TargetCandidateCount), state.CandidateTrafficPercent, 120)
		}
		apply(i, state.OldCount, state.CandidateCount, p.Stages[i].TargetTrafficPercent, p.Stages[i].MinimumObservationSeconds)
	}
	for state.OldCount > 0 {
		next := max(0, state.OldCount-2)
		observation := int64(120)
		if next == 0 {
			observation = p.Stages[5].MinimumObservationSeconds
		}
		apply(5, next, 20, 100, observation)
	}
	if sequence != 26 || seconds != 9600 || state.OldCount != 0 || state.CandidateCount != 20 || state.CandidateTrafficPercent != 100 {
		t.Fatalf("protocol changed: children=%d observation=%d state=%+v", sequence, seconds, state)
	}
}
