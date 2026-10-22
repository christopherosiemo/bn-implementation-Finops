package fleet

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixturePlan(now time.Time) FleetPlanV4 {
	p := FleetPlanV4{SchemaVersion: "4", Kind: Kind, ID: "fleet-plan", Binding: Binding{"tenant", "fleet-resource", "workload", "AWS", "asg-blue", "111122223333", "eu-west-1"}, CreatorID: "requester", Environment: "NON_PRODUCTION", IaC: IaCBinding{"TERRAFORM", "https://github.com/customer/config", strings.Repeat("a", 40), "sandbox", "state-lineage", 10, strings.Repeat("b", 64), "1.13.3", "customer-pipeline"}, Governance: Governance{"R2", true, "fleet-policy", 1, strings.Repeat("c", 64), ApproverRole}, Old: Cohort{"asg-blue", "aws_autoscaling_group.blue", "aws_launch_template.blue", 1, "m6i.4xlarge", 20, true, false, false}, Candidate: Cohort{"asg-green", "aws_autoscaling_group.green", "aws_launch_template.green", 2, "m6i.2xlarge", 0, true, false, false}, Traffic: TrafficControl{"CUSTOMER_TERRAFORM_PIPELINE", "aws_lb_listener_rule.app", "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/blue/id", "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/green/id"}, Budget: Budget{20, 2, 2, 100000, 20, "GBP", "60", "0.4", "0.2", 18000}, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(6 * time.Hour), Nonce: "parent-nonce"}
	for _, kind := range parentProofKinds {
		p.Proofs = append(p.Proofs, ProofRef{kind, kind + "-id", "1", strings.Repeat("d", 64), now.Add(-2 * time.Minute), now.Add(6 * time.Hour)})
	}
	p.Stages = DefaultStages(p, true)
	return p
}
func fixtureChild(p FleetPlanV4, stage int, now time.Time) ChildPlan {
	s := p.Stages[stage]
	iac := p.IaC
	iac.ConfigurationSHA256 = s.ConfigurationSHA256
	c := ChildPlan{SchemaVersion: "4", ID: "child-plan", ParentID: p.ID, ParentSHA256: Digest(p), StageID: s.ID, StageSHA256: Digest(s), Sequence: 1, Binding: p.Binding, IaC: iac, SavedPlanSHA256: BytesDigest([]byte("binary-plan")), PlanJSONSHA256: strings.Repeat("f", 64), Changes: []AllowedChange{}, Transition: Transition{20, 20, 0, 2, 0, 0, 2, 0}, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "child-nonce"}
	for _, kind := range append(append([]string{}, childProofKinds...), "CANDIDATE_HEALTH") {
		c.Proofs = append(c.Proofs, ProofRef{kind, kind + "-id", "1", strings.Repeat("d", 64), now.Add(-time.Minute), now.Add(time.Hour)})
	}
	return c
}
func clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func requireRejected(t *testing.T, e error) {
	t.Helper()
	if e == nil {
		t.Fatal("unsafe plan accepted")
	}
}

func TestFleetPlanBindsR2EvidenceAuthorityCostAndDistinctStatelessCohorts(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	p := fixturePlan(now)
	if e := ValidatePlan(p, p.Binding, now); e != nil {
		t.Fatal(e)
	}
	cost, e := WorstCaseCost(p.Budget)
	if e != nil || cost != "60.000000000000" {
		t.Fatal("retained old/surge cost omitted", cost, e)
	}
	for name, mutate := range map[string]func(*FleetPlanV4){
		"R1 policy": func(p *FleetPlanV4) { p.Governance.RiskClass = "R1" }, "same cohort": func(p *FleetPlanV4) { p.Candidate.ASGAddress = p.Old.ASGAddress }, "production": func(p *FleetPlanV4) { p.Environment = "PRODUCTION" }, "missing history": func(p *FleetPlanV4) { p.Proofs = p.Proofs[1:] }, "unknown IaC": func(p *FleetPlanV4) { p.IaC.Authority = "UNKNOWN" }, "data volume": func(p *FleetPlanV4) { p.Candidate.DataVolumes = true }, "autoscaling": func(p *FleetPlanV4) { p.Candidate.IndependentScaling = true }, "initial live candidate": func(p *FleetPlanV4) { p.Candidate.DesiredCount = 2 }, "unpinned LT": func(p *FleetPlanV4) { p.Candidate.LaunchTemplateVersion = 0 }, "oversized canary": func(p *FleetPlanV4) { p.Budget.MaxInFlight = 3 }, "cost underbudget": func(p *FleetPlanV4) { p.Budget.MaximumCost = "11.999999999999" }, "surge omitted": func(p *FleetPlanV4) { p.Budget.MaxSurgeCount = 2 }, "wrong account target": func(p *FleetPlanV4) {
			p.Traffic.CandidateTargetGroupARN = strings.ReplaceAll(p.Traffic.CandidateTargetGroupARN, "111122223333", "999988887777")
		}, "bad DAG": func(p *FleetPlanV4) { p.Stages[2].DependsOn = []string{p.Stages[0].ID} }, "unreviewed cleanup": func(p *FleetPlanV4) { p.Stages[5].CleanupReviewed = false }, "missing intermediates": func(p *FleetPlanV4) { p.Stages[2].IntermediateCandidateCounts = []int{2, 5} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone(p)
			mutate(&changed)
			requireRejected(t, ValidatePlan(changed, changed.Binding, now))
		})
	}
	raw, _ := json.Marshal(p)
	raw = append(raw[:len(raw)-1], []byte(`,"execution_ready":true}`)...)
	if _, e := DecodePlan(raw); e == nil {
		t.Fatal("unknown approval boolean accepted")
	}
}
func TestFleetExpansionSplitsRemaindersAndTrafficWaitsForHealthyCapacity(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	for stage, want := range map[int][]int{1: {0, 2}, 2: {2, 4, 5}, 3: {5, 7, 9, 10}, 4: {10, 12, 14, 16, 18, 20}} {
		if !sameInts(p.Stages[stage].IntermediateCandidateCounts, want) {
			t.Fatal("parent omitted deterministic remainder", stage)
		}
		for i := 1; i < len(want); i++ {
			c := fixtureChild(p, stage, now)
			c.Transition = Transition{20, 20, want[i-1], want[i], 0, 0, want[i] - want[i-1], 0}
			if e := ValidateChild(c, p, now); e != nil {
				t.Fatalf("stage%d step%d: %v", stage, i, e)
			}
		}
	}
	c := fixtureChild(p, 2, now)
	c.Transition = Transition{20, 20, 2, 5, 10, 10, 3, 0}
	requireRejected(t, ValidateChild(c, p, now))
	c = fixtureChild(p, 1, now)
	c.Transition.TrafficAfter = 10
	requireRejected(t, ValidateChild(c, p, now))
	c = fixtureChild(p, 1, now)
	c.Transition = Transition{20, 20, 2, 2, 0, 10, 0, 0}
	if e := ValidateChild(c, p, now); e != nil {
		t.Fatal(e)
	}
	c.Proofs = c.Proofs[:len(c.Proofs)-1]
	requireRejected(t, ValidateChild(c, p, now))
	c = fixtureChild(p, 1, now)
	c.CreatedAt = now.Add(-6 * time.Minute)
	requireRejected(t, ValidateChild(c, p, now))
}

func TestFleetImmutableParentAuthoritiesCoverTheEntireModeledProgram(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	p := fixturePlan(now)
	programEnd := p.CreatedAt.Add(time.Duration(p.Budget.MaximumDurationSeconds) * time.Second)
	for i, proof := range p.Proofs {
		t.Run(proof.Kind+"-expires-before-program-end", func(t *testing.T) {
			changed := clone(p)
			changed.Proofs[i].ExpiresAt = programEnd.Add(-time.Nanosecond)
			if e := ValidatePlan(changed, changed.Binding, now); e == nil || e.Error() != "FLEET_PARENT_PROOF_DURATION_INSUFFICIENT" {
				t.Fatal("immutable authority would expire before the modeled program ends", e)
			}
		})
	}
	// Equality covers every permitted forward instant: no new forward action
	// may begin at or after the cost-duration deadline itself.
	for i := range p.Proofs {
		p.Proofs[i].ExpiresAt = programEnd
	}
	p.ExpiresAt = programEnd
	if e := ValidatePlan(p, p.Binding, now); e != nil {
		t.Fatal("exact full-duration authority coverage rejected", e)
	}
	p.ExpiresAt = p.CreatedAt.Add(24 * time.Hour)
	if e := ValidatePlan(p, p.Binding, now); e != nil {
		t.Fatal("proof validity was incorrectly extended to unused parent TTL", e)
	}
	p.ExpiresAt = programEnd.Add(-time.Nanosecond)
	if e := ValidatePlan(p, p.Binding, now); e == nil || e.Error() != "FLEET_BLAST_OR_COST_BUDGET_INVALID" {
		t.Fatal("parent expires before its modeled program ends", e)
	}
}

func TestFleetProgramDurationIncludesEveryIntermediateHealthAndDelivery(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	for _, test := range []struct {
		cleanup bool
		want    int64
	}{{false, 12420}, {true, 17400}} {
		p.Stages = DefaultStages(p, test.cleanup)
		got, err := MinimumProgramDuration(p)
		if err != nil || got != test.want {
			t.Fatal("capacity substeps, traffic dwell, drain or delivery margin omitted", got, err)
		}
		p.Budget.MaximumDurationSeconds = test.want - 1
		if err = ValidatePlan(p, p.Binding, now); err == nil || err.Error() != "FLEET_INTERMEDIATE_HEALTH_AND_DELIVERY_EXCEED_DURATION_BUDGET" {
			t.Fatal("unfinishable modeled program accepted", err)
		}
		p.Budget.MaximumDurationSeconds = test.want
		if err = ValidatePlan(p, p.Binding, now); err != nil {
			t.Fatal("exact minimum modeled duration rejected", err)
		}
	}
	// A former two-hour program is short even though its terminal stage dwell
	// alone fits; hard2-instance expansion increments remain unchanged.
	p.Stages = DefaultStages(p, false)
	p.Budget.MaximumDurationSeconds = 7200
	if err := ValidatePlan(p, p.Binding, now); err == nil {
		t.Fatal("terminal-only duration estimate accepted")
	}
}
func TestFleetConcurrentBudgetIsPerTenantWorkloadAndNeverNativeTimerBased(t *testing.T) {
	p := fixturePlan(time.Now().UTC())
	next := Transition{InFlight: 2}
	requireRejected(t, CheckConcurrentBudget(p, next, []Flight{{"other-flight", "tenant", "workload", 1, 0}}))
	if e := CheckConcurrentBudget(p, next, []Flight{{"independent-workload", "tenant", "another-workload", 2, 2}}); e != nil {
		t.Fatal("independent workload budget coupled", e)
	}
	requireRejected(t, CheckConcurrentBudget(p, next, []Flight{{"foreign", "foreign-tenant", "workload", 0, 0}}))
}

func TestFleetForwardDeadlineAndObservationBudgetAreIndependentFromRecovery(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	p.ExpiresAt = p.CreatedAt.Add(24 * time.Hour)
	deadline := p.CreatedAt.Add(time.Duration(p.Budget.MaximumDurationSeconds) * time.Second)
	if !ForwardDeadline(p).Equal(deadline) {
		t.Fatal("modeled duration did not bound longer parent TTL")
	}
	if e := ValidatePlan(p, p.Binding, deadline); e == nil || e.Error() != "FLEET_COST_DURATION_EXPIRED" {
		t.Fatal("duration exhaustion did not fail closed", e)
	}
	tooShort := clone(p)
	tooShort.Budget.MaximumDurationSeconds = 7199
	if e := ValidatePlan(tooShort, tooShort.Binding, now); e == nil || e.Error() != "FLEET_OBSERVATIONS_EXCEED_DURATION_BUDGET" {
		t.Fatal("impossible observation schedule accepted", e)
	}
	shortTTL := clone(p)
	shortTTL.ExpiresAt = now.Add(time.Minute)
	if !ForwardDeadline(shortTTL).Equal(shortTTL.ExpiresAt) {
		t.Fatal("parent expiry was extended by cost deadline")
	}
	c := fixtureChild(p, 1, now)
	c.CreatedAt = deadline.Add(-time.Minute)
	c.ExpiresAt = deadline.Add(time.Minute)
	if e := ValidateChild(c, p, deadline.Add(-time.Minute)); e == nil {
		t.Fatal("child expiry extended modeled duration")
	}
}
func TestFleetV4SignaturesBindApproverAndDoNotReuseV3OrParentAuthority(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	approval := Approval{"approval", "tenant", "independent-approver", ApproverRole, Digest(p), now}
	envelope, e := Sign(p, []Approval{approval}, private, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = Verify(envelope, public, p.Binding, now); e != nil {
		t.Fatal(e)
	}
	c := fixtureChild(p, 1, now)
	child, e := SignChild(c, envelope, private, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyChild(child, envelope, public, p.Binding, now); e != nil {
		t.Fatal(e)
	}
	modified := clone(child)
	modified.Plan.SavedPlanSHA256 = strings.Repeat("a", 64)
	requireRejected(t, VerifyChild(modified, envelope, public, p.Binding, now))
	copied := child
	copied.Signature = envelope.Signature
	requireRejected(t, VerifyChild(copied, envelope, public, p.Binding, now))
	wrong := p.Binding
	wrong.AccountID = "999988887777"
	requireRejected(t, VerifyChild(child, envelope, public, wrong, now))
	for _, actor := range []Approval{{"approval", "tenant", "requester", ApproverRole, Digest(p), now}, {"approval", "tenant", "operator", "operator", Digest(p), now}} {
		_, e = Sign(p, []Approval{actor}, private, now)
		requireRejected(t, e)
	}
	requireRejected(t, Verify(envelope, public, p.Binding, p.ExpiresAt.Add(time.Second)))
}
func TestFleetRecoveryPreservesUnknownOwnershipAndRequiresFreshCompensation(t *testing.T) {
	for _, e := range []DispatchEvidence{{IntentRecorded: true}, {IntentRecorded: true, Dispatched: true}, {IntentRecorded: true, Dispatched: true, OutcomeKnown: false, Owned: true}} {
		if r := Recovery(e); r.Status != "RECONCILE" {
			t.Fatal("unknown provider outcome redispatched", r)
		}
	}
	if r := Recovery(DispatchEvidence{OutcomeKnown: true}); r.Status != "BLOCKED" {
		t.Fatal("unowned recovery authorized")
	}
	if r := Recovery(DispatchEvidence{OutcomeKnown: true, Owned: true, ReceiptID: "receipt", ReceiptSHA256: strings.Repeat("a", 64)}); r.Status != "RESTORE_OWNED" {
		t.Fatal(r)
	}
}

func TestFleetOwnedRecoveryRequiresExactReceiptAndFreshInverseDespiteExpiredParent(t *testing.T) {
	initial := time.Now().UTC()
	p := fixturePlan(initial)
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	parent, e := Sign(p, []Approval{{"approval", "tenant", "approver", ApproverRole, Digest(p), initial}}, private, initial)
	if e != nil {
		t.Fatal(e)
	}
	forward := terraformChild(p, 1, initial)
	original, e := SignChild(forward, parent, private, initial)
	if e != nil {
		t.Fatal(e)
	}
	owned := OwnedReceipt{"immutable-observer-receipt", p.ID, forward.ID, Digest(forward), p.Binding, p.IaC.PipelineID, forward.SavedPlanSHA256, "APPLIED", forward.IaC.StateSerial, forward.IaC.StateSerial + 1, initial.Add(time.Minute)}
	now := p.ExpiresAt.Add(time.Hour)
	c := clone(forward)
	c.ID = "fresh-recovery"
	c.CreatedAt = now
	c.ExpiresAt = now.Add(10 * time.Minute)
	c.Nonce = "recovery-nonce"
	c.CompensationFor = forward.ID
	c.CompensationReceiptSHA256 = Digest(owned)
	c.Proofs = nil
	c.IaC.StateSerial = owned.AfterStateSerial
	c.Transition = Transition{20, 20, 2, 0, 0, 0, 2, 0}
	for i := range c.Changes[0].Fields {
		before := c.Changes[0].Fields[i].Before
		c.Changes[0].Fields[i].Before = c.Changes[0].Fields[i].After
		c.Changes[0].Fields[i].After = before
	}
	recovery, e := SignRecovery(c, original, parent, owned, private, now)
	if e != nil {
		t.Fatal("owned recovery blocked by expired forward authority", e)
	}
	if e = VerifyRecovery(recovery, original, parent, owned, public, p.Binding, now); e != nil {
		t.Fatal(e)
	}
	_, e = SignChild(c, parent, private, now)
	requireRejected(t, e)
	for name, mutate := range map[string]func(*ChildPlan, *OwnedReceipt){"unknown outcome": func(c *ChildPlan, r *OwnedReceipt) { r.Status = "UNKNOWN"; c.CompensationReceiptSHA256 = Digest(*r) }, "foreign receipt": func(c *ChildPlan, r *OwnedReceipt) {
		r.Binding.TenantID = "foreign"
		c.CompensationReceiptSHA256 = Digest(*r)
	}, "fresh expansion": func(c *ChildPlan, r *OwnedReceipt) { c.Transition.CandidateAfter = 4 }, "wrong inverse value": func(c *ChildPlan, r *OwnedReceipt) { c.Changes[0].Fields[0].After = CanonicalJSON(1) }, "stale recovery": func(c *ChildPlan, r *OwnedReceipt) { c.CreatedAt = now.Add(-6 * time.Minute) }} {
		t.Run(name, func(t *testing.T) {
			changed, receipt := clone(c), owned
			mutate(&changed, &receipt)
			_, e := SignRecovery(changed, original, parent, receipt, private, now)
			requireRejected(t, e)
		})
	}
}
