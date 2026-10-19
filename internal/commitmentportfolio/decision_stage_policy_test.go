package commitmentportfolio

import (
	"context"
	"encoding/json"
	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	c "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecision"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Reuse the existing037 consistency fixture shape to exercise the ACTUAL Build
// decoder/arithmetic, rather than supply a PASS/FAIL label. These are explicit
// synthetic unit inputs, not persisted/native receipts or customer authority.
var stageStoredDimensions = []struct{ name, unit string }{{"cpu", "vCPU"}, {"memory", "bytes"}, {"network", "bytes/second"}, {"storage_iops", "operations/second"}, {"storage_throughput", "bytes/second"}}

type stageStoredCheck struct {
	Dimension string `json:"dimension"`
	Unit      string `json:"unit"`
	Capacity  string `json:"candidate_capacity"`
	P99       string `json:"observed_p99"`
	Forecast  string `json:"forecast_requirement"`
	Required  string `json:"required_with_reserve"`
	Reserve   int64  `json:"reserve_above_forecast_ppm"`
	Unused    int64  `json:"unused_capacity_ppm"`
	P95       *int64 `json:"observed_p95_utilization_ppm"`
	P95Limit  *int64 `json:"p95_planning_limit_ppm"`
	Rollback  *int64 `json:"p99_rollback_limit_ppm"`
	Projected int64  `json:"projected_p99_utilization_ppm"`
	Breaches  *int64 `json:"observed_capacity_breach_ppm"`
	Status    string `json:"status"`
}

func stageStoredCapacity(p native.PhysicalCapacity, name string) *string {
	switch name {
	case "cpu":
		return p.CPU
	case "memory":
		return p.Memory
	case "network":
		return p.Network
	case "storage_iops":
		return p.StorageIOPS
	default:
		return p.StorageThroughput
	}
}
func stageStoredPtr[T any](v T) *T    { return &v }
func stageStoredHash(s string) string { return b.Hash(s) }
func stageStoredPin(id string) b.GroupNativePin {
	return b.GroupNativePin{ReceiptID: id, RevisionID: id + "-revision", ReceiptSHA256: stageStoredHash(id + "-receipt"), RawSHA256: stageStoredHash(id + "-raw"), ReceiptVersionID: id + "-version", RevisionVersionID: id + "-revision-version"}
}
func stageStoredInput(t *testing.T) (fleetdecision.Input, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	selection := func(name, suffix string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + suffix + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: stageStoredHash(name + "registration")}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: stageStoredHash(name + "declaration")}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: stageStoredHash(name + "scope")}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: stageStoredHash("source")}
	}
	profile := workload.Profile{SchemaVersion: "1", ID: "requirements", WorkloadID: "workload", Version: 1, Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	groups := b.GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: stageStoredHash("oldproposal")}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: stageStoredHash("candidateproposal")}, Binding: g.Binding{Old: selection("old", "1"), Candidate: selection("candidate", "2")}}
	selected := a.Selection{Groups: groups, SafetyProfile: g.VersionedRef{ID: profile.ID, Version: 1, SHA256: workload.Hash(profile)}}
	oldMembership, candidateMembership, lt := stageStoredPin("old-membership"), stageStoredPin("candidate-membership"), stageStoredPin("candidate-lt")
	ids := []string{"i-0123456789abcdef0", "i-22222222222222222"}
	scope := c.ScopeCapture{SchemaVersion: "1", RequestID: "batch-request", Scope: c.Scope{Selection: selected, PopulationStatus: "OBSERVED_POINT", ObservedAt: now, MembershipPins: []b.GroupNativePin{oldMembership, candidateMembership}, CurrentMemberIDs: ids}, CandidateTemplate: &c.CandidateTemplate{ID: "lt-0123456789abcdef0", Version: "9007199254740993", InstanceType: "m6i.large", ImageID: "ami-0123456789abcdef0", SourcePin: lt, DefinitionSHA256: stageStoredHash("candidate-definition"), ReasonCodes: []string{}}, SourcePins: []b.GroupNativePin{oldMembership, candidateMembership, lt}, ReasonCodes: []string{}}
	scope.Scope.SnapshotSHA256 = c.ScopeHash(scope)
	dims := &b.Dimensions{AccountID: "111122223333", Region: "eu-west-1", Currency: "USD", InstanceType: "m6i.xlarge", OperatingSystem: "Linux", Tenancy: "Shared", LicenseModel: "No License required", PreinstalledSoftware: "NA", SKU: "OLD-SKU", Operation: "RunInstances", UsageType: "EUW1-BoxUsage:m6i.xlarge", Unit: "Hrs", CostBasis: "UNBLENDED"}
	candidateDims := *dims
	candidateDims.InstanceType = "m6i.large"
	candidateDims.SKU = "CANDIDATE-SKU"
	candidateDims.UsageType = "EUW1-BoxUsage:m6i.large"
	prices := b.GroupNativeEvidence{SchemaVersion: "1", Kind: b.GroupNativePriceKind, Selection: groups, SnapshotSHA256: stageStoredHash("rate-snapshot"), EconomicScopeSHA256: stageStoredHash("economic-scope"), SourcePins: append(append([]b.GroupNativePin{}, scope.SourcePins...), stageStoredPin("hardware-1"), stageStoredPin("hardware-2")), Baseline: b.Period{Start: now.Truncate(24*time.Hour).AddDate(0, 0, -14), End: now.Truncate(24 * time.Hour)}, BaselineScopeBasis: b.BaselineScopeBasis, CurrentMemberIDs: ids, ObservedAt: now, ValidUntil: now.Add(time.Hour), Status: "OBSERVED_CONDITIONAL", ReasonCodes: []string{"NO_PROVIDER_FUTURE_PRICE_GUARANTEE"}, Old: b.Rate{InstanceType: dims.InstanceType, Dimensions: dims, ObservedHourlyRate: stageStoredPtr("0.2"), UsageHours: stageStoredPtr("672"), ObservedComputeCost: stageStoredPtr("134.4"), SampleCount: 28, RateBasis: b.RateBasis, MemberCount: 2, MemberIDsHash: b.Hash(ids)}, Candidate: b.Rate{InstanceType: candidateDims.InstanceType, Dimensions: &candidateDims, ObservedHourlyRate: stageStoredPtr("0.12"), UsageHours: stageStoredPtr("24"), ObservedComputeCost: stageStoredPtr("2.88"), SampleCount: 1, RateBasis: b.RateBasis, MemberCount: 1}}
	prices.BillingSourceRefs = []b.SourceRef{{ReceiptID: "billing", RevisionID: "billing-revision", IngestionJobID: "billing-job", RawHash: stageStoredHash("billing-raw"), CanonicalHash: stageStoredHash("billing-canonical"), PeriodStart: prices.Baseline.Start, PeriodEnd: prices.Baseline.End}}
	in := fleetdecision.Input{RequestID: "joint-request", Scope: scope, Profile: profile}
	in.Assessment.NativeRates = prices
	stageStoredAssessment(t, &in, now)
	for i, id := range ids {
		in.Members = append(in.Members, fleetdecision.MemberDocument{Document: stageStoredMember(id, "resource-"+string(rune('1'+i)), i, in, now)})
	}
	stageStoredReseal(t, &in)
	return in, now
}

func stageStoredAssessment(t *testing.T, in *fleetdecision.Input, now time.Time) {
	t.Helper()
	prices := in.Assessment.NativeRates
	prices.ID = ""
	prices.ID = "group-native-rate-" + b.Hash(prices)
	v, e := a.Build(in.Scope.Scope.Selection, prices, nil, now)
	if e != nil {
		t.Fatal("unit stageStoredAssessment stageStoredInput", e)
	}
	in.Assessment = v
}
func stageStoredModelSeal(t *testing.T, m *c.MemberResult) {
	t.Helper()
	if m.ModelEvaluation != nil {
		raw, e := json.Marshal(m.ModelEvaluation)
		if e != nil {
			t.Fatal(e)
		}
		v, e := native.CapacityModelBodyHash(raw)
		if e != nil {
			t.Fatal(e)
		}
		m.ModelEvaluation.AssessmentHash = v
	}
}
func stageStoredReseal(t *testing.T, in *fleetdecision.Input) {
	t.Helper()
	rows := []c.MemberResult{}
	for i := range in.Members {
		m := &in.Members[i].Document
		stageStoredModelSeal(t, m)
		m.ID = ""
		m.ID = "fleet-capacity-member-" + b.Hash(*m)
		in.Members[i].Ref = fleetdecision.Ref{ID: m.ID, SHA256: b.Hash(*m)}
		rows = append(rows, *m)
	}
	batch, e := c.Summarize(in.Scope.Scope, rows)
	if e != nil {
		t.Fatal("unit batch stageStoredInput", e)
	}
	in.Batch = batch
	in.AssessmentRef = fleetdecision.Ref{ID: in.Assessment.ID, SHA256: b.Hash(in.Assessment)}
	in.ScopeRef = fleetdecision.Ref{ID: in.Scope.RequestID, SHA256: b.Hash(in.Scope)}
	in.BatchRef = fleetdecision.Ref{ID: "batch-result", SHA256: b.Hash(in.Batch)}
}

func stagePolicyQuery() (DecisionOptimizationQuery, time.Time) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	scope := DecisionScope{
		TenantID: "tenant", WorkloadID: "workload", PayerAccountID: "111122223333",
		UsageAccountIDs: []string{"111122223333"},
		ResourceIDs:     []string{"i-0123456789abcdef0", "i-22222222222222222"},
		Class:           "COMPUTE_SAVINGS_PLAN", Currency: "USD", ConfigurationSHA256: Hash("actual-configuration"),
		OwnershipRef:  Ref{Kind: "HISTORICAL_OWNERSHIP", ID: "ownership", SHA256: Hash("issued-ownership")},
		HistoryPeriod: Period{Start: now.Truncate(24 * time.Hour).Add(-14 * 24 * time.Hour), End: now.Truncate(24 * time.Hour)},
	}
	scope.SHA256 = Hash(scope)
	return DecisionOptimizationQuery{RequestID: "preparation", Scope: scope}, now
}

func stagePolicyValid(q DecisionOptimizationQuery, now time.Time) DecisionStagePolicy {
	return DecisionStagePolicy{
		SchemaVersion: "1", ID: "customer-policy", Revision: 1,
		Purpose: DecisionStagePolicyPurpose, Basis: DecisionStagePolicyBasis,
		TenantID: q.Scope.TenantID, WorkloadID: q.Scope.WorkloadID,
		OwnershipScopeSHA256: Hash("registered-ownership-scope"), ConfigurationSHA256: q.Scope.ConfigurationSHA256,
		ResourceIDs: append([]string{}, q.Scope.ResourceIDs...), SourceID: "source", OldProposalID: "old-proposal",
		ASGARN:    "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-000000000001:autoScalingGroupName/old",
		AccountID: "111122223333", Region: "eu-west-1",
		AllowedCandidates: []DecisionStagePolicyCandidate{
			{InstanceType: "m6i.large", ProposalID: "proposal-small", TemplateID: "lt-0123456789abcdef0", TemplateVersion: "9007199254740993", ImageID: "ami-0123456789abcdef0"},
			{InstanceType: "m6i.xlarge", ProposalID: "proposal-current", TemplateID: "lt-0123456789abcdef0", TemplateVersion: "9007199254740994", ImageID: "ami-0123456789abcdef0"},
		},
		SizeConstraintBasis: "CUSTOMER_APPROVED_EXHAUSTIVE_CATALOG",
		ControllerScope:     "CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY",
		CustomerApprovalID:  "customer-license-review", CustomerApprovalIssuer: "customer-policy-authority", CustomerApprovalSubject: "customer-reviewer",
		ValidUntil: now.Add(time.Hour),
	}
}

func TestDecisionStagePolicyRequiresActualScopedCustomerApproval(t *testing.T) {
	q, now := stagePolicyQuery()
	if err := validateDecisionStagePolicy(stagePolicyValid(q, now), q, now); err != nil {
		t.Fatal("explicit scoped customer policy was rejected", err)
	}
	// Each case changes a trust or exact-binding admission, rather than simply
	// asserting that a copied model flag has a particular value.
	cases := []struct {
		name   string
		change func(*DecisionStagePolicy)
	}{
		{"no-customer-approval", func(p *DecisionStagePolicy) { p.CustomerApprovalID = "" }},
		{"no-customer-issuer", func(p *DecisionStagePolicy) { p.CustomerApprovalIssuer = "" }},
		{"no-customer-subject", func(p *DecisionStagePolicy) { p.CustomerApprovalSubject = "" }},
		{"different-tenant", func(p *DecisionStagePolicy) { p.TenantID = "foreign" }},
		{"different-workload", func(p *DecisionStagePolicy) { p.WorkloadID = "foreign" }},
		{"different-config", func(p *DecisionStagePolicy) { p.ConfigurationSHA256 = Hash("other") }},
		{"missing-resource", func(p *DecisionStagePolicy) { p.ResourceIDs = p.ResourceIDs[:1] }},
		{"reordered-resource-scope", func(p *DecisionStagePolicy) { p.ResourceIDs[0], p.ResourceIDs[1] = p.ResourceIDs[1], p.ResourceIDs[0] }},
		{"native-point-cannot-issue-policy", func(p *DecisionStagePolicy) { p.Purpose = "NATIVE_HARDWARE_OBSERVATION" }},
		{"unapproved-size-basis", func(p *DecisionStagePolicy) { p.SizeConstraintBasis = "CURRENT_NATIVE_TYPE" }},
		{"unproven-controller-families", func(p *DecisionStagePolicy) { p.ControllerScope = "NO_ASG_MEMBERSHIP_OBSERVED" }},
		{"expired", func(p *DecisionStagePolicy) { p.ValidUntil = now }},
		{"wrong-region", func(p *DecisionStagePolicy) { p.Region = "us-east-1" }},
		{"malformed-account", func(p *DecisionStagePolicy) { p.AccountID = "not-an-account" }},
		{"candidate-omitted", func(p *DecisionStagePolicy) { p.AllowedCandidates = nil }},
		{"duplicate-candidate-type", func(p *DecisionStagePolicy) {
			p.AllowedCandidates[1].InstanceType = p.AllowedCandidates[0].InstanceType
		}},
		{"duplicate-issued-proposal", func(p *DecisionStagePolicy) { p.AllowedCandidates[1].ProposalID = p.AllowedCandidates[0].ProposalID }},
		{"unbounded-native-version", func(p *DecisionStagePolicy) { p.AllowedCandidates[0].TemplateVersion = "18446744073709551616" }},
		{"inexact-native-version", func(p *DecisionStagePolicy) { p.AllowedCandidates[0].TemplateVersion = "09007199254740993" }},
		{"missing-native-template", func(p *DecisionStagePolicy) { p.AllowedCandidates[0].TemplateID = "" }},
		{"missing-image", func(p *DecisionStagePolicy) { p.AllowedCandidates[0].ImageID = "" }},
		{"execution-not-implied", func(p *DecisionStagePolicy) { p.ExecutionAuthorized = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := stagePolicyValid(q, now)
			tc.change(&p)
			if err := validateDecisionStagePolicy(p, q, now); err == nil {
				t.Fatal("unapproved or mismatched policy acquired analytical authority")
			}
		})
	}
	// Missing native controller discovery is permitted as a truthful gap. It
	// does not invalidate an independently approved size catalog.
	p := stagePolicyValid(q, now)
	p.ControllerScope = "UNAVAILABLE"
	if err := validateDecisionStagePolicy(p, q, now); err != nil {
		t.Fatal("a controller gap erased the independent customer size constraint", err)
	}
}

func TestDecisionStagePolicySingleTypeNeedsBusinessOrLicenseAuthority(t *testing.T) {
	q, now := stagePolicyQuery()
	p := stagePolicyValid(q, now)
	p.AllowedCandidates = p.AllowedCandidates[1:]
	if err := validateDecisionStagePolicy(p, q, now); err == nil {
		t.Fatal("one current template was mistaken for an exhaustive size policy")
	}
	p.SizeConstraintBasis = "BUSINESS_OR_LICENSE_RESTRICTION"
	if err := validateDecisionStagePolicy(p, q, now); err != nil {
		t.Fatal("explicit separately approved business restriction was refused", err)
	}
	p.CustomerApprovalID = ""
	if err := validateDecisionStagePolicy(p, q, now); err == nil {
		t.Fatal("a business label bypassed customer approval")
	}
}

func TestDecisionStagePolicyMissingRepositoryCannotLoadAuthority(t *testing.T) {
	q, now := stagePolicyQuery()
	if _, err := (postgresDecisionStageRepository{}).loadDecisionStagePolicy(context.Background(), q, now); err == nil {
		t.Fatal("an unconfigured repository manufactured a selected policy")
	}
}

// Both candidate joins below consume the same absolute observed memory demand.
// The real037 decoder recomputes all five physical checks: 95% of 8GiB fails
// the smaller candidate, while the same demand is 47.5% of current16GiB.
func stageStoredCandidate(t *testing.T, kind string, production bool) (fleetdecision.Input, time.Time) {
	t.Helper()
	in, now := stageStoredInput(t)
	in.RequestID = "joint-" + kind
	in.Scope.RequestID = "batch-" + kind
	in.Scope.CandidateTemplate.InstanceType = kind
	if kind == "m6i.xlarge" {
		in.Scope.CandidateTemplate.Version = "9007199254740994"
	}
	in.Scope.CandidateTemplate.DefinitionSHA256 = Hash("native-template-definition-" + kind)
	pin := stageStoredPin("template-" + kind)
	in.Scope.CandidateTemplate.SourcePin = pin
	in.Scope.SourcePins[2] = pin
	in.Assessment.NativeRates.SourcePins[2] = pin
	in.Scope.Scope.Selection.Groups.CandidateProposal = g.SnapshotRef{ID: "proposal-" + kind, SHA256: Hash("issued-proposal-" + kind)}
	in.Assessment.NativeRates.Selection = in.Scope.Scope.Selection.Groups
	in.Assessment.NativeRates.Candidate.InstanceType = kind
	in.Assessment.NativeRates.Candidate.Dimensions.InstanceType = kind
	in.Assessment.NativeRates.Candidate.Dimensions.SKU = "CANDIDATE-" + kind
	in.Assessment.NativeRates.Candidate.Dimensions.UsageType = "EUW1-BoxUsage:" + kind
	if production {
		in.Profile.Criticality = "TIER_1"
		in.Scope.Scope.Selection.SafetyProfile.SHA256 = workload.Hash(in.Profile)
	}
	in.Scope.Scope.SnapshotSHA256 = c.ScopeHash(in.Scope)
	for i := range in.Members {
		m := &in.Members[i].Document
		m.BatchID = in.Scope.RequestID
		m.Scope = in.Scope.Scope
		m.CandidateTemplate = in.Scope.CandidateTemplate
		mapping := m.HardwareMapping
		mapping.Candidates[0].ID = kind
		if kind == "m6i.xlarge" {
			mapping.Candidates[0] = mapping.Current
			m.InputKind = "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST"
			m.ReasonCodes = append(m.ReasonCodes, "CURRENT_CONFIGURATION_BASELINE_ONLY")
		}
		result := m.ModelEvaluation
		result.Candidates[0].ID = kind
		if production {
			result.History["environment"] = "PRODUCTION"
		}
		for k, d := range stageStoredDimensions {
			capacity := *stageStoredCapacity(mapping.Candidates[0].Capacity, d.name)
			check := result.Candidates[0].Checks[k]
			observed := check["observed_p99"].(string)
			if d.name == "memory" {
				observed = stageStoredProduct("8589934592", "0.95")
			}
			check["candidate_capacity"] = capacity
			check["observed_p99"] = observed
			check["forecast_requirement"] = observed
			check["required_with_reserve"] = stageStoredProduct(observed, "1.3")
			check["projected_p99_utilization_ppm"] = stageStoredPPM(observed, capacity)
			check["status"] = "PASS"
			if d.name == "memory" && kind == "m6i.large" {
				check["status"] = "FAIL"
			}
			if d.name == "cpu" || d.name == "memory" {
				check["observed_p95_utilization_ppm"] = stageStoredPPM(observed, capacity)
			}
			result.Metrics[k]["observed_quantiles"] = model.Document{"p95": model.Document{"upper": observed, "status": "OBSERVED"}, "p99": model.Document{"upper": observed, "status": "OBSERVED"}}
		}
	}
	if kind == "m6i.xlarge" {
		in.Assessment.NativeRates.Status = "UNAVAILABLE"
		in.Assessment.NativeRates.Old = b.Rate{}
		in.Assessment.NativeRates.Candidate = b.Rate{}
		in.Assessment.NativeRates.ReasonCodes = []string{"CURRENT_CONFIGURATION_BASELINE_ONLY", "NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED"}
	}
	stageStoredAssessment(t, &in, now)
	stageStoredReseal(t, &in)
	return in, now
}

func stageStoredJoin(t *testing.T, in fleetdecision.Input, at time.Time) DecisionStageSizingJoin {
	t.Helper()
	decision, err := fleetdecision.Build(in, at)
	if err != nil {
		t.Fatal("synthetic stored037 consistency input did not build", err)
	}
	if decision.Status != "BLOCKED" || decision.ExecutionAuthorized || decision.GroupCapacityAuthorized || decision.EstimatedSaving != nil || decision.VerifiedSaving != nil || decision.ChangePlanID != nil {
		t.Fatal("physical fixture acquired nonphysical authority")
	}
	return DecisionStageSizingJoin{Input: in, Reference: Ref{Kind: "FLEET_JOINT_DECISION", ID: in.RequestID, SHA256: Hash(decision)}, ObservedAt: at}
}

func stageStoredCatalog(t *testing.T, production bool) (DecisionOptimizationQuery, DecisionStageInputs, time.Time) {
	t.Helper()
	q, now := stagePolicyQuery()
	small, _ := stageStoredCandidate(t, "m6i.large", production)
	current, _ := stageStoredCandidate(t, "m6i.xlarge", production)
	in := DecisionStageInputs{Scope: q.Scope, AssessedAt: now, Resources: map[string]string{q.Scope.ResourceIDs[0]: "resource-1", q.Scope.ResourceIDs[1]: "resource-2"}, Sizing: &DecisionStageSizingCatalog{
		Reference: Ref{Kind: "WORKLOAD_SIZE_CONSTRAINT", ID: "customer-policy", SHA256: Hash("actual-approved-policy")}, ConfigurationSHA256: q.Scope.ConfigurationSHA256,
		AllowedInstanceTypes: []string{"m6i.large", "m6i.xlarge"}, CurrentInstanceTypes: map[string]string{q.Scope.ResourceIDs[0]: "m6i.xlarge", q.Scope.ResourceIDs[1]: "m6i.xlarge"},
		Joins: []DecisionStageSizingJoin{stageStoredJoin(t, small, now), stageStoredJoin(t, current, now)},
	}}
	return q, in, now
}

func stageStoredUnknownMember(t *testing.T, join *DecisionStageSizingJoin, index int) {
	t.Helper()
	input := &join.Input
	// Use the same admitted missing-population reason as the real036 worker.
	member, err := c.Unavailable(input.Scope.Scope, input.Scope.RequestID, input.Scope.Scope.CurrentMemberIDs[index], "CAPACITY_MEMBER_TELEMETRY_POPULATION_UNAVAILABLE", join.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	input.Members[index].Document = member
	stageStoredReseal(t, input)
	*join = stageStoredJoin(t, *input, join.ObservedAt)
	decision, err := fleetdecision.Build(join.Input, join.ObservedAt)
	if err != nil || decision.Members[index].Status != "UNKNOWN" {
		t.Fatal("real unavailable member did not yield an explicit physical UNKNOWN", err)
	}
}

func TestDecisionStageRightsizeUsesStoredFiveDimensionEvidence(t *testing.T) {
	for _, production := range []bool{false, true} {
		name := "nonproduction"
		if production {
			name = "production"
		}
		t.Run(name, func(t *testing.T) {
			q, in, now := stageStoredCatalog(t, production)
			for i, want := range []string{"FAIL", "PASS"} {
				d, err := fleetdecision.Build(in.Sizing.Joins[i].Input, now)
				if err != nil || d.PhysicalStatus != want || d.Status != "BLOCKED" {
					t.Fatalf("real physical arithmetic did not derive %s independently of BLOCKED: %s %v", want, d.PhysicalStatus, err)
				}
			}
			out, err := assessDecisionRightsize(q, in, now)
			if err != nil || out.Disposition != "EVIDENCED_NO_CHANGE" || len(out.InputRefs) != 3 || out.ExecutionAuthorized || out.VerifiedSaving != nil || out.OriginalActionCompletedAt != nil {
				t.Fatal("complete approved candidate population did not yield bounded analytical no-change", out.Disposition, err)
			}
			if len(out.ReasonCodes) != 1 || out.ReasonCodes[0] != "ALL_OTHER_APPROVED_CANDIDATES_HAVE_AN_OBSERVED_PHYSICAL_FAILURE" {
				t.Fatal("physical no-change lost its exact scope and reason")
			}
		})
	}
}

func TestDecisionStageRightsizeMissingAndUnknownCannotBecomeNoChange(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *DecisionStageInputs)
	}{
		{"missing-current-candidate", func(_ *testing.T, in *DecisionStageInputs) { in.Sizing.Joins = in.Sizing.Joins[:1] }},
		{"missing-alternative", func(_ *testing.T, in *DecisionStageInputs) { in.Sizing.Joins = in.Sizing.Joins[1:] }},
		{"unknown-current-member", func(t *testing.T, in *DecisionStageInputs) { stageStoredUnknownMember(t, &in.Sizing.Joins[1], 0) }},
		// The other smaller member still FAILs, so aggregate037 remains FAIL.
		// Requiring every scoped member prevents that aggregate hiding UNKNOWN.
		{"unknown-alternative-member", func(t *testing.T, in *DecisionStageInputs) { stageStoredUnknownMember(t, &in.Sizing.Joins[0], 0) }},
		{"all-candidates-overall-blocked-but-current-physically-fails", func(_ *testing.T, in *DecisionStageInputs) {
			for id := range in.Sizing.CurrentInstanceTypes {
				in.Sizing.CurrentInstanceTypes[id] = "m6i.large"
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, in, now := stageStoredCatalog(t, false)
			tc.change(t, &in)
			out, err := assessDecisionRightsize(q, in, now)
			if err != nil || out.Disposition != "UNAVAILABLE" || out.ExecutionAuthorized || out.VerifiedSaving != nil {
				t.Fatal("missing/unknown/failed current evidence acquired no-change", out.Disposition, err)
			}
		})
	}
}

func TestDecisionStageRightsizeRejectsChangedStoredSourceAndTime(t *testing.T) {
	cases := []struct {
		name   string
		change func(*DecisionStageInputs, time.Time)
	}{
		{"assessment-content-hash", func(in *DecisionStageInputs, _ time.Time) {
			in.Sizing.Joins[0].Input.AssessmentRef.SHA256 = Hash("unissued-assessment")
		}},
		{"decision-content-hash", func(in *DecisionStageInputs, _ time.Time) {
			in.Sizing.Joins[0].Reference.SHA256 = Hash("unissued-decision")
		}},
		{"source-raw-pin", func(in *DecisionStageInputs, _ time.Time) {
			in.Sizing.Joins[0].Input.Members[0].Document.Hardware.SourcePin.RawSHA256 = Hash("other-raw")
		}},
		{"stored-observation-does-not-match-issued-hash", func(in *DecisionStageInputs, _ time.Time) {
			in.Sizing.Joins[0].ObservedAt = in.Sizing.Joins[0].ObservedAt.Add(-time.Second)
		}},
		{"missing-stored-observation", func(in *DecisionStageInputs, _ time.Time) { in.Sizing.Joins[0].ObservedAt = time.Time{} }},
		{"future-stored-observation", func(in *DecisionStageInputs, now time.Time) { in.Sizing.Joins[0].ObservedAt = now.Add(time.Second) }},
		{"expired-rate-assessment", func(in *DecisionStageInputs, now time.Time) {
			in.Sizing.Joins[0].Input.Assessment.ObservedAt = now.Add(-2*time.Minute - time.Nanosecond)
		}},
		{"expired-scope", func(in *DecisionStageInputs, now time.Time) {
			in.Sizing.Joins[0].Input.Scope.Scope.ObservedAt = now.Add(-5*time.Minute - time.Nanosecond)
		}},
		{"expired-member", func(in *DecisionStageInputs, now time.Time) {
			in.Sizing.Joins[0].Input.Members[0].Document.ObservedAt = now.Add(-5*time.Minute - time.Nanosecond)
		}},
		{"foreign-profile", func(in *DecisionStageInputs, _ time.Time) { in.Sizing.Joins[0].Input.Profile.WorkloadID = "foreign" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, in, now := stageStoredCatalog(t, false)
			tc.change(&in, now)
			if _, err := assessDecisionRightsize(q, in, now); err == nil {
				t.Fatal("changed source, scope, or issued observation time retained stored sizing authority")
			}
		})
	}
}
func stageStoredProduct(x, y string) string {
	a, _ := new(big.Rat).SetString(x)
	b, _ := new(big.Rat).SetString(y)
	s := new(big.Rat).Mul(a, b).FloatString(12)
	return strings.TrimRight(strings.TrimRight(s, "0"), ".")
}
func stageStoredPPM(x, y string) int64 {
	a, _ := new(big.Rat).SetString(x)
	b, _ := new(big.Rat).SetString(y)
	v := new(big.Rat).Mul(new(big.Rat).Quo(a, b), big.NewRat(1000000, 1))
	q, r := new(big.Int).QuoRem(v.Num(), v.Denom(), new(big.Int))
	if r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	return q.Int64()
}
func stageStoredDoc(v any) model.Document {
	raw, _ := json.Marshal(v)
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	out := model.Document{}
	if e := d.Decode(&out); e != nil {
		panic(e)
	}
	return out
}
func stageStoredMember(id, resource string, i int, in fleetdecision.Input, now time.Time) c.MemberResult {
	binding := telemetry.Binding{TenantID: "tenant", WorkloadID: "workload", ResourceID: resource, Provider: "AWS", ProviderResourceID: id, AccountID: "111122223333", Region: "eu-west-1"}
	hp := stageStoredPin("hardware-" + string(rune('1'+i)))
	ref := native.CapacityModelRef{ID: hp.ReceiptID, Version: "1", ReceiptID: hp.ReceiptID, SHA256: hp.RawSHA256, Binding: binding}
	telemetrySource := native.CapacityReceiptRef{ReceiptID: "telemetry-" + resource, BatchID: "telemetry-batch-" + resource, ConfigHash: stageStoredHash("connection" + resource), RawSHA256: stageStoredHash("telemetry-raw" + resource), CanonicalHash: stageStoredHash("telemetry-canonical" + resource)}
	telemetryRef := native.CapacityModelRef{ID: telemetrySource.BatchID, Version: telemetrySource.ConfigHash, ReceiptID: telemetrySource.ReceiptID, SHA256: telemetrySource.CanonicalHash, Binding: binding}
	cap := native.PhysicalCapacity{CPU: stageStoredPtr("2"), Memory: stageStoredPtr("8589934592"), Network: stageStoredPtr("100000000"), StorageIOPS: stageStoredPtr("3000"), StorageThroughput: stageStoredPtr("131072000")}
	old := cap
	old.CPU = stageStoredPtr("4")
	old.Memory = stageStoredPtr("17179869184")
	mapping := &native.CapacityMapping{Current: native.CapacityModelCatalog{ID: "m6i.xlarge", Count: 1, Capacity: old, SourceRef: ref}, Candidates: []native.CapacityModelCatalog{{ID: "m6i.large", Count: 1, Capacity: cap, SourceRef: ref}}}
	result := &native.CapacityModelResult{SchemaVersion: "4", ModelVersion: native.CapacityProxyModelVersion, Binding: binding, Status: "BLOCKED", History: model.Document{"start": in.Assessment.NativeRates.Baseline.Start.Format(time.RFC3339Nano), "end": in.Assessment.NativeRates.Baseline.End.Format(time.RFC3339Nano)}, Metrics: []model.Document{}, Forecasts: []model.Document{}, EvidenceRefs: []native.CapacityModelRef{ref}, Candidates: []native.CapacityModelCandidate{{ID: "m6i.large", Count: 1, Status: "BLOCKED", Checks: []model.Document{}, SourceRef: ref, ReasonCodes: []string{"COMMITMENT_COMPATIBILITY_UNKNOWN_OR_FALSE"}, Economics: native.CapacityModelEconomics{Status: "UNAVAILABLE", ReasonCodes: []string{"NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED"}}, FutureRisk: native.CapacityModelRisk{Status: "UNCALIBRATED", RequiredMaximumPPM: 10000, ReasonCode: "FUTURE_PROBABILITY_MODEL_NOT_CALIBRATED"}}}}
	result.History["cadence_seconds"] = 300
	result.History["timezone"] = "UTC"
	result.History["environment"] = "NON_PRODUCTION"
	result.EvidenceRefs = append(result.EvidenceRefs, telemetryRef)
	for _, d := range stageStoredDimensions {
		candidate := *stageStoredCapacity(cap, d.name)
		observed := stageStoredProduct(candidate, "0.2")
		v := stageStoredCheck{Dimension: d.name, Unit: d.unit, Capacity: candidate, P99: observed, Forecast: observed, Required: stageStoredProduct(observed, "1.3"), Reserve: 300000, Projected: 200000, Status: "PASS"}
		stat := "OBSERVED_INTERVAL_RATE"
		if d.name == "cpu" || d.name == "memory" {
			stat = "RAW_SAMPLE"
			v.P95 = stageStoredPtr(int64(200000))
			v.P95Limit = stageStoredPtr(int64(700000))
			v.Rollback = stageStoredPtr(int64(850000))
			if d.name == "memory" {
				v.P95Limit = stageStoredPtr(int64(750000))
				v.Rollback = stageStoredPtr(int64(900000))
			}
		}
		result.Candidates[0].Checks = append(result.Candidates[0].Checks, stageStoredDoc(v))
		result.Metrics = append(result.Metrics, model.Document{"name": d.name, "unit": d.unit, "statistic": stat, "coverage_ppm": 1000000, "time_coverage_ppm": 1000000, "sampling_coverage_ppm": 1000000, "observed_intervals": 4032, "expected_intervals": 4032, "missing_intervals": 0, "unknown_seconds": "0", "denominator": model.Document{"value": *stageStoredCapacity(old, d.name), "unit": d.unit}, "observed_quantiles": model.Document{"p95": model.Document{"upper": observed, "status": "OBSERVED"}, "p99": model.Document{"upper": observed, "status": "OBSERVED"}}})
		metric := result.Metrics[len(result.Metrics)-1]
		metric["cadence_seconds"] = 300
		metric["observed_samples"] = "4032"
		metric["source_refs"] = []native.CapacityModelRef{telemetryRef}
	}
	return c.MemberResult{SchemaVersion: "1", BatchID: in.Scope.RequestID, Scope: in.Scope.Scope, InstanceID: id, ResourceID: resource, Binding: &binding, ObservedAt: now, Hardware: &c.HardwarePin{SourcePin: hp, ReceiptID: hp.ReceiptID, SourceID: "source", RevisionID: hp.RevisionID, RegistrationVersion: 1, ConfigHash: stageStoredHash("source"), RawSHA256: hp.RawSHA256, ResourceSnapshotHash: stageStoredHash(resource), ResourceVersion: 1}, Telemetry: &c.TelemetryPin{ConnectionID: "connection-" + resource, ConnectionVersion: 1, RevisionID: "telemetry-revision-" + resource, ConfigHash: stageStoredHash("connection" + resource), PopulationHash: stageStoredHash("population" + resource), ReceiptIDs: []string{"telemetry-" + resource}, SourceRefs: []native.CapacityReceiptRef{telemetrySource}}, CandidateTemplate: in.Scope.CandidateTemplate, InputKind: "MODEL_REQUEST", InputHash: stageStoredHash("input" + resource), HardwareMapping: mapping, ModelRequested: true, ModelEvaluated: true, ModelEvaluation: result, CapacitySuitable: stageStoredPtr(false), Status: "BLOCKED", DemandMeaning: "REQUEST_THROUGHPUT_PROXY", ReasonCodes: []string{"GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}}
}

func TestDecisionStageCurrentBaselineMarkerAndActualCatalogCannotBecomeCandidate(t *testing.T) {
	for _, name := range []string{"ordinary-kind", "missing-baseline-reason", "hypothetical-default-cpu", "conditional-fleet-price"} {
		t.Run(name, func(t *testing.T) {
			in, now := stageStoredCandidate(t, "m6i.xlarge", false)
			switch name {
			case "ordinary-kind":
				in.Members[0].Document.InputKind = "MODEL_REQUEST"
			case "missing-baseline-reason":
				in.Members[0].Document.ReasonCodes = []string{"GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}
			case "hypothetical-default-cpu":
				in.Members[0].Document.HardwareMapping.Candidates[0].Capacity.CPU = stageStoredPtr("8")
			case "conditional-fleet-price":
				priced, _ := stageStoredInput(t)
				in.Assessment.NativeRates = priced.Assessment.NativeRates
				in.Assessment.NativeRates.Selection = in.Scope.Scope.Selection.Groups
				stageStoredAssessment(t, &in, now)
			}
			stageStoredReseal(t, &in)
			if _, err := fleetdecision.Build(in, now); err == nil {
				t.Fatal("baseline acquired candidate or conditional-price semantics")
			}
		})
	}
}
