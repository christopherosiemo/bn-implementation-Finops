package fleetassessment

import (
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

func fixture() (Selection, fleetbilling.GroupNativeEvidence, time.Time) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	selection := func(name, suffix string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + suffix + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: strings.Repeat("a", 64)}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: strings.Repeat("b", 64)}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: strings.Repeat("c", 64)}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: strings.Repeat("d", 64)}
	}
	s := Selection{Groups: fleetbilling.GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: strings.Repeat("e", 64)}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: strings.Repeat("f", 64)}, Binding: g.Binding{Old: selection("old", "1"), Candidate: selection("candidate", "2")}}, SafetyProfile: g.VersionedRef{ID: "requirements", Version: 1, SHA256: strings.Repeat("a", 64)}}
	oldDimensions := &fleetbilling.Dimensions{AccountID: "111122223333", Region: "eu-west-1", Currency: "USD", InstanceType: "m6i.xlarge", OperatingSystem: "Linux", Tenancy: "Shared", LicenseModel: "No License required", PreinstalledSoftware: "NA", SKU: "OLD-NATIVE-SKU", Operation: "RunInstances", UsageType: "EUW1-BoxUsage:m6i.xlarge", Unit: "Hrs", CostBasis: "UNBLENDED"}
	candidateDimensions := *oldDimensions
	candidateDimensions.InstanceType = "m6i.large"
	candidateDimensions.SKU = "CANDIDATE-NATIVE-SKU"
	candidateDimensions.UsageType = "EUW1-BoxUsage:m6i.large"
	e := fleetbilling.GroupNativeEvidence{SchemaVersion: "1", Kind: fleetbilling.GroupNativePriceKind, Selection: s.Groups, SnapshotSHA256: strings.Repeat("a", 64), CurrentMemberIDs: []string{"i-0123456789abcdef0", "i-22222222222222222"}, Old: fleetbilling.Rate{Dimensions: oldDimensions, ObservedHourlyRate: pointer("0.2"), MemberCount: 2, RateBasis: fleetbilling.RateBasis}, Candidate: fleetbilling.Rate{Dimensions: &candidateDimensions, ObservedHourlyRate: pointer("0.12"), MemberCount: 1, RateBasis: fleetbilling.RateBasis}, ObservedAt: now, ValidUntil: now.Add(time.Hour), Status: "OBSERVED_CONDITIONAL", ReasonCodes: []string{"NO_PROVIDER_FUTURE_PRICE_GUARANTEE"}}
	e.Old.InstanceType = "m6i.xlarge"
	e.Candidate.InstanceType = "m6i.large"
	e.Old.MemberIDsHash = fleetbilling.Hash(e.CurrentMemberIDs)
	e.Old.SampleCount = 28
	e.Candidate.SampleCount = 1
	e.Old.UsageHours = pointer("672")
	e.Candidate.UsageHours = pointer("24")
	e.Old.ObservedComputeCost = pointer("134.4")
	e.Candidate.ObservedComputeCost = pointer("2.88")
	e.Baseline = fleetbilling.Period{Start: now.Truncate(24*time.Hour).AddDate(0, 0, -14), End: now.Truncate(24 * time.Hour)}
	e.BaselineScopeBasis = fleetbilling.BaselineScopeBasis
	e.SourcePins = []fleetbilling.GroupNativePin{{ReceiptID: "native-member", RevisionID: "native-revision", ReceiptSHA256: strings.Repeat("c", 64), RawSHA256: strings.Repeat("d", 64)}}
	e.BillingSourceRefs = []fleetbilling.SourceRef{{ReceiptID: "native-billing", RevisionID: "billing-revision", IngestionJobID: "billing-job", RawHash: strings.Repeat("e", 64), CanonicalHash: strings.Repeat("f", 64), PeriodStart: e.Baseline.Start, PeriodEnd: e.Baseline.End}}
	seal(&e)
	return s, e, now
}
func seal(e *fleetbilling.GroupNativeEvidence) {
	e.ID = ""
	e.ID = "group-native-rate-" + fleetbilling.Hash(*e)
}
func member() MemberAssessment {
	return MemberAssessment{InstanceID: "i-0123456789abcdef0", ResourceID: "actual-member-resource", ResultID: "native-result", ResultSHA256: strings.Repeat("a", 64), HardwareReceiptID: "native-hardware", Status: "BLOCKED", DemandMeaning: "REQUEST_THROUGHPUT_PROXY"}
}
func TestTwoMemberExactHourlyScenarioIsConditionalAndNeverSavings(t *testing.T) {
	s, p, now := fixture()
	got, e := Build(s, p, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	scenario := got.Scenario
	if *scenario.OldHourlyCompute != "0.4" || *scenario.CandidateHourlyCompute != "0.24" || *scenario.HourlyComputeDifference != "0.16" || scenario.MemberCount != 2 || *scenario.Currency != "USD" {
		t.Fatal("incorrect exact signed scenario", scenario)
	}
	if got.Status != "BLOCKED" || got.ExecutionAuthorized || got.ChangePlanID != nil || got.VerifiedSaving != nil || scenario.EstimatedSaving != nil || scenario.VerifiedSaving != nil || scenario.ContractedAvoidableCost != nil || scenario.HardSpendCap || got.Capacity.GroupCapacityAuthorized || got.Capacity.CompletedBusinessWorkPreserved != nil {
		t.Fatal("analytical numbers acquired authority")
	}
	if got.Capacity.Status != "UNAVAILABLE" || len(got.Capacity.MissingInstanceIDs) != 2 || got.Scenario.Basis != ScenarioBasis {
		t.Fatal("missing member history became complete")
	}
	again, e := Build(s, p, nil, now)
	if e != nil || again.ID != got.ID {
		t.Fatal("immutable scenario replay changed")
	}
}
func TestNegativeAndZeroScenarioDifferencesRemainExact(t *testing.T) {
	for _, pair := range []struct{ candidate, want string }{{"0.3", "-0.2"}, {"0.2", "0"}, {"0.000000000001", "0.399999999998"}} {
		s, p, now := fixture()
		p.Candidate.ObservedHourlyRate = pointer(pair.candidate)
		seal(&p)
		got, e := Build(s, p, nil, now)
		if e != nil || *got.Scenario.HourlyComputeDifference != pair.want || got.Scenario.EstimatedSaving != nil {
			t.Fatal("signed exact difference changed", got.Scenario, e)
		}
	}
}
func TestUnknownIsNotZeroAndMemberChecksAreNotGroupCapacity(t *testing.T) {
	s, p, now := fixture()
	p.Status = "UNAVAILABLE"
	p.Candidate.ObservedHourlyRate = nil
	seal(&p)
	got, e := Build(s, p, []MemberAssessment{member()}, now)
	if e != nil {
		t.Fatal(e)
	}
	if got.Scenario.Status != "UNAVAILABLE" || got.Scenario.HourlyComputeDifference != nil || got.Scenario.CandidateHourlyCompute != nil || got.Capacity.Status != "PARTIAL" || len(got.Capacity.MissingInstanceIDs) != 1 {
		t.Fatal("unknown price or partial evidence invented")
	}
	m2 := member()
	m2.InstanceID = "i-22222222222222222"
	m2.ResourceID = "other-actual-member"
	m2.ResultID = "other-result"
	m2.HardwareReceiptID = "other-native-hardware"
	m2.DemandMeaning = "LEGACY_UNPROVEN_PROXY"
	got, e = Build(s, p, []MemberAssessment{member(), m2}, now)
	if e != nil || got.Capacity.Status != "CURRENT_MEMBER_RESULTS_OBSERVED" || got.Capacity.GroupCapacityAuthorized || got.Capacity.HistoricalMembership != "INTERVAL_OWNERSHIP_UNPROVEN" {
		t.Fatal("complete per-member references upgraded group authority", e)
	}
	m2.DemandMeaning = "UNAVAILABLE"
	got, e = Build(s, p, []MemberAssessment{m2}, now)
	if e != nil || got.Capacity.Status != "PARTIAL" || got.Capacity.Members[0].DemandMeaning != "UNAVAILABLE" || got.Capacity.CompletedBusinessWorkPreserved != nil {
		t.Fatal("missing model semantics were upgraded", e)
	}
}
func TestScopeCurrencyAndMonetaryReceiptTamperingReject(t *testing.T) {
	cases := map[string]func(*Selection, *fleetbilling.GroupNativeEvidence){
		"workload": func(s *Selection, _ *fleetbilling.GroupNativeEvidence) {
			s.Groups.Binding.Old.Target.WorkloadID = "foreign"
		},
		"proposal revision": func(s *Selection, _ *fleetbilling.GroupNativeEvidence) {
			s.Groups.OldProposal.SHA256 = strings.Repeat("f", 64)
		},
		"profile": func(s *Selection, _ *fleetbilling.GroupNativeEvidence) { s.SafetyProfile.Version = 0 },
		"currency": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) {
			p.Candidate.Dimensions.Currency = "GBP"
			seal(p)
		},
		"missing currency": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) {
			p.Old.Dimensions.Currency = ""
			p.Candidate.Dimensions.Currency = ""
			seal(p)
		},
		"expired": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) { p.ValidUntil = p.ObservedAt; seal(p) },
		"forged rate": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) {
			p.Candidate.ObservedHourlyRate = pointer("0.01")
		},
		"zero rate": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) {
			p.Candidate.ObservedHourlyRate = pointer("0")
			seal(p)
		},
		"missing rate": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) { p.Candidate.ObservedHourlyRate = nil; seal(p) },
		"claimed contract": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) {
			p.Candidate.RateBasis = "CONTRACTED_AVOIDABLE"
			seal(p)
		},
		"authority":      func(_ *Selection, p *fleetbilling.GroupNativeEvidence) { p.ExecutionAuthorized = true; seal(p) },
		"verified money": func(_ *Selection, p *fleetbilling.GroupNativeEvidence) { p.VerifiedSaving = pointer("1"); seal(p) },
		"spend cap":      func(_ *Selection, p *fleetbilling.GroupNativeEvidence) { p.HardSpendCap = true; seal(p) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, p, now := fixture()
			change(&s, &p)
			if _, e := Build(s, p, nil, now); e == nil {
				t.Fatal("invalid binding or rate accepted")
			}
		})
	}
}
func TestMemberMappingCannotBorrowRepresentativeOrUnprovenBusinessWork(t *testing.T) {
	for _, change := range []func(*MemberAssessment){func(m *MemberAssessment) { m.InstanceID = "i-fffffffffffffffff" }, func(m *MemberAssessment) { m.ResourceID = "" }, func(m *MemberAssessment) { m.ResultSHA256 = "" }, func(m *MemberAssessment) { m.HardwareReceiptID = "" }, func(m *MemberAssessment) { m.Status = "READY" }, func(m *MemberAssessment) { m.DemandMeaning = "COMPLETED_BUSINESS_WORK" }} {
		s, p, now := fixture()
		m := member()
		change(&m)
		if _, e := Build(s, p, []MemberAssessment{m}, now); e == nil {
			t.Fatal("member/result binding bypassed")
		}
	}
	s, p, now := fixture()
	if _, e := Build(s, p, []MemberAssessment{member(), member()}, now); e == nil {
		t.Fatal("representative result reused")
	}
}
func TestDecimal3812AndInputOwnership(t *testing.T) {
	for _, value := range []string{"99999999999999999999999999", "0.1234567890123", "NaN", "1e-3", "-0.1"} {
		s, p, now := fixture()
		p.Old.ObservedHourlyRate = pointer(value)
		seal(&p)
		if _, e := Build(s, p, nil, now); e == nil {
			t.Fatal("unsupported precision/overflow accepted", value)
		}
	}
	s, p, now := fixture()
	members := []MemberAssessment{member()}
	got, e := Build(s, p, members, now)
	if e != nil {
		t.Fatal(e)
	}
	id := got.ID
	*p.Old.ObservedHourlyRate = "7"
	p.Old.Dimensions.Currency = "GBP"
	p.CurrentMemberIDs[0] = "changed"
	members[0].ResultID = "changed"
	if *got.Scenario.OldHourlyRate != "0.2" || got.NativeRates.Old.Dimensions.Currency != "USD" || got.Capacity.Members[0].ResultID != "native-result" || got.ID != id {
		t.Fatal("input pointers changed immutable result")
	}
}
