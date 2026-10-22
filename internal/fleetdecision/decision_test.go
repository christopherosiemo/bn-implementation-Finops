package fleetdecision

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	c "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// These are consistency fixtures, not issued native facts or trusted prices.
func ptr[T any](v T) *T    { return &v }
func hash(s string) string { return b.Hash(s) }
func pin(id string) b.GroupNativePin {
	return b.GroupNativePin{ReceiptID: id, RevisionID: id + "-revision", ReceiptSHA256: hash(id + "-receipt"), RawSHA256: hash(id + "-raw"), ReceiptVersionID: id + "-version", RevisionVersionID: id + "-revision-version"}
}
func fixture(t *testing.T) (Input, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	selection := func(name, suffix string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + suffix + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: hash(name + "registration")}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: hash(name + "declaration")}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: hash(name + "scope")}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: hash("source")}
	}
	profile := workload.Profile{SchemaVersion: "1", ID: "requirements", WorkloadID: "workload", Version: 1, Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	groups := b.GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: hash("oldproposal")}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: hash("candidateproposal")}, Binding: g.Binding{Old: selection("old", "1"), Candidate: selection("candidate", "2")}}
	selected := a.Selection{Groups: groups, SafetyProfile: g.VersionedRef{ID: profile.ID, Version: 1, SHA256: workload.Hash(profile)}}
	oldMembership, candidateMembership, lt := pin("old-membership"), pin("candidate-membership"), pin("candidate-lt")
	ids := []string{"i-0123456789abcdef0", "i-22222222222222222"}
	scope := c.ScopeCapture{SchemaVersion: "1", RequestID: "batch-request", Scope: c.Scope{Selection: selected, PopulationStatus: "OBSERVED_POINT", ObservedAt: now, MembershipPins: []b.GroupNativePin{oldMembership, candidateMembership}, CurrentMemberIDs: ids}, CandidateTemplate: &c.CandidateTemplate{ID: "lt-0123456789abcdef0", Version: "9007199254740993", InstanceType: "m6i.large", ImageID: "ami-0123456789abcdef0", SourcePin: lt, DefinitionSHA256: hash("candidate-definition"), ReasonCodes: []string{}}, SourcePins: []b.GroupNativePin{oldMembership, candidateMembership, lt}, ReasonCodes: []string{}}
	scope.Scope.SnapshotSHA256 = c.ScopeHash(scope)
	dims := &b.Dimensions{AccountID: "111122223333", Region: "eu-west-1", Currency: "USD", InstanceType: "m6i.xlarge", OperatingSystem: "Linux", Tenancy: "Shared", LicenseModel: "No License required", PreinstalledSoftware: "NA", SKU: "OLD-SKU", Operation: "RunInstances", UsageType: "EUW1-BoxUsage:m6i.xlarge", Unit: "Hrs", CostBasis: "UNBLENDED"}
	candidateDims := *dims
	candidateDims.InstanceType = "m6i.large"
	candidateDims.SKU = "CANDIDATE-SKU"
	candidateDims.UsageType = "EUW1-BoxUsage:m6i.large"
	prices := b.GroupNativeEvidence{SchemaVersion: "1", Kind: b.GroupNativePriceKind, Selection: groups, SnapshotSHA256: hash("rate-snapshot"), EconomicScopeSHA256: hash("economic-scope"), SourcePins: append(append([]b.GroupNativePin{}, scope.SourcePins...), pin("hardware-1"), pin("hardware-2")), Baseline: b.Period{Start: now.Truncate(24*time.Hour).AddDate(0, 0, -14), End: now.Truncate(24 * time.Hour)}, BaselineScopeBasis: b.BaselineScopeBasis, CurrentMemberIDs: ids, ObservedAt: now, ValidUntil: now.Add(time.Hour), Status: "OBSERVED_CONDITIONAL", ReasonCodes: []string{"NO_PROVIDER_FUTURE_PRICE_GUARANTEE"}, Old: b.Rate{InstanceType: dims.InstanceType, Dimensions: dims, ObservedHourlyRate: ptr("0.2"), UsageHours: ptr("672"), ObservedComputeCost: ptr("134.4"), SampleCount: 28, RateBasis: b.RateBasis, MemberCount: 2, MemberIDsHash: b.Hash(ids)}, Candidate: b.Rate{InstanceType: candidateDims.InstanceType, Dimensions: &candidateDims, ObservedHourlyRate: ptr("0.12"), UsageHours: ptr("24"), ObservedComputeCost: ptr("2.88"), SampleCount: 1, RateBasis: b.RateBasis, MemberCount: 1}}
	prices.BillingSourceRefs = []b.SourceRef{{ReceiptID: "billing", RevisionID: "billing-revision", IngestionJobID: "billing-job", RawHash: hash("billing-raw"), CanonicalHash: hash("billing-canonical"), PeriodStart: prices.Baseline.Start, PeriodEnd: prices.Baseline.End}}
	in := Input{RequestID: "joint-request", Scope: scope, Profile: profile}
	in.Assessment.NativeRates = prices
	assessment(t, &in, now)
	for i, id := range ids {
		in.Members = append(in.Members, MemberDocument{Document: memberFixture(id, "resource-"+string(rune('1'+i)), i, in, now)})
	}
	reseal(t, &in)
	return in, now
}

func assessment(t *testing.T, in *Input, now time.Time) {
	t.Helper()
	prices := in.Assessment.NativeRates
	prices.ID = ""
	prices.ID = "group-native-rate-" + b.Hash(prices)
	v, e := a.Build(in.Scope.Scope.Selection, prices, nil, now)
	if e != nil {
		t.Fatal("unit assessment fixture", e)
	}
	in.Assessment = v
}
func modelSeal(t *testing.T, m *c.MemberResult) {
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
func reseal(t *testing.T, in *Input) {
	t.Helper()
	rows := []c.MemberResult{}
	for i := range in.Members {
		m := &in.Members[i].Document
		modelSeal(t, m)
		m.ID = ""
		m.ID = "fleet-capacity-member-" + b.Hash(*m)
		in.Members[i].Ref = Ref{m.ID, b.Hash(*m)}
		rows = append(rows, *m)
	}
	batch, e := c.Summarize(in.Scope.Scope, rows)
	if e != nil {
		t.Fatal("unit batch fixture", e)
	}
	in.Batch = batch
	in.AssessmentRef = Ref{in.Assessment.ID, b.Hash(in.Assessment)}
	in.ScopeRef = Ref{in.Scope.RequestID, b.Hash(in.Scope)}
	in.BatchRef = Ref{"batch-result", b.Hash(in.Batch)}
}
func product(x, y string) string {
	a, _ := new(big.Rat).SetString(x)
	b, _ := new(big.Rat).SetString(y)
	s := new(big.Rat).Mul(a, b).FloatString(12)
	return strings.TrimRight(strings.TrimRight(s, "0"), ".")
}
func ppm(x, y string) int64 {
	a, _ := new(big.Rat).SetString(x)
	b, _ := new(big.Rat).SetString(y)
	v := new(big.Rat).Mul(new(big.Rat).Quo(a, b), big.NewRat(1000000, 1))
	q, r := new(big.Int).QuoRem(v.Num(), v.Denom(), new(big.Int))
	if r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	return q.Int64()
}
func doc(v any) model.Document {
	raw, _ := json.Marshal(v)
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	out := model.Document{}
	if e := d.Decode(&out); e != nil {
		panic(e)
	}
	return out
}
func memberFixture(id, resource string, i int, in Input, now time.Time) c.MemberResult {
	binding := telemetry.Binding{TenantID: "tenant", WorkloadID: "workload", ResourceID: resource, Provider: "AWS", ProviderResourceID: id, AccountID: "111122223333", Region: "eu-west-1"}
	hp := pin("hardware-" + string(rune('1'+i)))
	ref := native.CapacityModelRef{ID: hp.ReceiptID, Version: "1", ReceiptID: hp.ReceiptID, SHA256: hp.RawSHA256, Binding: binding}
	telemetrySource := native.CapacityReceiptRef{ReceiptID: "telemetry-" + resource, BatchID: "telemetry-batch-" + resource, ConfigHash: hash("connection" + resource), RawSHA256: hash("telemetry-raw" + resource), CanonicalHash: hash("telemetry-canonical" + resource)}
	telemetryRef := native.CapacityModelRef{ID: telemetrySource.BatchID, Version: telemetrySource.ConfigHash, ReceiptID: telemetrySource.ReceiptID, SHA256: telemetrySource.CanonicalHash, Binding: binding}
	cap := native.PhysicalCapacity{CPU: ptr("2"), Memory: ptr("8589934592"), Network: ptr("100000000"), StorageIOPS: ptr("3000"), StorageThroughput: ptr("131072000")}
	old := cap
	old.CPU = ptr("4")
	old.Memory = ptr("17179869184")
	mapping := &native.CapacityMapping{Current: native.CapacityModelCatalog{ID: "m6i.xlarge", Count: 1, Capacity: old, SourceRef: ref}, Candidates: []native.CapacityModelCatalog{{ID: "m6i.large", Count: 1, Capacity: cap, SourceRef: ref}}}
	result := &native.CapacityModelResult{SchemaVersion: "4", ModelVersion: native.CapacityProxyModelVersion, Binding: binding, Status: "BLOCKED", History: model.Document{"start": in.Assessment.NativeRates.Baseline.Start.Format(time.RFC3339Nano), "end": in.Assessment.NativeRates.Baseline.End.Format(time.RFC3339Nano)}, Metrics: []model.Document{}, Forecasts: []model.Document{}, EvidenceRefs: []native.CapacityModelRef{ref}, Candidates: []native.CapacityModelCandidate{{ID: "m6i.large", Count: 1, Status: "BLOCKED", Checks: []model.Document{}, SourceRef: ref, ReasonCodes: []string{"COMMITMENT_COMPATIBILITY_UNKNOWN_OR_FALSE"}, Economics: native.CapacityModelEconomics{Status: "UNAVAILABLE", ReasonCodes: []string{"NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED"}}, FutureRisk: native.CapacityModelRisk{Status: "UNCALIBRATED", RequiredMaximumPPM: 10000, ReasonCode: "FUTURE_PROBABILITY_MODEL_NOT_CALIBRATED"}}}}
	result.History["cadence_seconds"] = 300
	result.History["timezone"] = "UTC"
	result.History["environment"] = "NON_PRODUCTION"
	result.EvidenceRefs = append(result.EvidenceRefs, telemetryRef)
	for _, d := range dimensions {
		candidate := *capacity(cap, d.name)
		observed := product(candidate, "0.2")
		v := check{Dimension: d.name, Unit: d.unit, Capacity: candidate, P99: observed, Forecast: observed, Required: product(observed, "1.3"), Reserve: 300000, Projected: 200000, Status: "PASS"}
		stat := "OBSERVED_INTERVAL_RATE"
		if d.name == "cpu" || d.name == "memory" {
			stat = "RAW_SAMPLE"
			v.P95 = ptr(int64(200000))
			v.P95Limit = ptr(int64(700000))
			v.Rollback = ptr(int64(850000))
			if d.name == "memory" {
				v.P95Limit = ptr(int64(750000))
				v.Rollback = ptr(int64(900000))
			}
		}
		result.Candidates[0].Checks = append(result.Candidates[0].Checks, doc(v))
		result.Metrics = append(result.Metrics, model.Document{"name": d.name, "unit": d.unit, "statistic": stat, "coverage_ppm": 1000000, "time_coverage_ppm": 1000000, "sampling_coverage_ppm": 1000000, "observed_intervals": 4032, "expected_intervals": 4032, "missing_intervals": 0, "unknown_seconds": "0", "denominator": model.Document{"value": *capacity(old, d.name), "unit": d.unit}, "observed_quantiles": model.Document{"p95": model.Document{"upper": observed, "status": "OBSERVED"}, "p99": model.Document{"upper": observed, "status": "OBSERVED"}}})
		metric := result.Metrics[len(result.Metrics)-1]
		metric["cadence_seconds"] = 300
		metric["observed_samples"] = "4032"
		metric["source_refs"] = []native.CapacityModelRef{telemetryRef}
	}
	return c.MemberResult{SchemaVersion: "1", BatchID: in.Scope.RequestID, Scope: in.Scope.Scope, InstanceID: id, ResourceID: resource, Binding: &binding, ObservedAt: now, Hardware: &c.HardwarePin{SourcePin: hp, ReceiptID: hp.ReceiptID, SourceID: "source", RevisionID: hp.RevisionID, RegistrationVersion: 1, ConfigHash: hash("source"), RawSHA256: hp.RawSHA256, ResourceSnapshotHash: hash(resource), ResourceVersion: 1}, Telemetry: &c.TelemetryPin{ConnectionID: "connection-" + resource, ConnectionVersion: 1, RevisionID: "telemetry-revision-" + resource, ConfigHash: hash("connection" + resource), PopulationHash: hash("population" + resource), ReceiptIDs: []string{"telemetry-" + resource}, SourceRefs: []native.CapacityReceiptRef{telemetrySource}}, CandidateTemplate: in.Scope.CandidateTemplate, InputKind: "NATIVE_CAPACITY_INPUT", InputHash: hash("input" + resource), HardwareMapping: mapping, ModelRequested: true, ModelEvaluated: true, ModelEvaluation: result, CapacitySuitable: ptr(false), Status: "BLOCKED", DemandMeaning: "REQUEST_THROUGHPUT_PROXY", ReasonCodes: []string{"GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}}
}

func TestExactConditionalJoinSeparatesPhysicalFromAuthority(t *testing.T) {
	in, now := fixture(t)
	out, e := Build(in, now)
	if e != nil {
		t.Fatal(e)
	}
	if out.PhysicalStatus != "PASS" || len(out.Members) != 2 || *out.Scenario.OldHourlyCompute != "0.4" || *out.Scenario.CandidateHourlyCompute != "0.24" || *out.Scenario.HourlyComputeDifference != "0.16" {
		t.Fatalf("wrong conditional observations: %+v", out)
	}
	for _, m := range out.Members {
		if m.Status != "PASS" || len(m.Dimensions) != 5 {
			t.Fatal("physical completeness lost")
		}
	}
	if out.Status != "BLOCKED" || out.PlanEligible || out.ExecutionAuthorized || out.GroupCapacityAuthorized || out.ContractedAvoidableCost != nil || out.EstimatedSaving != nil || out.VerifiedSaving != nil || out.ChangePlanID != nil || out.CompletedBusinessWorkPreserved != nil || out.Scenario.ContractedAvoidableCost != nil || out.Scenario.EstimatedSaving != nil || out.Scenario.VerifiedSaving != nil {
		t.Fatal("observations acquired authority")
	}
	if in.Members[0].Document.ModelEvaluation.Candidates[0].CapacitySuitable {
		t.Fatal("fixture injected commitment compatibility")
	}
	again, e := Build(in, now)
	if e != nil || out.ID != again.ID {
		t.Fatal("determinism failed")
	}
	canonical := doc(out)
	canonical["id"] = ""
	if out.ID != "group-joint-decision-"+b.Hash(canonical) {
		t.Fatal("typed ID does not match canonical persisted-document hash")
	}
	*in.Assessment.Scenario.HourlyComputeDifference = "999"
	if *out.Scenario.HourlyComputeDifference != "0.16" {
		t.Fatal("output aliases input")
	}
}

func TestPhysicalFailureUnknownAndInsufficientAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*c.MemberResult)
	}{
		{"memory95", "FAIL", func(m *c.MemberResult) {
			ch := m.ModelEvaluation.Candidates[0].Checks[1]
			ch["observed_p95_utilization_ppm"] = int64(950000)
			ch["observed_p99"] = product(ch["candidate_capacity"].(string), "0.95")
			ch["forecast_requirement"] = ch["observed_p99"]
			ch["required_with_reserve"] = product(ch["observed_p99"].(string), "1.3")
			ch["projected_p99_utilization_ppm"] = 950000
			ch["status"] = "FAIL"
			qs := m.ModelEvaluation.Metrics[1]["observed_quantiles"].(model.Document)
			qs["p95"] = model.Document{"upper": ch["observed_p99"], "status": "OBSERVED"}
			qs["p99"] = qs["p95"]
		}},
		{"fourfoldCPU", "FAIL", func(m *c.MemberResult) {
			ch := m.ModelEvaluation.Candidates[0].Checks[0]
			ch["forecast_requirement"] = "1.6"
			ch["required_with_reserve"] = "2.08"
			ch["status"] = "FAIL"
		}},
		{"missing-storage-check", "UNKNOWN", func(m *c.MemberResult) {
			m.ModelEvaluation.Candidates[0].Checks = m.ModelEvaluation.Candidates[0].Checks[:4]
		}},
		{"missing-storage-metric", "UNKNOWN", func(m *c.MemberResult) { m.ModelEvaluation.Metrics = m.ModelEvaluation.Metrics[:4] }},
		{"unsupported-statistic", "UNKNOWN", func(m *c.MemberResult) { m.ModelEvaluation.Metrics[2]["statistic"] = "AVERAGE" }},
		{"incomplete-coverage", "UNKNOWN", func(m *c.MemberResult) { m.ModelEvaluation.Metrics[2]["sampling_coverage_ppm"] = 999999 }},
		{"insufficient-history", "UNKNOWN", func(m *c.MemberResult) { m.ModelEvaluation.Status = "INSUFFICIENT_OBSERVATION" }},
		{"failed-even-when-insufficient", "FAIL", func(m *c.MemberResult) {
			m.ModelEvaluation.Status = "INSUFFICIENT_OBSERVATION"
			ch := m.ModelEvaluation.Candidates[0].Checks[0]
			ch["forecast_requirement"] = "1.6"
			ch["required_with_reserve"] = "2.08"
			ch["status"] = "FAIL"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, now := fixture(t)
			tc.change(&in.Members[0].Document)
			reseal(t, &in)
			out, e := Build(in, now)
			if e != nil || out.PhysicalStatus != tc.want || out.Members[0].Status != tc.want {
				t.Fatalf("got %s, %v", out.PhysicalStatus, e)
			}
		})
	}
}

func TestConditionalDifferenceZeroNegativeAndUnknown(t *testing.T) {
	for _, tc := range []struct{ rate, want string }{{"0.2", "0"}, {"0.3", "-0.2"}, {"0.000000000001", "0.399999999998"}} {
		t.Run(tc.want, func(t *testing.T) {
			in, now := fixture(t)
			p := &in.Assessment.NativeRates
			p.Candidate.ObservedHourlyRate = ptr(tc.rate)
			p.Candidate.ObservedComputeCost = ptr(product(tc.rate, "24"))
			assessment(t, &in, now)
			reseal(t, &in)
			out, e := Build(in, now)
			if e != nil || *out.Scenario.HourlyComputeDifference != tc.want || out.EstimatedSaving != nil {
				t.Fatal(out.Scenario, e)
			}
		})
	}
	in, now := fixture(t)
	in.Assessment.NativeRates.Status = "UNAVAILABLE"
	in.Assessment.NativeRates.Old = b.Rate{}
	in.Assessment.NativeRates.Candidate = b.Rate{}
	assessment(t, &in, now)
	reseal(t, &in)
	out, e := Build(in, now)
	if e != nil || out.Scenario.HourlyComputeDifference != nil || out.Scenario.OldHourlyCompute != nil || out.PhysicalStatus != "PASS" {
		t.Fatal("unknown price became zero or physical failure", e)
	}
}

func TestMismatchedOrTamperedDocumentsReject(t *testing.T) {
	cases := map[string]func(*Input){
		"assessment-hash": func(in *Input) { in.AssessmentRef.SHA256 = hash("wrong") },
		"member-hash":     func(in *Input) { in.Members[0].Ref.SHA256 = hash("wrong") },
		"scope-hash":      func(in *Input) { in.Scope.Scope.SnapshotSHA256 = hash("wrong"); in.ScopeRef.SHA256 = b.Hash(in.Scope) },
		"profile":         func(in *Input) { in.Profile.Version++ },
		"pair": func(in *Input) {
			in.Scope.Scope.Selection.Groups.CandidateProposal.SHA256 = hash("other")
			in.Scope.Scope.SnapshotSHA256 = c.ScopeHash(in.Scope)
			in.ScopeRef.SHA256 = b.Hash(in.Scope)
		},
		"partial-roster":        func(in *Input) { in.Members = in.Members[:1] },
		"missing-batch-member":  func(in *Input) { in.Batch.Members = in.Batch.Members[:1]; in.BatchRef.SHA256 = b.Hash(in.Batch) },
		"representative-result": func(in *Input) { in.Members[1] = in.Members[0] },
		"candidate-template":    func(in *Input) { in.Members[0].Document.CandidateTemplate = &c.CandidateTemplate{}; reseal(t, in) },
		"candidate-version-leading-zero": func(in *Input) {
			in.Scope.CandidateTemplate.Version = "01"
			in.Scope.Scope.SnapshotSHA256 = c.ScopeHash(in.Scope)
			in.ScopeRef.SHA256 = b.Hash(in.Scope)
		},
		"missing-source-pin": func(in *Input) {
			in.Scope.SourcePins[2] = pin("foreign-template")
			in.Scope.Scope.SnapshotSHA256 = c.ScopeHash(in.Scope)
			in.ScopeRef.SHA256 = b.Hash(in.Scope)
		},
		"native-pin-version": func(in *Input) {
			in.Assessment.NativeRates.SourcePins[0].ReceiptVersionID = "null"
			assessment(t, in, in.Assessment.ObservedAt)
			reseal(t, in)
		},
		"inconsistent-rate-cost": func(in *Input) {
			in.Assessment.NativeRates.Candidate.ObservedComputeCost = ptr("2.89")
			assessment(t, in, in.Assessment.ObservedAt)
			reseal(t, in)
		},
		"forged-scenario": func(in *Input) {
			in.Assessment.Scenario.HourlyComputeDifference = ptr("9")
			in.AssessmentRef.SHA256 = b.Hash(in.Assessment)
		},
		"model-hash": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.AssessmentHash = hash("fake")
			m := &in.Members[0].Document
			m.ID = ""
			m.ID = "fleet-capacity-member-" + b.Hash(*m)
			in.Members[0].Ref = Ref{m.ID, b.Hash(*m)}
		},
		"model-nil":       func(in *Input) { in.Members[0].Document.ModelEvaluation = nil; reseal(t, in) },
		"foreign-binding": func(in *Input) { in.Members[0].Document.Binding.WorkloadID = "other"; reseal(t, in) },
		"historical-scope": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.History["end"] = in.Assessment.NativeRates.Baseline.End.Add(-time.Hour).Format(time.RFC3339Nano)
			reseal(t, in)
		},
		"model-money": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.Candidates[0].Economics.EstimatedSaving = ptr("1")
			reseal(t, in)
		},
		"injected-risk": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.Candidates[0].FutureRisk.Status = "CALIBRATED"
			reseal(t, in)
		},
		"model-overall-suitable": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.Candidates[0].CapacitySuitable = true
			in.Members[0].Document.CapacitySuitable = ptr(true)
			reseal(t, in)
		},
		"physical-status-lie": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.Candidates[0].Checks[0]["status"] = "FAIL"
			reseal(t, in)
		},
		"projected-lie": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.Candidates[0].Checks[0]["projected_p99_utilization_ppm"] = 1
			reseal(t, in)
		},
		"unknown-dimension": func(in *Input) {
			in.Members[0].Document.ModelEvaluation.Candidates[0].Checks[0]["dimension"] = "completed_business_work"
			reseal(t, in)
		},
		"duplicate-check": func(in *Input) {
			m := in.Members[0].Document.ModelEvaluation
			m.Candidates[0].Checks = append(m.Candidates[0].Checks, m.Candidates[0].Checks[0])
			reseal(t, in)
		},
		"raw-price-in-model": func(in *Input) {
			in.Members[0].Document.HardwareMapping.Candidates[0].Pricing = model.Document{"rate": "0.12"}
			reseal(t, in)
		},
		"zero-observed-at": func(in *Input) { in.Members[0].Document.ObservedAt = time.Time{}; reseal(t, in) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in, now := fixture(t)
			mutate(&in)
			if _, e := Build(in, now); e == nil {
				t.Fatal("invalid joined evidence accepted")
			}
		})
	}
}

func TestUnevaluatedMemberRemainsExplicitUnknown(t *testing.T) {
	in, now := fixture(t)
	m := &in.Members[1].Document
	m.ModelEvaluated = false
	m.ModelRequested = false
	m.ModelEvaluation = nil
	m.CapacitySuitable = nil
	m.Status = "UNAVAILABLE"
	reseal(t, &in)
	out, e := Build(in, now)
	if e != nil || out.PhysicalStatus != "UNKNOWN" || len(out.Members) != 2 || out.Members[1].Status != "UNKNOWN" {
		t.Fatal("missing member was extrapolated", e)
	}
}

func TestCountWindowUnitAndSourceClosure(t *testing.T) {
	for name, mutate := range map[string]func(*c.MemberResult){
		"window-count":     func(m *c.MemberResult) { m.ModelEvaluation.Metrics[0]["expected_intervals"] = 1 },
		"fractional-count": func(m *c.MemberResult) { m.ModelEvaluation.Metrics[0]["observed_intervals"] = 1.5 },
		"sample-nonfinite": func(m *c.MemberResult) { m.ModelEvaluation.Metrics[0]["observed_samples"] = "NaN" },
		"wrong-unit":       func(m *c.MemberResult) { m.ModelEvaluation.Metrics[0]["unit"] = "percent" },
		"denominator": func(m *c.MemberResult) {
			m.ModelEvaluation.Metrics[0]["denominator"] = model.Document{"value": "200", "unit": "vCPU"}
		},
		"history-cadence": func(m *c.MemberResult) { m.ModelEvaluation.History["cadence_seconds"] = 600 },
		"understated-reserve": func(m *c.MemberResult) {
			m.ModelEvaluation.Candidates[0].Checks[0]["required_with_reserve"] = m.ModelEvaluation.Candidates[0].Checks[0]["forecast_requirement"]
		},
		"foreign-metric-source": func(m *c.MemberResult) {
			m.ModelEvaluation.Metrics[0]["source_refs"] = []native.CapacityModelRef{{ID: "foreign"}}
		},
		"missing-retained-source": func(m *c.MemberResult) { m.ModelEvaluation.EvidenceRefs = m.ModelEvaluation.EvidenceRefs[:1] },
		"hardware-source":         func(m *c.MemberResult) { m.Hardware.SourceID = "foreign" },
		"telemetry-config":        func(m *c.MemberResult) { m.Telemetry.ConfigHash = hash("foreign") },
	} {
		t.Run(name, func(t *testing.T) {
			in, now := fixture(t)
			mutate(&in.Members[0].Document)
			reseal(t, &in)
			if _, e := Build(in, now); e == nil {
				t.Fatal("metric/window/source mismatch accepted")
			}
		})
	}
}

func TestRequiredReserveUsesExactHalfEvenModelQuantization(t *testing.T) {
	for _, tc := range []struct {
		forecast, required string
		reserve            int64
		ok                 bool
	}{
		{"1.6", "2.08", 300000, true}, {"1.6", "1.6", 300000, false},
		{"0.000000000005", "0.000000000006", 100000, true},
		{"0.000000000003", "0.000000000004", 500000, true},
		{"0.000000000003", "0.000000000005", 500000, false},
		// The producer's unrounded1/60 times1.1 rounds differently from its
		// retained forecast. This unsupported precision is conservatively held.
		{"0.016666666667", "0.018333333333", 100000, false},
	} {
		f, _ := number(tc.forecast)
		r, _ := number(tc.required)
		if requiredEqual(f, r, tc.reserve) != tc.ok {
			t.Fatalf("reserve rounding mismatch: %+v", tc)
		}
	}
}

func TestReserveRefusalNamesUnsupportedSummaryPrecision(t *testing.T) {
	in, now := fixture(t)
	m := in.Members[0].Document.ModelEvaluation
	m.Candidates[0].Checks[0]["required_with_reserve"] = m.Candidates[0].Checks[0]["forecast_requirement"]
	reseal(t, &in)
	_, e := Build(in, now)
	if !errors.Is(e, ErrReservePrecision) || !errors.Is(e, ErrJoin) {
		t.Fatal("reserve mismatch lost its explicit conservative refusal", e)
	}
}

func TestRateRefusalNamesUnsupportedSummaryPrecision(t *testing.T) {
	r := b.Rate{ObservedHourlyRate: ptr("0.033333333333"), UsageHours: ptr("3"), ObservedComputeCost: ptr("0.1")}
	if e := rateConsistency(r); !errors.Is(e, ErrRatePrecision) || !errors.Is(e, ErrJoin) {
		t.Fatal("rounded rate mismatch lost explicit unsupported-precision refusal", e)
	}
}

func TestIndependentRequestsAtIdenticalObservationTimeHaveDistinctIDs(t *testing.T) {
	in, now := fixture(t)
	first, e := Build(in, now)
	if e != nil {
		t.Fatal(e)
	}
	in.RequestID = "other-joint-request"
	second, e := Build(in, now)
	if e != nil || first.ID == second.ID || first.RequestID == second.RequestID || !first.ObservedAt.Equal(second.ObservedAt) {
		t.Fatal("different analytical requests collided", e)
	}
	in.RequestID = ""
	if _, e = Build(in, now); !errors.Is(e, ErrJoin) {
		t.Fatal("unbound analytical result accepted", e)
	}
}

func TestExpiredObservationsAndUnknownMoneyRefuse(t *testing.T) {
	in, now := fixture(t)
	if _, e := Build(in, now.Add(3*time.Minute)); e == nil {
		t.Fatal("renewed join time revived old rate observation")
	}
	in, now = fixture(t)
	in.Assessment.NativeRates.ValidUntil = now.Add(time.Second)
	assessment(t, &in, now)
	reseal(t, &in)
	if _, e := Build(in, now.Add(2*time.Second)); e == nil {
		t.Fatal("expired conditional quote accepted")
	}
	in, now = fixture(t)
	in.Scope.Scope.ObservedAt = now.Add(-6 * time.Minute)
	in.Scope.Scope.SnapshotSHA256 = c.ScopeHash(in.Scope)
	for i := range in.Members {
		in.Members[i].Document.Scope = in.Scope.Scope
	}
	reseal(t, &in)
	if _, e := Build(in, now); e == nil {
		t.Fatal("expired population scope accepted")
	}
	in, now = fixture(t)
	in.Assessment.NativeRates.Status = "UNAVAILABLE"
	assessment(t, &in, now)
	reseal(t, &in)
	if _, e := Build(in, now); e == nil {
		t.Fatal("unavailable rates retained monetary fields")
	}
}
