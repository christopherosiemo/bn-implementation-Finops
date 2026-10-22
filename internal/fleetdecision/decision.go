// Package fleetdecision joins issued035/036 observations without granting
// financial or execution authority. Hashes check consistency, not origin or
// currentness; the repository resolves issued inputs under publication locks.
package fleetdecision

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"time"

	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	c "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

var ErrJoin = errors.New("GROUP_DECISION_INPUTS_DO_NOT_JOIN")

// A retained rounded forecast cannot establish the producer's hidden precision.
// Refuse mismatched reserve arithmetic explicitly; never substitute an epsilon.
var ErrReservePrecision = fmt.Errorf("GROUP_DECISION_RESERVE_ARITHMETIC_OR_UNSUPPORTED_PRECISION: %w", ErrJoin)
var ErrRatePrecision = fmt.Errorf("GROUP_DECISION_RATE_ARITHMETIC_OR_UNSUPPORTED_PRECISION: %w", ErrJoin)
var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Ref struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}
type MemberDocument struct {
	Ref      Ref            `json:"ref"`
	Document c.MemberResult `json:"document"`
}

// Input is private resolved data, never a public proof or monetary upload DTO.
type Input struct {
	RequestID     string           `json:"request_id"`
	AssessmentRef Ref              `json:"assessment_ref"`
	Assessment    a.Assessment     `json:"assessment"`
	ScopeRef      Ref              `json:"scope_ref"`
	Scope         c.ScopeCapture   `json:"scope"`
	BatchRef      Ref              `json:"batch_ref"`
	Batch         c.BatchResult    `json:"batch"`
	Members       []MemberDocument `json:"members"`
	Profile       workload.Profile `json:"profile"`
}
type Dimension struct {
	Name                string   `json:"name"`
	Unit                string   `json:"unit"`
	Status              string   `json:"status"`
	CandidateCapacity   *string  `json:"candidate_capacity"`
	RequiredWithReserve *string  `json:"required_with_reserve"`
	ReasonCodes         []string `json:"reason_codes"`
}
type Member struct {
	InstanceID string      `json:"instance_id"`
	Result     Ref         `json:"result"`
	Status     string      `json:"status"`
	Dimensions []Dimension `json:"dimensions"`
}
type Decision struct {
	SchemaVersion                  string           `json:"schema_version"`
	ID                             string           `json:"id"`
	RequestID                      string           `json:"request_id"`
	Selection                      a.Selection      `json:"selection"`
	ObservedAt                     time.Time        `json:"observed_at"`
	Inputs                         []Ref            `json:"inputs"`
	Members                        []Member         `json:"members"`
	PhysicalStatus                 string           `json:"physical_status"`
	Scenario                       a.HourlyScenario `json:"scenario"`
	ContractedAvoidableCost        *string          `json:"contracted_avoidable_cost"`
	EstimatedSaving                *string          `json:"estimated_saving"`
	VerifiedSaving                 *string          `json:"verified_saving"`
	Status                         string           `json:"status"`
	GroupCapacityAuthorized        bool             `json:"group_capacity_authorized"`
	CompletedBusinessWorkPreserved *bool            `json:"completed_business_work_preserved"`
	PlanEligible                   bool             `json:"plan_eligible"`
	ExecutionAuthorized            bool             `json:"execution_authorized"`
	ChangePlanID                   *string          `json:"change_plan_id"`
	ReasonCodes                    []string         `json:"reason_codes"`
}

var dimensions = []struct{ name, unit string }{
	{"cpu", "vCPU"}, {"memory", "bytes"}, {"network", "bytes/second"},
	{"storage_iops", "operations/second"}, {"storage_throughput", "bytes/second"},
}

func same(x, y any) bool { return b.Hash(x) == b.Hash(y) }
func number(s string) (*big.Rat, error) {
	if !decimal.MatchString(s) {
		return nil, ErrJoin
	}
	v, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, ErrJoin
	}
	return v, nil
}
func bound(v any, limit int) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > limit {
		return ErrJoin
	}
	return nil
}
func reference(r Ref, v any) error {
	if r.ID == "" || !sha.MatchString(r.SHA256) || r.SHA256 != b.Hash(v) {
		return ErrJoin
	}
	return nil
}
func validPin(p b.GroupNativePin) bool {
	return p.ReceiptID != "" && p.RevisionID != "" && sha.MatchString(p.ReceiptSHA256) && sha.MatchString(p.RawSHA256) && p.ReceiptVersionID != "" && p.ReceiptVersionID != "null" && p.RevisionVersionID != "" && p.RevisionVersionID != "null"
}
func pins(in []b.GroupNativePin) (map[string]b.GroupNativePin, error) {
	out := map[string]b.GroupNativePin{}
	for _, p := range in {
		if !validPin(p) || out[p.ReceiptID].ReceiptID != "" {
			return nil, ErrJoin
		}
		out[p.ReceiptID] = p
	}
	return out, nil
}
func joinPin(p b.GroupNativePin, set map[string]b.GroupNativePin) bool {
	return validPin(p) && set[p.ReceiptID] == p
}
func rateConsistency(r b.Rate) error {
	if r.ObservedHourlyRate == nil || r.UsageHours == nil || r.ObservedComputeCost == nil {
		return ErrJoin
	}
	x, e := number(*r.ObservedHourlyRate)
	if e != nil {
		return e
	}
	h, e := number(*r.UsageHours)
	if e != nil {
		return e
	}
	cost, e := number(*r.ObservedComputeCost)
	if e != nil || x.Sign() <= 0 || h.Sign() <= 0 || cost.Sign() <= 0 {
		return ErrJoin
	}
	if new(big.Rat).Mul(x, h).Cmp(cost) != 0 {
		return ErrRatePrecision
	}
	return nil
}
func aggregate(prior, next string) string {
	if prior == "FAIL" || next == "FAIL" {
		return "FAIL"
	}
	if prior == "UNKNOWN" || next == "UNKNOWN" {
		return "UNKNOWN"
	}
	return "PASS"
}

// Build checks exact record linkage and derives dimensional observations. It
// does not rerun the model, certify native origin, or create a trusted issuer.
func Build(in Input, now time.Time) (Decision, error) {
	out := Decision{SchemaVersion: "1", RequestID: in.RequestID, Selection: in.Assessment.Selection, ObservedAt: now.UTC(), PhysicalStatus: "PASS", Status: "BLOCKED", Members: []Member{}, ReasonCodes: []string{"PURE_JOIN_NOT_SOURCE_AUTHENTICATION", "CONTRACTED_AVOIDABLE_TERMS_UNAVAILABLE", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE", "COMPLETED_BUSINESS_WORK_PRESERVATION_UNPROVEN", "TOPOLOGY_SLO_RISK_RECOVERY_GATES_INDEPENDENT", "PLAN_AND_EXECUTION_NOT_AUTHORIZED"}}
	if !requestIDPattern.MatchString(in.RequestID) || now.IsZero() || len(in.Members) < 1 || len(in.Members) > c.MaximumMembers || bound(in.Assessment, 1<<20) != nil || bound(in.Scope, 128<<10) != nil || bound(in.Batch, 128<<10) != nil || bound(in.Profile, 128<<10) != nil {
		return out, ErrJoin
	}
	if reference(in.AssessmentRef, in.Assessment) != nil || in.AssessmentRef.ID != in.Assessment.ID || reference(in.ScopeRef, in.Scope) != nil || in.ScopeRef.ID != in.Scope.RequestID || reference(in.BatchRef, in.Batch) != nil {
		return out, ErrJoin
	}
	if c.ValidateScope(in.Scope.Scope) != nil || in.Scope.SchemaVersion != "1" || in.Scope.Scope.PopulationStatus != "OBSERVED_POINT" || in.Scope.ExecutionAuthorized || in.Scope.VerifiedSaving != nil || c.ScopeHash(in.Scope) != in.Scope.Scope.SnapshotSHA256 || !same(in.Assessment.Selection, in.Scope.Scope.Selection) || !same(in.Batch.Scope, in.Scope.Scope) {
		return out, ErrJoin
	}
	if workload.Validate(in.Profile) != nil || in.Profile.ID != in.Assessment.Selection.SafetyProfile.ID || in.Profile.Version != in.Assessment.Selection.SafetyProfile.Version || workload.Hash(in.Profile) != in.Assessment.Selection.SafetyProfile.SHA256 || in.Profile.WorkloadID != in.Assessment.Selection.Groups.Binding.Old.Target.WorkloadID {
		return out, ErrJoin
	}
	if in.Assessment.ObservedAt.IsZero() || in.Scope.Scope.ObservedAt.IsZero() || in.Assessment.ObservedAt.After(now.Add(5*time.Second)) || in.Scope.Scope.ObservedAt.After(now.Add(5*time.Second)) {
		return out, ErrJoin
	}
	if in.Assessment.ObservedAt.Before(now.Add(-2*time.Minute)) || in.Scope.Scope.ObservedAt.Before(now.Add(-5*time.Minute)) {
		return out, ErrJoin
	}
	rebuilt, e := a.Build(in.Assessment.Selection, in.Assessment.NativeRates, in.Assessment.Capacity.Members, in.Assessment.ObservedAt)
	if e != nil || !same(rebuilt, in.Assessment) {
		return out, ErrJoin
	}
	out.Scenario = rebuilt.Scenario
	prices := in.Assessment.NativeRates
	if !same(prices.CurrentMemberIDs, in.Scope.Scope.CurrentMemberIDs) || len(prices.CurrentMemberIDs) != len(in.Members) || prices.Status == "OBSERVED_CONDITIONAL" && !prices.ValidUntil.After(now) {
		return out, ErrJoin
	}
	if prices.Status == "OBSERVED_CONDITIONAL" {
		if e := rateConsistency(prices.Old); e != nil {
			return out, e
		}
		if e := rateConsistency(prices.Candidate); e != nil {
			return out, e
		}
	}
	if prices.Status != "OBSERVED_CONDITIONAL" && (prices.Status != "UNAVAILABLE" || !same(prices.Old, b.Rate{}) || !same(prices.Candidate, b.Rate{})) {
		return out, ErrJoin
	}
	ratePins, e := pins(prices.SourcePins)
	if e != nil {
		return out, e
	}
	scopePins, e := pins(in.Scope.SourcePins)
	if e != nil {
		return out, e
	}
	for _, p := range in.Scope.SourcePins {
		if !joinPin(p, ratePins) {
			return out, ErrJoin
		}
	}
	if len(in.Scope.Scope.MembershipPins) != 2 {
		return out, ErrJoin
	}
	for _, p := range in.Scope.Scope.MembershipPins {
		if !joinPin(p, scopePins) {
			return out, ErrJoin
		}
	}
	candidate := in.Scope.CandidateTemplate
	if candidate == nil || candidate.ID == "" || candidate.Version == "" || candidate.ImageID == "" || !sha.MatchString(candidate.DefinitionSHA256) || len(candidate.ReasonCodes) != 0 || !joinPin(candidate.SourcePin, scopePins) || prices.Status == "OBSERVED_CONDITIONAL" && candidate.InstanceType != prices.Candidate.InstanceType {
		return out, ErrJoin
	}
	version, e := strconv.ParseUint(candidate.Version, 10, 64)
	if e != nil || version == 0 || strconv.FormatUint(version, 10) != candidate.Version {
		return out, ErrJoin
	}
	memberRows := make([]c.MemberResult, 0, len(in.Members))
	resources, hardware, connections := map[string]bool{}, map[string]bool{}, map[string]bool{}
	total := 0
	for _, row := range in.Members {
		m := row.Document
		if m.SchemaVersion != "1" || m.ObservedAt.IsZero() || bound(m, 1<<20) != nil || reference(row.Ref, m) != nil || row.Ref.ID != m.ID || m.BatchID != in.Scope.RequestID || m.ObservedAt.After(now.Add(5*time.Second)) {
			return out, ErrJoin
		}
		if m.ObservedAt.Before(now.Add(-5 * time.Minute)) {
			return out, ErrJoin
		}
		raw, _ := json.Marshal(m)
		total += len(raw)
		if total > 32<<20 {
			return out, ErrJoin
		}
		memberRows = append(memberRows, m)
		member, e := physical(m, row.Ref, in, ratePins)
		if e != nil {
			return out, e
		}
		if m.InputKind == "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST" {
			out.ReasonCodes = append(out.ReasonCodes, "CURRENT_CONFIGURATION_BASELINE_ONLY")
		}
		if m.ResourceID != "" {
			if resources[m.ResourceID] {
				return out, ErrJoin
			}
			resources[m.ResourceID] = true
		}
		if m.Hardware != nil {
			if hardware[m.Hardware.ReceiptID] {
				return out, ErrJoin
			}
			hardware[m.Hardware.ReceiptID] = true
		}
		if m.Telemetry != nil {
			if connections[m.Telemetry.ConnectionID] {
				return out, ErrJoin
			}
			connections[m.Telemetry.ConnectionID] = true
		}
		out.Members = append(out.Members, member)
		out.PhysicalStatus = aggregate(out.PhysicalStatus, member.Status)
	}
	summary, e := c.Summarize(in.Scope.Scope, memberRows)
	if e != nil || !same(summary, in.Batch) {
		return out, ErrJoin
	}
	sort.Slice(out.Members, func(i, j int) bool { return out.Members[i].InstanceID < out.Members[j].InstanceID })
	out.Inputs = []Ref{in.AssessmentRef, in.ScopeRef, in.BatchRef, {ID: in.Profile.ID, SHA256: workload.Hash(in.Profile)}}
	for _, m := range out.Members {
		out.Inputs = append(out.Inputs, m.Result)
	}
	// Deep freeze pointer-bearing scenario fields; callers retain their inputs.
	raw, e := json.Marshal(out)
	if e != nil {
		return out, e
	}
	if e = json.Unmarshal(raw, &out); e != nil {
		return out, e
	}
	out.ID = "group-joint-decision-" + b.Hash(out)
	return out, nil
}

type check struct {
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

func capacity(p native.PhysicalCapacity, name string) *string {
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
func decode(v any, out any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return ErrJoin
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrJoin
	}
	return nil
}
func physical(m c.MemberResult, ref Ref, in Input, ratePins map[string]b.GroupNativePin) (Member, error) {
	out := Member{InstanceID: m.InstanceID, Result: ref, Status: "PASS", Dimensions: []Dimension{}}
	unknown := func() (Member, error) {
		out.Status = "UNKNOWN"
		for _, d := range dimensions {
			out.Dimensions = append(out.Dimensions, Dimension{Name: d.name, Unit: d.unit, Status: "UNKNOWN", ReasonCodes: []string{"MEMBER_PHYSICAL_EVIDENCE_UNAVAILABLE"}})
		}
		return out, nil
	}
	if !m.ModelEvaluated {
		if m.ModelEvaluation != nil || m.CapacitySuitable != nil {
			return out, ErrJoin
		}
		return unknown()
	}
	p := in.Scope.Scope.Selection.Groups.Binding.Old.Target
	if m.Binding == nil || m.Binding.TenantID != p.TenantID || m.Binding.WorkloadID != p.WorkloadID || m.Binding.Provider != "AWS" || m.Binding.ProviderResourceID != m.InstanceID || m.Binding.ResourceID != m.ResourceID || m.Binding.AccountID != p.AccountID || m.Binding.Region != p.Region || m.Hardware == nil || m.Telemetry == nil || m.HardwareMapping == nil || m.ModelEvaluation == nil || m.CandidateTemplate == nil || !same(m.CandidateTemplate, in.Scope.CandidateTemplate) || !joinPin(m.Hardware.SourcePin, ratePins) || m.Hardware.SourcePin.ReceiptID != m.Hardware.ReceiptID || m.Hardware.SourcePin.RevisionID != m.Hardware.RevisionID || m.Hardware.SourcePin.RawSHA256 != m.Hardware.RawSHA256 || !sha.MatchString(m.Telemetry.PopulationHash) || !sha.MatchString(m.InputHash) {
		return out, ErrJoin
	}
	mapResult := m.HardwareMapping
	result := m.ModelEvaluation
	if !m.ModelRequested || m.Status != "BLOCKED" || m.DemandMeaning != "REQUEST_THROUGHPUT_PROXY" || m.Hardware.SourceID != in.Scope.Scope.Selection.Groups.Binding.Old.SourceID || m.Hardware.RegistrationVersion != in.Scope.Scope.Selection.Groups.Binding.Old.SourceRegistrationVersion || m.Hardware.ConfigHash != in.Scope.Scope.Selection.Groups.Binding.Old.SourceConfigSHA256 || m.Hardware.ResourceVersion < 1 || !sha.MatchString(m.Hardware.ResourceSnapshotHash) || m.Telemetry.ConnectionVersion < 1 || m.Telemetry.RevisionID == "" || !sha.MatchString(m.Telemetry.ConfigHash) {
		return out, ErrJoin
	}
	telemetryRefs, e := metricRefs(m)
	if e != nil {
		return out, e
	}
	if len(mapResult.Candidates) != 1 || mapResult.Candidates[0].ID != in.Scope.CandidateTemplate.InstanceType || mapResult.Candidates[0].Count != 1 || mapResult.Current.Count != 1 || mapResult.Current.Pricing != nil || mapResult.Candidates[0].Pricing != nil || mapResult.Current.CommitmentCompatible != nil || mapResult.Candidates[0].CommitmentCompatible != nil || len(result.Candidates) != 1 || result.SchemaVersion != "4" || result.ModelVersion != native.CapacityProxyModelVersion || result.Binding != *m.Binding || result.Status != "BLOCKED" && result.Status != "INSUFFICIENT_OBSERVATION" {
		return out, ErrJoin
	}
	baselineReason := false
	for _, reason := range m.ReasonCodes {
		baselineReason = baselineReason || reason == "CURRENT_CONFIGURATION_BASELINE_ONLY"
	}
	baseline := m.InputKind == "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST"
	if mapResult.Current.ID == mapResult.Candidates[0].ID {
		// A same-type physical observation is a current configuration baseline,
		// never a hypothetical default-CPU candidate or positive fleet money.
		if !baseline || !baselineReason || !same(mapResult.Current, mapResult.Candidates[0]) || in.Assessment.NativeRates.Status == "OBSERVED_CONDITIONAL" {
			return out, ErrJoin
		}
	} else if baseline || baselineReason {
		return out, ErrJoin
	}
	if in.Assessment.NativeRates.Status == "OBSERVED_CONDITIONAL" && mapResult.Current.ID != in.Assessment.NativeRates.Old.InstanceType {
		return out, ErrJoin
	}
	if mapResult.Current.SourceRef != mapResult.Candidates[0].SourceRef || mapResult.Current.SourceRef.ID != m.Hardware.ReceiptID || mapResult.Current.SourceRef.Version != strconv.FormatInt(m.Hardware.RegistrationVersion, 10) {
		return out, ErrJoin
	}
	raw, e := json.Marshal(result)
	if e != nil {
		return out, ErrJoin
	}
	modelHash, e := native.CapacityModelBodyHash(raw)
	if e != nil || modelHash != result.AssessmentHash {
		return out, ErrJoin
	}
	start, e1 := time.Parse(time.RFC3339Nano, model.String(result.History, "start"))
	end, e2 := time.Parse(time.RFC3339Nano, model.String(result.History, "end"))
	if e1 != nil || e2 != nil || !start.Equal(in.Assessment.NativeRates.Baseline.Start) || !end.Equal(in.Assessment.NativeRates.Baseline.End) {
		return out, ErrJoin
	}
	var history struct {
		Cadence     int64  `json:"cadence_seconds"`
		Timezone    string `json:"timezone"`
		Environment string `json:"environment"`
	}
	historyRaw, _ := json.Marshal(result.History)
	if json.Unmarshal(historyRaw, &history) != nil || history.Cadence < 1 || history.Cadence > 86400 || history.Timezone != in.Profile.Timezone || history.Environment != "NON_PRODUCTION" && history.Environment != "PRODUCTION" || end.Sub(start)%(time.Duration(history.Cadence)*time.Second) != 0 {
		return out, ErrJoin
	}
	if (in.Profile.Criticality == "NON_PRODUCTION") != (history.Environment == "NON_PRODUCTION") {
		return out, ErrJoin
	}
	expectedIntervals := int64(end.Sub(start)/time.Second) / history.Cadence
	modelCandidate := result.Candidates[0]
	economic := modelCandidate.Economics
	if modelCandidate.ID != mapResult.Candidates[0].ID || modelCandidate.Count != 1 || modelCandidate.SourceRef != mapResult.Candidates[0].SourceRef || modelCandidate.SourceRef.Binding != *m.Binding || modelCandidate.SourceRef.ReceiptID != m.Hardware.ReceiptID || modelCandidate.SourceRef.SHA256 != m.Hardware.RawSHA256 || m.CapacitySuitable == nil || *m.CapacitySuitable != modelCandidate.CapacitySuitable || modelCandidate.CapacitySuitable || economic.Status != "UNAVAILABLE" || economic.Currency != nil || economic.CurrentCost != nil || economic.CandidateCost != nil || economic.EstimatedSaving != nil || economic.VerifiedSaving != nil || len(economic.PriceSourceRefs) != 0 || modelCandidate.FutureRisk.Status != "UNCALIBRATED" || modelCandidate.FutureRisk.ProbabilityUpperPPM != nil {
		return out, ErrJoin
	}
	checks := map[string]check{}
	for _, d := range modelCandidate.Checks {
		var v check
		if decode(d, &v) != nil || checks[v.Dimension].Dimension != "" {
			return out, ErrJoin
		}
		known := false
		for _, want := range dimensions {
			known = known || v.Dimension == want.name
		}
		if !known {
			return out, ErrJoin
		}
		checks[v.Dimension] = v
	}
	for _, want := range dimensions {
		d := Dimension{Name: want.name, Unit: want.unit, Status: "UNKNOWN", ReasonCodes: []string{}}
		v, ok := checks[want.name]
		expected := capacity(mapResult.Candidates[0].Capacity, want.name)
		if !ok || expected == nil {
			d.ReasonCodes = []string{"REQUIRED_PHYSICAL_CHECK_UNAVAILABLE"}
			out.Dimensions = append(out.Dimensions, d)
			out.Status = aggregate(out.Status, d.Status)
			continue
		}
		cap, e := number(v.Capacity)
		req, e2 := number(v.Required)
		observed, e3 := number(v.P99)
		forecast, e4 := number(v.Forecast)
		if e != nil || e2 != nil || e3 != nil || e4 != nil || cap.Sign() <= 0 || v.Capacity != *expected || v.Unit != want.unit || v.Reserve != in.Profile.Headroom.ReserveAboveForecastPPM || v.Unused != 0 || v.Projected < 0 || forecast.Cmp(observed) < 0 || !projectedEqual(observed, cap, v.Projected) {
			return out, ErrJoin
		}
		if !requiredEqual(forecast, req, v.Reserve) {
			return out, ErrReservePrecision
		}
		pass := cap.Cmp(req) >= 0
		if want.name == "cpu" || want.name == "memory" {
			limit, rollback := min(int64(700000), 1000000-in.Profile.Headroom.CPUFreePPM), in.Profile.Saturation.CPUP99PPM
			if want.name == "memory" {
				limit, rollback = min(int64(750000), 1000000-in.Profile.Headroom.MemoryFreePPM), in.Profile.Saturation.MemoryP99PPM
			}
			if v.P95 == nil || v.P95Limit == nil || v.Rollback == nil || *v.P95 < 0 || *v.P95Limit != limit || *v.Rollback != rollback {
				return out, ErrJoin
			}
			pass = pass && *v.P95 <= limit && v.Projected <= rollback
		} else if v.P95Limit != nil || v.Rollback != nil {
			return out, ErrJoin
		}
		d.Status = "FAIL"
		if pass {
			d.Status = "PASS"
		}
		if v.Status != d.Status {
			return out, ErrJoin
		}
		complete, e := metricComplete(result.Metrics, want.name, want.unit, capacity(mapResult.Current.Capacity, want.name), v, expectedIntervals, history.Cadence, telemetryRefs)
		if e != nil {
			return out, e
		}
		if pass && (!complete || result.Status == "INSUFFICIENT_OBSERVATION") {
			d.Status = "UNKNOWN"
			d.ReasonCodes = []string{"REQUIRED_PHYSICAL_STATISTICS_UNAVAILABLE"}
		}
		d.CandidateCapacity = &v.Capacity
		d.RequiredWithReserve = &v.Required
		out.Dimensions = append(out.Dimensions, d)
		out.Status = aggregate(out.Status, d.Status)
	}
	return out, nil
}

func projectedEqual(observed, capacity *big.Rat, want int64) bool {
	x := new(big.Rat).Mul(new(big.Rat).Quo(observed, capacity), big.NewRat(1000000, 1))
	q, r := new(big.Int).QuoRem(x.Num(), x.Denom(), new(big.Int))
	if r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	return q.IsInt64() && q.Int64() == want
}

// Python's money() quantizes to 12 decimal places using round-half-even.
// Require that exact operation on the retained forecast. Cases whose hidden
// pre-serialization precision would alter the answer are conservatively refused.
func requiredEqual(forecast, required *big.Rat, reserve int64) bool {
	want := new(big.Rat).Mul(forecast, big.NewRat(1000000+reserve, 1000000))
	scale := big.NewInt(1000000000000)
	scaled := new(big.Rat).Mul(want, new(big.Rat).SetInt(scale))
	q, r := new(big.Int).QuoRem(scaled.Num(), scaled.Denom(), new(big.Int))
	cmp := new(big.Int).Lsh(r, 1).Cmp(scaled.Denom())
	if cmp > 0 || cmp == 0 && q.Bit(0) == 1 {
		q.Add(q, big.NewInt(1))
	}
	return required.Cmp(new(big.Rat).SetFrac(q, scale)) == 0
}

// Missing statistics cannot become PASS. This checks retained summary linkage;
// it does not authenticate raw samples or reproduce the forecasting algorithm.
func metricComplete(rows []model.Document, name, unit string, current *string, v check, expectedIntervals, cadence int64, refs map[native.CapacityModelRef]bool) (bool, error) {
	var found model.Document
	for _, row := range rows {
		if model.String(row, "name") == name {
			if found != nil {
				return false, ErrJoin
			}
			found = row
		}
	}
	if found == nil {
		return false, nil
	}
	var s struct {
		Name, Unit, Statistic string
		Coverage              int64                     `json:"coverage_ppm"`
		Time                  int64                     `json:"time_coverage_ppm"`
		Sampling              int64                     `json:"sampling_coverage_ppm"`
		Observed              int64                     `json:"observed_intervals"`
		Expected              int64                     `json:"expected_intervals"`
		Missing               int64                     `json:"missing_intervals"`
		Unknown               string                    `json:"unknown_seconds"`
		Cadence               int64                     `json:"cadence_seconds"`
		Samples               string                    `json:"observed_samples"`
		Refs                  []native.CapacityModelRef `json:"source_refs"`
		Denominator           struct {
			Value string
			Unit  string
		}
		Quantiles map[string]struct {
			Upper  *string
			Status string
		} `json:"observed_quantiles"`
	}
	raw, e := json.Marshal(found)
	if e != nil || json.Unmarshal(raw, &s) != nil {
		return false, ErrJoin
	}
	if s.Name != name || s.Unit != unit || current == nil || s.Denominator.Value != *current || s.Denominator.Unit != unit {
		return false, ErrJoin
	}
	if s.Cadence != cadence || s.Expected != expectedIntervals || len(s.Refs) == 0 {
		return false, ErrJoin
	}
	seen := map[native.CapacityModelRef]bool{}
	for _, ref := range s.Refs {
		if !refs[ref] || seen[ref] {
			return false, ErrJoin
		}
		seen[ref] = true
	}
	samples, e := strconv.ParseUint(s.Samples, 10, 64)
	if e != nil || strconv.FormatUint(samples, 10) != s.Samples {
		return false, ErrJoin
	}
	stat := "OBSERVED_INTERVAL_RATE"
	if name == "cpu" || name == "memory" {
		stat = "RAW_SAMPLE"
	}
	if s.Statistic != stat {
		return false, nil
	}
	u, e := number(s.Unknown)
	if e != nil {
		return false, ErrJoin
	}
	q := s.Quantiles["p99"]
	if q.Status != "OBSERVED" || q.Upper == nil {
		return false, nil
	}
	if *q.Upper != v.P99 {
		return false, ErrJoin
	}
	if name == "cpu" || name == "memory" {
		q95 := s.Quantiles["p95"]
		if q95.Status != "OBSERVED" || q95.Upper == nil {
			return false, nil
		}
		p95, e := number(*q95.Upper)
		cap, _ := number(v.Capacity)
		if e != nil || v.P95 == nil || !projectedEqual(p95, cap, *v.P95) {
			return false, ErrJoin
		}
	}
	return s.Coverage == 1000000 && s.Time == 1000000 && s.Sampling == 1000000 && s.Observed >= 30 && s.Expected == s.Observed && samples >= uint64(s.Observed) && s.Missing == 0 && u.Sign() == 0, nil
}

func metricRefs(m c.MemberResult) (map[native.CapacityModelRef]bool, error) {
	refs := map[native.CapacityModelRef]bool{}
	ids := map[string]bool{}
	for _, id := range m.Telemetry.ReceiptIDs {
		if id == "" || ids[id] {
			return nil, ErrJoin
		}
		ids[id] = true
	}
	if len(ids) == 0 || len(ids) != len(m.Telemetry.SourceRefs) {
		return nil, ErrJoin
	}
	seen := map[string]bool{}
	for _, r := range m.Telemetry.SourceRefs {
		if !ids[r.ReceiptID] || seen[r.ReceiptID] || r.BatchID == "" || r.ConfigHash != m.Telemetry.ConfigHash || !sha.MatchString(r.RawSHA256) || !sha.MatchString(r.CanonicalHash) {
			return nil, ErrJoin
		}
		seen[r.ReceiptID] = true
		ref := native.CapacityModelRef{ID: r.BatchID, Version: r.ConfigHash, ReceiptID: r.ReceiptID, SHA256: r.CanonicalHash, Binding: *m.Binding}
		if refs[ref] {
			return nil, ErrJoin
		}
		refs[ref] = true
	}
	for ref := range refs {
		found := false
		for _, retained := range m.ModelEvaluation.EvidenceRefs {
			found = found || retained == ref
		}
		if !found {
			return nil, ErrJoin
		}
	}
	return refs, nil
}
