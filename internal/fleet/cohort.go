package fleet

import (
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Cohort inputs are selected from authenticated immutable SLO receipts by a
// private server factory. This calculation checks scope and arithmetic; it does
// not authenticate an exporter, establish membership, prove CPU/memory headroom,
// preserve application demand, or authorize a deployment on its own.
type CohortLimits struct {
	ObjectiveID              string `json:"objective_id"`
	ObjectiveVersion         int64  `json:"objective_version"`
	ObjectiveSHA256          string `json:"objective_sha256"`
	MaximumErrorRatePPM      int64  `json:"maximum_error_rate_ppm"`
	MinimumAvailabilityPPM   int64  `json:"minimum_availability_ppm"`
	MaximumP95MS             int64  `json:"maximum_p95_ms"`
	MaximumP99MS             int64  `json:"maximum_p99_ms"`
	MinimumLatencySamples    int64  `json:"minimum_latency_samples"`
	MaximumRegressionPercent int64  `json:"maximum_regression_percent"`
}
type CohortBucket struct {
	UpperBoundMS *int64 `json:"upper_bound_ms"`
	Count        int64  `json:"count"`
}
type CohortMemberWindow struct {
	Binding                  Binding        `json:"binding"`
	ObjectiveID              string         `json:"objective_id"`
	ObjectiveVersion         int64          `json:"objective_version"`
	ObjectiveSHA256          string         `json:"objective_sha256"`
	InstanceID               string         `json:"instance_id"`
	SourceID                 string         `json:"source_id"`
	SourceSHA256             string         `json:"source_sha256"`
	EvaluationID             string         `json:"evaluation_id"`
	EvaluationSHA256         string         `json:"evaluation_sha256"`
	ReceiptIDs               []string       `json:"receipt_ids"`
	RequestCount             int64          `json:"request_count"`
	ErrorCount               int64          `json:"error_count"`
	AvailabilityGoodSeconds  int64          `json:"availability_good_seconds"`
	AvailabilityTotalSeconds int64          `json:"availability_total_seconds"`
	LatencySamples           int64          `json:"latency_samples"`
	LatencyBuckets           []CohortBucket `json:"latency_buckets"`
}
type CohortWindow struct {
	Binding          Binding              `json:"binding"`
	ASG              string               `json:"asg"`
	Role             string               `json:"role"`
	ObjectiveID      string               `json:"objective_id"`
	ObjectiveVersion int64                `json:"objective_version"`
	ObjectiveSHA256  string               `json:"objective_sha256"`
	Start            time.Time            `json:"start"`
	End              time.Time            `json:"end"`
	Members          []CohortMemberWindow `json:"members"`
}
type CohortInput struct {
	Now                                                              time.Time
	Parent                                                           FleetPlanV4
	Limits                                                           CohortLimits
	FrozenBlueMemberIDs, CurrentBlueMemberIDs, CurrentGreenMemberIDs []string
	Baseline, BlueControl, Green                                     CohortWindow
}
type QuantileBounds struct {
	LowerMS int64  `json:"lower_ms"`
	UpperMS *int64 `json:"upper_ms"`
}
type CohortComparison struct {
	SchemaVersion     string         `json:"schema_version"`
	Binding           Binding        `json:"binding"`
	ParentSHA256      string         `json:"parent_sha256"`
	ObjectiveID       string         `json:"objective_id"`
	ObjectiveVersion  int64          `json:"objective_version"`
	ObjectiveSHA256   string         `json:"objective_sha256"`
	Status            string         `json:"status"`
	ReasonCodes       []string       `json:"reason_codes"`
	BaselineSHA256    string         `json:"baseline_sha256"`
	BlueControlSHA256 string         `json:"blue_control_sha256"`
	GreenSHA256       string         `json:"green_sha256"`
	BaselineP95       QuantileBounds `json:"baseline_p95"`
	BaselineP99       QuantileBounds `json:"baseline_p99"`
	BlueControlP95    QuantileBounds `json:"blue_control_p95"`
	BlueControlP99    QuantileBounds `json:"blue_control_p99"`
	GreenP95          QuantileBounds `json:"green_p95"`
	GreenP99          QuantileBounds `json:"green_p99"`
	ObservedAt        time.Time      `json:"observed_at"`
	Hash              string         `json:"hash"`
}

const cohortMaxCount int64 = 1_000_000_000_000

var cohortInstance = regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)

type cohortAggregate struct {
	requests, errors, good, total, samples int64
	buckets                                []CohortBucket
}

func sameMemberSet(members []CohortMemberWindow, expected []string) bool {
	if len(members) == 0 || len(members) > 4096 || len(members) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range expected {
		if !cohortInstance.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, m := range members {
		if !seen[m.InstanceID] {
			return false
		}
		delete(seen, m.InstanceID)
	}
	return len(seen) == 0
}
func cohortAdd(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > cohortMaxCount-b {
		return 0, false
	}
	return a + b, true
}
func aggregateCohort(w CohortWindow, ids []string, role, asg string, p FleetPlanV4, l CohortLimits) (cohortAggregate, string) {
	a := cohortAggregate{}
	if w.Binding != p.Binding || w.ASG != asg || w.Role != role || w.ObjectiveID != l.ObjectiveID || w.ObjectiveVersion != l.ObjectiveVersion || w.ObjectiveSHA256 != l.ObjectiveSHA256 || !sameMemberSet(w.Members, ids) {
		return a, "COHORT_SCOPE_MISMATCH"
	}
	duration := w.End.Sub(w.Start)
	if duration < 2*time.Minute || duration > 60*time.Minute || duration%time.Minute != 0 || !w.Start.Equal(w.Start.Truncate(time.Minute)) || !w.End.Equal(w.End.Truncate(time.Minute)) {
		return a, "COHORT_COMPLETE_WINDOW_REQUIRED"
	}
	sources, receipts, evaluations := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range w.Members {
		if m.Binding.TenantID != p.Binding.TenantID || m.Binding.WorkloadID != p.Binding.WorkloadID || m.Binding.Provider != p.Binding.Provider || m.Binding.Region != p.Binding.Region || m.Binding.AccountID != p.Binding.AccountID || m.Binding.ProviderResourceID != m.InstanceID || m.Binding.ResourceID == "" || m.ObjectiveID != l.ObjectiveID || m.ObjectiveVersion != l.ObjectiveVersion || m.ObjectiveSHA256 != l.ObjectiveSHA256 {
			return a, "COHORT_MEMBER_SCOPE_MISMATCH"
		}
		if m.SourceID == "" || sources[m.SourceID] || !hashPattern.MatchString(m.SourceSHA256) || m.EvaluationID == "" || evaluations[m.EvaluationID] || !hashPattern.MatchString(m.EvaluationSHA256) || int64(len(m.ReceiptIDs)) != int64(duration/time.Minute) {
			return a, "COHORT_MEMBER_EVIDENCE_REQUIRED"
		}
		sources[m.SourceID] = true
		evaluations[m.EvaluationID] = true
		for _, id := range m.ReceiptIDs {
			if id == "" || receipts[id] {
				return a, "COHORT_RECEIPT_REUSE"
			}
			receipts[id] = true
		}
		if m.RequestCount < 0 || m.RequestCount > cohortMaxCount || m.ErrorCount < 0 || m.ErrorCount > m.RequestCount || m.LatencySamples < 0 || m.LatencySamples > m.RequestCount || m.AvailabilityTotalSeconds != int64(duration/time.Second) || m.AvailabilityGoodSeconds < 0 || m.AvailabilityGoodSeconds > m.AvailabilityTotalSeconds || len(m.LatencyBuckets) < 2 || len(m.LatencyBuckets) > 256 {
			return a, "COHORT_COUNTERS_OR_COVERAGE_INVALID"
		}
		var count, previous int64
		for i, b := range m.LatencyBuckets {
			if b.Count < 0 || b.Count > cohortMaxCount {
				return a, "COHORT_HISTOGRAM_INVALID"
			}
			var ok bool
			count, ok = cohortAdd(count, b.Count)
			if !ok {
				return a, "COHORT_HISTOGRAM_INVALID"
			}
			if i == len(m.LatencyBuckets)-1 {
				if b.UpperBoundMS != nil {
					return a, "COHORT_HISTOGRAM_TERMINAL_REQUIRED"
				}
			} else {
				if b.UpperBoundMS == nil || *b.UpperBoundMS <= previous || *b.UpperBoundMS > 86_400_000 {
					return a, "COHORT_HISTOGRAM_INVALID"
				}
				previous = *b.UpperBoundMS
			}
		}
		if count != m.LatencySamples {
			return a, "COHORT_HISTOGRAM_COUNT_MISMATCH"
		}
		if m.RequestCount == 0 || m.LatencySamples < l.MinimumLatencySamples {
			return a, "COHORT_MEMBER_LATENCY_OR_DEMAND_UNKNOWN"
		}
		if cohortRatio(m.ErrorCount, m.RequestCount).Cmp(big.NewRat(l.MaximumErrorRatePPM, 1_000_000)) > 0 || cohortRatio(m.AvailabilityGoodSeconds, m.AvailabilityTotalSeconds).Cmp(big.NewRat(l.MinimumAvailabilityPPM, 1_000_000)) < 0 {
			return a, "COHORT_MEMBER_HARD_LIMIT_BREACH"
		}
		individual := cohortAggregate{samples: m.LatencySamples, buckets: m.LatencyBuckets}
		for _, q := range []struct {
			bounds QuantileBounds
			limit  int64
		}{{cohortQuantile(individual, 95), l.MaximumP95MS}, {cohortQuantile(individual, 99), l.MaximumP99MS}} {
			if q.bounds.UpperMS == nil {
				return a, "COHORT_MEMBER_LATENCY_TAIL_UNKNOWN"
			}
			if q.bounds.LowerMS > q.limit {
				return a, "COHORT_MEMBER_HARD_LIMIT_BREACH"
			}
			if *q.bounds.UpperMS > q.limit {
				return a, "COHORT_MEMBER_HARD_LIMIT_UNCERTAIN"
			}
		}
		if a.buckets == nil {
			a.buckets = make([]CohortBucket, len(m.LatencyBuckets))
			for i, b := range m.LatencyBuckets {
				a.buckets[i] = CohortBucket{UpperBoundMS: b.UpperBoundMS}
			}
		}
		if len(a.buckets) != len(m.LatencyBuckets) {
			return a, "COHORT_HISTOGRAM_LAYOUT_MISMATCH"
		}
		for i, b := range m.LatencyBuckets {
			prior := a.buckets[i].UpperBoundMS
			if (prior == nil) != (b.UpperBoundMS == nil) || prior != nil && *prior != *b.UpperBoundMS {
				return a, "COHORT_HISTOGRAM_LAYOUT_MISMATCH"
			}
			var ok bool
			a.buckets[i].Count, ok = cohortAdd(a.buckets[i].Count, b.Count)
			if !ok {
				return a, "COHORT_COUNT_LIMIT"
			}
		}
		for _, pair := range []struct {
			out *int64
			add int64
		}{{&a.requests, m.RequestCount}, {&a.errors, m.ErrorCount}, {&a.good, m.AvailabilityGoodSeconds}, {&a.total, m.AvailabilityTotalSeconds}, {&a.samples, m.LatencySamples}} {
			v, ok := cohortAdd(*pair.out, pair.add)
			if !ok {
				return a, "COHORT_COUNT_LIMIT"
			}
			*pair.out = v
		}
	}
	return a, ""
}
func cohortQuantile(a cohortAggregate, percent int64) QuantileBounds {
	if a.samples == 0 {
		return QuantileBounds{}
	}
	rank := (a.samples*percent + 99) / 100
	var cumulative, lower int64
	for _, b := range a.buckets {
		cumulative += b.Count
		if cumulative >= rank {
			return QuantileBounds{lower, b.UpperBoundMS}
		}
		if b.UpperBoundMS != nil {
			lower = *b.UpperBoundMS
		}
	}
	return QuantileBounds{}
}
func cohortRatio(n, d int64) *big.Rat {
	if d <= 0 {
		return nil
	}
	return new(big.Rat).SetFrac(big.NewInt(n), big.NewInt(d))
}
func cohortRegression(current, baseline QuantileBounds, percent int64) string {
	if current.UpperMS == nil || baseline.UpperMS == nil || baseline.LowerMS <= 0 {
		return "UNKNOWN"
	}
	upperAllowed := new(big.Rat).Mul(big.NewRat(*baseline.UpperMS, 1), big.NewRat(100+percent, 100))
	lowerAllowed := new(big.Rat).Mul(big.NewRat(baseline.LowerMS, 1), big.NewRat(100+percent, 100))
	if big.NewRat(current.LowerMS, 1).Cmp(upperAllowed) > 0 {
		return "BREACH"
	}
	if big.NewRat(*current.UpperMS, 1).Cmp(lowerAllowed) <= 0 {
		return "CLEAR"
	}
	return "UNKNOWN"
}

func CohortComparisonHash(r CohortComparison) string { r.Hash = ""; return Digest(r) }

// CompareCohorts compares separate physical cohorts explicitly. New green
// sources are not mislabeled as the old blue SourceHash. Both current cohorts
// must independently satisfy hard limits; green must also pass regression
// against the immutable pre-plan blue window and the concurrent blue control.
func CompareCohorts(in CohortInput) CohortComparison {
	l, p := in.Limits, in.Parent
	r := CohortComparison{SchemaVersion: "1", Binding: p.Binding, ParentSHA256: Digest(p), ObjectiveID: l.ObjectiveID, ObjectiveVersion: l.ObjectiveVersion, ObjectiveSHA256: l.ObjectiveSHA256, Status: "CLEAR", ReasonCodes: []string{}, BaselineSHA256: Digest(in.Baseline), BlueControlSHA256: Digest(in.BlueControl), GreenSHA256: Digest(in.Green), ObservedAt: in.Now.UTC()}
	mark := func(status, reason string) {
		if status == "BREACH" || r.Status != "BREACH" {
			r.Status = status
		}
		r.ReasonCodes = append(r.ReasonCodes, reason)
	}
	finish := func() CohortComparison { sort.Strings(r.ReasonCodes); r.Hash = CohortComparisonHash(r); return r }
	invalid := func(reason string) CohortComparison {
		status := "BLOCKED"
		if strings.HasSuffix(reason, "_BREACH") {
			status = "BREACH"
		}
		mark(status, reason)
		return finish()
	}
	if in.Now.IsZero() || l.ObjectiveID == "" || l.ObjectiveVersion < 1 || !hashPattern.MatchString(l.ObjectiveSHA256) || l.MaximumErrorRatePPM < 0 || l.MaximumErrorRatePPM > 1_000_000 || l.MinimumAvailabilityPPM < 0 || l.MinimumAvailabilityPPM > 1_000_000 || l.MaximumP95MS <= 0 || l.MaximumP99MS < l.MaximumP95MS || l.MaximumP99MS > 86_400_000 || l.MinimumLatencySamples < 1 || l.MinimumLatencySamples > cohortMaxCount || l.MaximumRegressionPercent < 0 || l.MaximumRegressionPercent > 1000 {
		mark("BLOCKED", "COHORT_POLICY_INVALID")
		return finish()
	}
	if ValidatePlan(p, p.Binding, p.CreatedAt) != nil {
		mark("BLOCKED", "COHORT_PARENT_INVALID")
		return finish()
	}
	if len(in.FrozenBlueMemberIDs) != p.Old.DesiredCount || in.Baseline.End.After(p.CreatedAt) || in.Baseline.End.Before(p.CreatedAt.Add(-2*time.Minute)) || in.Green.Start.Before(in.Baseline.End) || !in.BlueControl.Start.Equal(in.Green.Start) || !in.BlueControl.End.Equal(in.Green.End) || in.Green.End.Before(in.Now.Add(-2*time.Minute)) || in.Green.End.After(in.Now.Add(5*time.Second)) {
		mark("BLOCKED", "COHORT_FROZEN_BASELINE_OR_CURRENT_WINDOW_INVALID")
		return finish()
	}
	blue := map[string]bool{}
	for _, id := range in.FrozenBlueMemberIDs {
		blue[id] = true
	}
	for _, id := range in.CurrentBlueMemberIDs {
		blue[id] = true
	}
	for _, id := range in.CurrentGreenMemberIDs {
		if blue[id] {
			mark("BLOCKED", "COHORT_PHYSICAL_MEMBER_OVERLAP")
			return finish()
		}
	}
	base, reason := aggregateCohort(in.Baseline, in.FrozenBlueMemberIDs, "FROZEN_BLUE_BASELINE", p.Old.ID, p, l)
	if reason != "" {
		return invalid(reason)
	}
	control, reason := aggregateCohort(in.BlueControl, in.CurrentBlueMemberIDs, "CURRENT_BLUE_CONTROL", p.Old.ID, p, l)
	if reason != "" {
		return invalid(reason)
	}
	green, reason := aggregateCohort(in.Green, in.CurrentGreenMemberIDs, "CURRENT_GREEN", p.Candidate.ID, p, l)
	if reason != "" {
		return invalid(reason)
	}
	priorReceipts := map[string]bool{}
	priorSources := map[string]bool{}
	for _, w := range []CohortWindow{in.Baseline, in.BlueControl} {
		for _, m := range w.Members {
			priorSources[m.SourceID] = true
			for _, id := range m.ReceiptIDs {
				if priorReceipts[id] {
					mark("BLOCKED", "COHORT_RECEIPT_REUSE")
					return finish()
				}
				priorReceipts[id] = true
			}
		}
	}
	for _, m := range in.Green.Members {
		if priorSources[m.SourceID] {
			mark("BLOCKED", "COHORT_SOURCE_REUSED_ACROSS_PHYSICAL_COHORTS")
			return finish()
		}
		for _, id := range m.ReceiptIDs {
			if priorReceipts[id] {
				mark("BLOCKED", "COHORT_RECEIPT_REUSE")
				return finish()
			}
		}
	}
	r.BaselineP95, r.BaselineP99 = cohortQuantile(base, 95), cohortQuantile(base, 99)
	r.BlueControlP95, r.BlueControlP99 = cohortQuantile(control, 95), cohortQuantile(control, 99)
	r.GreenP95, r.GreenP99 = cohortQuantile(green, 95), cohortQuantile(green, 99)
	for _, v := range []struct {
		name     string
		a        cohortAggregate
		p95, p99 QuantileBounds
	}{{"BASELINE", base, r.BaselineP95, r.BaselineP99}, {"BLUE_CONTROL", control, r.BlueControlP95, r.BlueControlP99}, {"GREEN", green, r.GreenP95, r.GreenP99}} {
		if v.a.requests == 0 || v.a.samples < l.MinimumLatencySamples {
			mark("BLOCKED", v.name+"_LATENCY_OR_DEMAND_UNMEASURABLE")
		}
		if v.a.requests > 0 && cohortRatio(v.a.errors, v.a.requests).Cmp(big.NewRat(l.MaximumErrorRatePPM, 1_000_000)) > 0 {
			mark("BREACH", v.name+"_ERROR_RATE_LIMIT")
		}
		if v.a.total == 0 {
			mark("BLOCKED", v.name+"_AVAILABILITY_UNKNOWN")
		} else if cohortRatio(v.a.good, v.a.total).Cmp(big.NewRat(l.MinimumAvailabilityPPM, 1_000_000)) < 0 {
			mark("BREACH", v.name+"_AVAILABILITY_LIMIT")
		}
		for _, q := range []struct {
			name  string
			b     QuantileBounds
			limit int64
		}{{"P95", v.p95, l.MaximumP95MS}, {"P99", v.p99, l.MaximumP99MS}} {
			if q.b.UpperMS == nil {
				mark("BLOCKED", v.name+"_"+q.name+"_UNBOUNDED")
			} else if q.b.LowerMS > q.limit {
				mark("BREACH", v.name+"_"+q.name+"_HARD_LIMIT")
			} else if *q.b.UpperMS > q.limit {
				mark("BLOCKED", v.name+"_"+q.name+"_HARD_LIMIT_UNCERTAIN")
			}
		}
	}
	for _, v := range []struct {
		name              string
		current, baseline QuantileBounds
	}{{"GREEN_BASELINE_P95", r.GreenP95, r.BaselineP95}, {"GREEN_BASELINE_P99", r.GreenP99, r.BaselineP99}, {"GREEN_CONTROL_P95", r.GreenP95, r.BlueControlP95}, {"GREEN_CONTROL_P99", r.GreenP99, r.BlueControlP99}, {"CONTROL_BASELINE_P95", r.BlueControlP95, r.BaselineP95}, {"CONTROL_BASELINE_P99", r.BlueControlP99, r.BaselineP99}} {
		switch cohortRegression(v.current, v.baseline, l.MaximumRegressionPercent) {
		case "BREACH":
			mark("BREACH", v.name+"_REGRESSION")
		case "UNKNOWN":
			mark("BLOCKED", v.name+"_REGRESSION_UNCERTAIN")
		}
	}
	for _, w := range []CohortWindow{in.BlueControl, in.Green} {
		for _, m := range w.Members {
			member := cohortAggregate{samples: m.LatencySamples, buckets: m.LatencyBuckets}
			checks := []struct {
				name              string
				current, baseline QuantileBounds
			}{{"P95_BASELINE", cohortQuantile(member, 95), r.BaselineP95}, {"P99_BASELINE", cohortQuantile(member, 99), r.BaselineP99}}
			if w.Role == "CURRENT_GREEN" {
				checks = append(checks, struct {
					name              string
					current, baseline QuantileBounds
				}{"P95_CONTROL", cohortQuantile(member, 95), r.BlueControlP95}, struct {
					name              string
					current, baseline QuantileBounds
				}{"P99_CONTROL", cohortQuantile(member, 99), r.BlueControlP99})
			}
			for _, q := range checks {
				switch cohortRegression(q.current, q.baseline, l.MaximumRegressionPercent) {
				case "BREACH":
					mark("BREACH", w.Role+":"+m.InstanceID+":"+q.name+"_REGRESSION")
				case "UNKNOWN":
					mark("BLOCKED", w.Role+":"+m.InstanceID+":"+q.name+"_UNCERTAIN")
				}
			}
		}
	}
	return finish()
}
