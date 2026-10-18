package slo

import (
	"math/big"
	"sort"
	"strings"
	"time"
)

func ptr(v int64) *int64 { return &v }
func ratio(n, d int64, ceil bool) *int64 {
	if d == 0 {
		return nil
	}
	a := new(big.Int).Mul(big.NewInt(n), big.NewInt(1_000_000))
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(a, big.NewInt(d), r)
	if ceil && r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return ptr(q.Int64())
}
func limit(n, d, ppm int64, maximum bool) bool {
	left := new(big.Int).Mul(big.NewInt(n), big.NewInt(1_000_000))
	right := new(big.Int).Mul(big.NewInt(d), big.NewInt(ppm))
	if maximum {
		return left.Cmp(right) <= 0
	}
	return left.Cmp(right) >= 0
}
func percentile(b []Bucket, n, p int64) (*int64, *int64) {
	if n == 0 {
		return nil, nil
	}
	rank := (n*p + 99) / 100
	var cumulative, lower int64
	for _, v := range b {
		cumulative += v.Count
		if cumulative >= rank {
			return ptr(lower), v.UpperBoundMS
		}
		if v.UpperBoundMS != nil {
			lower = *v.UpperBoundMS
		}
	}
	return nil, nil
}
func Evaluate(in Input) Evaluation {
	o, s := in.Objective, in.Source
	end := in.Now.UTC().Truncate(time.Minute)
	start := end.Add(-time.Duration(o.EvaluationMinutes) * time.Minute)
	e := Evaluation{Status: "CLEAR", ReasonCodes: []string{}, ObjectiveID: o.ID, ObjectiveVersion: o.Version, ObjectiveHash: ObjectiveHash(o), SourceID: s.ID, SourceHash: SourceHash(s), ResourceID: s.ResourceID, WorkloadID: s.WorkloadID, WindowStart: start, WindowEnd: end, ExpectedIntervals: o.EvaluationMinutes, LatencyStatus: "INSUFFICIENT", HardChecks: []Check{}, RegressionChecks: []Check{}, ReceiptIDs: []string{}}
	reasons := map[string]bool{}
	fail := func(r string) { reasons[r] = true }
	check := func(name string, ok bool, reason string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			fail(reason)
		} else {
			reason = "SLO_" + strings.ToUpper(name) + "_WITHIN_LIMIT"
		}
		e.HardChecks = append(e.HardChecks, Check{name, status, reason})
	}
	if ValidateObjective(o) != nil || o.ID == "" || o.Version < 1 {
		fail("SLO_OBJECTIVE_REQUIRED")
	}
	if s.SchemaVersion != "1" || s.ID == "" || !s.Enabled || s.ObjectiveID != o.ID || s.WorkloadID != o.WorkloadID || s.TenantID == "" || s.ResourceID == "" {
		fail("SLO_SOURCE_BINDING_INVALID")
	}
	rs := append([]Receipt{}, in.Receipts...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].IntervalStart.Before(rs[j].IntervalStart) })
	expected := start
	var previousSequence int64
	var histogram []Bucket
	valid := true
	for _, r := range rs {
		if ValidateInterval(r.Interval) != nil || r.ID == "" || r.WriterRole != "finops_activity" || r.Subject != s.Subject || r.Binding != s.Binding() || r.TenantID != s.TenantID || r.SourceID != s.ID || r.ObjectiveID != o.ID || r.ResourceID != s.ResourceID || r.WorkloadID != s.WorkloadID {
			fail("SLO_RECEIPT_BINDING_INVALID")
			valid = false
			continue
		}
		if !r.IntervalStart.Equal(expected) || r.IntervalEnd.After(end) || previousSequence > 0 && r.Sequence != previousSequence+1 {
			fail("SLO_COVERAGE_GAP")
			valid = false
		}
		if r.ReceivedAt.Before(r.IntervalEnd.Add(-5*time.Second)) || r.ReceivedAt.After(r.IntervalEnd.Add(2*time.Minute)) || r.ReceivedAt.After(in.Now.Add(5*time.Second)) {
			fail("SLO_RECEIPT_TIME_INVALID")
			valid = false
		}
		expected = r.IntervalEnd
		previousSequence = r.Sequence
		e.ObservedIntervals++
		e.ReceiptIDs = append(e.ReceiptIDs, r.ID)
		if r.ReceivedAt.After(e.ReceivedAt) {
			e.ReceivedAt = r.ReceivedAt
		}
		e.RequestCount += r.RequestCount
		e.ErrorCount += r.ErrorCount
		e.LatencySamples += r.Latency.SampleCount
		if open(o, r.IntervalStart) {
			e.AvailabilityGoodSeconds += r.AvailabilityGoodSeconds
			e.AvailabilityTotalSeconds += r.AvailabilityTotalSeconds
		}
		if histogram == nil {
			histogram = append([]Bucket{}, r.Latency.Buckets...)
		} else if len(histogram) != len(r.Latency.Buckets) {
			fail("SLO_HISTOGRAM_LAYOUT_MISMATCH")
			valid = false
		} else {
			for n, b := range r.Latency.Buckets {
				a := histogram[n].UpperBoundMS
				if (a == nil) != (b.UpperBoundMS == nil) || a != nil && *a != *b.UpperBoundMS {
					fail("SLO_HISTOGRAM_LAYOUT_MISMATCH")
					valid = false
				}
				histogram[n].Count += b.Count
			}
		}
	}
	if e.ExpectedIntervals > 0 {
		e.CoveragePPM = int64(e.ObservedIntervals) * 1_000_000 / int64(e.ExpectedIntervals)
	}
	if !expected.Equal(end) || e.ObservedIntervals != e.ExpectedIntervals || !valid {
		fail("SLO_COVERAGE_GAP")
	}
	if e.ReceivedAt.IsZero() || in.Now.Sub(e.ReceivedAt) > 2*time.Minute || in.Now.Sub(end) > 2*time.Minute {
		fail("SLO_EVIDENCE_STALE")
	}
	if len(reasons) == 0 {
		noDemand := e.RequestCount == 0 && closed(o, start, end)
		e.ErrorRatePPM = ratio(e.ErrorCount, e.RequestCount, true)
		e.AvailabilityPPM = ratio(e.AvailabilityGoodSeconds, e.AvailabilityTotalSeconds, false)
		if e.AvailabilityTotalSeconds == 0 {
			e.HardChecks = append(e.HardChecks, Check{"availability", "NOT_APPLICABLE", "SLO_CLOSED_WINDOW"})
		} else {
			check("availability", limit(e.AvailabilityGoodSeconds, e.AvailabilityTotalSeconds, o.Limits.MinAvailabilityPPM, false), "SLO_AVAILABILITY_BREACH")
		}
		if e.RequestCount > 0 {
			check("error_rate", limit(e.ErrorCount, e.RequestCount, o.Limits.MaxErrorRatePPM, true), "SLO_ERROR_RATE_BREACH")
		} else if noDemand {
			e.HardChecks = append(e.HardChecks, Check{"error_rate", "NOT_APPLICABLE", "SLO_CLOSED_NO_DEMAND"})
		} else {
			check("error_rate", false, "SLO_NO_DEMAND_OPEN_WINDOW")
		}
		if noDemand {
			e.LatencyStatus = "NO_DEMAND"
			e.HardChecks = append(e.HardChecks, Check{"latency", "NOT_APPLICABLE", "SLO_CLOSED_NO_DEMAND"})
		} else if e.LatencySamples < o.Limits.MinLatencySamples {
			check("latency_samples", false, "SLO_LATENCY_SAMPLES_INSUFFICIENT")
		} else {
			e.P95LowerMS, e.P95LatencyMS = percentile(histogram, e.LatencySamples, 95)
			e.P99LowerMS, e.P99LatencyMS = percentile(histogram, e.LatencySamples, 99)
			if e.P95LatencyMS == nil || e.P99LatencyMS == nil {
				check("latency", false, "SLO_LATENCY_UNBOUNDED")
			} else {
				e.LatencyStatus = "OBSERVED"
				check("p95_latency", *e.P95LatencyMS <= o.Limits.MaxP95LatencyMS, "SLO_P95_HARD_BREACH")
				check("p99_latency", *e.P99LatencyMS <= o.Limits.MaxP99LatencyMS, "SLO_P99_HARD_BREACH")
			}
		}
	}
	if !in.StopAt.IsZero() || !in.RequiredReadyAt.IsZero() {
		for _, r := range StopAllowed(o, in.StopAt, in.RequiredReadyAt) {
			fail(r)
		}
	}
	if o.Regression.Enabled {
		b := in.Baseline
		if in.CaptureBaseline {
			if e.LatencyStatus != "OBSERVED" {
				fail("SLO_REGRESSION_BASELINE_UNMEASURABLE")
				e.RegressionChecks = append(e.RegressionChecks, Check{"latency_regression", "INDETERMINATE", "SLO_REGRESSION_BASELINE_UNMEASURABLE"})
			} else {
				e.RegressionChecks = append(e.RegressionChecks, Check{"latency_regression", "PASS", "SLO_REGRESSION_BASELINE_CAPTURED"})
			}
		} else if b == nil || b.Status != "CLEAR" || b.ObjectiveID != o.ID || b.ObjectiveHash != e.ObjectiveHash || b.SourceHash != e.SourceHash || b.CoveragePPM != 1_000_000 || b.LatencyStatus != "OBSERVED" || b.P95LowerMS == nil || b.P99LowerMS == nil || b.EvaluationHash == "" || EvaluationHash(*b) != b.EvaluationHash {
			fail("SLO_REGRESSION_BASELINE_REQUIRED")
			e.RegressionChecks = append(e.RegressionChecks, Check{"latency_regression", "INDETERMINATE", "SLO_REGRESSION_BASELINE_REQUIRED"})
		} else {
			e.BaselineEvaluationID, e.BaselineEvaluationHash = b.ID, b.EvaluationHash
			for _, x := range []struct {
				name          string
				current, base *int64
			}{{"p95_latency", e.P95LatencyMS, b.P95LowerMS}, {"p99_latency", e.P99LatencyMS, b.P99LowerMS}} {
				status, reason := "PASS", "SLO_REGRESSION_WITHIN_LIMIT"
				if x.current == nil || x.base == nil {
					status, reason = "INDETERMINATE", "SLO_REGRESSION_CURRENT_UNMEASURABLE"
				} else if new(big.Int).Mul(big.NewInt(*x.current), big.NewInt(100)).Cmp(new(big.Int).Mul(big.NewInt(*x.base), big.NewInt(100+o.Regression.MaxPercent))) > 0 {
					status, reason = "FAIL", "SLO_LATENCY_REGRESSION"
				}
				if status != "PASS" {
					fail(reason)
				}
				e.RegressionChecks = append(e.RegressionChecks, Check{x.name, status, reason})
			}
		}
	} else {
		e.RegressionChecks = append(e.RegressionChecks, Check{"latency_regression", "NOT_APPLICABLE", "SLO_REGRESSION_DISABLED"})
	}
	e.ReasonCodes = SortedReasons(reasons)
	if len(e.ReasonCodes) > 0 {
		e.Status = "BLOCKED"
	}
	e.EvaluationHash = EvaluationHash(e)
	return e
}
