package service

import (
	"math/big"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
)

type fleetRegressionCheck struct {
	Minute     time.Time `json:"minute"`
	InstanceID string    `json:"instance_id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
}
type fleetContinuousRegression struct {
	Status        string                 `json:"status"`
	ReasonCodes   []string               `json:"reason_codes"`
	CheckCount    int                    `json:"check_count"`
	ChecksSHA256  string                 `json:"checks_sha256"`
	UnsafePreview []fleetRegressionCheck `json:"unsafe_preview"`
}

func fleetMergeHistogram(out []fleet.CohortBucket, in []fleet.CohortBucket) ([]fleet.CohortBucket, bool) {
	if len(out) == 0 {
		out = make([]fleet.CohortBucket, len(in))
		for i, b := range in {
			out[i].UpperBoundMS = b.UpperBoundMS
		}
	}
	if len(out) != len(in) {
		return out, false
	}
	for i, b := range in {
		prior := out[i].UpperBoundMS
		if (prior == nil) != (b.UpperBoundMS == nil) || prior != nil && *prior != *b.UpperBoundMS {
			return out, false
		}
		value, ok := fleetCountAdd(out[i].Count, b.Count)
		if !ok {
			return out, false
		}
		out[i].Count = value
	}
	return out, true
}
func fleetRegressionBound(current, baseline fleet.QuantileBounds, percent int64) string {
	if current.UpperMS == nil || baseline.UpperMS == nil || baseline.LowerMS <= 0 {
		return "UNKNOWN"
	}
	upper := new(big.Rat).Mul(big.NewRat(*baseline.UpperMS, 1), big.NewRat(100+percent, 100))
	lower := new(big.Rat).Mul(big.NewRat(baseline.LowerMS, 1), big.NewRat(100+percent, 100))
	if big.NewRat(current.LowerMS, 1).Cmp(upper) > 0 {
		return "BREACH"
	}
	if big.NewRat(*current.UpperMS, 1).Cmp(lower) <= 0 {
		return "CLEAR"
	}
	return "UNKNOWN"
}
func fleetMinuteHistogram(p fleetHealthPopulation, at time.Time) ([]fleet.CohortBucket, int64, bool) {
	var buckets []fleet.CohortBucket
	var count int64
	for _, member := range p.Window.Members {
		found := false
		for _, row := range p.Receipts[member.InstanceID] {
			if !row.Receipt.IntervalStart.Equal(at) {
				continue
			}
			if found {
				return nil, 0, false
			}
			found = true
			in := []fleet.CohortBucket{}
			for _, b := range row.Receipt.Latency.Buckets {
				in = append(in, fleet.CohortBucket{UpperBoundMS: b.UpperBoundMS, Count: b.Count})
			}
			var ok bool
			buckets, ok = fleetMergeHistogram(buckets, in)
			if !ok {
				return nil, 0, false
			}
			count, ok = fleetCountAdd(count, row.Receipt.Latency.SampleCount)
			if !ok {
				return nil, 0, false
			}
		}
		if !found {
			return nil, 0, false
		}
	}
	return buckets, count, count > 0
}

// The full-window comparison is necessary but insufficient: one low-volume
// regressed minute must not disappear inside a high-volume healthy hour. These
// checks compare every actual physical member and concurrent minute, preserving
// histogram uncertainty instead of inventing interpolated percentile values.
func fleetCheckContinuousRegression(baseline fleet.CohortWindow, blue, green fleetHealthPopulation, percent int64) fleetContinuousRegression {
	return fleetCheckRegression(baseline, blue, green, percent, false)
}

func fleetCheckRegression(baseline fleet.CohortWindow, blue, green fleetHealthPopulation, percent int64, singlePopulation bool) fleetContinuousRegression {
	r := fleetContinuousRegression{Status: "CLEAR", ReasonCodes: []string{}, UnsafePreview: []fleetRegressionCheck{}}
	reasons := map[string]bool{}
	checks := []fleetRegressionCheck{}
	add := func(at time.Time, id, name, status string) {
		check := fleetRegressionCheck{at, id, name, status}
		checks = append(checks, check)
		if status == "CLEAR" {
			return
		}
		if status == "BREACH" || r.Status != "BREACH" {
			r.Status = "BLOCKED"
			if status == "BREACH" {
				r.Status = "BREACH"
			}
		}
		reasons["COHORT_MINUTE_"+name+"_"+status] = true
		if len(r.UnsafePreview) < 16 {
			r.UnsafePreview = append(r.UnsafePreview, check)
		}
	}
	var base []fleet.CohortBucket
	var baseCount int64
	for _, member := range baseline.Members {
		var ok bool
		base, ok = fleetMergeHistogram(base, member.LatencyBuckets)
		if !ok {
			add(baseline.Start, "", "BASELINE_HISTOGRAM", "UNKNOWN")
			break
		}
		baseCount, ok = fleetCountAdd(baseCount, member.LatencySamples)
		if !ok {
			add(baseline.Start, "", "BASELINE_COUNT", "UNKNOWN")
			break
		}
	}
	window := blue.Window
	if len(blue.Window.Members) == 0 {
		window = green.Window
	}
	if percent < 0 || percent > 1000 || len(baseline.Members) == 0 || !singlePopulation && (len(blue.Window.Members) == 0 || len(green.Window.Members) == 0 || !blue.Window.Start.Equal(green.Window.Start) || !blue.Window.End.Equal(green.Window.End)) || singlePopulation && (len(blue.Window.Members) == 0) == (len(green.Window.Members) == 0) || window.End.Sub(window.Start) < 2*time.Minute || window.End.Sub(window.Start) > 60*time.Minute {
		add(blue.Window.Start, "", "SCOPE", "UNKNOWN")
		r.ReasonCodes = slo.SortedReasons(reasons)
		r.CheckCount = len(checks)
		r.ChecksSHA256 = fleet.Digest(checks)
		return r
	}
	for _, population := range []fleetHealthPopulation{blue, green} {
		for _, member := range population.Window.Members {
			for _, q := range []struct {
				percent int64
				name    string
			}{{95, "P95"}, {99, "P99"}} {
				add(window.Start, member.InstanceID, q.name+"_FULL_FROZEN_BASELINE", fleetRegressionBound(fleetHistogramQuantile(member.LatencyBuckets, member.LatencySamples, q.percent), fleetHistogramQuantile(base, baseCount, q.percent), percent))
			}
		}
	}
	for at := window.Start; at.Before(window.End); at = at.Add(time.Minute) {
		control, controlCount, ok := fleetMinuteHistogram(blue, at)
		if !ok && !singlePopulation {
			add(at, "", "CONTROL_HISTOGRAM", "UNKNOWN")
			continue
		}
		for _, population := range []fleetHealthPopulation{blue, green} {
			for _, member := range population.Window.Members {
				found := false
				for _, row := range population.Receipts[member.InstanceID] {
					if !row.Receipt.IntervalStart.Equal(at) {
						continue
					}
					found = true
					buckets := []fleet.CohortBucket{}
					for _, b := range row.Receipt.Latency.Buckets {
						buckets = append(buckets, fleet.CohortBucket{UpperBoundMS: b.UpperBoundMS, Count: b.Count})
					}
					for _, q := range []struct {
						percent int64
						name    string
					}{{95, "P95"}, {99, "P99"}} {
						current := fleetHistogramQuantile(buckets, row.Receipt.Latency.SampleCount, q.percent)
						add(at, member.InstanceID, q.name+"_FROZEN_BASELINE", fleetRegressionBound(current, fleetHistogramQuantile(base, baseCount, q.percent), percent))
						if population.Window.Role == "CURRENT_GREEN" && !singlePopulation {
							add(at, member.InstanceID, q.name+"_BLUE_CONTROL", fleetRegressionBound(current, fleetHistogramQuantile(control, controlCount, q.percent), percent))
						}
					}
				}
				if !found {
					add(at, member.InstanceID, "MEMBER_RECEIPT", "UNKNOWN")
				}
			}
		}
	}
	r.ReasonCodes = slo.SortedReasons(reasons)
	r.CheckCount = len(checks)
	r.ChecksSHA256 = fleet.Digest(checks)
	return r
}
