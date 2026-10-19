package telemetry

import (
	"encoding/json"
	"math/big"
	"sort"
	"strconv"
	"time"
)

type weightedValue struct {
	value  *big.Rat
	weight int64
}

func emptyEvaluation(now time.Time) Evaluation {
	return Evaluation{SchemaVersion: "1", Status: "BLOCKED", ReasonCodes: []string{}, EvaluatedAt: now.UTC(), Metrics: []MetricResult{}}
}
func sealEvaluation(e Evaluation) Evaluation {
	e.ReasonCodes = unique(e.ReasonCodes)
	e.Hash = ""
	e.Hash = Hash(e)
	return e
}
func requiredDefinitions(defs []Definition, required []string) ([]Definition, []string) {
	if len(required) == 0 {
		return defs, []string{}
	}
	m := map[string]Definition{}
	for _, d := range defs {
		m[d.Metric] = d
	}
	out := []Definition{}
	missing := []string{}
	for _, name := range unique(required) {
		if d, ok := m[name]; ok {
			out = append(out, d)
		} else {
			missing = append(missing, "TELEMETRY_REQUIRED_METRIC_MISSING:"+name)
		}
	}
	return out, missing
}
func grouping(segments []Segment, def string, start, end time.Time) map[string][]Segment {
	m := map[string][]Segment{}
	for _, s := range segments {
		if s.DefinitionID == def && !s.End.Before(start) && !s.End.After(end) {
			m[s.StreamID] = append(m[s.StreamID], s)
		}
	}
	for k := range m {
		sort.Slice(m[k], func(i, j int) bool { return m[k][i].End.Before(m[k][j].End) })
	}
	return m
}

// EvaluateWindow assesses whole native intervals ending at real observations.
// Per-metric bounds are explicit: no interpolation aligns unrelated scrapes.
func EvaluateWindow(in WindowInput) Evaluation {
	e := emptyEvaluation(in.Now)
	if in.Now.IsZero() || in.Minutes < 2 || in.Minutes > 60 {
		e.ReasonCodes = []string{"TELEMETRY_WINDOW_INVALID"}
		return sealEvaluation(e)
	}
	defs, missing := requiredDefinitions(in.Definitions, in.RequiredMetrics)
	e.ReasonCodes = append(e.ReasonCodes, missing...)
	e.Start = in.Now.Add(-time.Duration(in.Minutes) * time.Minute)
	e.End = in.Now
	for _, d := range defs {
		groups := grouping(in.Segments, d.ID, in.Now.Add(-time.Duration(in.Minutes+20)*time.Minute), in.Now.Add(5*time.Second))
		if len(groups) != 1 {
			r := unavailableMetric(d, e.Start, e.End, "TELEMETRY_SINGLE_STREAM_REQUIRED")
			e.Metrics = append(e.Metrics, r)
			continue
		}
		var points []Segment
		for _, v := range groups {
			points = v
		}
		end := points[len(points)-1].End
		if end.After(in.Now.Add(5*time.Second)) || end.Before(in.Now.Add(-2*time.Minute)) {
			e.Metrics = append(e.Metrics, unavailableMetric(d, e.Start, e.End, "TELEMETRY_SOURCE_STALE"))
			continue
		}
		wanted := end.Add(-time.Duration(in.Minutes) * time.Minute)
		selected := []Segment{}
		cursor := end
		for i := len(points) - 1; i >= 0; i-- {
			s := points[i]
			if !s.End.Equal(cursor) {
				break
			}
			selected = append(selected, s)
			cursor = s.Start
			if !cursor.After(wanted) {
				break
			}
		}
		start := cursor
		sort.Slice(selected, func(i, j int) bool { return selected[i].End.Before(selected[j].End) })
		r := summarize(d, selected, start, end, false)
		if start.After(wanted) || wanted.Sub(start) > 2*time.Duration(d.CadenceSeconds)*time.Second {
			r.Status = "BLOCKED"
			r.ReasonCodes = unique(append(r.ReasonCodes, "TELEMETRY_CONTIGUOUS_WINDOW_INCOMPLETE"))
		}
		e.Metrics = append(e.Metrics, r)
		if e.Start.IsZero() || start.Before(e.Start) {
			e.Start = start
		}
		if end.After(e.End) {
			e.End = end
		}
	}
	return finishEvaluation(e)
}

// EvaluateHistory uses complete local calendar days and retains actual native
// interval bounds. A boundary interval may extend by at most one cadence; its
// count is never fractionally apportioned to a fabricated midnight bucket.
func EvaluateHistory(in HistoryInput) Evaluation {
	evaluation, _ := EvaluateHistoryWithSegments(in)
	return evaluation
}

// EvaluateHistoryWithSegments derives intervals from the original samples and
// returns those same intervals with their history evaluation. It accepts no
// caller-derived segments and keeps no cache between requests. Consumers that
// also publish the intervals can avoid deriving their provenance hashes twice.
func EvaluateHistoryWithSegments(in HistoryInput) (Evaluation, []Segment) {
	e := emptyEvaluation(in.Now)
	e.HistoryDays = in.Days
	e.Timezone = in.Timezone
	loc, err := time.LoadLocation(in.Timezone)
	if err != nil || in.Now.IsZero() || (in.Days != 14 && in.Days != 30 && in.Days != 90) {
		e.ReasonCodes = []string{"TELEMETRY_HISTORY_WINDOW_INVALID"}
		return sealEvaluation(e), nil
	}
	now := in.Now.In(loc)
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC()
	start := end.In(loc).AddDate(0, 0, -in.Days).UTC()
	e.Start = start
	e.End = end
	segments := Segments(in.Samples, in.Definitions)
	defs, missing := requiredDefinitions(in.Definitions, in.RequiredMetrics)
	e.ReasonCodes = append(e.ReasonCodes, missing...)
	for _, d := range defs {
		groups := grouping(segments, d.ID, start, end)
		if len(groups) != 1 {
			e.Metrics = append(e.Metrics, unavailableMetric(d, start, end, "TELEMETRY_SINGLE_STREAM_REQUIRED"))
			continue
		}
		var selected []Segment
		for _, v := range groups {
			selected = v
		}
		e.Metrics = append(e.Metrics, summarize(d, selected, start, end, true))
	}
	return finishEvaluation(e), segments
}

// An unavailable observation is not zero demand. Retain the requested window,
// expected coverage and registered statistic, with every measured value null.
func unavailableMetric(d Definition, start, end time.Time, reason string) MetricResult {
	r := MetricResult{Start: start, End: end, DefinitionID: d.ID, Metric: d.Metric, Unit: d.Unit, Status: "BLOCKED", ReasonCodes: []string{reason}, SegmentIDs: []string{}, Statistic: "OBSERVED_SAMPLE_DISTRIBUTION"}
	if d.Type == "SUM" {
		r.Unit = d.Unit + "/second"
		r.Statistic = "OBSERVED_INTERVAL_RATE_DISTRIBUTION"
	} else if d.Type == "HISTOGRAM" {
		r.Statistic = "EXPLICIT_BUCKET_UPPER_BOUND_DISTRIBUTION"
	}
	if d.CadenceSeconds > 0 && end.After(start) {
		cadence := time.Duration(d.CadenceSeconds) * time.Second
		r.ExpectedSamples = int64(end.Sub(start) / cadence)
		if end.Sub(start)%cadence != 0 {
			r.ExpectedSamples++
		}
		r.UnknownDurationNS = int64(end.Sub(start))
	}
	return r
}
func finishEvaluation(e Evaluation) Evaluation {
	e.Status = "READY"
	if len(e.Metrics) == 0 {
		e.ReasonCodes = append(e.ReasonCodes, "TELEMETRY_EVIDENCE_MISSING")
	}
	for i := range e.Metrics {
		if e.Metrics[i].SegmentHash == "" {
			e.Metrics[i].SegmentHash = Hash(e.Metrics[i].SegmentIDs)
		}
		m := e.Metrics[i]
		if m.Status != "READY" {
			e.Status = "BLOCKED"
		}
		e.ReasonCodes = append(e.ReasonCodes, m.ReasonCodes...)
	}
	// Informational tail/no-demand reasons do not independently negate coverage.
	for _, r := range e.ReasonCodes {
		if r != "TELEMETRY_NO_DEMAND" && r != "TELEMETRY_TAIL_SAMPLE_INSUFFICIENT" {
			e.Status = "BLOCKED"
		}
	}
	return sealEvaluation(e)
}
func summarize(d Definition, segments []Segment, start, end time.Time, history bool) MetricResult {
	r := MetricResult{Start: start, End: end, DefinitionID: d.ID, Metric: d.Metric, Unit: d.Unit, Status: "READY", ReasonCodes: []string{}, SegmentIDs: []string{}}
	if d.Type == "SUM" {
		r.Unit = d.Unit + "/second"
	}
	cadence := time.Duration(d.CadenceSeconds) * time.Second
	if cadence <= 0 || !end.After(start) {
		r.Status = "BLOCKED"
		r.ReasonCodes = []string{"TELEMETRY_INTERVAL_INVALID"}
		return r
	}
	r.ExpectedSamples = int64(end.Sub(start) / cadence)
	if r.ExpectedSamples < 1 {
		r.ExpectedSamples = 1
	}
	if history && end.Sub(start)%cadence != 0 {
		r.ExpectedSamples++
	}
	values := []weightedValue{}
	var histogram *Histogram
	total := new(big.Rat)
	slots := map[int64]bool{}
	var phase time.Duration
	phaseSet := false
	cursor := start
	for _, s := range segments {
		if s.Status != "OBSERVED" || s.Type != d.Type || s.Unit != d.Unit || !s.End.After(s.Start) || s.End.Sub(s.Start) > time.Duration(d.MaxGapSeconds)*time.Second {
			r.ReasonCodes = append(r.ReasonCodes, s.ReasonCodes...)
			r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_UNKNOWN_INTERVAL")
			continue
		}
		if s.End.After(end) || history && d.Type == "GAUGE" && s.End.Equal(end) || history && d.Type != "GAUGE" && s.End.Equal(start) || s.End.Before(start) {
			continue
		}
		if !history && s.Start.Before(start) {
			r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_PARTIAL_INTERVAL")
			continue
		}
		if history && (s.Start.Before(start.Add(-cadence)) || s.Start.After(end)) {
			r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_BOUNDARY_UNCERTAIN")
			continue
		}
		if !phaseSet {
			phase = s.End.Sub(start) % cadence
			if !history {
				phase = s.End.Sub(start)
			}
			phaseSet = true
		}
		index := int64((s.End.Sub(start) - phase + cadence/2) / cadence)
		if history && d.Type != "GAUGE" && phase == 0 {
			index--
		}
		if index < 0 || index >= r.ExpectedSamples || slots[index] {
			r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_CADENCE_CONFLICT")
			continue
		}
		slots[index] = true
		if s.Start.After(cursor.Add(time.Duration(d.MaxGapSeconds-d.CadenceSeconds) * time.Second)) {
			r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_OBSERVATION_GAP")
		}
		from, to := s.Start, s.End
		if from.Before(start) {
			from = start
		}
		if to.After(end) {
			to = end
		}
		if from.Before(cursor) {
			from = cursor
		}
		if to.After(from) {
			r.ObservedDurationNS += int64(to.Sub(from))
			cursor = to
		}
		if r.Start.Equal(start) && history && r.ObservedSamples == 0 {
			r.Start = s.Start
		}
		if history {
			r.End = s.End
		}
		r.ObservedSamples++
		r.SegmentIDs = append(r.SegmentIDs, s.ID)
		if d.Type == "HISTOGRAM" {
			if !validHistogram(s.Histogram) {
				r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_HISTOGRAM_INVALID")
				continue
			}
			if histogram == nil {
				histogram = cloneHistogram(s.Histogram)
			} else if !addHistogram(histogram, s.Histogram) {
				r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_HISTOGRAM_LAYOUT_OR_OVERFLOW")
				histogram = nil
				break
			}
		} else {
			x, ok := number(s.Value)
			if !ok {
				r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_VALUE_INVALID")
				continue
			}
			if d.Unit == "ratio" && (x.Sign() < 0 || x.Cmp(big.NewRat(1, 1)) > 0) {
				r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_RATIO_OUT_OF_RANGE")
				continue
			}
			weight := int64(1)
			if d.Type == "SUM" {
				if x.Sign() < 0 {
					r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_COUNTER_INVALID")
					continue
				}
				total.Add(total, x)
				x = new(big.Rat).Quo(x, big.NewRat(int64(s.End.Sub(s.Start)), 1e9))
				weight = int64(s.End.Sub(s.Start))
				r.Unit = d.Unit + "/second"
			}
			values = append(values, weightedValue{x, weight})
		}
	}
	r.CoveragePPM = int64(len(slots)) * 1000000 / r.ExpectedSamples
	if r.CoveragePPM > 1000000 {
		r.CoveragePPM = 1000000
	}
	r.UnknownDurationNS = int64(end.Sub(start)) - r.ObservedDurationNS
	if r.UnknownDurationNS < 0 {
		r.UnknownDurationNS = 0
	}
	if r.CoveragePPM != 1000000 || r.ObservedSamples == 0 {
		r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_COVERAGE_INCOMPLETE")
	}
	if d.Type == "HISTOGRAM" {
		r.Statistic = "EXPLICIT_BUCKET_UPPER_BOUND_DISTRIBUTION"
		r.Histogram = histogram
		if histogram != nil {
			n := strconv.FormatUint(histogram.Count, 10)
			r.Total = &n
			r.P50 = histogramQuantile(histogram, 500)
			r.P90 = histogramQuantile(histogram, 900)
			r.P95 = histogramQuantile(histogram, 950)
			r.P99 = histogramQuantile(histogram, 990)
			r.P999 = histogramQuantile(histogram, 999)
			r.Maximum = histogramQuantile(histogram, 1000)
			if histogram.Count == 0 {
				r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_NO_DEMAND")
			} else if r.P99 == nil {
				if histogram.Count < 100 {
					r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_TAIL_SAMPLE_INSUFFICIENT")
				} else {
					r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_HISTOGRAM_QUANTILE_UNBOUNDED")
				}
			}
		}
	} else {
		r.Statistic = "OBSERVED_SAMPLE_DISTRIBUTION"
		if d.Type == "SUM" {
			r.Statistic = "OBSERVED_INTERVAL_RATE_DISTRIBUTION"
			v := ratDecimal(total)
			r.Total = &v
		}
		r.P50 = weightedQuantile(values, 500, 2)
		r.P90 = weightedQuantile(values, 900, 10)
		r.P95 = weightedQuantile(values, 950, 20)
		r.P99 = weightedQuantile(values, 990, 100)
		r.P999 = weightedQuantile(values, 999, 1000)
		r.Maximum = weightedQuantile(values, 1000, 1)
		if len(values) > 0 && r.P99 == nil {
			r.ReasonCodes = append(r.ReasonCodes, "TELEMETRY_TAIL_SAMPLE_INSUFFICIENT")
		}
	}
	r.ReasonCodes = unique(r.ReasonCodes)
	// The immutable receipt objects retain full bucket populations. Summaries
	// include the aggregate histogram only when it fits the bounded metadata
	// budget; quantile bounds/counts and the segment hash still bind all bins.
	if r.Histogram != nil {
		if raw, _ := json.Marshal(r.Histogram); len(raw) > 2048 {
			r.Histogram = nil
		}
	}
	r.SegmentCount = len(r.SegmentIDs)
	r.SegmentHash = Hash(r.SegmentIDs)
	if len(r.SegmentIDs) > 16 {
		r.SegmentIDsTruncated = true
		r.SegmentIDs = append([]string{}, r.SegmentIDs[:16]...)
	}
	for _, reason := range r.ReasonCodes {
		if reason != "TELEMETRY_NO_DEMAND" && reason != "TELEMETRY_TAIL_SAMPLE_INSUFFICIENT" {
			r.Status = "BLOCKED"
		}
	}
	return r
}
func addHistogram(a, b *Histogram) bool {
	if !sameBounds(a, b) || ^uint64(0)-a.Count < b.Count {
		return false
	}
	for i, n := range b.BucketCounts {
		if ^uint64(0)-a.BucketCounts[i] < n {
			return false
		}
	}
	a.Count += b.Count
	for i, n := range b.BucketCounts {
		a.BucketCounts[i] += n
	}
	return validHistogram(a)
}
func histogramQuantile(h *Histogram, permille uint64) *string {
	if h == nil || h.Count == 0 {
		return nil
	}
	minimum := uint64(1)
	switch permille {
	case 500:
		minimum = 2
	case 900:
		minimum = 10
	case 950:
		minimum = 20
	case 990:
		minimum = 100
	case 999:
		minimum = 1000
	}
	if h.Count < minimum {
		return nil
	}
	// big.Int avoids Count*999 overflowing uint64.
	target := new(big.Int).Mul(new(big.Int).SetUint64(h.Count), new(big.Int).SetUint64(permille))
	target.Add(target, big.NewInt(999))
	target.Quo(target, big.NewInt(1000))
	running := new(big.Int)
	for i, n := range h.BucketCounts {
		running.Add(running, new(big.Int).SetUint64(n))
		if running.Cmp(target) >= 0 {
			if i >= len(h.Bounds) {
				return nil
			}
			s := h.Bounds[i]
			return &s
		}
	}
	return nil
}
func weightedQuantile(values []weightedValue, permille int64, minimum int) *string {
	if len(values) < minimum {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i].value.Cmp(values[j].value) < 0 })
	sum := new(big.Int)
	for _, v := range values {
		sum.Add(sum, big.NewInt(v.weight))
	}
	target := new(big.Int).Mul(sum, big.NewInt(permille))
	target.Add(target, big.NewInt(999))
	target.Quo(target, big.NewInt(1000))
	running := new(big.Int)
	for _, v := range values {
		running.Add(running, big.NewInt(v.weight))
		if running.Cmp(target) >= 0 {
			s := ratDecimal(v.value)
			return &s
		}
	}
	return nil
}
