package telemetry

import (
	"math/big"
	"sort"
	"time"
)

// Segments derives only deltas bounded by actual observations. It never uses
// increase/rate extrapolation, assumes a counter reset started at zero, or
// apportions an interval into invented UTC-minute counts.
func Segments(samples []Sample, definitions []Definition) []Segment {
	defs := map[string]Definition{}
	for _, d := range definitions {
		defs[d.ID] = d
	}
	groups := map[string][]Sample{}
	for _, s := range samples {
		groups[s.DefinitionID+":"+s.StreamID] = append(groups[s.DefinitionID+":"+s.StreamID], s)
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []Segment{}
	for _, key := range keys {
		points := groups[key]
		sort.Slice(points, func(i, j int) bool {
			if points[i].Time.Equal(points[j].Time) {
				return sampleID(points[i]) < sampleID(points[j])
			}
			return points[i].Time.Before(points[j].Time)
		})
		d, known := defs[points[0].DefinitionID]
		var previous *Sample
		for i := range points {
			s := points[i]
			if s.ID == "" {
				s.ID = sampleID(s)
			}
			if previous != nil && s.Time.Equal(previous.Time) {
				if sampleID(s) == sampleID(*previous) {
					continue
				}
				seg := baseSegment(s, s.Time)
				seg.Status = "UNKNOWN"
				seg.ReasonCodes = []string{"TELEMETRY_SAMPLE_CONFLICT"}
				seg.SampleIDs = unique([]string{previous.ID, s.ID})
				seg.ID = Hash(seg)
				out = append(out, seg)
				previous = nil
				continue
			}
			start := s.StartTime
			if s.Temporality != "DELTA" && previous != nil {
				start = previous.Time
			}
			if start.IsZero() {
				start = s.Time
			}
			seg := baseSegment(s, start)
			if previous != nil && s.Temporality != "DELTA" {
				seg.SampleIDs = unique([]string{previous.ID, s.ID})
				seg.RawHashes = unique(append(append([]string{previous.RawSHA256, s.RawSHA256}, previous.SourceHashes...), s.SourceHashes...))
			}
			bad := func(reason string) {
				seg.Status = "UNKNOWN"
				seg.ReasonCodes = unique(append(seg.ReasonCodes, reason))
				seg.Value = ""
				seg.Histogram = nil
			}
			if !known || s.Type != d.Type || s.Unit != d.Unit || s.Metric != d.Metric || s.StreamID == "" {
				bad("TELEMETRY_DEFINITION_MISMATCH")
			} else if len(s.ReasonCodes) > 0 {
				bad("TELEMETRY_SAMPLE_UNKNOWN")
			} else if previous != nil && (len(previous.ReasonCodes) > 0 || previous.Type != d.Type || previous.Unit != d.Unit || previous.Metric != d.Metric || previous.Temporality != s.Temporality) {
				bad("TELEMETRY_PREVIOUS_SAMPLE_UNKNOWN")
			} else if s.Type == "GAUGE" {
				seg.Statistic = "OBSERVED_SAMPLE_DISTRIBUTION"
				if _, ok := number(s.Value); !ok {
					bad("TELEMETRY_VALUE_INVALID")
				} else {
					seg.Value = s.Value
				}
				if previous == nil {
					bad("TELEMETRY_PREVIOUS_SAMPLE_REQUIRED")
				} else if s.Time.Sub(previous.Time) > time.Duration(d.MaxGapSeconds)*time.Second {
					bad("TELEMETRY_OBSERVATION_GAP")
				}
			} else if s.Temporality == "DELTA" {
				if !s.Time.After(s.StartTime) || s.Time.Sub(s.StartTime) > time.Duration(d.MaxGapSeconds)*time.Second {
					bad("TELEMETRY_DELTA_INTERVAL_INVALID")
				} else if previous != nil && !s.StartTime.Equal(previous.Time) {
					bad("TELEMETRY_DELTA_DISCONTINUITY")
				} else if s.Type == "SUM" {
					r, ok := number(s.Value)
					if !ok || r.Sign() < 0 {
						bad("TELEMETRY_COUNTER_INVALID")
					} else {
						seg.Value = s.Value
					}
				} else if validHistogram(s.Histogram) {
					seg.Histogram = cloneHistogram(s.Histogram)
				} else {
					bad("TELEMETRY_HISTOGRAM_INVALID")
				}
			} else if s.Temporality == "CUMULATIVE" {
				if previous == nil {
					bad("TELEMETRY_PREVIOUS_SAMPLE_REQUIRED")
				} else if s.Epoch == "" || previous.Epoch == "" {
					bad("TELEMETRY_EPOCH_UNPROVEN")
				} else if s.Epoch != previous.Epoch {
					bad("TELEMETRY_COUNTER_RESET")
					seg.Status = "RESET"
				} else if s.Time.Sub(previous.Time) > time.Duration(d.MaxGapSeconds)*time.Second {
					bad("TELEMETRY_OBSERVATION_GAP")
				} else if s.Type == "SUM" {
					a, ok := number(s.Value)
					b, prior := number(previous.Value)
					if !ok || !prior || a.Sign() < 0 || b.Sign() < 0 {
						bad("TELEMETRY_COUNTER_INVALID")
					} else if a.Cmp(b) < 0 {
						bad("TELEMETRY_COUNTER_RESET")
						seg.Status = "RESET"
					} else {
						seg.Value = ratDecimal(new(big.Rat).Sub(a, b))
					}
				} else {
					h, ok := histogramDelta(s.Histogram, previous.Histogram)
					if !ok {
						bad("TELEMETRY_HISTOGRAM_RESET_OR_LAYOUT_CHANGED")
						seg.Status = "RESET"
					} else {
						seg.Histogram = h
					}
				}
			} else {
				bad("TELEMETRY_TEMPORALITY_UNSUPPORTED")
			}
			if !seg.End.After(seg.Start) && seg.Status == "OBSERVED" {
				bad("TELEMETRY_INTERVAL_INVALID")
			}
			seg.ID = Hash(seg)
			out = append(out, seg)
			copy := s
			previous = &copy
		}
	}
	return out
}
func baseSegment(s Sample, start time.Time) Segment {
	return Segment{DefinitionID: s.DefinitionID, StreamID: s.StreamID, Metric: s.Metric, Type: s.Type, Unit: s.Unit, Statistic: s.Statistic, Start: start.UTC(), End: s.Time.UTC(), Status: "OBSERVED", ReasonCodes: append([]string{}, s.ReasonCodes...), SampleIDs: []string{s.ID}, RawHashes: unique(append([]string{s.RawSHA256}, s.SourceHashes...))}
}
func cloneHistogram(h *Histogram) *Histogram {
	if h == nil {
		return nil
	}
	return &Histogram{h.Count, append([]string{}, h.Bounds...), append([]uint64{}, h.BucketCounts...)}
}
func sameBounds(a, b *Histogram) bool {
	if a == nil || b == nil || len(a.Bounds) != len(b.Bounds) {
		return false
	}
	for i := range a.Bounds {
		x, ok := number(a.Bounds[i])
		y, other := number(b.Bounds[i])
		if !ok || !other || x.Cmp(y) != 0 {
			return false
		}
	}
	return true
}
func histogramDelta(current, previous *Histogram) (*Histogram, bool) {
	if !validHistogram(current) || !validHistogram(previous) || !sameBounds(current, previous) || current.Count < previous.Count {
		return nil, false
	}
	h := &Histogram{Count: current.Count - previous.Count, Bounds: append([]string{}, current.Bounds...), BucketCounts: make([]uint64, len(current.BucketCounts))}
	for i, n := range current.BucketCounts {
		if n < previous.BucketCounts[i] {
			return nil, false
		}
		h.BucketCounts[i] = n - previous.BucketCounts[i]
	}
	return h, validHistogram(h)
}
