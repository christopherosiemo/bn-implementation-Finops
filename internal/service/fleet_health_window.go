package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
)

// These inputs are selected by the private database factory, never decoded from
// an HTTP health assertion. Retaining raw bytes lets the factory recheck the
// immutable receipt rather than treating its projected counters as authority.
type fleetSLOReceipt struct {
	Receipt slo.Receipt
	Raw     []byte
}
type fleetMinuteCheck struct {
	ReceiptID   string    `json:"receipt_id"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	Status      string    `json:"status"`
	ReasonCodes []string  `json:"reason_codes"`
}
type fleetMemberEvaluation struct {
	SchemaVersion string                   `json:"schema_version"`
	Kind          string                   `json:"kind"`
	WindowStart   time.Time                `json:"window_start"`
	WindowEnd     time.Time                `json:"window_end"`
	Status        string                   `json:"status"`
	ReasonCodes   []string                 `json:"reason_codes"`
	Member        fleet.CohortMemberWindow `json:"member"`
	MinuteChecks  []fleetMinuteCheck       `json:"minute_checks"`
	Hash          string                   `json:"hash"`
}

var fleetHealthHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var fleetHealthInstance = regexp.MustCompile(`^i-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)

func fleetHealthDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func fleetMemberEvaluationHash(e fleetMemberEvaluation) string {
	e.Hash, e.Member.EvaluationID, e.Member.EvaluationSHA256 = "", "", ""
	return fleet.Digest(e)
}
func fleetCeilMinute(at time.Time) time.Time {
	minute := at.UTC().Truncate(time.Minute)
	if at.Equal(minute) {
		return minute
	}
	return minute.Add(time.Minute)
}

func fleetChildObservationStage(stage fleet.Stage, child fleet.ChildPlan) fleet.Stage {
	// Intermediate capacity steps need fresh independent health before traffic.
	// The full signed canary/expansion dwell begins only once both the intended
	// population and traffic weight have been reached by a child.
	if child.Transition.CandidateAfter != stage.TargetCandidateCount || child.Transition.TrafficAfter != stage.TargetTrafficPercent || stage.Kind == fleet.DrainOld && child.Transition.OldAfter != 0 {
		stage.MinimumObservationSeconds = 120
	}
	return stage
}

func fleetRecoveryWindow(appliedAt, now time.Time, minutes int) (time.Time, time.Time, error) {
	end := now.UTC().Truncate(time.Minute)
	start := end.Add(-time.Duration(minutes) * time.Minute)
	if appliedAt.IsZero() || now.IsZero() || minutes < 2 || minutes > 60 || appliedAt.After(now.Add(5*time.Second)) {
		return start, end, errors.New("COHORT_RECOVERY_WINDOW_INVALID")
	}
	if start.Before(fleetCeilMinute(appliedAt)) {
		return start, end, errors.New("COHORT_RECOVERY_OBSERVATION_PENDING")
	}
	return start, end, nil
}

// A server-stamped original APPLIED receipt anchors the observation. Retrying a
// health check cannot slide past an earlier failed or missing minute. Larger
// signed windows need a later separately reviewed implementation, not truncation.
func fleetStageWindow(appliedAt, now time.Time, stage fleet.Stage) (time.Time, time.Time, error) {
	start, observedEnd := fleetCeilMinute(appliedAt), now.UTC().Truncate(time.Minute)
	if appliedAt.IsZero() || now.IsZero() || appliedAt.After(now.Add(5*time.Second)) || stage.MinimumObservationSeconds < 0 || stage.MinimumObservationSeconds > 3600 {
		return start, observedEnd, errors.New("COHORT_OBSERVATION_ANCHOR_INVALID")
	}
	required := time.Duration((stage.MinimumObservationSeconds+59)/60) * time.Minute
	if required < 2*time.Minute {
		required = 2 * time.Minute
	}
	end := start.Add(required)
	if observedEnd.Before(end) {
		return start, observedEnd, errors.New("COHORT_SIGNED_OBSERVATION_PENDING")
	}
	// A fixed end permits the normal bounded receipt delivery delay without
	// expanding a60-minute stage into an unsupported62-minute pseudo-window.
	// Current health is checked separately; an outage never renews this window.
	if now.After(end.Add(2 * time.Minute)) {
		return start, end, errors.New("COHORT_ANCHORED_WINDOW_STALE")
	}
	return start, end, nil
}

// Only an absent, still-deliverable minute is pending. A received breach,
// malformed receipt, quiet minute or an older settled gap is already unsafe.
func fleetMemberDeliveryPending(e fleetMemberEvaluation, start, end, now time.Time, rows []fleetSLOReceipt) bool {
	if e.Status != "BLOCKED" {
		return false
	}
	for _, reason := range e.ReasonCodes {
		if reason != "COHORT_FULL_WINDOW_COVERAGE_GAP" && reason != "COHORT_MEMBER_LATENCY_SAMPLES_INSUFFICIENT" {
			return false
		}
	}
	missing := false
	for at := start; at.Before(end); at = at.Add(time.Minute) {
		found := false
		for _, row := range rows {
			found = found || row.Receipt.IntervalStart.Equal(at) && row.Receipt.IntervalEnd.Equal(at.Add(time.Minute))
		}
		if !found {
			missing = true
			if now.After(at.Add(3 * time.Minute)) {
				return false
			}
		}
	}
	return missing
}

func fleetCountAdd(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || b > slo.MaxCount || a > slo.MaxCount-b {
		return 0, false
	}
	return a + b, true
}
func fleetRatioLimit(n, d, ppm int64, maximum bool) bool {
	if d <= 0 {
		return false
	}
	l := new(big.Int).Mul(big.NewInt(n), big.NewInt(1_000_000))
	r := new(big.Int).Mul(big.NewInt(d), big.NewInt(ppm))
	if maximum {
		return l.Cmp(r) <= 0
	}
	return l.Cmp(r) >= 0
}
func fleetHistogramQuantile(buckets []fleet.CohortBucket, samples, percent int64) fleet.QuantileBounds {
	if samples <= 0 || samples > slo.MaxCount {
		return fleet.QuantileBounds{}
	}
	rank := (samples*percent + 99) / 100
	var cumulative, lower int64
	for _, b := range buckets {
		cumulative += b.Count
		if cumulative >= rank {
			return fleet.QuantileBounds{LowerMS: lower, UpperMS: b.UpperBoundMS}
		}
		if b.UpperBoundMS != nil {
			lower = *b.UpperBoundMS
		}
	}
	return fleet.QuantileBounds{}
}
func fleetSLIHardChecks(requests, errorsCount, good, total, samples int64, buckets []fleet.CohortBucket, limits slo.Limits) (string, []string) {
	status, reasons := "CLEAR", map[string]bool{}
	mark := func(s, reason string) {
		if s == "BREACH" || status != "BREACH" {
			status = s
		}
		reasons[reason] = true
	}
	if requests == 0 || samples == 0 {
		mark("BLOCKED", "COHORT_MEMBER_QUIET_OR_LATENCY_UNKNOWN")
	} else if !fleetRatioLimit(errorsCount, requests, limits.MaxErrorRatePPM, true) {
		mark("BREACH", "COHORT_MEMBER_ERROR_RATE_BREACH")
	}
	if !fleetRatioLimit(good, total, limits.MinAvailabilityPPM, false) {
		mark("BREACH", "COHORT_MEMBER_AVAILABILITY_BREACH")
	}
	for _, q := range []struct {
		percent int64
		limit   int64
	}{{95, limits.MaxP95LatencyMS}, {99, limits.MaxP99LatencyMS}} {
		bounds := fleetHistogramQuantile(buckets, samples, q.percent)
		if bounds.UpperMS == nil {
			mark("BLOCKED", "COHORT_MEMBER_LATENCY_TAIL_UNKNOWN")
		} else if bounds.LowerMS > q.limit {
			mark("BREACH", "COHORT_MEMBER_LATENCY_HARD_BREACH")
		} else if *bounds.UpperMS > q.limit {
			mark("BLOCKED", "COHORT_MEMBER_LATENCY_HARD_UNCERTAIN")
		}
	}
	return status, slo.SortedReasons(reasons)
}

// fleetBuildMemberWindow computes a distinct fleet-window snapshot. It does not
// rewrite objective.evaluation_minutes or manufacture a legacy SLO evaluation.
// Every complete minute must have real demand and satisfy hard limits, including
// an unhealthy quiet member that a fleet aggregate could otherwise hide.
func fleetBuildMemberWindow(b fleet.Binding, objective slo.Objective, source slo.Source, start, end, asOf time.Time, selected []fleetSLOReceipt) fleetMemberEvaluation {
	e := fleetMemberEvaluation{SchemaVersion: "1", Kind: "FLEET_MEMBER_SLO_WINDOW", WindowStart: start, WindowEnd: end, Status: "CLEAR", ReasonCodes: []string{}, MinuteChecks: []fleetMinuteCheck{}}
	m := &e.Member
	*m = fleet.CohortMemberWindow{Binding: b, ObjectiveID: objective.ID, ObjectiveVersion: objective.Version, ObjectiveSHA256: slo.ObjectiveHash(objective), InstanceID: b.ProviderResourceID, SourceID: source.ID, SourceSHA256: slo.SourceHash(source), ReceiptIDs: []string{}, LatencyBuckets: []fleet.CohortBucket{}}
	reasons := map[string]bool{}
	mark := func(status, reason string) {
		if status == "BREACH" || e.Status != "BREACH" {
			e.Status = status
		}
		reasons[reason] = true
	}
	finish := func() fleetMemberEvaluation {
		e.ReasonCodes = slo.SortedReasons(reasons)
		e.Hash = fleetMemberEvaluationHash(e)
		m.EvaluationID, m.EvaluationSHA256 = "fleet-member-"+e.Hash, e.Hash
		return e
	}
	duration := end.Sub(start)
	if fleet.ValidateBinding(b) != nil || !fleetHealthInstance.MatchString(b.ProviderResourceID) || slo.ValidateObjective(objective) != nil || objective.ID == "" || objective.Version < 1 || source.SchemaVersion != "1" || source.ID == "" || !source.Enabled || source.Issuer == "" || source.Subject == "" || source.Binding() != (slo.Binding{TenantID: b.TenantID, WorkloadID: b.WorkloadID, ResourceID: b.ResourceID, ProviderResourceID: b.ProviderResourceID, AccountID: b.AccountID, Region: b.Region}) || source.ObjectiveID != objective.ID || objective.WorkloadID != b.WorkloadID {
		mark("BLOCKED", "COHORT_MEMBER_REGISTERED_SCOPE_INVALID")
		return finish()
	}
	if asOf.IsZero() || end.After(asOf.Add(5*time.Second)) || start.IsZero() || duration < 2*time.Minute || duration > 60*time.Minute || duration%time.Minute != 0 || !start.Equal(start.UTC().Truncate(time.Minute)) || !end.Equal(end.UTC().Truncate(time.Minute)) || len(selected) > 60 {
		mark("BLOCKED", "COHORT_COMPLETE_WINDOW_REQUIRED")
		return finish()
	}
	rows := append([]fleetSLOReceipt{}, selected...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Receipt.IntervalStart.Before(rows[j].Receipt.IntervalStart) })
	cursor, previousSequence := start, int64(0)
	seen := map[string]bool{}
	for _, row := range rows {
		r := row.Receipt
		decoded, err := slo.DecodeInterval(row.Raw)
		if err != nil || slo.Hash(decoded) != slo.Hash(r.Interval) || !fleetHealthHash.MatchString(r.BodySHA256) || fleetHealthDigest(row.Raw) != r.BodySHA256 || r.ID == "" || seen[r.ID] || r.WriterRole != "finops_activity" || r.Binding != source.Binding() || r.SourceID != source.ID || r.TenantID != b.TenantID || r.Subject != source.Subject || r.ObjectiveID != objective.ID || r.ResourceID != b.ResourceID || r.WorkloadID != b.WorkloadID {
			mark("BLOCKED", "COHORT_ORIGINAL_RECEIPT_BINDING_INVALID")
			continue
		}
		seen[r.ID] = true
		if !r.IntervalStart.Equal(cursor) || r.IntervalStart.Before(start) || r.IntervalEnd.After(end) || previousSequence > 0 && r.Sequence != previousSequence+1 {
			mark("BLOCKED", "COHORT_FULL_WINDOW_COVERAGE_GAP")
		}
		if r.ReceivedAt.IsZero() || r.ReceivedAt.Before(r.IntervalEnd.Add(-5*time.Second)) || r.ReceivedAt.After(r.IntervalEnd.Add(2*time.Minute)) || r.ReceivedAt.After(asOf.Add(5*time.Second)) {
			mark("BLOCKED", "COHORT_RECEIPT_RECEIVE_TIME_INVALID")
		}
		cursor, previousSequence = r.IntervalEnd, r.Sequence
		m.ReceiptIDs = append(m.ReceiptIDs, r.ID)
		buckets := make([]fleet.CohortBucket, len(r.Latency.Buckets))
		for i, bucket := range r.Latency.Buckets {
			buckets[i] = fleet.CohortBucket{UpperBoundMS: bucket.UpperBoundMS, Count: bucket.Count}
		}
		status, minuteReasons := fleetSLIHardChecks(r.RequestCount, r.ErrorCount, r.AvailabilityGoodSeconds, r.AvailabilityTotalSeconds, r.Latency.SampleCount, buckets, objective.Limits)
		e.MinuteChecks = append(e.MinuteChecks, fleetMinuteCheck{r.ID, r.IntervalStart, r.IntervalEnd, status, minuteReasons})
		for _, reason := range minuteReasons {
			mark(status, reason)
		}
		if len(m.LatencyBuckets) == 0 {
			for _, bucket := range buckets {
				m.LatencyBuckets = append(m.LatencyBuckets, fleet.CohortBucket{UpperBoundMS: bucket.UpperBoundMS})
			}
		}
		if len(m.LatencyBuckets) != len(buckets) {
			mark("BLOCKED", "COHORT_HISTOGRAM_LAYOUT_CHANGED")
			continue
		}
		for i, bucket := range buckets {
			prior := m.LatencyBuckets[i].UpperBoundMS
			if (prior == nil) != (bucket.UpperBoundMS == nil) || prior != nil && *prior != *bucket.UpperBoundMS {
				mark("BLOCKED", "COHORT_HISTOGRAM_LAYOUT_CHANGED")
				continue
			}
			value, ok := fleetCountAdd(m.LatencyBuckets[i].Count, bucket.Count)
			if !ok {
				mark("BLOCKED", "COHORT_COUNTER_BOUND_EXCEEDED")
			} else {
				m.LatencyBuckets[i].Count = value
			}
		}
		for _, pair := range []struct {
			out *int64
			add int64
		}{{&m.RequestCount, r.RequestCount}, {&m.ErrorCount, r.ErrorCount}, {&m.AvailabilityGoodSeconds, r.AvailabilityGoodSeconds}, {&m.AvailabilityTotalSeconds, r.AvailabilityTotalSeconds}, {&m.LatencySamples, r.Latency.SampleCount}} {
			value, ok := fleetCountAdd(*pair.out, pair.add)
			if !ok {
				mark("BLOCKED", "COHORT_COUNTER_BOUND_EXCEEDED")
			} else {
				*pair.out = value
			}
		}
	}
	if !cursor.Equal(end) || len(m.ReceiptIDs) != int(duration/time.Minute) {
		mark("BLOCKED", "COHORT_FULL_WINDOW_COVERAGE_GAP")
	}
	if m.LatencySamples < objective.Limits.MinLatencySamples {
		mark("BLOCKED", "COHORT_MEMBER_LATENCY_SAMPLES_INSUFFICIENT")
	}
	return finish()
}
