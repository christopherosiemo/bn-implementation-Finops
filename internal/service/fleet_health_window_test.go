package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
)

func fleetHealthWindowFixture(minutes int) (fleet.Binding, slo.Objective, slo.Source, time.Time, time.Time, []fleetSLOReceipt) {
	end := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	start := end.Add(-time.Duration(minutes) * time.Minute)
	b := fleet.Binding{TenantID: "tenant", ResourceID: "physical-resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}
	o := slo.Objective{SchemaVersion: "1", ID: "objective", Version: 1, WorkloadID: b.WorkloadID, EvaluationMinutes: 2, Limits: slo.Limits{MaxErrorRatePPM: 1000, MinAvailabilityPPM: 990000, MaxP95LatencyMS: 200, MaxP99LatencyMS: 250, MinLatencySamples: 100}, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC"}, Regression: slo.Regression{Enabled: true, MaxPercent: 15}}
	s := slo.Source{SchemaVersion: "1", ID: "source", TenantID: b.TenantID, ObjectiveID: o.ID, WorkloadID: b.WorkloadID, ResourceID: b.ResourceID, ProviderResourceID: b.ProviderResourceID, AccountID: b.AccountID, Region: b.Region, Issuer: "https://machine.invalid", Subject: "off-instance-gateway", Enabled: true}
	rows := []fleetSLOReceipt{}
	for i := 0; i < minutes; i++ {
		lo, hi := int64(99), int64(100)
		in := slo.Interval{SchemaVersion: "1", SourceID: s.ID, ObjectiveID: o.ID, WorkloadID: b.WorkloadID, ResourceID: b.ResourceID, Sequence: int64(i + 1), IntervalStart: start.Add(time.Duration(i) * time.Minute), IntervalEnd: start.Add(time.Duration(i+1) * time.Minute), RequestCount: 1000, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: 1000, Buckets: []slo.Bucket{{UpperBoundMS: &lo}, {UpperBoundMS: &hi, Count: 1000}, {UpperBoundMS: nil}}}}
		raw, _ := json.Marshal(in)
		r := slo.Receipt{Interval: in, ID: fmt.Sprintf("receipt-%d", i), TenantID: b.TenantID, Subject: s.Subject, ReceivedAt: in.IntervalEnd.Add(time.Second), BodySHA256: fleetHealthDigest(raw), IdempotencyKey: fmt.Sprintf("key-%d", i), WriterRole: "finops_activity", Binding: s.Binding()}
		rows = append(rows, fleetSLOReceipt{Receipt: r, Raw: raw})
	}
	return b, o, s, start, end, rows
}

func fleetRewriteWindowReceipt(row *fleetSLOReceipt) {
	row.Raw, _ = json.Marshal(row.Receipt.Interval)
	row.Receipt.BodySHA256 = fleetHealthDigest(row.Raw)
}

func TestFleetDeliveryGraceNeverLatchesAnUnsettledMinuteOrHidesAnOlderFailure(t *testing.T) {
	b, o, s, start, end, rows := fleetHealthWindowFixture(3)
	now := end.Add(30 * time.Second)
	late := rows[:2]
	e := fleetBuildMemberWindow(b, o, s, start, end, now, late)
	if !fleetMemberDeliveryPending(e, start, end, now, late) {
		t.Fatal("legitimate bounded delivery delay became permanent failure", e.ReasonCodes)
	}
	if fleetMemberDeliveryPending(e, start, end, end.Add(2*time.Minute+time.Nanosecond), late) {
		t.Fatal("missing minute remained pending beyond delivery deadline")
	}
	older := rows[1:]
	e = fleetBuildMemberWindow(b, o, s, start, end, now, older)
	if fleetMemberDeliveryPending(e, start, end, now, older) {
		t.Fatal("settled earlier coverage gap hidden by fresh tail")
	}
	late[0].Receipt.ErrorCount = 100
	fleetRewriteWindowReceipt(&late[0])
	e = fleetBuildMemberWindow(b, o, s, start, end, now, late)
	if e.Status != "BREACH" || fleetMemberDeliveryPending(e, start, end, now, late) {
		t.Fatal("received breach delayed behind missing last minute")
	}
}

func TestFleetMemberWholeWindowPreservesObjectiveAndAuthenticatedMinuteProvenance(t *testing.T) {
	b, o, s, start, end, rows := fleetHealthWindowFixture(60)
	e := fleetBuildMemberWindow(b, o, s, start, end, end.Add(time.Second), rows)
	if e.Status != "CLEAR" || len(e.MinuteChecks) != 60 || len(e.Member.ReceiptIDs) != 60 || e.Member.ObjectiveSHA256 != slo.ObjectiveHash(o) || o.EvaluationMinutes != 2 || e.Member.RequestCount != 60000 || e.Member.AvailabilityTotalSeconds != 3600 || e.Hash != fleetMemberEvaluationHash(e) || e.Member.EvaluationSHA256 != e.Hash {
		t.Fatal("full-stage snapshot lost its distinct duration, original objective or authenticated coverage", e.Status, e.ReasonCodes)
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	reordered := fleetBuildMemberWindow(b, o, s, start, end, end.Add(time.Second), rows)
	if reordered.Hash != e.Hash {
		t.Fatal("database row order changed immutable window identity")
	}
}

func TestFleetMemberWindowCannotHideQuietGapsOrEarlierBreachBehindGoodAggregate(t *testing.T) {
	for name, mutate := range map[string]func(*slo.Objective, []fleetSLOReceipt) []fleetSLOReceipt{
		"missing earlier minute with fresh tail": func(_ *slo.Objective, rows []fleetSLOReceipt) []fleetSLOReceipt {
			return append(rows[:10], rows[11:]...)
		},
		"quiet earlier minute": func(_ *slo.Objective, rows []fleetSLOReceipt) []fleetSLOReceipt {
			rows[0].Receipt.RequestCount, rows[0].Receipt.Latency.SampleCount, rows[0].Receipt.Latency.Buckets[1].Count = 0, 0, 0
			fleetRewriteWindowReceipt(&rows[0])
			return rows
		},
		"one-minute errors hidden in fleet total": func(_ *slo.Objective, rows []fleetSLOReceipt) []fleetSLOReceipt {
			rows[0].Receipt.ErrorCount = 10 // 1% that minute; only0.0167% over60min.
			fleetRewriteWindowReceipt(&rows[0])
			return rows
		},
		"one-minute availability hidden in window total": func(_ *slo.Objective, rows []fleetSLOReceipt) []fleetSLOReceipt {
			rows[0].Receipt.AvailabilityGoodSeconds = 59
			fleetRewriteWindowReceipt(&rows[0])
			return rows
		},
		"one-minute latency hidden in window percentile": func(_ *slo.Objective, rows []fleetSLOReceipt) []fleetSLOReceipt {
			a, z := int64(299), int64(300)
			rows[0].Receipt.Latency.Buckets = []slo.Bucket{{UpperBoundMS: &a}, {UpperBoundMS: &z, Count: 1000}, {UpperBoundMS: nil}}
			fleetRewriteWindowReceipt(&rows[0])
			return rows
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, o, s, start, end, rows := fleetHealthWindowFixture(60)
			rows = mutate(&o, rows)
			got := fleetBuildMemberWindow(b, o, s, start, end, end.Add(time.Second), rows)
			if got.Status == "CLEAR" || len(got.ReasonCodes) == 0 {
				t.Fatal("an earlier missing or unhealthy minute disappeared in the aggregate")
			}
			if strings.Contains(name, "hidden") && got.Status != "BREACH" {
				t.Fatal("definite hard-limit breach was reduced to uncertainty", got.Status, got.ReasonCodes)
			}
		})
	}
}

func TestFleetMemberWindowRejectsForgedReboundOrUncertainReceipts(t *testing.T) {
	for name, mutate := range map[string]func(*fleet.Binding, *slo.Objective, *slo.Source, []fleetSLOReceipt) []fleetSLOReceipt{
		"wrong physical instance": func(b *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			b.ProviderResourceID = "i-99999999999999999"
			return r
		},
		"wrong tenant": func(b *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			b.TenantID = "other"
			return r
		},
		"objective changed": func(_ *fleet.Binding, o *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			o.ID = "new-objective"
			o.Version++
			return r
		},
		"source disabled": func(_ *fleet.Binding, _ *slo.Objective, s *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			s.Enabled = false
			return r
		},
		"wrong writer": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[0].Receipt.WriterRole = "finops_api"
			return r
		},
		"wrong machine subject": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[0].Receipt.Subject = "console"
			return r
		},
		"raw bytes changed": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[0].Raw = append(r[0].Raw, ' ')
			return r
		},
		"receipt counters changed": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[0].Receipt.ErrorCount++
			return r
		},
		"delayed historical submission": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[0].Receipt.ReceivedAt = r[0].Receipt.IntervalEnd.Add(3 * time.Minute)
			return r
		},
		"sequence skipped": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[1].Receipt.Sequence += 2
			fleetRewriteWindowReceipt(&r[1])
			return r
		},
		"duplicate receipt": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[1].Receipt.ID = r[0].Receipt.ID
			return r
		},
		"unbounded histogram tail": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			r[0].Receipt.Latency.Buckets[1].Count = 0
			r[0].Receipt.Latency.Buckets[2].Count = 1000
			fleetRewriteWindowReceipt(&r[0])
			return r
		},
		"overflowing window counters": func(_ *fleet.Binding, _ *slo.Objective, _ *slo.Source, r []fleetSLOReceipt) []fleetSLOReceipt {
			for i := range r {
				r[i].Receipt.RequestCount, r[i].Receipt.Latency.SampleCount, r[i].Receipt.Latency.Buckets[1].Count = slo.MaxCount, slo.MaxCount, slo.MaxCount
				fleetRewriteWindowReceipt(&r[i])
			}
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, o, s, start, end, rows := fleetHealthWindowFixture(2)
			rows = mutate(&b, &o, &s, rows)
			if got := fleetBuildMemberWindow(b, o, s, start, end, end.Add(time.Second), rows); got.Status == "CLEAR" {
				t.Fatal("misbound or uncertain whole-window evidence accepted")
			}
		})
	}
}

func TestFleetSignedObservationWindowCannotSlideOrCountPreApplyMinutes(t *testing.T) {
	anchor := time.Date(2026, 10, 18, 10, 0, 30, 0, time.UTC)
	stage := fleet.Stage{MinimumObservationSeconds: 3600}
	wantStart := anchor.Truncate(time.Minute).Add(time.Minute)
	start, end, err := fleetStageWindow(anchor, wantStart.Add(time.Hour), stage)
	if err != nil || !start.Equal(wantStart) || end.Sub(start) != time.Hour {
		t.Fatal("signed60-minute observation was not anchored after actual apply", err)
	}
	if _, _, err = fleetStageWindow(anchor, wantStart.Add(59*time.Minute), stage); err == nil || err.Error() != "COHORT_SIGNED_OBSERVATION_PENDING" {
		t.Fatal("partial canary observation accepted", err)
	}
	if _, _, err = fleetStageWindow(anchor, wantStart.Add(63*time.Minute), stage); err == nil || err.Error() != "COHORT_ANCHORED_WINDOW_STALE" {
		t.Fatal("long-running command silently slid past an earlier bad minute", err)
	}
	if _, end, err = fleetStageWindow(anchor, wantStart.Add(61*time.Minute), stage); err != nil || !end.Equal(wantStart.Add(time.Hour)) {
		t.Fatal("bounded delivery delay changed the signed observation window", err)
	}
	stage.MinimumObservationSeconds = 60
	if _, _, err = fleetStageWindow(anchor, wantStart.Add(time.Minute), stage); err == nil {
		t.Fatal("less than two complete minutes became independent health")
	}
}

func TestFleetIntermediateHealthAndFreshOwnedRecoveryUseSeparateWindows(t *testing.T) {
	stage := fleet.Stage{Kind: fleet.Expand25, TargetCandidateCount: 5, TargetTrafficPercent: 25, MinimumObservationSeconds: 900}
	for _, transition := range []fleet.Transition{{CandidateAfter: 4, TrafficAfter: 10}, {CandidateAfter: 5, TrafficAfter: 10}} {
		if got := fleetChildObservationStage(stage, fleet.ChildPlan{Transition: transition}); got.MinimumObservationSeconds != 120 {
			t.Fatal("intermediate capacity pretended to complete the signed terminal dwell")
		}
	}
	if got := fleetChildObservationStage(stage, fleet.ChildPlan{Transition: fleet.Transition{CandidateAfter: 5, TrafficAfter: 25}}); got.MinimumObservationSeconds != 900 {
		t.Fatal("terminal traffic child lost its full signed dwell")
	}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	start, end, err := fleetRecoveryWindow(now.Add(-24*time.Hour), now, 2)
	if err != nil || !end.Equal(now) || !start.Equal(now.Add(-2*time.Minute)) {
		t.Fatal("fresh owned recovery was stranded by the old failed forward window", err)
	}
	if _, _, err = fleetRecoveryWindow(now.Add(-30*time.Second), now, 2); err == nil {
		t.Fatal("pre-inverse observations proved recovery")
	}
}

func TestFleetNativePhysicalMetricUnitsAreExplicitAndBounded(t *testing.T) {
	for _, tc := range []struct {
		value, unit string
		want        bool
	}{{"0.7", "ratio", true}, {"70", "percent", true}, {"0.7000001", "ratio", false}, {"70.00001", "percent", false}, {"70", "ratio", false}, {"0.7", "bytes", false}, {"-0.1", "ratio", false}, {"NaN", "ratio", false}} {
		value := tc.value
		if got := fleetNativeMetricWithin(&value, tc.unit, 700000); got != tc.want {
			t.Fatal("physical units or threshold boundary changed", tc.value, tc.unit, got)
		}
	}
}

func TestFleetContinuousRegressionCannotHideAnEarlierLowVolumeRegression(t *testing.T) {
	makePopulation := func(role, instance string) fleetHealthPopulation {
		b, o, s, start, end, rows := fleetHealthWindowFixture(60)
		b.ProviderResourceID = instance
		s.ProviderResourceID = instance
		for i := range rows {
			rows[i].Receipt.Binding = s.Binding()
		}
		member := fleetBuildMemberWindow(b, o, s, start, end, end.Add(time.Second), rows)
		if member.Status != "CLEAR" {
			t.Fatal(member.ReasonCodes)
		}
		return fleetHealthPopulation{Window: fleet.CohortWindow{Role: role, Start: start, End: end, Members: []fleet.CohortMemberWindow{member.Member}}, Receipts: map[string][]fleetSLOReceipt{instance: rows}}
	}
	blue := makePopulation("CURRENT_BLUE_CONTROL", "i-00000000000000001")
	green := makePopulation("CURRENT_GREEN", "i-00000000000000002")
	baseline := blue.Window
	if got := fleetCheckContinuousRegression(baseline, blue, green, 15); got.Status != "CLEAR" || got.CheckCount != 364 || !fleetHealthHash.MatchString(got.ChecksSHA256) {
		t.Fatal("separate exact physical minute checks failed", got)
	}
	for _, tc := range []struct {
		lo, hi int64
		status string
	}{{134, 135, "BREACH"}, {114, 115, "BLOCKED"}} {
		rows := green.Receipts["i-00000000000000002"]
		lo, hi := tc.lo, tc.hi
		rows[0].Receipt.RequestCount, rows[0].Receipt.Latency.SampleCount = 1, 1
		rows[0].Receipt.Latency.Buckets = []slo.Bucket{{UpperBoundMS: &lo}, {UpperBoundMS: &hi, Count: 1}, {UpperBoundMS: nil}}
		fleetRewriteWindowReceipt(&rows[0])
		got := fleetCheckContinuousRegression(baseline, blue, green, 15)
		if got.Status != tc.status || len(got.UnsafePreview) == 0 || !got.UnsafePreview[0].Minute.Equal(blue.Window.Start) {
			t.Fatal("one low-demand regressed minute vanished behind the healthy hour", got)
		}
	}
}
