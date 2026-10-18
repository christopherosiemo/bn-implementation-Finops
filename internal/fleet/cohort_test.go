package fleet

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func cohortFixture() CohortInput {
	now := time.Now().UTC().Truncate(time.Minute)
	p := fixturePlan(now.Add(-10 * time.Minute))
	input := CohortInput{Now: now, Parent: p, Limits: CohortLimits{ObjectiveID: "objective", ObjectiveVersion: 1, ObjectiveSHA256: strings.Repeat("a", 64), MaximumErrorRatePPM: 10000, MinimumAvailabilityPPM: 990000, MaximumP95MS: 200, MaximumP99MS: 250, MinimumLatencySamples: 100, MaximumRegressionPercent: 15}}
	makeWindow := func(role, asg string, start time.Time, first, count int) CohortWindow {
		w := CohortWindow{Binding: p.Binding, ASG: asg, Role: role, ObjectiveID: input.Limits.ObjectiveID, ObjectiveVersion: 1, ObjectiveSHA256: input.Limits.ObjectiveSHA256, Start: start, End: start.Add(2 * time.Minute)}
		for i := 0; i < count; i++ {
			lo, hi := int64(99), int64(100)
			id := fmt.Sprintf("i-%017x", first+i)
			memberBinding := p.Binding
			memberBinding.ProviderResourceID = id
			memberBinding.ResourceID = "resource-" + id
			w.Members = append(w.Members, CohortMemberWindow{InstanceID: id, SourceID: "s-" + id, SourceSHA256: strings.Repeat("b", 64), EvaluationID: role + id, EvaluationSHA256: strings.Repeat("c", 64), ReceiptIDs: []string{role + id + "-1", role + id + "-2"}, RequestCount: 1000, ErrorCount: 1, AvailabilityGoodSeconds: 120, AvailabilityTotalSeconds: 120, LatencySamples: 1000, LatencyBuckets: []CohortBucket{{&lo, 0}, {&hi, 1000}, {nil, 0}}})
			w.Members[len(w.Members)-1].Binding = memberBinding
			w.Members[len(w.Members)-1].ObjectiveID = input.Limits.ObjectiveID
			w.Members[len(w.Members)-1].ObjectiveVersion = 1
			w.Members[len(w.Members)-1].ObjectiveSHA256 = input.Limits.ObjectiveSHA256
		}
		return w
	}
	input.Baseline = makeWindow("FROZEN_BLUE_BASELINE", p.Old.ID, p.CreatedAt.Add(-3*time.Minute), 1, 20)
	input.BlueControl = makeWindow("CURRENT_BLUE_CONTROL", p.Old.ID, now.Add(-2*time.Minute), 1, 20)
	input.Green = makeWindow("CURRENT_GREEN", p.Candidate.ID, now.Add(-2*time.Minute), 100, 2)
	for _, m := range input.Baseline.Members {
		input.FrozenBlueMemberIDs = append(input.FrozenBlueMemberIDs, m.InstanceID)
	}
	for _, m := range input.BlueControl.Members {
		input.CurrentBlueMemberIDs = append(input.CurrentBlueMemberIDs, m.InstanceID)
	}
	for _, m := range input.Green.Members {
		input.CurrentGreenMemberIDs = append(input.CurrentGreenMemberIDs, m.InstanceID)
	}
	return input
}
func cohortLatency(w *CohortWindow, lower, upper int64) {
	for i := range w.Members {
		lo, hi := lower, upper
		w.Members[i].LatencyBuckets = []CohortBucket{{&lo, 0}, {&hi, 1000}, {nil, 0}}
	}
}
func TestFleetCohortSeparateSourcesConservativeRegressionAndHardLimits(t *testing.T) {
	in := cohortFixture()
	r := CompareCohorts(in)
	if r.Status != "CLEAR" || r.Hash == "" || CohortComparisonHash(r) != r.Hash {
		t.Fatal("explicit cohort comparison failed", r)
	}
	for name, mutate := range map[string]func(*CohortInput){
		"cross account member":       func(in *CohortInput) { in.Green.Members[0].Binding.AccountID = "999988887777" },
		"cross workload member":      func(in *CohortInput) { in.Green.Members[0].Binding.WorkloadID = "other" },
		"different member objective": func(in *CohortInput) { in.Green.Members[0].ObjectiveVersion = 2 },
		"35 percent exceeds 15":      func(in *CohortInput) { cohortLatency(&in.Green, 134, 135) },
		"independent p99 hard limit": func(in *CohortInput) {
			in.Limits.MaximumRegressionPercent = 1000
			for i := range in.Green.Members {
				a, b, c := int64(99), int64(100), int64(300)
				in.Green.Members[i].LatencyBuckets = []CohortBucket{{&a, 0}, {&b, 950}, {&c, 50}, {nil, 0}}
			}
		},
		"error hard limit":             func(in *CohortInput) { in.Green.Members[0].ErrorCount = 100 },
		"availability hard limit":      func(in *CohortInput) { in.Green.Members[0].AvailabilityGoodSeconds = 100 },
		"unhealthy concurrent control": func(in *CohortInput) { cohortLatency(&in.BlueControl, 134, 135) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone(in)
			mutate(&changed)
			got := CompareCohorts(changed)
			if got.Status == "CLEAR" {
				t.Fatal("unsafe health accepted", got)
			}
		})
	}
	changed := clone(in)
	cohortLatency(&changed.Green, 134, 135)
	if got := CompareCohorts(changed); got.Status != "BREACH" {
		t.Fatal("known 35% regression did not breach 15% limit", got)
	}
	changed = clone(in)
	cohortLatency(&changed.Green, 114, 115)
	if got := CompareCohorts(changed); got.Status != "BLOCKED" {
		t.Fatal("histogram uncertainty became exact 15% guarantee", got)
	}
	changed = clone(in)
	cohortLatency(&changed.Green, 109, 110)
	if got := CompareCohorts(changed); got.Status != "CLEAR" {
		t.Fatal("bounded below-threshold regression blocked", got)
	}
	changed = clone(in)
	a, b, lo, hi := int64(99), int64(100), int64(134), int64(135)
	changed.Green.Members[0].LatencyBuckets = []CohortBucket{{&a, 0}, {&b, 0}, {&lo, 0}, {&hi, 1000}, {nil, 0}}
	changed.Green.Members[1].RequestCount = 1_000_000
	changed.Green.Members[1].LatencySamples = 1_000_000
	changed.Green.Members[1].LatencyBuckets = []CohortBucket{{&a, 0}, {&b, 1_000_000}, {&lo, 0}, {&hi, 0}, {nil, 0}}
	if got := CompareCohorts(changed); got.Status != "BREACH" {
		t.Fatal("high-volume healthy member concealed slow candidate", got)
	}
}
func TestFleetCohortMissingMemberScopeReceiptOrTailCannotProveHealth(t *testing.T) {
	in := cohortFixture()
	for name, mutate := range map[string]func(*CohortInput){
		"representative member":     func(in *CohortInput) { in.Green.Members = in.Green.Members[:1] },
		"cross account":             func(in *CohortInput) { in.Green.Binding.AccountID = "999988887777" },
		"different objective":       func(in *CohortInput) { in.Green.ObjectiveSHA256 = strings.Repeat("d", 64) },
		"same source hash hack":     func(in *CohortInput) { in.Green.Members[0].SourceID = in.BlueControl.Members[0].SourceID },
		"reused current receipt":    func(in *CohortInput) { in.Green.Members[0].ReceiptIDs[0] = in.BlueControl.Members[0].ReceiptIDs[0] },
		"missing complete interval": func(in *CohortInput) { in.Green.Members[0].ReceiptIDs = in.Green.Members[0].ReceiptIDs[:1] },
		"zero demand": func(in *CohortInput) {
			for i := range in.Green.Members {
				in.Green.Members[i].RequestCount = 0
				in.Green.Members[i].ErrorCount = 0
				in.Green.Members[i].LatencySamples = 0
				for j := range in.Green.Members[i].LatencyBuckets {
					in.Green.Members[i].LatencyBuckets[j].Count = 0
				}
			}
		},
		"unbounded p99 tail": func(in *CohortInput) {
			for i := range in.Green.Members {
				in.Green.Members[i].LatencyBuckets[1].Count = 980
				in.Green.Members[i].LatencyBuckets[2].Count = 20
			}
		},
		"postplan baseline": func(in *CohortInput) {
			in.Baseline.Start = in.Parent.CreatedAt
			in.Baseline.End = in.Parent.CreatedAt.Add(2 * time.Minute)
		},
		"stale current":           func(in *CohortInput) { in.Now = in.Now.Add(3 * time.Minute) },
		"mismatched control time": func(in *CohortInput) { in.BlueControl.End = in.BlueControl.End.Add(-time.Minute) },
		"physical overlap": func(in *CohortInput) {
			in.CurrentGreenMemberIDs[0] = in.CurrentBlueMemberIDs[0]
			in.Green.Members[0].InstanceID = in.CurrentBlueMemberIDs[0]
		},
		"retired frozen blue reused as green": func(in *CohortInput) {
			id := in.FrozenBlueMemberIDs[0]
			in.CurrentBlueMemberIDs = in.CurrentBlueMemberIDs[1:]
			in.BlueControl.Members = in.BlueControl.Members[1:]
			in.CurrentGreenMemberIDs[0] = id
			in.Green.Members[0].InstanceID = id
			in.Green.Members[0].SourceID = "new-source-retired-blue"
		},
		"overflow counts": func(in *CohortInput) { in.Green.Members[0].LatencyBuckets[0].Count = cohortMaxCount },
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone(in)
			mutate(&changed)
			if got := CompareCohorts(changed); got.Status == "CLEAR" {
				t.Fatal("missing or misbound evidence accepted", got)
			}
		})
	}
}
