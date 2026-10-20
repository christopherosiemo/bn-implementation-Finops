package service

import (
	"testing"
	"time"
)

func TestFleetCohortObservationAdmissionPreservesCompleteCommonWindow(t *testing.T) {
	minute := time.Date(2026, 10, 20, 12, 34, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		wait   time.Duration
	}{
		{"fresh_minute", 0, 0},
		{"ordinary_collection", 30 * time.Second, 0},
		{"exact_margin", 45 * time.Second, 0},
		{"near_boundary", 59 * time.Second, 1100 * time.Millisecond},
		{"last_nanosecond", time.Minute - time.Nanosecond, 100*time.Millisecond + time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := minute.Add(tc.offset)
			end, delay := fleetCohortObservationAdmission(now)
			if delay != tc.wait {
				t.Fatalf("admission delay %s, want %s", delay, tc.wait)
			}
			if delay > 0 {
				if !end.IsZero() || delay > fleetCohortObservationAdmissionMargin+100*time.Millisecond {
					t.Fatal("waiting admission exposed an interval or exceeded its fixed bound")
				}
				actual := now.Add(delay)
				end, delay = fleetCohortObservationAdmission(actual)
				if delay != 0 || !end.Equal(minute.Add(time.Minute)) {
					t.Fatal("next actual minute was not admitted")
				}
				now = actual
			}
			if end.After(now) || !end.Equal(end.UTC().Truncate(time.Minute)) {
				t.Fatal("admission invented a future or incomplete minute")
			}
			oldestEnd := end.Add(-time.Minute)
			if 2*time.Minute-now.Sub(oldestEnd) < fleetCohortObservationAdmissionMargin {
				t.Fatal("oldest complete interval has insufficient receive margin")
			}
		})
	}
}

func TestFleetCohortObservationAdmissionUsesUTCAndWaitsOnlyNearBoundary(t *testing.T) {
	zone := time.FixedZone("offset", 5*3600+1800)
	for millisecond := 0; millisecond < 60000; millisecond++ {
		now := time.Date(2026, 10, 20, 12, 34, 0, 0, time.UTC).Add(time.Duration(millisecond) * time.Millisecond).In(zone)
		end, delay := fleetCohortObservationAdmission(now)
		if (delay > 0) != (millisecond > 45000) {
			t.Fatal("wait admission did not preserve its exact fixed boundary")
		}
		if delay == 0 && (!end.Equal(now.UTC().Truncate(time.Minute)) || end.Location() != time.UTC) {
			t.Fatal("non-UTC or changed completed window")
		}
	}
}
