package groupfixtureproducer

import (
	"errors"
	"time"
)

const healthMeasurementV2 = "GO_MONOTONIC_HTTP_V2"
const healthClockRevision = "GO_MONOTONIC_V1"
const maximumHealthClockDiscontinuity = time.Second

var errHealthClock = errors.New("GROUP_FIXTURE_HEALTH_CLOCK_DISCONTINUITY")
var ErrHealthCoverage = errors.New("GROUP_FIXTURE_HEALTH_COVERAGE_UNKNOWN")

// CheckHealthReceiptChain validates only the captured chain's immutable
// quality. It does not certify a baseline duration, stage health, source
// authentication or permission. A failed frozen chain cannot improve by
// appending more samples, so collectors should stop instead of waiting.
func CheckHealthReceiptChain(binding HealthBinding, receipts []HealthReceipt) error {
	p, err := population(receipts, binding, false)
	if err != nil {
		return err
	}
	if !p.complete {
		return ErrHealthCoverage
	}
	return nil
}

// HealthClock preserves UTC evidence independently of monotonic duration.
// Receipt clocks are conservative spans inside the two server heartbeats:
// after the first response was received, and before the next request started.
// They exclude snapshot round trips instead of inventing observed time.
// These are trusted local-producer measurements, not portable clock proofs.
type HealthClock struct {
	Revision             string    `json:"revision"`
	StartedAt            time.Time `json:"started_at"`
	FinishedAt           time.Time `json:"finished_at"`
	ElapsedNS            int64     `json:"elapsed_ns"`
	WallMinusMonotonicNS int64     `json:"wall_minus_monotonic_ns"`
}

func healthClock(start, end time.Time) HealthClock {
	elapsed := end.Sub(start).Nanoseconds()
	return HealthClock{healthClockRevision, start.UTC(), end.UTC(), elapsed, end.UTC().Sub(start.UTC()).Nanoseconds() - elapsed}
}

func validHealthClock(c *HealthClock) bool {
	if c == nil || c.Revision != healthClockRevision || c.StartedAt.IsZero() || c.FinishedAt.IsZero() || c.FinishedAt.Before(c.StartedAt) || c.ElapsedNS <= 0 || c.ElapsedNS > int64(time.Minute) {
		return false
	}
	wall := c.FinishedAt.Sub(c.StartedAt).Nanoseconds()
	return c.WallMinusMonotonicNS == wall-c.ElapsedNS && c.WallMinusMonotonicNS <= int64(maximumHealthClockDiscontinuity) && c.WallMinusMonotonicNS >= -int64(maximumHealthClockDiscontinuity)
}

func healthObservationClock(schema string, o HealthObservation) error {
	if schema == "1" {
		// V1's exact bytes and wall-duration interpretation remain unchanged.
		if o.Clock != nil || o.ReadError || o.ElapsedNS != o.FinishedAt.Sub(o.StartedAt).Nanoseconds() {
			return ErrHealth
		}
		return nil
	}
	if !validHealthClock(o.Clock) || o.Clock.StartedAt != o.StartedAt || o.Clock.FinishedAt != o.FinishedAt || o.Clock.ElapsedNS != o.ElapsedNS {
		return errHealthClock
	}
	return nil
}
