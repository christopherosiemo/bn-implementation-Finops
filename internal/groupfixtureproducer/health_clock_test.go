package groupfixtureproducer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

func TestHealthV1BytesAndInterpretationRemainImmutable(t *testing.T) {
	r := syntheticHealthReceipt(healthBinding(), time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), time.Minute, 10*time.Millisecond, 1, "", 0)
	// This projection is the exact original v1 field sequence and types.
	type oldObservation struct {
		StartedAt      time.Time `json:"started_at"`
		FinishedAt     time.Time `json:"finished_at"`
		ElapsedNS      int64     `json:"elapsed_ns"`
		StatusCode     int       `json:"status_code"`
		TransportError bool      `json:"transport_error"`
	}
	type oldReceipt struct {
		SchemaVersion  string           `json:"schema_version"`
		InstallationID string           `json:"installation_id"`
		Binding        HealthBinding    `json:"binding"`
		Sequence       uint64           `json:"sequence"`
		PreviousSHA256 string           `json:"previous_sha256"`
		Before         HealthSnapshot   `json:"before"`
		After          HealthSnapshot   `json:"after"`
		Observations   []oldObservation `json:"observations"`
		SHA256         string           `json:"sha256"`
	}
	old := oldReceipt{r.SchemaVersion, r.InstallationID, r.Binding, r.Sequence, r.PreviousSHA256, r.Before, r.After, nil, r.SHA256}
	for _, o := range r.Observations {
		old.Observations = append(old.Observations, oldObservation{o.StartedAt, o.FinishedAt, o.ElapsedNS, o.StatusCode, o.TransportError})
	}
	actual, _ := json.Marshal(r)
	want, _ := json.Marshal(old)
	if !bytes.Equal(actual, want) {
		t.Fatal("v1 serialized bytes changed")
	}
	old.SHA256 = ""
	unsigned, _ := json.Marshal(old)
	if HealthReceiptSHA256(r) != g.BytesDigest(unsigned) {
		t.Fatal("v1 content hash changed")
	}
	r.Observations[0].TransportError = true
	r.SHA256 = HealthReceiptSHA256(r)
	p, e := population([]HealthReceipt{r}, r.Binding, false)
	if e != nil || p.complete {
		t.Fatal("legacy unknown error was reinterpreted")
	}
}

// These conversions test v2 algebra, not native elapsed time or authority.
func v2HealthReceipt(r HealthReceipt, spanElapsed time.Duration) HealthReceipt {
	r.SchemaVersion = "2"
	r.MeasurementRevision = healthMeasurementV2
	r.Clock = &HealthClock{healthClockRevision, r.Before.CapturedAt, r.After.CapturedAt, int64(spanElapsed), r.After.CapturedAt.Sub(r.Before.CapturedAt).Nanoseconds() - int64(spanElapsed)}
	for i := range r.Observations {
		o := &r.Observations[i]
		o.Clock = &HealthClock{healthClockRevision, o.StartedAt, o.FinishedAt, o.ElapsedNS, 0}
	}
	r.SHA256 = HealthReceiptSHA256(r)
	return r
}

func TestHealthV2SeparatesClockSlewFromLatencyAndErrors(t *testing.T) {
	b := healthBinding()
	r := v2HealthReceipt(syntheticHealthReceipt(b, time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), time.Minute, 10*time.Millisecond, 1, "", 0), time.Minute)
	for i := range r.Observations {
		o := &r.Observations[i]
		o.ElapsedNS = int64(5 * time.Millisecond)
		o.Clock.ElapsedNS = o.ElapsedNS
		o.Clock.WallMinusMonotonicNS = int64(5 * time.Millisecond)
	}
	r.SHA256 = HealthReceiptSHA256(r)
	p, e := population([]HealthReceipt{r}, b, false)
	if e != nil || !p.complete || *healthQuantile(p.latencies, 95) != int64(5*time.Millisecond) {
		t.Fatal("small recorded UTC offset became transport failure or wall latency", e)
	}
	for _, mutate := range []func(*HealthReceipt){
		func(r *HealthReceipt) { r.Clock.WallMinusMonotonicNS++ },
		func(r *HealthReceipt) {
			r.Clock.ElapsedNS -= int64(time.Second) + 1
			r.Clock.WallMinusMonotonicNS = int64(time.Second) + 1
		},
		func(r *HealthReceipt) {
			r.Observations[0].FinishedAt = r.Observations[0].StartedAt.Add(-time.Nanosecond)
		},
		func(r *HealthReceipt) { r.MeasurementRevision = "unknown" },
	} {
		raw, _ := json.Marshal(r)
		var bad HealthReceipt
		_ = json.Unmarshal(raw, &bad)
		mutate(&bad)
		bad.SHA256 = HealthReceiptSHA256(bad)
		if _, err := population([]HealthReceipt{bad}, b, false); err == nil {
			t.Fatal("clock regression/discontinuity or revision forgery accepted")
		}
	}
}

func TestHealthV2RequiresBothUTCAndMonotonicFullWindows(t *testing.T) {
	b := healthBinding()
	start := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	rows := func(n int, at time.Time, elapsed time.Duration) []HealthReceipt {
		out := []HealthReceipt{}
		for i := 0; i < n; i++ {
			r := syntheticHealthReceipt(b, at.Add(time.Duration(i)*time.Minute), time.Minute, 10*time.Millisecond, uint64(i+1), "", uint64(i*40))
			if i > 0 {
				r.Before = out[i-1].After
				r.After.PeakSinceSequence = r.Before.Sequence
				r.PreviousSHA256 = out[i-1].SHA256
			}
			r = v2HealthReceipt(r, elapsed)
			out = append(out, r)
		}
		return out
	}
	baseline := rows(2, start.Add(-2*time.Minute), time.Minute)
	current := rows(15, start, 59*time.Second)
	w := EvaluateHealthWindow(b, g.DefaultStages(20)[5], start, baseline, current, healthLimits(), start.Add(15*time.Minute))
	if w.Status != "BLOCKED" || !hasHealthReason(w, "MONOTONIC_OBSERVATION_WINDOW_INCOMPLETE") || w.MonotonicDurationNS == nil || *w.MonotonicDurationNS != int64(885*time.Second) {
		t.Fatal("UTC alone earned terminal coverage", w.ReasonCodes)
	}
	current = rows(16, start, 59*time.Second)
	w = EvaluateHealthWindow(b, g.DefaultStages(20)[5], start, baseline, current, healthLimits(), start.Add(16*time.Minute))
	if w.Status != "OBSERVED" {
		t.Fatal("complete dual-clock coverage refused", w.ReasonCodes)
	}
	shortBase := rows(2, start.Add(-2*time.Minute), 59*time.Second)
	w = EvaluateHealthWindow(b, g.DefaultStages(20)[5], start, shortBase, current, healthLimits(), start.Add(16*time.Minute))
	if w.Status != "BLOCKED" || !hasHealthReason(w, "BASELINE_MONOTONIC_OBSERVATION_WINDOW_INCOMPLETE") {
		t.Fatal("UTC alone earned baseline coverage")
	}
}

func TestHealthV2ActualBodyReadErrorIsNotClockOrTransportError(t *testing.T) {
	b := healthBinding()
	fixture, _ := NewHTTPHealthFixture(b, func(context.Context) error { return nil }, 1, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/work" {
			w.Header().Set("Content-Length", "4096")
		}
		fixture.ServeHTTP(w, r)
	}))
	defer server.Close()
	c, _ := NewHealthCollector(HealthInstallation{ID: "actual-truncated-body", Binding: b, TargetURL: server.URL})
	r, e := c.Collect(t.Context(), 40, 1)
	if e != nil {
		t.Fatal(e)
	}
	if r.SchemaVersion != "2" || r.Clock == nil || r.MeasurementRevision != healthMeasurementV2 {
		t.Fatal("collector omitted versioned monotonic evidence")
	}
	for _, o := range r.Observations {
		if o.TransportError || !o.ReadError || o.StatusCode != 200 || !validHealthClock(o.Clock) {
			t.Fatal("actual truncated HTTP body error provenance lost")
		}
	}
	p, e := population([]HealthReceipt{r}, b, false)
	if e != nil || p.complete || p.errors != 40 {
		t.Fatal("body read failure earned complete coverage", e)
	}
}
