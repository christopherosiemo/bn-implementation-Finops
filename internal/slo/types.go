// Package slo evaluates independently collected service observations. Missing
// evidence, insufficient samples and histogram uncertainty never prove health.
package slo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const MaxCount int64 = 1_000_000_000_000

type Limits struct {
	MaxErrorRatePPM    int64 `json:"max_error_rate_ppm"`
	MinAvailabilityPPM int64 `json:"min_availability_ppm"`
	MaxP95LatencyMS    int64 `json:"max_p95_latency_ms"`
	MaxP99LatencyMS    int64 `json:"max_p99_latency_ms"`
	MinLatencySamples  int64 `json:"min_latency_samples"`
}
type Window struct {
	Days      []int  `json:"days"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}
type Availability struct {
	Mode     string   `json:"mode"`
	Timezone string   `json:"timezone"`
	Windows  []Window `json:"windows"`
}
type Regression struct {
	Enabled    bool  `json:"enabled"`
	MaxPercent int64 `json:"max_percent"`
}
type Objective struct {
	SchemaVersion     string       `json:"schema_version"`
	ID                string       `json:"id"`
	Version           int64        `json:"version"`
	WorkloadID        string       `json:"workload_id"`
	Limits            Limits       `json:"limits"`
	EvaluationMinutes int          `json:"evaluation_minutes"`
	Availability      Availability `json:"availability"`
	Regression        Regression   `json:"regression"`
}
type Source struct {
	SchemaVersion      string `json:"schema_version"`
	ID                 string `json:"id"`
	TenantID           string `json:"tenant_id"`
	ObjectiveID        string `json:"objective_id"`
	WorkloadID         string `json:"workload_id"`
	ResourceID         string `json:"resource_id"`
	ProviderResourceID string `json:"provider_resource_id"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
	Issuer             string `json:"issuer"`
	Subject            string `json:"subject"`
	Enabled            bool   `json:"enabled"`
}
type Bucket struct {
	UpperBoundMS *int64 `json:"upper_bound_ms"`
	Count        int64  `json:"count"`
}
type Histogram struct {
	Unit        string   `json:"unit"`
	Buckets     []Bucket `json:"buckets"`
	SampleCount int64    `json:"sample_count"`
}
type Interval struct {
	SchemaVersion            string    `json:"schema_version"`
	SourceID                 string    `json:"source_id"`
	ObjectiveID              string    `json:"objective_id"`
	WorkloadID               string    `json:"workload_id"`
	ResourceID               string    `json:"resource_id"`
	Sequence                 int64     `json:"sequence"`
	IntervalStart            time.Time `json:"interval_start"`
	IntervalEnd              time.Time `json:"interval_end"`
	RequestCount             int64     `json:"request_count"`
	ErrorCount               int64     `json:"error_count"`
	AvailabilityGoodSeconds  int64     `json:"availability_good_seconds"`
	AvailabilityTotalSeconds int64     `json:"availability_total_seconds"`
	Latency                  Histogram `json:"latency"`
}
type Binding struct {
	TenantID           string `json:"tenant_id"`
	WorkloadID         string `json:"workload_id"`
	ResourceID         string `json:"resource_id"`
	ProviderResourceID string `json:"provider_resource_id"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
}

func (s Source) Binding() Binding {
	return Binding{s.TenantID, s.WorkloadID, s.ResourceID, s.ProviderResourceID, s.AccountID, s.Region}
}

type Receipt struct {
	Interval
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Subject        string    `json:"subject"`
	ReceivedAt     time.Time `json:"received_at"`
	BodySHA256     string    `json:"body_sha256"`
	IdempotencyKey string    `json:"idempotency_key"`
	WriterRole     string    `json:"writer_role"`
	Binding        Binding   `json:"binding"`
}
type Check struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}
type Evaluation struct {
	ID                       string    `json:"id,omitempty"`
	EvaluationHash           string    `json:"evaluation_hash,omitempty"`
	Status                   string    `json:"status"`
	ReasonCodes              []string  `json:"reason_codes"`
	ObjectiveID              string    `json:"objective_id"`
	ObjectiveVersion         int64     `json:"objective_version"`
	ObjectiveHash            string    `json:"objective_hash"`
	SourceID                 string    `json:"source_id"`
	SourceHash               string    `json:"source_hash"`
	ResourceID               string    `json:"resource_id"`
	WorkloadID               string    `json:"workload_id"`
	WindowStart              time.Time `json:"window_start"`
	WindowEnd                time.Time `json:"window_end"`
	ReceivedAt               time.Time `json:"received_at"`
	ExpectedIntervals        int       `json:"expected_intervals"`
	ObservedIntervals        int       `json:"observed_intervals"`
	CoveragePPM              int64     `json:"coverage_ppm"`
	RequestCount             int64     `json:"request_count"`
	ErrorCount               int64     `json:"error_count"`
	AvailabilityGoodSeconds  int64     `json:"availability_good_seconds"`
	AvailabilityTotalSeconds int64     `json:"availability_total_seconds"`
	ErrorRatePPM             *int64    `json:"error_rate_ppm"`
	AvailabilityPPM          *int64    `json:"availability_ppm"`
	LatencySamples           int64     `json:"latency_samples"`
	P95LatencyMS             *int64    `json:"p95_latency_ms"`
	P99LatencyMS             *int64    `json:"p99_latency_ms"`
	P95LowerMS               *int64    `json:"p95_lower_ms"`
	P99LowerMS               *int64    `json:"p99_lower_ms"`
	LatencyStatus            string    `json:"latency_status"`
	HardChecks               []Check   `json:"hard_checks"`
	RegressionChecks         []Check   `json:"regression_checks"`
	ReceiptIDs               []string  `json:"receipt_ids"`
	BaselineEvaluationID     string    `json:"baseline_evaluation_id,omitempty"`
	BaselineEvaluationHash   string    `json:"baseline_evaluation_hash,omitempty"`
}
type Input struct {
	Now                     time.Time
	Objective               Objective
	Source                  Source
	Receipts                []Receipt
	Baseline                *Evaluation
	CaptureBaseline         bool
	StopAt, RequiredReadyAt time.Time
}

func Hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ObjectiveHash(v Objective) string   { return Hash(v) }
func SourceHash(v Source) string         { return Hash(v) }
func EvaluationHash(v Evaluation) string { v.ID = ""; v.EvaluationHash = ""; return Hash(v) }
func Document(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func ParseObjective(d model.Document) (Objective, error) {
	var o Objective
	b, e := json.Marshal(d)
	if e == nil {
		e = json.Unmarshal(b, &o)
	}
	if e == nil {
		e = ValidateObjective(o)
	}
	return o, e
}
func ParseEvaluation(d model.Document) (Evaluation, error) {
	var e Evaluation
	b, err := json.Marshal(d)
	if err == nil {
		err = json.Unmarshal(b, &e)
	}
	return e, err
}
func minute(s string) (int, error) {
	t, e := time.Parse("15:04", s)
	if e != nil || t.Format("15:04") != s {
		return 0, errors.New("SLO_AVAILABILITY_INVALID")
	}
	return t.Hour()*60 + t.Minute(), nil
}
func ValidateObjective(o Objective) error {
	l := o.Limits
	if o.SchemaVersion != "1" || o.WorkloadID == "" || o.EvaluationMinutes < 2 || o.EvaluationMinutes > 60 || l.MaxErrorRatePPM < 0 || l.MaxErrorRatePPM > 1_000_000 || l.MinAvailabilityPPM < 0 || l.MinAvailabilityPPM > 1_000_000 || l.MaxP95LatencyMS <= 0 || l.MaxP99LatencyMS < l.MaxP95LatencyMS || l.MaxP99LatencyMS > 86_400_000 || l.MinLatencySamples < 1 || l.MinLatencySamples > MaxCount || o.Regression.MaxPercent < 0 || o.Regression.MaxPercent > 1000 {
		return errors.New("SLO_OBJECTIVE_INVALID")
	}
	if _, e := time.LoadLocation(o.Availability.Timezone); e != nil {
		return errors.New("SLO_AVAILABILITY_INVALID")
	}
	if o.Availability.Mode == "ALWAYS" {
		if len(o.Availability.Windows) != 0 {
			return errors.New("SLO_AVAILABILITY_INVALID")
		}
		return nil
	}
	if o.Availability.Mode != "WINDOWS" || len(o.Availability.Windows) == 0 || len(o.Availability.Windows) > 32 {
		return errors.New("SLO_AVAILABILITY_INVALID")
	}
	for _, w := range o.Availability.Windows {
		a, e := minute(w.StartTime)
		b, e2 := minute(w.EndTime)
		if e != nil || e2 != nil || a >= b || len(w.Days) == 0 || len(w.Days) > 7 {
			return errors.New("SLO_AVAILABILITY_INVALID")
		}
		seen := map[int]bool{}
		for _, d := range w.Days {
			if d < 0 || d > 6 || seen[d] {
				return errors.New("SLO_AVAILABILITY_INVALID")
			}
			seen[d] = true
		}
	}
	return nil
}
func open(o Objective, at time.Time) bool {
	if o.Availability.Mode == "ALWAYS" {
		return true
	}
	loc, e := time.LoadLocation(o.Availability.Timezone)
	if e != nil {
		return true
	}
	t := at.In(loc)
	m := t.Hour()*60 + t.Minute()
	for _, w := range o.Availability.Windows {
		a, _ := minute(w.StartTime)
		b, _ := minute(w.EndTime)
		for _, d := range w.Days {
			if d == int(t.Weekday()) && m >= a && m < b {
				return true
			}
		}
	}
	return false
}
func closed(o Objective, start, end time.Time) bool {
	if !end.After(start) || end.Sub(start) > 7*24*time.Hour {
		return false
	}
	for t := start.Truncate(time.Minute); t.Before(end); t = t.Add(time.Minute) {
		if open(o, t) {
			return false
		}
	}
	return true
}
func StopAllowed(o Objective, start, end time.Time) []string {
	if ValidateObjective(o) != nil || !closed(o, start, end) {
		return []string{"SLO_AVAILABILITY_WINDOW_CONFLICT"}
	}
	return []string{}
}
func ValidateInterval(i Interval) error {
	if i.SchemaVersion != "1" || i.SourceID == "" || i.ObjectiveID == "" || i.WorkloadID == "" || i.ResourceID == "" || i.Sequence < 1 || i.IntervalEnd.Sub(i.IntervalStart) != time.Minute || i.IntervalStart.Second() != 0 || i.IntervalStart.Nanosecond() != 0 {
		return errors.New("SLO_INTERVAL_INVALID")
	}
	_, a := i.IntervalStart.Zone()
	_, b := i.IntervalEnd.Zone()
	if a != 0 || b != 0 {
		return errors.New("SLO_INTERVAL_INVALID")
	}
	if i.RequestCount < 0 || i.RequestCount > MaxCount || i.ErrorCount < 0 || i.ErrorCount > i.RequestCount || i.AvailabilityTotalSeconds != 60 || i.AvailabilityGoodSeconds < 0 || i.AvailabilityGoodSeconds > 60 || i.Latency.Unit != "milliseconds" || i.Latency.SampleCount != i.RequestCount || len(i.Latency.Buckets) == 0 || len(i.Latency.Buckets) > 256 {
		return errors.New("SLO_OBSERVATION_INVALID")
	}
	var total int64
	previous := int64(-1)
	for n, b := range i.Latency.Buckets {
		if b.Count < 0 || b.Count > MaxCount-total {
			return errors.New("SLO_HISTOGRAM_INVALID")
		}
		total += b.Count
		if b.UpperBoundMS == nil {
			if n != len(i.Latency.Buckets)-1 {
				return errors.New("SLO_HISTOGRAM_INVALID")
			}
		} else {
			if n == len(i.Latency.Buckets)-1 || *b.UpperBoundMS <= previous || *b.UpperBoundMS > 86_400_000 {
				return errors.New("SLO_HISTOGRAM_INVALID")
			}
			previous = *b.UpperBoundMS
		}
	}
	if total != i.Latency.SampleCount {
		return errors.New("SLO_HISTOGRAM_INVALID")
	}
	return nil
}
func DecodeInterval(raw []byte) (Interval, error) {
	var in Interval
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return in, e
	}
	for _, k := range []string{"schema_version", "source_id", "objective_id", "workload_id", "resource_id", "sequence", "interval_start", "interval_end", "request_count", "error_count", "availability_good_seconds", "availability_total_seconds", "latency"} {
		if v, ok := fields[k]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return in, errors.New("SLO_FIELDS_REQUIRED")
		}
	}
	var h map[string]json.RawMessage
	if e := json.Unmarshal(fields["latency"], &h); e != nil {
		return in, e
	}
	for _, k := range []string{"unit", "buckets", "sample_count"} {
		if v, ok := h[k]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return in, errors.New("SLO_FIELDS_REQUIRED")
		}
	}
	var buckets []map[string]json.RawMessage
	if e := json.Unmarshal(h["buckets"], &buckets); e != nil {
		return in, e
	}
	for _, b := range buckets {
		if _, ok := b["upper_bound_ms"]; !ok {
			return in, errors.New("SLO_FIELDS_REQUIRED")
		}
		if v, ok := b["count"]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return in, errors.New("SLO_FIELDS_REQUIRED")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&in); e != nil {
		return in, e
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return in, errors.New("SLO_ONE_OBJECT_REQUIRED")
	}
	return in, ValidateInterval(in)
}
func SortedReasons(m map[string]bool) []string {
	out := []string{}
	for r := range m {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
