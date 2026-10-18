// Package telemetry preserves native observations and their actual time bounds.
// It does not relabel sampled or cumulative data as exact UTC minute receipts.
package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const MaxSamples = 250000
const MaxBodyBytes = 32 << 20

type Binding struct {
	TenantID           string `json:"tenant_id"`
	ResourceID         string `json:"resource_id"`
	WorkloadID         string `json:"workload_id"`
	Provider           string `json:"provider"`
	ProviderResourceID string `json:"provider_resource_id"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
}
type Definition struct {
	ID                 string            `json:"id"`
	Version            string            `json:"version"`
	Metric             string            `json:"metric"`
	Name               string            `json:"name"`
	Unit               string            `json:"unit"`
	Type               string            `json:"type"`
	Monotonic          bool              `json:"monotonic"`
	CadenceSeconds     int               `json:"cadence_seconds"`
	MaxGapSeconds      int               `json:"max_gap_seconds"`
	Attributes         map[string]string `json:"attributes"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
	EpochMetric        string            `json:"epoch_metric,omitempty"`
	EpochAttributes    map[string]string `json:"epoch_attributes,omitempty"`
}
type Connection struct {
	SchemaVersion string       `json:"schema_version"`
	ID            string       `json:"id"`
	Version       int64        `json:"version"`
	Kind          string       `json:"kind"`
	ReadBindingID string       `json:"read_binding_id,omitempty"`
	Issuer        string       `json:"issuer,omitempty"`
	Subject       string       `json:"subject,omitempty"`
	Binding       Binding      `json:"binding"`
	Enabled       bool         `json:"enabled"`
	Definitions   []Definition `json:"definitions"`
}
type Histogram struct {
	Count        uint64   `json:"count"`
	Bounds       []string `json:"bounds"`
	BucketCounts []uint64 `json:"bucket_counts"`
}
type Sample struct {
	ID                 string            `json:"id"`
	DefinitionID       string            `json:"definition_id"`
	StreamID           string            `json:"stream_id"`
	Metric             string            `json:"metric"`
	Type               string            `json:"type"`
	Unit               string            `json:"unit"`
	Statistic          string            `json:"statistic"`
	Temporality        string            `json:"temporality"`
	StartTime          time.Time         `json:"start_time"`
	Time               time.Time         `json:"time"`
	Epoch              string            `json:"epoch"`
	Attributes         map[string]string `json:"attributes"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
	ScopeAttributes    map[string]string `json:"scope_attributes"`
	OriginalAttributes model.Document    `json:"original_attributes,omitempty"`
	Value              string            `json:"value,omitempty"`
	Histogram          *Histogram        `json:"histogram,omitempty"`
	RawSHA256          string            `json:"raw_sha256"`
	SourceHashes       []string          `json:"source_hashes,omitempty"`
	ReasonCodes        []string          `json:"reason_codes"`
}
type Rejection struct {
	DefinitionID string `json:"definition_id,omitempty"`
	Metric       string `json:"metric,omitempty"`
	Count        int    `json:"count"`
	ReasonCode   string `json:"reason_code"`
}
type Batch struct {
	SchemaVersion string      `json:"schema_version"`
	ConnectionID  string      `json:"connection_id"`
	ConfigHash    string      `json:"config_hash"`
	Binding       Binding     `json:"binding"`
	SourceKind    string      `json:"source_kind"`
	RawSHA256     string      `json:"raw_sha256"`
	CollectedAt   time.Time   `json:"collected_at"`
	Start         time.Time   `json:"start"`
	End           time.Time   `json:"end"`
	Samples       []Sample    `json:"samples"`
	Rejections    []Rejection `json:"rejections"`
	Warnings      []string    `json:"warnings"`
	Raw           []byte      `json:"-"`
}
type Segment struct {
	ID           string     `json:"id"`
	DefinitionID string     `json:"definition_id"`
	StreamID     string     `json:"stream_id"`
	Metric       string     `json:"metric"`
	Type         string     `json:"type"`
	Unit         string     `json:"unit"`
	Statistic    string     `json:"statistic"`
	Start        time.Time  `json:"start"`
	End          time.Time  `json:"end"`
	Status       string     `json:"status"`
	ReasonCodes  []string   `json:"reason_codes"`
	Value        string     `json:"value,omitempty"`
	Histogram    *Histogram `json:"histogram,omitempty"`
	SampleIDs    []string   `json:"sample_ids"`
	RawHashes    []string   `json:"raw_hashes"`
}
type MetricResult struct {
	Start               time.Time  `json:"start"`
	End                 time.Time  `json:"end"`
	DefinitionID        string     `json:"definition_id"`
	Metric              string     `json:"metric"`
	Unit                string     `json:"unit"`
	Status              string     `json:"status"`
	ReasonCodes         []string   `json:"reason_codes"`
	ObservedSamples     int        `json:"observed_samples"`
	ExpectedSamples     int64      `json:"expected_samples"`
	CoveragePPM         int64      `json:"coverage_ppm"`
	ObservedDurationNS  int64      `json:"observed_duration_ns"`
	UnknownDurationNS   int64      `json:"unknown_duration_ns"`
	P50                 *string    `json:"p50"`
	P90                 *string    `json:"p90"`
	P95                 *string    `json:"p95"`
	P99                 *string    `json:"p99"`
	P999                *string    `json:"p999"`
	Maximum             *string    `json:"maximum"`
	Total               *string    `json:"total"`
	Histogram           *Histogram `json:"histogram,omitempty"`
	SegmentIDs          []string   `json:"segment_ids"`
	SegmentCount        int        `json:"segment_count"`
	SegmentHash         string     `json:"segment_hash"`
	SegmentIDsTruncated bool       `json:"segment_ids_truncated"`
	Statistic           string     `json:"statistic"`
}
type Evaluation struct {
	SchemaVersion string         `json:"schema_version"`
	Status        string         `json:"status"`
	ReasonCodes   []string       `json:"reason_codes"`
	Start         time.Time      `json:"start"`
	End           time.Time      `json:"end"`
	EvaluatedAt   time.Time      `json:"evaluated_at"`
	Metrics       []MetricResult `json:"metrics"`
	Hash          string         `json:"hash"`
	HistoryDays   int            `json:"history_days,omitempty"`
	Timezone      string         `json:"timezone,omitempty"`
}
type WindowInput struct {
	Now             time.Time
	Definitions     []Definition
	Segments        []Segment
	Minutes         int
	RequiredMetrics []string
}
type HistoryInput struct {
	Now             time.Time
	Definitions     []Definition
	Samples         []Sample
	Days            int
	Timezone        string
	RequiredMetrics []string
}

func Hash(v any) string              { b, _ := json.Marshal(v); return BytesHash(b) }
func BytesHash(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ConfigHash(c Connection) string { return Hash(c) }

// CanonicalHash excludes transport/receipt time so an exact body replay remains
// the same publication. RawSHA256 separately binds the original wire bytes.
func CanonicalHash(b Batch) string {
	return Hash(model.Document{"schema_version": b.SchemaVersion, "connection_id": b.ConnectionID, "config_hash": b.ConfigHash, "binding": b.Binding, "source_kind": b.SourceKind, "start": b.Start, "end": b.End, "samples": b.Samples, "rejections": b.Rejections, "warnings": b.Warnings})
}
func Document(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func ParseConnection(d model.Document) (Connection, error) {
	var c Connection
	b, e := json.Marshal(d)
	if e == nil {
		e = json.Unmarshal(b, &c)
	}
	if e == nil {
		e = ValidateConnection(c)
	}
	return c, e
}

var namePattern = regexp.MustCompile(`^[A-Za-z_:][A-Za-z0-9_:]*$`)
var labelPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var ec2ID = regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var accountID = regexp.MustCompile(`^[0-9]{12}$`)
var decimalPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

func number(s string) (*big.Rat, bool) {
	if len(s) > 128 || !decimalPattern.MatchString(s) {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Num().BitLen() > 512 || r.Denom().BitLen() > 512 {
		return nil, false
	}
	return r, true
}
func ValidateConnection(c Connection) error {
	b := c.Binding
	if c.SchemaVersion != "1" || c.ID == "" || c.Version < 1 || b.TenantID == "" || b.ResourceID == "" || b.WorkloadID == "" || b.Provider != "AWS" || !ec2ID.MatchString(b.ProviderResourceID) || !accountID.MatchString(b.AccountID) || b.Region != "eu-west-1" || len(c.Definitions) < 1 || len(c.Definitions) > 32 {
		return errors.New("TELEMETRY_BINDING_INVALID")
	}
	if c.Kind == "PROMETHEUS" {
		if c.ReadBindingID == "" {
			return errors.New("TELEMETRY_READ_BINDING_REQUIRED")
		}
	} else if c.Kind == "OTLP" {
		if c.Issuer == "" || c.Subject == "" {
			return errors.New("TELEMETRY_MACHINE_BINDING_REQUIRED")
		}
	} else {
		return errors.New("TELEMETRY_PROTOCOL_UNSUPPORTED")
	}
	seen := map[string]bool{}
	metrics := map[string]bool{}
	for _, d := range c.Definitions {
		if d.ID == "" || d.Version == "" || d.Metric == "" || d.Name == "" || d.Unit == "" || seen[d.ID] || metrics[d.Metric] || d.CadenceSeconds < 1 || d.CadenceSeconds > 300 || d.MaxGapSeconds < d.CadenceSeconds || d.MaxGapSeconds > 600 || len(d.Attributes) > 32 || len(d.ResourceAttributes) > 32 || len(d.EpochAttributes) > 32 {
			return errors.New("TELEMETRY_DEFINITION_INVALID")
		}
		seen[d.ID], metrics[d.Metric] = true, true
		if len(d.ID) > 256 || len(d.Version) > 256 || len(d.Metric) > 256 || len(d.Name) > 256 || len(d.Unit) > 128 {
			return errors.New("TELEMETRY_DEFINITION_INVALID")
		}
		for _, attrs := range []map[string]string{d.Attributes, d.ResourceAttributes, d.EpochAttributes} {
			for k, v := range attrs {
				if k == "" || len(k) > 256 || len(v) > 1024 {
					return errors.New("TELEMETRY_ATTRIBUTE_INVALID")
				}
			}
		}
		if d.Type != "GAUGE" && d.Type != "SUM" && d.Type != "HISTOGRAM" {
			return errors.New("TELEMETRY_TYPE_UNSUPPORTED")
		}
		if d.Type == "SUM" && !d.Monotonic {
			return errors.New("TELEMETRY_NON_MONOTONIC_SUM_UNSUPPORTED")
		}
		if c.Kind == "PROMETHEUS" {
			if !namePattern.MatchString(d.Name) || d.EpochMetric != "" && !namePattern.MatchString(d.EpochMetric) {
				return errors.New("TELEMETRY_SELECTOR_INVALID")
			}
			for k := range mergeLabels(d.Attributes, d.EpochAttributes) {
				if !labelPattern.MatchString(k) || k == "__name__" || k == "le" {
					return errors.New("TELEMETRY_SELECTOR_INVALID")
				}
			}
			if d.Type != "GAUGE" && d.EpochMetric == "" {
				return errors.New("TELEMETRY_EPOCH_METRIC_REQUIRED")
			}
		}
	}
	return nil
}
func validHistogram(h *Histogram) bool {
	if h == nil || len(h.Bounds) > 256 || len(h.BucketCounts) != len(h.Bounds)+1 {
		return false
	}
	var last *big.Rat
	var total uint64
	for _, s := range h.Bounds {
		r, ok := number(s)
		if !ok || r.Sign() < 0 || last != nil && r.Cmp(last) <= 0 {
			return false
		}
		last = r
	}
	for _, n := range h.BucketCounts {
		if ^uint64(0)-total < n {
			return false
		}
		total += n
	}
	return total == h.Count
}
func sampleID(s Sample) string { s.ID = ""; s.RawSHA256 = ""; s.SourceHashes = nil; return Hash(s) }
func streamID(d Definition, a, r, scope map[string]string, original model.Document) string {
	return Hash(model.Document{"definition_id": d.ID, "definition_version": d.Version, "attributes": a, "resource_attributes": r, "scope": scope, "original_attributes": original})
}
func reasons(m map[string]bool) []string {
	a := []string{}
	for s := range m {
		a = append(a, s)
	}
	sort.Strings(a)
	return a
}
func unique(a []string) []string {
	m := map[string]bool{}
	for _, s := range a {
		if s != "" {
			m[s] = true
		}
	}
	return reasons(m)
}
func newBatch(c Connection, raw []byte, at time.Time) Batch {
	return Batch{SchemaVersion: "1", ConnectionID: c.ID, ConfigHash: ConfigHash(c), Binding: c.Binding, SourceKind: c.Kind, RawSHA256: BytesHash(raw), CollectedAt: at.UTC(), Samples: []Sample{}, Rejections: []Rejection{}, Warnings: []string{}, Raw: append([]byte{}, raw...)}
}
func reject(b *Batch, d Definition, n int, reason string) {
	b.Rejections = append(b.Rejections, Rejection{d.ID, d.Metric, n, reason})
}
func finish(b *Batch) {
	sort.Slice(b.Samples, func(i, j int) bool {
		a, c := b.Samples[i], b.Samples[j]
		if a.StreamID != c.StreamID {
			return a.StreamID < c.StreamID
		}
		return a.Time.Before(c.Time)
	})
	seen := map[string]string{}
	out := []Sample{}
	for _, s := range b.Samples {
		s.RawSHA256 = b.RawSHA256
		s.SourceHashes = []string{b.RawSHA256}
		s.ID = sampleID(s)
		key := s.StreamID + "/" + s.Time.UTC().Format(time.RFC3339Nano)
		if id, ok := seen[key]; ok {
			if id != s.ID {
				b.Rejections = append(b.Rejections, Rejection{s.DefinitionID, s.Metric, 1, "TELEMETRY_SAMPLE_CONFLICT"})
			}
			continue
		}
		seen[key] = s.ID
		out = append(out, s)
		if b.Start.IsZero() || s.Time.Before(b.Start) {
			b.Start = s.Time
		}
		if s.Time.After(b.End) {
			b.End = s.Time
		}
	}
	b.Samples = out
}
