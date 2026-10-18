package multicloud

import (
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"
)

type MetricDefinition struct {
	Name                 string `json:"name"`
	Unit                 string `json:"unit"`
	Kind                 string `json:"kind"`
	ValueType            string `json:"value_type"`
	Statistic            string `json:"statistic"`
	NativeCadenceSeconds int64  `json:"native_cadence_seconds"`
}
type MetricsRequest struct {
	Instance        InstanceIdentity `json:"instance"`
	Period          Period           `json:"period"`
	MetricNames     []string         `json:"metric_names"`
	IntervalSeconds int64            `json:"interval_seconds"`
}
type NativeHistogram struct {
	Count        string   `json:"count"`
	Bounds       []string `json:"bounds"`
	BucketCounts []string `json:"bucket_counts"`
}
type MetricPoint struct {
	Time         time.Time        `json:"time"`
	StartTime    *time.Time       `json:"start_time"`
	Value        *string          `json:"value"`
	Histogram    *NativeHistogram `json:"histogram"`
	SourceSHA256 []string         `json:"source_sha256"`
	ReasonCodes  []string         `json:"reason_codes"`
	Native       Document         `json:"-"`
}
type MetricSeries struct {
	ID         string           `json:"id"`
	Definition MetricDefinition `json:"definition"`
	Attributes Document         `json:"attributes"`
	Points     []MetricPoint    `json:"points"`
}
type MetricsSnapshot struct {
	SchemaVersion  string           `json:"schema_version"`
	RegistrationID string           `json:"registration_id"`
	ConfigHash     string           `json:"config_hash"`
	Instance       InstanceIdentity `json:"instance"`
	ObservedAt     time.Time        `json:"observed_at"`
	Period         Period           `json:"period"`
	Status         string           `json:"status"`
	CoverageStatus string           `json:"coverage_status"`
	Objects        []Object         `json:"objects"`
	Series         []MetricSeries   `json:"series"`
	ReasonCodes    []string         `json:"reason_codes"`
	Revision       string           `json:"revision"`
}

func (s MetricsSnapshot) ExecutionReady() bool { return false }
func newMetrics(r InventoryRegistration, in MetricsRequest, now time.Time) MetricsSnapshot {
	return MetricsSnapshot{SchemaVersion: "multicloud-metrics-1", RegistrationID: r.ID, ConfigHash: Hash(r), Instance: in.Instance, ObservedAt: now, Period: in.Period, Status: "PROVISIONAL", CoverageStatus: "UNKNOWN", Objects: []Object{}, Series: []MetricSeries{}, ReasonCodes: []string{"NO_EXECUTION_AUTHORITY", "RAW_QUERY_SUCCESS_IS_NOT_OBSERVATION_COMPLETENESS", "WORKLOAD_AND_SLO_EVIDENCE_REQUIRED"}}
}
func sealMetrics(s MetricsSnapshot) MetricsSnapshot {
	s.ReasonCodes = unique(s.ReasonCodes)
	for i := range s.Series {
		sort.Slice(s.Series[i].Points, func(a, b int) bool { return s.Series[i].Points[a].Time.Before(s.Series[i].Points[b].Time) })
	}
	copy := s
	copy.ObservedAt = time.Time{}
	copy.Revision = ""
	s.Revision = Hash(copy)
	return s
}
func metricsObject(s *MetricsSnapshot, o Object) error {
	var total int64
	for _, p := range s.Objects {
		total += p.Bytes
	}
	if len(s.Objects) >= 2000 || total+o.Bytes > MaxCollectionBytes {
		return errors.New("METRICS_COLLECTION_LIMIT")
	}
	s.Objects = append(s.Objects, o)
	return nil
}
func validateMetrics(r InventoryRegistration, in MetricsRequest, now time.Time) error {
	if e := ValidateInventory(r); e != nil {
		return e
	}
	i := in.Instance
	if i.Provider != r.Provider || i.TenantID != r.TenantID || !periodValid(in.Period, now) || len(in.MetricNames) == 0 || len(in.MetricNames) > 12 {
		return errors.New("METRICS_BINDING_OR_PERIOD_INVALID")
	}
	if r.Azure != nil {
		if i.SubscriptionID != r.Azure.SubscriptionID || !azureInstancePath(r, i.ResourceID, i.Name) || !guid.MatchString(i.VMID) || !(in.IntervalSeconds == 60 || in.IntervalSeconds == 300 || in.IntervalSeconds == 3600) {
			return errors.New("AZURE_METRICS_BINDING_INVALID")
		}
	} else {
		if i.ProjectID != r.GCP.ProjectID || !contains(r.GCP.Zones, i.Zone) || !numericInstanceID(i.NumericID) || !gceName.MatchString(i.Name) || i.ResourceID != "//compute.googleapis.com/projects/"+i.ProjectID+"/zones/"+i.Zone+"/instances/"+i.Name || in.IntervalSeconds != 0 {
			return errors.New("GCP_METRICS_BINDING_INVALID")
		}
	}
	seen := map[string]bool{}
	for _, name := range in.MetricNames {
		if seen[name] {
			return errors.New("METRIC_DEFINITION_DUPLICATE")
		}
		seen[name] = true
		if _, e := NativeMetric(r.Provider, name); e != nil {
			return e
		}
	}
	return nil
}

// NativeMetric is deliberately bounded. Metric units and aggregation semantics
// are native, not normalized into invented utilization or percentile values.
func NativeMetric(provider, name string) (MetricDefinition, error) {
	d := MetricDefinition{Name: name, NativeCadenceSeconds: 60}
	if provider == "AZURE" {
		d.Kind = "GAUGE"
		d.ValueType = "DOUBLE"
		switch name {
		case "Percentage CPU":
			d.Unit = "Percent"
			d.Statistic = "INTERVAL_MAXIMUM"
		case "Available Memory Bytes":
			d.Unit = "Bytes"
			d.Statistic = "INTERVAL_AVERAGE"
		case "Disk Read Operations/Sec", "Disk Write Operations/Sec":
			d.Unit = "CountPerSecond"
			d.Statistic = "INTERVAL_AVERAGE"
		case "Network In Total", "Network Out Total", "Disk Read Bytes", "Disk Write Bytes":
			d.Unit = "Bytes"
			d.Kind = "DELTA"
			d.Statistic = "INTERVAL_TOTAL"
		default:
			return d, errors.New("NATIVE_METRIC_UNSUPPORTED")
		}
		return d, nil
	}
	if provider != "GCP" {
		return d, errors.New("NATIVE_METRIC_UNSUPPORTED")
	}
	d.Statistic = "RAW_POINT"
	d.ValueType = "INT64"
	d.Kind = "DELTA"
	switch name {
	case "compute.googleapis.com/instance/cpu/utilization":
		d.Unit = "10^2.%"
		d.Kind = "GAUGE"
		d.ValueType = "DOUBLE"
	case "compute.googleapis.com/instance/network/received_bytes_count", "compute.googleapis.com/instance/network/sent_bytes_count", "compute.googleapis.com/instance/disk/read_bytes_count", "compute.googleapis.com/instance/disk/write_bytes_count":
		d.Unit = "By"
	case "compute.googleapis.com/instance/disk/read_ops_count", "compute.googleapis.com/instance/disk/write_ops_count":
		d.Unit = "1"
	case "agent.googleapis.com/memory/bytes_used":
		d.Unit = "By"
		d.Kind = "GAUGE"
	case "agent.googleapis.com/memory/percent_used":
		d.Unit = "%"
		d.Kind = "GAUGE"
		d.ValueType = "DOUBLE"
	default:
		return d, errors.New("NATIVE_METRIC_UNSUPPORTED")
	}
	return d, nil
}
func metricAggregation(d MetricDefinition) string {
	switch d.Statistic {
	case "INTERVAL_MAXIMUM":
		return "Maximum"
	case "INTERVAL_AVERAGE":
		return "Average"
	case "INTERVAL_TOTAL":
		return "Total"
	}
	return ""
}

// WarehouseDecimal preserves raw precision in Record/MetricPoint. A future
// DECIMAL(38,12) sink must publish unavailable+gap instead of rounding it.
func WarehouseDecimal(raw *string) (*string, []string) {
	if raw == nil {
		return nil, []string{"VALUE_UNKNOWN"}
	}
	text, e := decimal(*raw)
	if e != nil {
		return nil, []string{"DECIMAL_INVALID"}
	}
	parts := strings.Split(strings.TrimPrefix(text, "-"), ".")
	integer := strings.TrimLeft(parts[0], "0")
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	if len(integer) > 26 || len(fraction) > 12 {
		return nil, []string{"WAREHOUSE_DECIMAL_PRECISION_UNSUPPORTED"}
	}
	return &text, []string{}
}

// ParseGCPDistribution supports only native explicit buckets with exact integer
// counts. Linear/exponential/summary approximations are not relabelled explicit.
func ParseGCPDistribution(native Document) (*NativeHistogram, error) {
	count := str(native, "count")
	total, ok := new(big.Int).SetString(count, 10)
	if !ok || total.Sign() < 0 || total.BitLen() > 63 {
		return nil, errors.New("NATIVE_HISTOGRAM_COUNT_INVALID")
	}
	options := obj(native["bucketOptions"])
	explicit := obj(options["explicitBuckets"])
	if len(explicit) == 0 || len(obj(options["linearBuckets"])) > 0 || len(obj(options["exponentialBuckets"])) > 0 {
		return nil, errors.New("NATIVE_HISTOGRAM_FORMAT_UNSUPPORTED")
	}
	bounds := list(explicit["bounds"])
	counts := list(native["bucketCounts"])
	if len(bounds) > 2000 || len(counts) != len(bounds)+1 {
		return nil, errors.New("NATIVE_HISTOGRAM_BUCKETS_INVALID")
	}
	out := &NativeHistogram{Count: count, Bounds: []string{}, BucketCounts: []string{}}
	var previous *big.Rat
	for _, v := range bounds {
		value, e := decimal(v)
		if e != nil {
			return nil, errors.New("NATIVE_HISTOGRAM_BOUND_INVALID")
		}
		n, _ := new(big.Rat).SetString(value)
		if previous != nil && n.Cmp(previous) <= 0 {
			return nil, errors.New("NATIVE_HISTOGRAM_BOUNDS_NOT_INCREASING")
		}
		previous = n
		out.Bounds = append(out.Bounds, value)
	}
	sum := new(big.Int)
	for _, v := range counts {
		text, ok := v.(string)
		if !ok {
			return nil, errors.New("NATIVE_HISTOGRAM_BUCKET_COUNT_INVALID")
		}
		n, ok := new(big.Int).SetString(text, 10)
		if !ok || n.Sign() < 0 || n.BitLen() > 63 || n.String() != text {
			return nil, errors.New("NATIVE_HISTOGRAM_BUCKET_COUNT_INVALID")
		}
		sum.Add(sum, n)
		out.BucketCounts = append(out.BucketCounts, text)
	}
	if sum.Cmp(total) != 0 {
		return nil, errors.New("NATIVE_HISTOGRAM_COUNT_MISMATCH")
	}
	return out, nil
}
