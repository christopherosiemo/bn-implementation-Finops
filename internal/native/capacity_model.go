package native

import (
	"encoding/json"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

type CapacityModelRef struct {
	ID        string            `json:"id"`
	Version   string            `json:"version"`
	ReceiptID string            `json:"receipt_id"`
	SHA256    string            `json:"sha256"`
	Binding   telemetry.Binding `json:"binding"`
}
type PhysicalCapacity struct {
	CPU               *string `json:"cpu"`
	Memory            *string `json:"memory"`
	Network           *string `json:"network"`
	StorageIOPS       *string `json:"storage_iops"`
	StorageThroughput *string `json:"storage_throughput"`
}
type CapacityModelCatalog struct {
	ID                   string           `json:"id"`
	Count                int              `json:"count"`
	Capacity             PhysicalCapacity `json:"capacity"`
	Architecture         string           `json:"architecture"`
	CPUModel             string           `json:"cpu_model"`
	OperatingSystem      string           `json:"operating_system"`
	Licensing            string           `json:"licensing"`
	Region               string           `json:"region"`
	Zones                []string         `json:"zones"`
	Accelerator          string           `json:"accelerator"`
	LocalStorage         bool             `json:"local_storage"`
	DiskTypes            []string         `json:"disk_types"`
	CommitmentCompatible *bool            `json:"commitment_compatible"`
	SourceRef            CapacityModelRef `json:"source_ref"`
	Pricing              any              `json:"pricing"`
}
type CapacityModelPoint struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Value *string   `json:"value"`
}
type CapacityModelMetric struct {
	Name         string               `json:"name"`
	Unit         string               `json:"unit"`
	Statistic    string               `json:"statistic"`
	SemanticRole string               `json:"semantic_role,omitempty"`
	SourceMetric string               `json:"source_metric,omitempty"`
	SourceUnit   string               `json:"source_unit,omitempty"`
	Denominator  *string              `json:"denominator,omitempty"`
	SourceRefs   []CapacityModelRef   `json:"source_refs"`
	Points       []CapacityModelPoint `json:"points"`
}
type CapacityModelEvent struct {
	ID         string           `json:"id"`
	Start      time.Time        `json:"start"`
	End        time.Time        `json:"end"`
	Multiplier string           `json:"multiplier"`
	SourceRef  CapacityModelRef `json:"source_ref"`
}
type CapacityModelHistory struct {
	Start           time.Time `json:"start"`
	End             time.Time `json:"end"`
	Timezone        string    `json:"timezone"`
	Environment     string    `json:"environment"`
	HighSeasonality bool      `json:"high_seasonality"`
	CadenceSeconds  int       `json:"cadence_seconds"`
}
type CapacityModelRequest struct {
	SchemaVersion      string                 `json:"schema_version"`
	ModelVersion       string                 `json:"model_version,omitempty"`
	Binding            telemetry.Binding      `json:"binding"`
	AsOf               time.Time              `json:"as_of"`
	History            CapacityModelHistory   `json:"history"`
	Metrics            []CapacityModelMetric  `json:"metrics"`
	Current            CapacityModelCatalog   `json:"current"`
	Candidates         []CapacityModelCatalog `json:"candidates"`
	Policy             map[string]int64       `json:"policy"`
	Events             []CapacityModelEvent   `json:"events"`
	ForecastHorizons   []string               `json:"forecast_horizons"`
	PricingPeriodHours string                 `json:"pricing_period_hours"`
}
type CapacityMapping struct {
	Request          *CapacityModelRequest  `json:"-"`
	Current          CapacityModelCatalog   `json:"current"`
	Candidates       []CapacityModelCatalog `json:"candidates"`
	ReasonCodes      []string               `json:"reason_codes"`
	CandidateReasons map[string][]string    `json:"candidate_reasons"`
	Assumptions      []string               `json:"assumptions"`
}

var capacityNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]{1,12})?$`)

const CapacityProxyModelVersion = "capacity-weekday-block-v2"
const CapacityRequestProxyRole = "REQUEST_THROUGHPUT_PROXY"

var capacitySHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

func capacityRat(s string) *big.Rat {
	if len(s) > 64 || !capacityNumber.MatchString(s) {
		return nil
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil
	}
	return r
}
func capacityText(r *big.Rat, ceil bool) string {
	scale := big.NewInt(1_000_000_000_000)
	n := new(big.Int).Mul(r.Num(), scale)
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(n, r.Denom(), rem)
	if ceil && rem.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	whole, fraction := new(big.Int), new(big.Int)
	whole.QuoRem(q, scale, fraction)
	s := fraction.String()
	return whole.String() + "." + strings.Repeat("0", 12-len(s)) + s
}
func capacityValue(r *big.Rat) *string {
	if r == nil || r.Sign() <= 0 {
		return nil
	}
	s := capacityText(r, false)
	return &s
}
func physicalMap(p PhysicalCapacity) map[string]*string {
	return map[string]*string{"cpu": p.CPU, "memory": p.Memory, "network": p.Network, "storage_iops": p.StorageIOPS, "storage_throughput": p.StorageThroughput}
}
func hasHardware(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func hardwareCatalog(e provider.HardwareEvidence, typ provider.HardwareType, current bool, ref CapacityModelRef) (CapacityModelCatalog, []string) {
	i := e.Instance
	reasons := []string{}
	c := CapacityModelCatalog{ID: typ.Name, Count: 1, Architecture: i.Architecture, OperatingSystem: i.PlatformDetails, Licensing: i.UsageOperation, Region: e.Region, Zones: []string{}, Accelerator: "NONE", DiskTypes: []string{}, SourceRef: ref, Pricing: nil, CommitmentCompatible: nil}
	if typ.Manufacturer != "" {
		c.CPUModel = "AWS_INSTANCE_FAMILY:" + strings.Split(typ.Name, ".")[0] + ":" + typ.Manufacturer
	}
	for _, o := range e.Offerings {
		if o.Type == typ.Name && o.Location == i.Placement.Zone && o.LocationType == "availability-zone" {
			c.Zones = []string{i.Placement.Zone}
		}
	}
	if len(c.Zones) != 1 {
		reasons = append(reasons, "CAPACITY_AZ_OFFERING_UNOBSERVED")
	}
	if c.CPUModel == "" || !hasHardware(typ.Architectures, i.Architecture) || i.Architecture == "" || i.PlatformDetails != "Linux/UNIX" || i.UsageOperation != "RunInstances" || i.Placement.Tenancy != "default" || i.RootDevice != "ebs" || i.Virtualization != "hvm" || !hasHardware(typ.RootDevices, "ebs") || !hasHardware(typ.Virtualizations, "hvm") || !hasHardware(typ.UsageClasses, "on-demand") || e.Image.ID != i.ImageID || e.Image.State != "available" || e.Image.Architecture != i.Architecture || e.Image.Virtualization != i.Virtualization || e.Image.RootDevice != "ebs" {
		reasons = append(reasons, "CAPACITY_NATIVE_COMPATIBILITY_UNPROVEN")
	}
	if i.ENA == nil || !*i.ENA || e.Image.ENASupport == nil || !*e.Image.ENASupport || typ.ENASupport != "required" && typ.ENASupport != "supported" {
		reasons = append(reasons, "CAPACITY_ENA_COMPATIBILITY_UNPROVEN")
	}
	if typ.StorageSupported == nil || *typ.StorageSupported || typ.Burstable == nil || *typ.Burstable || typ.BareMetal == nil || *typ.BareMetal || len(typ.GPUs) > 0 || len(typ.FPGAs) > 0 || len(typ.Inference) > 0 || typ.Hypervisor != "nitro" {
		reasons = append(reasons, "CAPACITY_SPECIAL_HARDWARE_UNSUPPORTED")
	}
	if typ.VCPU.Default != nil && *typ.VCPU.Default > 0 {
		c.Capacity.CPU = capacityValue(new(big.Rat).SetInt64(int64(*typ.VCPU.Default)))
	}
	if current {
		c.Capacity.CPU = nil
		if i.CPU.Cores != nil && i.CPU.Threads != nil && *i.CPU.Cores > 0 && *i.CPU.Threads > 0 && *i.CPU.Cores <= 4096 && *i.CPU.Threads <= 8 && typ.VCPU.Default != nil && *i.CPU.Cores**i.CPU.Threads <= *typ.VCPU.Default {
			c.Capacity.CPU = capacityValue(new(big.Rat).SetInt64(int64(*i.CPU.Cores * *i.CPU.Threads)))
		}
	}
	if typ.Memory.MiB != nil && *typ.Memory.MiB > 0 && *typ.Memory.MiB <= 1<<40 {
		c.Capacity.Memory = capacityValue(new(big.Rat).SetInt(new(big.Int).Mul(big.NewInt(*typ.Memory.MiB), big.NewInt(1048576))))
	}
	// A peak/burst limit and free-form "Up to" text are never denominators.
	if len(typ.NetworkCards) == 1 && typ.NetworkCards[0].Index != nil && *typ.NetworkCards[0].Index == 0 {
		if r := capacityRat(typ.NetworkCards[0].Baseline); r != nil {
			c.Capacity.Network = capacityValue(new(big.Rat).Mul(r, big.NewRat(1_000_000_000, 8)))
		}
	}
	// Initial physical mapper supports one pinned gp3 EBS volume only. Multiple
	// device contention/striping is unknown, rather than an optimistic sum.
	if len(e.Volumes) == 1 && len(i.Devices) == 1 && e.Volumes[0].ID == i.Devices[0].VolumeID && e.Volumes[0].Type == "gp3" && i.EBSOptimized != nil && *i.EBSOptimized {
		v := e.Volumes[0]
		c.DiskTypes = []string{v.Type}
		if typ.EBS.BaselineIOPS != nil && *typ.EBS.BaselineIOPS > 0 && v.IOPS != nil && *v.IOPS > 0 {
			n := *typ.EBS.BaselineIOPS
			if *v.IOPS < n {
				n = *v.IOPS
			}
			c.Capacity.StorageIOPS = capacityValue(new(big.Rat).SetInt64(n))
		}
		if r := capacityRat(typ.EBS.BaselineMBps); r != nil && v.ThroughputMiBps != nil && *v.ThroughputMiBps > 0 {
			instance := new(big.Rat).Mul(r, big.NewRat(1_000_000, 1))
			volume := new(big.Rat).SetInt(new(big.Int).Mul(big.NewInt(*v.ThroughputMiBps), big.NewInt(1048576)))
			if volume.Cmp(instance) < 0 {
				instance = volume
			}
			c.Capacity.StorageThroughput = capacityValue(instance)
		}
	}
	for name, value := range physicalMap(c.Capacity) {
		if value == nil {
			reasons = append(reasons, "CAPACITY_"+strings.ToUpper(name)+"_DENOMINATOR_UNAVAILABLE")
		}
	}
	return c, sortedUnique(reasons)
}

// BuildCapacityModelInput maps only server-selected immutable populations and
// ingester hardware receipts. It accepts no monetary catalogue. Companion
// denominators must be observed throughout history; today's type cannot silently
// reinterpret old utilization ratios from another physical configuration.
func BuildCapacityModelInput(p CapacityPopulation, profile workload.Profile, receipt model.Document) (CapacityMapping, error) {
	return buildCapacityModelInput(p, profile, receipt, false)
}

// BuildCurrentCapacityModelInput evaluates only the observed configuration.
// It is not a candidate change or deployment simulation. In particular both
// catalog sides retain the actual observed CPU options, never type defaults.
func BuildCurrentCapacityModelInput(p CapacityPopulation, profile workload.Profile, receipt model.Document) (CapacityMapping, error) {
	return buildCapacityModelInput(p, profile, receipt, true)
}

func buildCapacityModelInput(p CapacityPopulation, profile workload.Profile, receipt model.Document, currentBaseline bool) (CapacityMapping, error) {
	m := CapacityMapping{Candidates: []CapacityModelCatalog{}, ReasonCodes: []string{}, CandidateReasons: map[string][]string{}, Assumptions: []string{"Per-resource analysis; candidate default CPU options are hypothetical, not deployment proof.", "CPU and memory utilization use source-observed constant denominator gauges cross-checked with native hardware.", "Network directions and disk read/write deltas are conservatively combined over identical actual intervals.", "AWS network Gbps and EBS MB/s use decimal units; volume throughput MiB/s uses binary units.", "Candidate pricing and commitment compatibility remain unknown; no execution authority or verified savings."}}
	block := func(code string) { m.ReasonCodes = append(m.ReasonCodes, code) }
	var e provider.HardwareEvidence
	raw, _ := json.Marshal(receipt["native"])
	if json.Unmarshal(raw, &e) != nil || e.Provider != "AWS" || e.Region != p.Binding.Region || e.AccountID != p.Binding.AccountID || e.Instance.ID != p.Binding.ProviderResourceID || !capacitySHA.MatchString(e.RawSHA256) || model.String(receipt, "id") == "" || model.String(receipt, "kind") != "AWS_EC2_HARDWARE" || model.String(receipt, "writer_role") != "finops_ingester" {
		block("CAPACITY_NATIVE_HARDWARE_PROVENANCE_REQUIRED")
		return m, nil
	}
	ref := CapacityModelRef{ID: model.String(receipt, "id"), Version: strconv.FormatInt(model.Number(receipt, "registration_version"), 10), ReceiptID: model.String(receipt, "id"), SHA256: e.RawSHA256, Binding: p.Binding}
	types := map[string]provider.HardwareType{}
	for _, typ := range e.Types {
		if _, exists := types[typ.Name]; exists {
			block("CAPACITY_NATIVE_CATALOG_CONFLICT")
		}
		types[typ.Name] = typ
	}
	current, ok := types[e.Instance.Type]
	if !ok {
		block("CAPACITY_CURRENT_HARDWARE_UNAVAILABLE")
		return m, nil
	}
	var reasons []string
	m.Current, reasons = hardwareCatalog(e, current, true, ref)
	m.ReasonCodes = append(m.ReasonCodes, reasons...)
	selected := model.Strings(receipt, "candidate_types")
	if currentBaseline {
		if len(selected) != 1 || selected[0] != e.Instance.Type {
			block("CAPACITY_CURRENT_BASELINE_EXACT_TYPE_REQUIRED")
		} else {
			m.Candidates = append(m.Candidates, m.Current)
			m.Assumptions[0] = "Read-only current configuration baseline; both catalogs use identical observed capacities and CPU options. No candidate change or deployment is authorized."
		}
	}
	for _, name := range model.Strings(receipt, "candidate_types") {
		if currentBaseline {
			continue
		}
		if name == e.Instance.Type {
			continue
		}
		typ, ok := types[name]
		if !ok {
			m.CandidateReasons[name] = []string{"CAPACITY_CANDIDATE_HARDWARE_UNAVAILABLE"}
			continue
		}
		c, why := hardwareCatalog(e, typ, false, ref)
		if strings.Split(name, ".")[0] != strings.Split(e.Instance.Type, ".")[0] {
			why = append(why, "CAPACITY_CPU_FAMILY_MIGRATION_UNPROVEN")
		}
		if len(why) > 0 {
			m.CandidateReasons[name] = sortedUnique(why)
		}
		m.Candidates = append(m.Candidates, c)
	}
	if len(m.Candidates) == 0 {
		block("CAPACITY_CANDIDATE_CATALOG_REQUIRED")
	}
	if len(m.CandidateReasons) > 0 {
		block("CAPACITY_CANDIDATE_COMPATIBILITY_UNPROVEN")
	}
	if workload.Validate(profile) != nil || profile.ID != p.SafetyProfileID || profile.Version != p.SafetyProfileVersion || profile.WorkloadID != p.Binding.WorkloadID || profile.Timezone != p.Timezone || p.PopulationHash != CapacityPopulationHash(p) || p.Environment != "NON_PRODUCTION" && p.Environment != "PRODUCTION" {
		block("CAPACITY_PROFILE_OR_POPULATION_BINDING_INVALID")
	}
	for _, reason := range p.ReasonCodes {
		block(reason)
	}
	if p.Evaluation.Status != "READY" {
		block("CAPACITY_NATIVE_HISTORY_NOT_READY")
		for _, reason := range p.Evaluation.ReasonCodes {
			block(reason)
		}
	}
	if p.Environment == "PRODUCTION" && profile.Criticality == "NON_PRODUCTION" {
		block("CAPACITY_ENVIRONMENT_CLASSIFICATION_CONFLICT")
	}
	if len(m.ReasonCodes) > 0 {
		m.ReasonCodes = sortedUnique(m.ReasonCodes)
		return m, nil
	}
	refs := []CapacityModelRef{}
	rawHashes := map[string]bool{}
	for _, r := range p.SourceRefs {
		if r.ReceiptID == "" || r.BatchID == "" || r.ConfigHash != p.ConfigHash || !capacitySHA.MatchString(r.RawSHA256) || !capacitySHA.MatchString(r.CanonicalHash) {
			block("CAPACITY_NATIVE_TELEMETRY_PROVENANCE_REQUIRED")
			continue
		}
		refs = append(refs, CapacityModelRef{ID: r.BatchID, Version: r.ConfigHash, ReceiptID: r.ReceiptID, SHA256: r.CanonicalHash, Binding: p.Binding})
		rawHashes[r.RawSHA256] = true
	}
	if len(refs) == 0 {
		block("CAPACITY_NATIVE_TELEMETRY_PROVENANCE_REQUIRED")
	}
	names := []string{"cpu_utilization", "memory_utilization", "cpu_capacity", "memory_capacity", "network_in", "network_out", "disk_read_operations", "disk_write_operations", "disk_read_bytes", "disk_write_bytes", "request_count"}
	defs := map[string]telemetry.Definition{}
	cadence := 0
	for _, d := range p.Definitions {
		if !hasHardware(names, d.Metric) {
			continue
		}
		if _, exists := defs[d.Metric]; exists {
			block("CAPACITY_MULTIPLE_DEFINITIONS_UNBOUND")
		}
		defs[d.Metric] = d
		if cadence == 0 {
			cadence = d.CadenceSeconds
		}
		if d.CadenceSeconds != cadence || cadence < 1 {
			block("CAPACITY_MIXED_CADENCE_UNSUPPORTED")
		}
	}
	for _, name := range names {
		if _, ok := defs[name]; !ok {
			block("CAPACITY_" + strings.ToUpper(name) + "_METRIC_REQUIRED")
		}
	}
	groups := map[string][]telemetry.Segment{}
	streams := map[string]string{}
	for _, s := range p.Segments {
		d, ok := defs[s.Metric]
		if !ok {
			continue
		}
		if s.End.Before(p.Start) || s.End.Equal(p.Start) || !s.Start.Before(p.End) {
			continue
		}
		if s.Start.Before(p.Start) || s.End.After(p.End) || !s.End.After(s.Start) || s.DefinitionID != d.ID || s.Type != d.Type || s.Unit != d.Unit {
			block("CAPACITY_NATIVE_INTERVAL_MAPPING_REQUIRED")
			continue
		}
		if s.StreamID == "" {
			block("CAPACITY_NATIVE_STREAM_BINDING_REQUIRED")
		}
		if old := streams[s.Metric]; old != "" && old != s.StreamID {
			block("CAPACITY_MULTIPLE_STREAMS_UNBOUND")
		}
		streams[s.Metric] = s.StreamID
		if s.Status == "OBSERVED" {
			if len(s.RawHashes) == 0 {
				block("CAPACITY_SEGMENT_PROVENANCE_MISSING")
			}
			for _, hash := range s.RawHashes {
				if !rawHashes[hash] {
					block("CAPACITY_SEGMENT_PROVENANCE_MISMATCH")
				}
			}
		}
		groups[s.Metric] = append(groups[s.Metric], s)
	}
	for _, name := range names {
		sort.Slice(groups[name], func(i, j int) bool { return groups[name][i].Start.Before(groups[name][j].Start) })
		var previous time.Time
		for _, s := range groups[name] {
			if !previous.IsZero() && s.Start.Before(previous) {
				block("CAPACITY_NATIVE_INTERVAL_OVERLAP")
			}
			previous = s.End
		}
	}
	if len(m.ReasonCodes) > 0 {
		m.ReasonCodes = sortedUnique(m.ReasonCodes)
		return m, nil
	}
	for metric, denominator := range map[string]*string{"cpu_capacity": m.Current.Capacity.CPU, "memory_capacity": m.Current.Capacity.Memory} {
		unit := "bytes"
		if metric == "cpu_capacity" {
			unit = "vCPU"
		}
		if defs[metric].Type != "GAUGE" || defs[metric].Unit != unit {
			block("CAPACITY_OBSERVED_DENOMINATOR_UNIT_INVALID")
			continue
		}
		previous := p.Start
		for _, s := range groups[metric] {
			r := capacityRat(s.Value)
			want := capacityRat(*denominator)
			if !s.Start.Equal(previous) || s.Status != "OBSERVED" || s.Statistic != "OBSERVED_SAMPLE_DISTRIBUTION" || r == nil || r.Cmp(want) != 0 {
				block("CAPACITY_HISTORICAL_DENOMINATOR_UNPROVEN")
			}
			previous = s.End
		}
		if !previous.Equal(p.End) {
			block("CAPACITY_HISTORICAL_DENOMINATOR_UNPROVEN")
		}
	}
	if len(m.ReasonCodes) > 0 {
		m.ReasonCodes = sortedUnique(m.ReasonCodes)
		return m, nil
	}
	metrics := []CapacityModelMetric{}
	for metric, name := range map[string]string{"cpu_utilization": "cpu", "memory_utilization": "memory"} {
		denom := m.Current.Capacity.CPU
		unit := "vCPU"
		if name == "memory" {
			denom = m.Current.Capacity.Memory
			unit = "bytes"
		}
		stream := CapacityModelMetric{Name: name, Unit: unit, Statistic: "RAW_SAMPLE", Denominator: denom, SourceRefs: refs, Points: []CapacityModelPoint{}}
		if defs[metric].Type != "GAUGE" || defs[metric].Unit != "ratio" {
			block("CAPACITY_UTILIZATION_UNIT_INVALID")
		}
		for _, s := range groups[metric] {
			var value *string
			if s.Status == "OBSERVED" {
				r := capacityRat(s.Value)
				if r == nil || r.Cmp(big.NewRat(1, 1)) > 0 || s.Statistic != "OBSERVED_SAMPLE_DISTRIBUTION" {
					block("CAPACITY_UTILIZATION_POPULATION_INVALID")
				} else {
					v := capacityText(new(big.Rat).Mul(r, capacityRat(*denom)), true)
					value = &v
				}
			}
			stream.Points = append(stream.Points, CapacityModelPoint{s.Start, s.End, value})
		}
		metrics = append(metrics, stream)
	}
	for _, spec := range []struct {
		name, unit string
		metrics    []string
		denom      *string
	}{{"network", "bytes/second", []string{"network_in", "network_out"}, m.Current.Capacity.Network}, {"storage_iops", "operations/second", []string{"disk_read_operations", "disk_write_operations"}, m.Current.Capacity.StorageIOPS}, {"storage_throughput", "bytes/second", []string{"disk_read_bytes", "disk_write_bytes"}, m.Current.Capacity.StorageThroughput}, {"demand", "", []string{"request_count"}, nil}} {
		unit := "bytes"
		if spec.name == "storage_iops" || spec.name == "demand" {
			unit = "count"
		}
		intervals := map[string][]telemetry.Segment{}
		for _, metric := range spec.metrics {
			d := defs[metric]
			if d.Type != "SUM" || d.Unit != unit && !(metric == "request_count" && d.Unit == "requests") {
				block("CAPACITY_NATIVE_COUNTER_UNIT_INVALID")
			}
			for _, s := range groups[metric] {
				key := s.Start.Format(time.RFC3339Nano) + "/" + s.End.Format(time.RFC3339Nano)
				intervals[key] = append(intervals[key], s)
			}
		}
		stream := CapacityModelMetric{Name: spec.name, Unit: spec.unit, Statistic: "OBSERVED_INTERVAL_RATE", Denominator: spec.denom, SourceRefs: refs, Points: []CapacityModelPoint{}}
		if spec.name == "demand" {
			stream.SemanticRole = CapacityRequestProxyRole
			stream.SourceMetric = "request_count"
			stream.SourceUnit = defs["request_count"].Unit
			stream.Unit = stream.SourceUnit + "/second"
		}
		for _, parts := range intervals {
			r := new(big.Rat)
			known := len(parts) == len(spec.metrics)
			for _, s := range parts {
				n := capacityRat(s.Value)
				if s.Status != "OBSERVED" || n == nil {
					known = false
				} else {
					r.Add(r, n)
				}
			}
			var value *string
			if known {
				r.Mul(r, big.NewRat(1_000_000_000, parts[0].End.Sub(parts[0].Start).Nanoseconds()))
				v := capacityText(r, true)
				value = &v
			}
			stream.Points = append(stream.Points, CapacityModelPoint{parts[0].Start, parts[0].End, value})
		}
		sort.Slice(stream.Points, func(i, j int) bool { return stream.Points[i].Start.Before(stream.Points[j].Start) })
		metrics = append(metrics, stream)
	}
	for _, metric := range metrics {
		if len(metric.Points) > 100000 {
			block("CAPACITY_MODEL_POINT_LIMIT")
		}
	}
	if len(m.ReasonCodes) > 0 {
		m.ReasonCodes = sortedUnique(m.ReasonCodes)
		return m, nil
	}
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].Name < metrics[j].Name })
	events := []CapacityModelEvent{}
	profileRef := CapacityModelRef{ID: profile.ID, Version: strconv.FormatInt(profile.Version, 10), ReceiptID: "requirements:" + profile.ID, SHA256: p.SafetyProfileHash, Binding: p.Binding}
	for _, event := range profile.DemandEvents {
		events = append(events, CapacityModelEvent{event.ID, event.Start, event.End, capacityText(big.NewRat(event.DemandMultiplierPPM, 1_000_000), false), profileRef})
	}
	req := CapacityModelRequest{SchemaVersion: "4", Binding: p.Binding, AsOf: p.AsOf, History: CapacityModelHistory{p.Start, p.End, p.Timezone, p.Environment, profile.HighSeasonality, cadence}, Metrics: metrics, Current: m.Current, Candidates: m.Candidates, Policy: map[string]int64{"cpu_p95_max_ppm": 700000, "memory_p95_max_ppm": 750000, "cpu_free_ppm": profile.Headroom.CPUFreePPM, "memory_free_ppm": profile.Headroom.MemoryFreePPM, "reserve_above_forecast_ppm": profile.Headroom.ReserveAboveForecastPPM, "cpu_p99_rollback_ppm": profile.Saturation.CPUP99PPM, "memory_p99_rollback_ppm": profile.Saturation.MemoryP99PPM, "min_replicas": int64(profile.MinReplicas), "min_zones": int64(profile.MinZones)}, Events: events, ForecastHorizons: []string{"7_day", "30_day", "90_day", "annual"}, PricingPeriodHours: capacityText(big.NewRat(p.End.Sub(p.Start).Nanoseconds(), int64(time.Hour)), false)}
	m.Request = &req
	m.Request.ModelVersion = CapacityProxyModelVersion
	return m, nil
}
