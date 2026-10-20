// Package workload defines action-specific requirements. These declarations are
// policy, not observations: recording an RPO or a headroom target proves neither.
package workload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"sort"
	"time"
)

type WeeklyWindow struct {
	Days      []int  `json:"days"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}
type Blackout struct {
	ID     string    `json:"id"`
	Reason string    `json:"reason"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
}
type DemandEvent struct {
	ID                  string    `json:"id"`
	Reason              string    `json:"reason"`
	Start               time.Time `json:"start"`
	End                 time.Time `json:"end"`
	DemandMultiplierPPM int64     `json:"demand_multiplier_ppm"`
}
type Headroom struct {
	// Free fractions constrain projected utilization: 300000 means at most 70%.
	CPUFreePPM    int64 `json:"cpu_free_ppm"`
	MemoryFreePPM int64 `json:"memory_free_ppm"`
	// A reserve of 300000 independently requires capacity >= forecast * 1.30.
	ReserveAboveForecastPPM int64 `json:"reserve_above_forecast_ppm"`
}
type Saturation struct {
	CPUP99PPM    int64 `json:"cpu_p99_ppm"`
	MemoryP99PPM int64 `json:"memory_p99_ppm"`
}
type Profile struct {
	SchemaVersion            string          `json:"schema_version"`
	ID                       string          `json:"id,omitempty"`
	WorkloadID               string          `json:"workload_id,omitempty"`
	Version                  int64           `json:"version,omitempty"`
	Criticality              string          `json:"criticality"`
	Statefulness             string          `json:"statefulness"`
	HighSeasonality          bool            `json:"high_seasonality"`
	Timezone                 string          `json:"timezone"`
	MinReplicas              int             `json:"min_replicas"`
	MinZones                 int             `json:"min_zones"`
	Headroom                 Headroom        `json:"headroom"`
	Saturation               Saturation      `json:"saturation"`
	RTOSeconds               int64           `json:"rto_seconds"`
	RPOSeconds               *int64          `json:"rpo_seconds"`
	Maintenance              []WeeklyWindow  `json:"maintenance"`
	RecurringBlackouts       []WeeklyWindow  `json:"recurring_blackouts"`
	Blackouts                []Blackout      `json:"blackouts"`
	DemandEvents             []DemandEvent   `json:"demand_events"`
	MaxSimultaneousChangePPM int64           `json:"max_simultaneous_change_ppm"`
	VMCooldownSeconds        int64           `json:"vm_cooldown_seconds"`
	Database                 *DatabaseLimits `json:"database,omitempty"`
	Storage                  *StorageLimits  `json:"storage,omitempty"`
}

// Requirements only. Nullable flags preserve an undeclared requirement; none
// of these declarations is proof of a backup, attachment or healthy workload.
type StorageLimits struct {
	IOPSMaxFraction          string `json:"iops_max_fraction"`
	ThroughputMaxFraction    string `json:"throughput_max_fraction"`
	MaxReadLatencySeconds    string `json:"max_read_latency_seconds"`
	MaxWriteLatencySeconds   string `json:"max_write_latency_seconds"`
	MaxDiskQueueDepth        string `json:"max_disk_queue_depth"`
	MinBurstBalancePercent   string `json:"min_burst_balance_percent"`
	SnapshotRetentionDays    int    `json:"snapshot_retention_days"`
	QuarantineDays           int    `json:"quarantine_days"`
	BackupRequired           *bool  `json:"backup_required"`
	AllowDurabilityReduction *bool  `json:"allow_durability_reduction"`
	RequireMultiAttach       *bool  `json:"require_multi_attach"`
	FilesystemReviewRequired *bool  `json:"filesystem_review_required"`
}

// These are customer policy limits, not assertions that an observation exists.
type DatabaseLimits struct {
	ConnectionsMaxFraction string `json:"connections_max_fraction"`
	IOPSMaxFraction        string `json:"iops_max_fraction"`
	ThroughputMaxFraction  string `json:"throughput_max_fraction"`
	StorageMaxFraction     string `json:"storage_max_fraction"`
	MaxReadLatencySeconds  string `json:"max_read_latency_seconds"`
	MaxWriteLatencySeconds string `json:"max_write_latency_seconds"`
	MaxDiskQueueDepth      string `json:"max_disk_queue_depth"`
	MaxReplicaLagSeconds   string `json:"max_replica_lag_seconds"`
}

func Decode(raw []byte) (Profile, error) {
	var p Profile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, errors.New("SAFETY_PROFILE_INVALID")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return p, errors.New("SAFETY_PROFILE_INVALID")
	}
	return p, Validate(p)
}
func Hash(p Profile) string {
	raw, _ := json.Marshal(p)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func minute(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' || s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' || s[3] < '0' || s[3] > '9' || s[4] < '0' || s[4] > '9' {
		return 0, false
	}
	h, m := int(s[0]-'0')*10+int(s[1]-'0'), int(s[3]-'0')*10+int(s[4]-'0')
	return h*60 + m, h < 24 && m < 60
}
func validWeekly(w WeeklyWindow) bool {
	a, ok := minute(w.StartTime)
	if !ok {
		return false
	}
	b, ok := minute(w.EndTime)
	if w.EndTime == "24:00" {
		b, ok = 1440, true
	}
	if !ok || a == b || len(w.Days) < 1 || len(w.Days) > 7 {
		return false
	}
	seen := map[int]bool{}
	for _, d := range w.Days {
		if d < 0 || d > 6 || seen[d] {
			return false
		}
		seen[d] = true
	}
	return true
}
func Validate(p Profile) error {
	invalid := errors.New("SAFETY_PROFILE_INVALID")
	if p.Storage != nil {
		decimal := regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,12})?$`)
		for _, text := range []string{p.Storage.IOPSMaxFraction, p.Storage.ThroughputMaxFraction} {
			v, ok := new(big.Rat).SetString(text)
			if !decimal.MatchString(text) || !ok || v.Sign() <= 0 || v.Cmp(big.NewRat(1, 1)) > 0 {
				return invalid
			}
		}
		for _, text := range []string{p.Storage.MaxReadLatencySeconds, p.Storage.MaxWriteLatencySeconds, p.Storage.MaxDiskQueueDepth, p.Storage.MinBurstBalancePercent} {
			v, ok := new(big.Rat).SetString(text)
			if !decimal.MatchString(text) || !ok || v.Sign() < 0 {
				return invalid
			}
		}
		burst, _ := new(big.Rat).SetString(p.Storage.MinBurstBalancePercent)
		if burst.Cmp(big.NewRat(100, 1)) > 0 || p.Storage.SnapshotRetentionDays < 1 || p.Storage.SnapshotRetentionDays > 36500 || p.Storage.QuarantineDays < 1 || p.Storage.QuarantineDays > 36500 {
			return invalid
		}
	}
	if p.Database != nil {
		decimal := regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,12})?$`)
		for _, text := range []string{p.Database.ConnectionsMaxFraction, p.Database.IOPSMaxFraction, p.Database.ThroughputMaxFraction, p.Database.StorageMaxFraction} {
			v, ok := new(big.Rat).SetString(text)
			if !decimal.MatchString(text) || !ok || v.Sign() <= 0 || v.Cmp(big.NewRat(1, 1)) > 0 {
				return invalid
			}
		}
		for _, text := range []string{p.Database.MaxReadLatencySeconds, p.Database.MaxWriteLatencySeconds, p.Database.MaxDiskQueueDepth, p.Database.MaxReplicaLagSeconds} {
			v, ok := new(big.Rat).SetString(text)
			if !decimal.MatchString(text) || !ok || v.Sign() < 0 {
				return invalid
			}
		}
	}
	if p.SchemaVersion != "1" || p.MinReplicas < 1 || p.MinReplicas > 1000000 || p.MinZones < 1 || p.MinZones > p.MinReplicas || p.MinZones > 100 {
		return invalid
	}
	switch p.Criticality {
	case "TIER_0", "TIER_1", "TIER_2", "TIER_3", "NON_PRODUCTION":
	default:
		return invalid
	}
	switch p.Statefulness {
	case "STATELESS", "STATEFUL", "UNKNOWN":
	default:
		return invalid
	}
	if _, err := time.LoadLocation(p.Timezone); err != nil || p.Timezone == "" {
		return invalid
	}
	if p.Headroom.CPUFreePPM < 1 || p.Headroom.CPUFreePPM >= 1000000 || p.Headroom.MemoryFreePPM < 1 || p.Headroom.MemoryFreePPM >= 1000000 || p.Headroom.ReserveAboveForecastPPM < 0 || p.Headroom.ReserveAboveForecastPPM > 10000000 {
		return invalid
	}
	if p.Saturation.CPUP99PPM < 1 || p.Saturation.CPUP99PPM > 1000000 || p.Saturation.MemoryP99PPM < 1 || p.Saturation.MemoryP99PPM > 1000000 {
		return invalid
	}
	if p.RTOSeconds < 1 || p.RTOSeconds > 604800 || p.RPOSeconds != nil && (*p.RPOSeconds < 0 || *p.RPOSeconds > 604800) || p.MaxSimultaneousChangePPM < 1 || p.MaxSimultaneousChangePPM > 1000000 || p.VMCooldownSeconds < 0 || p.VMCooldownSeconds > 31536000 {
		return invalid
	}
	if len(p.Maintenance) > 64 || len(p.RecurringBlackouts) > 64 || len(p.Blackouts) > 256 || len(p.DemandEvents) > 256 {
		return invalid
	}
	for _, w := range append(append([]WeeklyWindow{}, p.Maintenance...), p.RecurringBlackouts...) {
		if !validWeekly(w) {
			return invalid
		}
	}
	ids := map[string]bool{}
	for _, b := range p.Blackouts {
		if b.ID == "" || len(b.ID) > 200 || b.Reason == "" || len(b.Reason) > 2000 || ids[b.ID] || b.Start.IsZero() || !b.End.After(b.Start) {
			return invalid
		}
		ids[b.ID] = true
	}
	ids = map[string]bool{}
	for _, e := range p.DemandEvents {
		if e.ID == "" || len(e.ID) > 200 || e.Reason == "" || len(e.Reason) > 2000 || ids[e.ID] || e.Start.IsZero() || !e.End.After(e.Start) || e.DemandMultiplierPPM < 1000000 || e.DemandMultiplierPPM > 1000000000 {
			return invalid
		}
		ids[e.ID] = true
	}
	return nil
}
func inWeekly(at time.Time, w WeeklyWindow) bool {
	a, _ := minute(w.StartTime)
	b, _ := minute(w.EndTime)
	if w.EndTime == "24:00" {
		b = 1440
	}
	m := at.Hour()*60 + at.Minute()
	day := int(at.Weekday())
	for _, d := range w.Days {
		if a < b && day == d && m >= a && m < b {
			return true
		}
		if a > b && (day == d && m >= a || day == (d+1)%7 && m < b) {
			return true
		}
	}
	return false
}

type WindowEvaluation struct {
	Status      string    `json:"status"`
	ReasonCodes []string  `json:"reason_codes"`
	ProfileHash string    `json:"profile_hash"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
}

// EvaluateWindow checks the entire real-time interval. Fall-back hours are both
// subject to the local rule; nonexistent spring-forward minutes are never made up.
// This function is for new optional changes only. Owned compensation never calls it.
func EvaluateWindow(p Profile, start, end time.Time) WindowEvaluation {
	r := WindowEvaluation{"CLEAR", []string{}, Hash(p), start.UTC(), end.UTC()}
	reasons := map[string]bool{}
	if Validate(p) != nil || start.IsZero() || !end.After(start) || end.Sub(start) > 7*24*time.Hour {
		reasons["SAFETY_WINDOW_INVALID"] = true
	} else {
		loc, _ := time.LoadLocation(p.Timezone)
		for _, b := range p.Blackouts {
			if start.Before(b.End) && end.After(b.Start) {
				reasons["BLACKOUT_ACTIVE"] = true
			}
		}
		check := func(t time.Time) {
			local := t.In(loc)
			allowed := false
			for _, w := range p.Maintenance {
				if inWeekly(local, w) {
					allowed = true
				}
			}
			if !allowed {
				reasons["OUTSIDE_MAINTENANCE_WINDOW"] = true
			}
			for _, w := range p.RecurringBlackouts {
				if inWeekly(local, w) {
					reasons["BLACKOUT_ACTIVE"] = true
				}
			}
		}
		check(start)
		for t := start.Truncate(time.Minute).Add(time.Minute); t.Before(end); t = t.Add(time.Minute) {
			check(t)
		}
		check(end.Add(-time.Nanosecond))
	}
	for code := range reasons {
		r.ReasonCodes = append(r.ReasonCodes, code)
	}
	sort.Strings(r.ReasonCodes)
	if len(reasons) > 0 {
		r.Status = "BLOCKED"
	}
	return r
}

type TopologyEvaluation struct {
	Status             string   `json:"status"`
	ReasonCodes        []string `json:"reason_codes"`
	HealthyReplicas    int      `json:"healthy_replicas"`
	HealthyZones       int      `json:"healthy_zones"`
	SimultaneousBudget int      `json:"simultaneous_budget"`
}

// healthyZones must be computed from the exact surviving healthy members after
// the proposed change, never copied from a pre-change zone count.
func EvaluateTopology(p Profile, healthyReplicas, healthyZones, baselineFleetSize, inProgress, proposed int) TopologyEvaluation {
	r := TopologyEvaluation{"CLEAR", []string{}, healthyReplicas, healthyZones, 0}
	if Validate(p) != nil || healthyReplicas < 0 || healthyZones < 0 || baselineFleetSize < 1 || baselineFleetSize > 1000000 || inProgress < 0 || proposed < 0 {
		r.ReasonCodes = append(r.ReasonCodes, "TOPOLOGY_EVIDENCE_INVALID")
	} else {
		r.SimultaneousBudget = int(int64(baselineFleetSize) * p.MaxSimultaneousChangePPM / 1000000)
		// Tiny fleets still require an explicitly sufficient policy budget. Rounding
		// a 10% budget up to one for a singleton would silently authorize 100%.
		if healthyReplicas-proposed < p.MinReplicas {
			r.ReasonCodes = append(r.ReasonCodes, "MIN_REPLICAS_NOT_PRESERVED")
		}
		if healthyZones < p.MinZones {
			r.ReasonCodes = append(r.ReasonCodes, "MIN_ZONES_NOT_PRESERVED")
		}
		if inProgress+proposed > r.SimultaneousBudget {
			r.ReasonCodes = append(r.ReasonCodes, "BLAST_RADIUS_EXCEEDED")
		}
	}
	if len(r.ReasonCodes) > 0 {
		r.Status = "BLOCKED"
	}
	return r
}
