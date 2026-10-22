package workload

import (
	"errors"
	"math/big"
	"regexp"
)

// Business constraints only. These declarations establish no metric, quota,
// observed zero, workload safety, performance capability or execution authority.
type AWSServiceLimits struct {
	CPUHeadroomFraction            string `json:"cpu_headroom_fraction,omitempty"`
	MemoryHeadroomFraction         string `json:"memory_headroom_fraction,omitempty"`
	CPUMaxFraction                 string `json:"cpu_max_fraction,omitempty"`
	MemoryMaxFraction              string `json:"memory_max_fraction,omitempty"`
	ReadTargetUtilizationFraction  string `json:"read_target_utilization_fraction,omitempty"`
	WriteTargetUtilizationFraction string `json:"write_target_utilization_fraction,omitempty"`
	MinReadCapacityUnits           string `json:"min_read_capacity_units,omitempty"`
	MinWriteCapacityUnits          string `json:"min_write_capacity_units,omitempty"`
	MaxReplicationLagSeconds       string `json:"max_replication_lag_seconds,omitempty"`
	MaxSwapBytes                   string `json:"max_swap_bytes,omitempty"`
	MaxEvictions                   string `json:"max_evictions,omitempty"`
	MinReplicasPerShard            string `json:"min_replicas_per_shard,omitempty"`
	LowRequestsPerSecond           string `json:"low_requests_per_second,omitempty"`
	LowBytesPerSecond              string `json:"low_bytes_per_second,omitempty"`
	MaxErrorRate                   string `json:"max_error_rate,omitempty"`
	MaxLatencyMS                   string `json:"max_latency_ms,omitempty"`
	MaxQueueAgeMS                  string `json:"max_queue_age_ms,omitempty"`
	BurstRequirementsKnown         *bool  `json:"burst_requirements_known,omitempty"`
	AutoscalingReviewed            *bool  `json:"autoscaling_reviewed,omitempty"`
	FailoverRequired               *bool  `json:"failover_required,omitempty"`
	DisasterRecoveryRequired       *bool  `json:"disaster_recovery_required,omitempty"`
	RecoveryRequirementsKnown      *bool  `json:"recovery_requirements_known,omitempty"`
	Purpose                        string `json:"purpose,omitempty"`
}

func validateAWSServiceLimits(p AWSServiceLimits) error {
	invalid := errors.New("AWS_SERVICE_REQUIREMENTS_INVALID")
	decimal := regexp.MustCompile(`^(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)
	for _, s := range []string{p.CPUHeadroomFraction, p.MemoryHeadroomFraction, p.CPUMaxFraction, p.MemoryMaxFraction, p.ReadTargetUtilizationFraction, p.WriteTargetUtilizationFraction, p.MaxErrorRate} {
		if s == "" {
			continue
		}
		n, ok := new(big.Rat).SetString(s)
		if !decimal.MatchString(s) || !ok || n.Sign() < 0 || n.Cmp(big.NewRat(1, 1)) > 0 {
			return invalid
		}
	}
	for _, s := range []string{p.CPUHeadroomFraction, p.MemoryHeadroomFraction} {
		if s != "" {
			n, _ := new(big.Rat).SetString(s)
			if n.Cmp(big.NewRat(1, 1)) >= 0 {
				return invalid
			}
		}
	}
	for _, s := range []string{p.ReadTargetUtilizationFraction, p.WriteTargetUtilizationFraction} {
		if s != "" {
			n, _ := new(big.Rat).SetString(s)
			if n.Sign() <= 0 {
				return invalid
			}
		}
	}
	for _, s := range []string{p.MinReadCapacityUnits, p.MinWriteCapacityUnits, p.MaxReplicationLagSeconds, p.MaxSwapBytes, p.MaxEvictions, p.MinReplicasPerShard, p.LowRequestsPerSecond, p.LowBytesPerSecond, p.MaxLatencyMS, p.MaxQueueAgeMS} {
		if s == "" {
			continue
		}
		n, ok := new(big.Rat).SetString(s)
		if !decimal.MatchString(s) || !ok || n.Sign() < 0 {
			return invalid
		}
	}
	for _, s := range []string{p.MinReadCapacityUnits, p.MinWriteCapacityUnits, p.MinReplicasPerShard} {
		if s == "" {
			continue
		}
		n, _ := new(big.Rat).SetString(s)
		if !n.IsInt() {
			return invalid
		}
	}
	switch p.Purpose {
	case "", "UNKNOWN", "ACTIVE", "FAILOVER", "DR", "MAINTENANCE", "PRIVATE_INTEGRATION":
	default:
		return invalid
	}
	return nil
}
