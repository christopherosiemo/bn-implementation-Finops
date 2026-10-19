package fleethistory

import (
	"errors"
	"math/big"
	"regexp"
	"strings"
	"time"
)

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var instancePattern = regexp.MustCompile(`^i-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var templatePattern = regexp.MustCompile(`^lt-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var asgPattern = regexp.MustCompile(`^arn:aws:autoscaling:eu-west-1:([0-9]{12}):autoScalingGroup:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:autoScalingGroupName/[A-Za-z0-9_./=+,@-]{1,255}$`)
var integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func invalid(code string) error { return errors.New(code) }
func text(s string, max int) bool {
	return s != "" && len(s) <= max && !strings.ContainsAny(s, "\x00\r\n")
}
func count(s string) (*big.Int, bool) {
	if len(s) > 128 || !integerPattern.MatchString(s) {
		return nil, false
	}
	n, ok := new(big.Int).SetString(s, 10)
	return n, ok && n.BitLen() <= 512
}
func sourceVersionValid(system string, v *int64) bool {
	if system == "ACTIVITY_SOURCE" {
		return v == nil
	}
	return v != nil && *v > 0
}
func versionAtLeast(current, captured *int64) bool {
	return current == nil && captured == nil || current != nil && captured != nil && *current >= *captured
}
func ValidateBinding(b Binding) error {
	if !text(b.TenantID, 256) || !text(b.WorkloadID, 256) || b.Provider != "AWS" || !accountPattern.MatchString(b.AccountID) || b.Region != "eu-west-1" {
		return invalid("HISTORY_BINDING_INVALID")
	}
	return nil
}
func ValidateRegistration(r Registration) error {
	match := asgPattern.FindStringSubmatch(r.ASGARN)
	if ValidateBinding(r.Binding) != nil || r.SchemaVersion != SchemaVersion || !text(r.ID, 256) || r.Version < 1 || !text(r.FleetID, 256) || len(match) != 2 || match[1] != r.Binding.AccountID || !text(r.SourceID, 256) || r.SourceSystem != "AWS_SOURCE_CONNECTION" || r.SourceRegistrationVersion < 1 || !hashPattern.MatchString(r.SourceConfigHash) || r.CadenceSeconds < 1 || r.CadenceSeconds > 600 || r.MaxGapSeconds < r.CadenceSeconds || r.MaxGapSeconds > 600 {
		return invalid("HISTORY_REGISTRATION_INVALID")
	}
	return nil
}
func validateRef(ref SourceRef, binding Binding, kind, target string) error {
	key := "tenant/" + binding.TenantID + "/"
	if kind != "INDEPENDENT_COMPLETED_WORK" && ref.SourceSystem != "AWS_SOURCE_CONNECTION" || kind == "INDEPENDENT_COMPLETED_WORK" && ref.SourceSystem != "ACTIVITY_SOURCE" && ref.SourceSystem != "NATIVE_TELEMETRY_CONNECTION" {
		return invalid("HISTORY_SOURCE_NAMESPACE_INVALID")
	}
	if ref.Binding != binding || ref.Kind != kind || ref.Target != target || !text(ref.SourceID, 256) || !sourceVersionValid(ref.SourceSystem, ref.SourceRegistrationVersion) || !text(ref.ReceiptID, 256) || !hashPattern.MatchString(ref.ConfigHash) || !hashPattern.MatchString(ref.RawSHA256) || !hashPattern.MatchString(ref.CanonicalHash) || ref.CapturedAt.IsZero() {
		return invalid("HISTORY_SOURCE_REFERENCE_INVALID")
	}
	if ref.StorageKind == "POSTGRES_RECEIPT" {
		if ref.SourceSystem != "ACTIVITY_SOURCE" || kind != "INDEPENDENT_COMPLETED_WORK" || ref.RevisionID != "" || ref.Archive != nil {
			return invalid("HISTORY_POSTGRES_RECEIPT_INVALID")
		}
		return nil
	}
	if ref.StorageKind != "VERSIONED_OBJECT" || ref.SourceSystem == "ACTIVITY_SOURCE" || !text(ref.RevisionID, 256) || ref.Archive == nil {
		return invalid("HISTORY_VERSIONED_OBJECT_REQUIRED")
	}
	if !text(ref.Archive.Bucket, 256) || !strings.HasPrefix(ref.Archive.Key, key) || len(ref.Archive.Key) > 2048 || strings.ContainsAny(ref.Archive.Key, "\x00\r\n\\") || strings.Contains(ref.Archive.Key, "..") || !text(ref.Archive.VersionID, 1024) || ref.Archive.VersionID == "null" || ref.Archive.SHA256 != ref.RawSHA256 {
		return invalid("HISTORY_SOURCE_REFERENCE_INVALID")
	}
	return nil
}
func ValidateObservation(r Registration, o MembershipObservation) error {
	if ValidateRegistration(r) != nil || o.SchemaVersion != SchemaVersion || !text(o.ID, 256) || o.RegistrationID != r.ID || o.RegistrationVersion != r.Version || o.RegistrationHash != RegistrationHash(r) || o.ASGARN != r.ASGARN || o.ObservedAt.IsZero() || !o.ObservedAt.Equal(o.Source.CapturedAt) || o.ReceivedAt.IsZero() || o.ObservedAt.After(o.ReceivedAt.Add(5*time.Second)) || o.Source.CapturedAt.After(o.ReceivedAt.Add(5*time.Second)) || o.Source.SourceID != r.SourceID || o.Source.SourceSystem != r.SourceSystem || !versionAtLeast(o.Source.SourceRegistrationVersion, &r.SourceRegistrationVersion) || o.Source.ConfigHash != r.SourceConfigHash || len(o.Members) > 256 || o.Members == nil || o.CorrectsID == o.ID || o.CorrectsID != "" && !text(o.CorrectsID, 256) {
		return invalid("HISTORY_OBSERVATION_INVALID")
	}
	if err := validateRef(o.Source, r.Binding, "AWS_FLEET_MEMBERSHIP", r.ASGARN); err != nil {
		return err
	}
	seen, resources := map[string]bool{}, map[string]bool{}
	for _, m := range o.Members {
		if !instancePattern.MatchString(m.InstanceID) || seen[m.InstanceID] || m.LaunchTime != nil && (m.LaunchTime.IsZero() || m.LaunchTime.After(o.ObservedAt)) || !templatePattern.MatchString(m.LaunchTemplateID) || m.LaunchTemplateVersion < 1 || m.ResourceID != "" && (!text(m.ResourceID, 256) || resources[m.ResourceID]) {
			return invalid("HISTORY_MEMBER_INCARNATION_INVALID")
		}
		if m.Hardware != nil {
			if err := validateRef(*m.Hardware, r.Binding, "AWS_EC2_HARDWARE", m.InstanceID); err != nil {
				return err
			}
			if m.LaunchTime != nil && m.Hardware.CapturedAt.Before(*m.LaunchTime) || m.Hardware.CapturedAt.After(o.ReceivedAt.Add(5*time.Second)) {
				return invalid("HISTORY_MEMBER_CAPTURE_TIME_INVALID")
			}
		}
		seen[m.InstanceID] = true
		if m.ResourceID != "" {
			resources[m.ResourceID] = true
		}
	}
	return nil
}
func ValidateDemandDefinition(r Registration, d DemandDefinition) error {
	if ValidateRegistration(r) != nil || d.SchemaVersion != SchemaVersion || !text(d.ID, 256) || d.Version < 1 || d.Binding != r.Binding || !text(d.Metric, 256) || !text(d.MetricDefinitionID, 256) || !text(d.MetricDefinitionVersion, 256) || !text(d.Unit, 128) || !text(d.BusinessOperation, 512) || !text(d.SemanticContractID, 256) || !hashPattern.MatchString(d.SemanticContractHash) || !text(d.SourceID, 256) || !sourceVersionValid(d.SourceSystem, d.SourceRegistrationVersion) || !hashPattern.MatchString(d.SourceConfigHash) || d.CadenceSeconds < 1 || d.CadenceSeconds > 600 || d.MaxGapSeconds < d.CadenceSeconds || d.MaxGapSeconds > 600 {
		return invalid("DEMAND_DEFINITION_INVALID")
	}
	if d.Aggregation != "SINGLE_EXTERNAL_TOTAL" {
		return invalid("DEMAND_PARTITION_AGGREGATION_UNSUPPORTED")
	}
	if d.SourceSystem != "ACTIVITY_SOURCE" && d.SourceSystem != "NATIVE_TELEMETRY_CONNECTION" {
		return invalid("DEMAND_SOURCE_NAMESPACE_INVALID")
	}
	if d.SourceSystem == "ACTIVITY_SOURCE" && (d.ValueField != "COMPLETED" || d.Temporality != "DELTA") {
		return invalid("DEMAND_ACTIVITY_COMPLETED_INTERVAL_REQUIRED")
	}
	if d.SourceSystem == "NATIVE_TELEMETRY_CONNECTION" && d.ValueField != "NATIVE_MONOTONIC_COUNT" {
		return invalid("DEMAND_NATIVE_VALUE_FIELD_UNSUPPORTED")
	}
	if d.Meaning != "COMPLETED_WORK" || d.Origin != "INDEPENDENT_EXTERNAL_SYSTEM" {
		return invalid("DEMAND_COMPLETED_WORK_MEANING_REQUIRED")
	}
	if d.Temporality != "DELTA" && d.Temporality != "CUMULATIVE" {
		return invalid("DEMAND_TEMPORALITY_UNSUPPORTED")
	}
	return nil
}
func ValidateDemandSample(r Registration, d DemandDefinition, s DemandSample) error {
	if err := ValidateDemandDefinition(r, d); err != nil {
		return err
	}
	if s.SchemaVersion != SchemaVersion || !text(s.ID, 256) || s.DefinitionID != d.ID || s.DefinitionVersion != d.Version || s.DefinitionHash != DefinitionHash(d) || s.MetricDefinitionID != d.MetricDefinitionID || s.MetricDefinitionVersion != d.MetricDefinitionVersion || s.Start.IsZero() || s.Time.IsZero() || !s.Time.After(s.Start) || s.Epoch != nil && (s.Epoch.IsZero() || s.Epoch.After(s.Start)) || s.ReceivedAt.IsZero() || s.Time.After(s.ReceivedAt.Add(5*time.Second)) || s.Source.CapturedAt.After(s.ReceivedAt.Add(5*time.Second)) || s.Source.SourceID != d.SourceID || s.Source.SourceSystem != d.SourceSystem || !versionAtLeast(s.Source.SourceRegistrationVersion, d.SourceRegistrationVersion) || s.Source.ConfigHash != d.SourceConfigHash || s.CorrectsID == s.ID || s.CorrectsID != "" && !text(s.CorrectsID, 256) {
		return invalid("DEMAND_SAMPLE_INVALID")
	}
	if s.Partition != "" {
		return invalid("DEMAND_PARTITIONS_UNSUPPORTED")
	}
	if d.Temporality == "CUMULATIVE" && (s.Epoch == nil || !s.Start.Equal(*s.Epoch)) {
		return invalid("DEMAND_COUNTER_EPOCH_INVALID")
	}
	if s.Source.StorageKind == "POSTGRES_RECEIPT" && (s.Epoch != nil || !s.Source.CapturedAt.Equal(s.ReceivedAt)) {
		return invalid("DEMAND_ACTIVITY_RECEIPT_TIME_INVALID")
	}
	if s.Value != nil {
		if _, ok := count(*s.Value); !ok {
			return invalid("DEMAND_INTEGER_COUNT_INVALID")
		}
	}
	return validateRef(s.Source, r.Binding, "INDEPENDENT_COMPLETED_WORK", r.Binding.WorkloadID)
}
