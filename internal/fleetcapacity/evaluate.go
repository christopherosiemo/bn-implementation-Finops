package fleetcapacity

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

func ValidateScope(s Scope) error {
	invalid := errors.New("FLEET_CAPACITY_SCOPE_INVALID")
	if fleetbilling.ValidateGroupSelection(s.Selection.Groups) != nil || s.Selection.SafetyProfile.ID == "" || s.Selection.SafetyProfile.Version < 1 || !sha.MatchString(s.Selection.SafetyProfile.SHA256) || !sha.MatchString(s.SnapshotSHA256) || s.ObservedAt.IsZero() || len(s.CurrentMemberIDs) > MaximumMembers {
		return invalid
	}
	if s.PopulationStatus != "OBSERVED_POINT" && s.PopulationStatus != "UNAVAILABLE" {
		return invalid
	}
	if s.PopulationStatus == "UNAVAILABLE" && len(s.CurrentMemberIDs) != 0 || len(s.MembershipPins) > 2 {
		return invalid
	}
	seen := map[string]bool{}
	for _, id := range s.CurrentMemberIDs {
		if !instance.MatchString(id) || seen[id] {
			return invalid
		}
		seen[id] = true
	}
	if s.PopulationStatus == "OBSERVED_POINT" && len(s.MembershipPins) < 1 {
		return invalid
	}
	seen = map[string]bool{}
	for _, pin := range s.MembershipPins {
		if pin.ReceiptID == "" || seen[pin.ReceiptID] || pin.RevisionID == "" || !sha.MatchString(pin.ReceiptSHA256) || !sha.MatchString(pin.RawSHA256) || pin.ReceiptVersionID == "" || pin.ReceiptVersionID == "null" || pin.RevisionVersionID == "" || pin.RevisionVersionID == "null" {
			return invalid
		}
		seen[pin.ReceiptID] = true
	}
	return nil
}

func frozen[T any](value T) (T, error) {
	var out T
	raw, e := json.Marshal(value)
	if e == nil {
		e = json.Unmarshal(raw, &out)
	}
	return out, e
}
func resultID(r MemberResult) string {
	r.ID = ""
	return "fleet-capacity-member-" + fleetbilling.Hash(r)
}
func finish(r MemberResult) (MemberResult, error) {
	r.ReasonCodes = unique(r.ReasonCodes)
	if raw, e := json.Marshal(r); e != nil || len(raw) > 1<<20 {
		return MemberResult{}, errors.New("FLEET_CAPACITY_MEMBER_RESULT_LIMIT")
	}
	out, e := frozen(r)
	if e != nil {
		return out, e
	}
	out.ID = resultID(out)
	return out, nil
}
func gap(p Plan, code string) (Plan, error) {
	p.Result.Status = "UNAVAILABLE"
	p.Result.ReasonCodes = unique(append(p.Result.ReasonCodes, code))
	p.Result.InputKind = "MAPPING_OBSERVATION"
	p.Result.InputHash = fleetbilling.Hash(p.Result.HardwareMapping)
	var e error
	p.Result, e = finish(p.Result)
	return p, e
}

// Unavailable records a missing or no-longer-current member without asserting
// fresh resource, hardware, telemetry, model or capacity facts. It preserves
// the old immutable membership point so revocation cannot erase its gaps.
func Unavailable(scope Scope, batchID, instanceID, reason string, now time.Time) (MemberResult, error) {
	if ValidateScope(scope) != nil || batchID == "" || now.IsZero() || scope.ObservedAt.After(now.Add(5*time.Second)) || !regexp.MustCompile(`^(?:FLEET_)?CAPACITY_[A-Z0-9_]{1,100}$`).MatchString(reason) {
		return MemberResult{}, errors.New("FLEET_CAPACITY_GAP_INVALID")
	}
	found := false
	for _, id := range scope.CurrentMemberIDs {
		found = found || id == instanceID
	}
	if !found {
		return MemberResult{}, errors.New("FLEET_CAPACITY_GAP_INVALID")
	}
	r := MemberResult{SchemaVersion: "1", BatchID: batchID, Scope: scope, InstanceID: instanceID, ObservedAt: now.UTC(), InputKind: "UNAVAILABLE", Status: "UNAVAILABLE", DemandMeaning: "UNAVAILABLE", ReasonCodes: []string{reason, "EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE", "GROUP_HISTORICAL_INTERVAL_OWNERSHIP_UNPROVEN", "COMPLETED_BUSINESS_WORK_PRESERVATION_UNPROVEN"}}
	r.InputHash = fleetbilling.Hash(model.Document{"scope": scope, "instance_id": instanceID, "reason": reason})
	return finish(r)
}

// Prepare reuses the existing physical/interval mapper, restricting its native
// catalogue to the exact selected candidate launch template. Every invocation
// remains one real inventory member; counts are never multiplied into a fleet
// capacity or completed-business-work claim.
func Prepare(in MemberInput, now time.Time) (Plan, error) {
	invalid := errors.New("FLEET_CAPACITY_MEMBER_SELECTION_INVALID")
	if ValidateScope(in.Scope) != nil || in.BatchID == "" || !instance.MatchString(in.InstanceID) || now.IsZero() || in.Scope.ObservedAt.After(now.Add(5*time.Second)) {
		return Plan{}, invalid
	}
	member := false
	for _, id := range in.Scope.CurrentMemberIDs {
		member = member || id == in.InstanceID
	}
	if !member || in.Scope.PopulationStatus != "OBSERVED_POINT" {
		return Plan{}, invalid
	}
	p := Plan{Result: MemberResult{SchemaVersion: "1", BatchID: in.BatchID, Scope: in.Scope, InstanceID: in.InstanceID, ObservedAt: now.UTC(), Status: "BLOCKED", ReasonCodes: []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE", "GROUP_HISTORICAL_INTERVAL_OWNERSHIP_UNPROVEN", "COMPLETED_BUSINESS_WORK_PRESERVATION_UNPROVEN"}, DemandMeaning: "UNAVAILABLE", InputKind: "MAPPING_OBSERVATION"}}
	target := in.Scope.Selection.Groups.Binding.Old.Target
	if in.Resource == nil {
		return gap(p, "CAPACITY_MEMBER_INVENTORY_MAPPING_UNAVAILABLE")
	}
	binding := telemetry.Binding{TenantID: target.TenantID, WorkloadID: target.WorkloadID, ResourceID: model.String(in.Resource, "id"), Provider: "AWS", ProviderResourceID: in.InstanceID, AccountID: target.AccountID, Region: target.Region}
	p.Result.ResourceID = binding.ResourceID
	p.Result.Binding = &binding
	if binding.ResourceID == "" || model.String(in.Resource, "provider") != "AWS" || model.String(in.Resource, "provider_resource_id") != in.InstanceID || model.String(in.Resource, "workload_id") != target.WorkloadID || model.String(in.Resource, "account_id") != target.AccountID || model.String(in.Resource, "region") != target.Region {
		return gap(p, "CAPACITY_MEMBER_INVENTORY_BINDING_CHANGED")
	}
	if workload.Validate(in.Profile) != nil || in.Profile.ID != in.Scope.Selection.SafetyProfile.ID || in.Profile.Version != in.Scope.Selection.SafetyProfile.Version || in.Profile.WorkloadID != target.WorkloadID || workload.Hash(in.Profile) != in.Scope.Selection.SafetyProfile.SHA256 {
		return gap(p, "CAPACITY_SAFETY_PROFILE_CHANGED")
	}
	if in.Population == nil {
		return gap(p, "CAPACITY_MEMBER_TELEMETRY_POPULATION_UNAVAILABLE")
	}
	population := *in.Population
	connection, err := telemetry.ParseConnection(in.Connection)
	if err != nil || !connection.Enabled || model.Bool(in.Connection, "revoked") || connection.Binding != binding || population.Binding != binding || population.ConnectionID != connection.ID || population.ConnectionVersion != connection.Version || population.ConfigHash != telemetry.ConfigHash(connection) || population.PopulationHash != native.CapacityPopulationHash(population) || population.SafetyProfileID != in.Profile.ID || population.SafetyProfileVersion != in.Profile.Version || population.SafetyProfileHash != in.Scope.Selection.SafetyProfile.SHA256 || population.SchemaVersion != "1" || population.AsOf.Before(now.Add(-2*time.Minute)) || population.AsOf.After(now.Add(5*time.Second)) || model.String(in.Connection, "revision_id") == "" || model.String(in.Connection, "config_hash") != population.ConfigHash || len(population.SourceRefs) != len(population.ReceiptIDs) || len(population.SourceRefs) > 2048 || len(population.Segments) > telemetry.MaxSamples {
		return gap(p, "CAPACITY_MEMBER_TELEMETRY_BINDING_CHANGED")
	}
	p.Result.Telemetry = &TelemetryPin{ConnectionID: connection.ID, ConnectionVersion: connection.Version, RevisionID: model.String(in.Connection, "revision_id"), ConfigHash: population.ConfigHash, PopulationHash: population.PopulationHash, ReceiptIDs: population.ReceiptIDs, SourceRefs: population.SourceRefs}
	if in.Hardware == nil {
		return gap(p, "CAPACITY_MEMBER_HARDWARE_UNAVAILABLE")
	}
	var bound telemetry.Binding
	var hardware provider.HardwareEvidence
	collected, e := time.Parse(time.RFC3339Nano, model.String(in.Hardware, "collected_at"))
	rawref := document(in.Hardware["raw_object"])
	if decode(in.Hardware["binding"], &bound) != nil || decode(in.Hardware["native"], &hardware) != nil || bound != binding || model.String(in.Hardware, "id") == "" || model.String(in.Hardware, "source_id") == "" || model.String(in.Hardware, "revision_id") == "" || model.String(in.Hardware, "kind") != "AWS_EC2_HARDWARE" || model.String(in.Hardware, "writer_role") != "finops_ingester" || e != nil || collected.Before(now.Add(-2*time.Minute)) || collected.After(now.Add(5*time.Second)) || !hardware.CollectedAt.Equal(collected) || model.String(in.Hardware, "resource_snapshot_hash") != telemetry.Hash(in.Resource) || model.Number(in.Hardware, "resource_version") != model.Number(in.Resource, "version") || model.Number(in.Hardware, "registration_version") < 1 || !sha.MatchString(model.String(in.Hardware, "config_hash")) || hardware.RawSHA256 != model.String(rawref, "body_sha256") || model.String(rawref, "version_id") == "" || model.String(rawref, "version_id") == "null" {
		return gap(p, "CAPACITY_MEMBER_HARDWARE_BINDING_CHANGED")
	}
	if in.HardwareEvidence == nil || fleetbilling.Hash(in.HardwareEvidence.Receipt) != fleetbilling.Hash(in.Hardware) {
		return gap(p, "CAPACITY_MEMBER_HARDWARE_RAW_UNAVAILABLE")
	}
	selected := in.Scope.Selection.Groups.Binding.Old
	if model.String(in.Hardware, "source_id") == in.Scope.Selection.Groups.Binding.Candidate.SourceID {
		selected = in.Scope.Selection.Groups.Binding.Candidate
	}
	hardwareSourcePin, e := nativePin(*in.HardwareEvidence, selected, "AWS_EC2_HARDWARE", now)
	if e != nil {
		return gap(p, "CAPACITY_MEMBER_HARDWARE_RAW_BINDING_CHANGED")
	}
	parsed, e := provider.ParseHardwareEvidence(in.HardwareEvidence.Raw, binding.AccountID, binding.Region, binding.ProviderResourceID, model.Strings(in.Hardware, "candidate_types"), collected)
	if e != nil || fleetbilling.Hash(parsed) != fleetbilling.Hash(hardware) || provider.ValidateHardwareEvidence(parsed, binding.ProviderResourceID, model.Strings(in.Hardware, "candidate_types")) != nil {
		return gap(p, "CAPACITY_MEMBER_HARDWARE_RAW_BINDING_CHANGED")
	}
	hardware = parsed
	p.Result.Hardware = &HardwarePin{SourcePin: hardwareSourcePin, ReceiptID: model.String(in.Hardware, "id"), SourceID: model.String(in.Hardware, "source_id"), RevisionID: model.String(in.Hardware, "revision_id"), RegistrationVersion: model.Number(in.Hardware, "registration_version"), ConfigHash: model.String(in.Hardware, "config_hash"), RawSHA256: hardware.RawSHA256, ResourceSnapshotHash: model.String(in.Hardware, "resource_snapshot_hash"), ResourceVersion: model.Number(in.Hardware, "resource_version")}
	if in.Candidate == nil {
		return gap(p, "CAPACITY_CANDIDATE_NATIVE_TEMPLATE_UNAVAILABLE")
	}
	c := *in.Candidate
	p.Result.CandidateTemplate = &c
	if c.DefinitionSHA256 != fleetbilling.Hash(c.definition) || c.ID != c.definition.Template.ID || c.Version != strconv.FormatUint(c.definition.Template.Version, 10) || c.InstanceType != c.definition.Template.Data.InstanceType || c.ImageID != c.definition.Template.Data.ImageID || c.SourcePin != c.definition.Pin || fleetbilling.Hash(c.ReasonCodes) != fleetbilling.Hash(c.definition.Reasons) || !sha.MatchString(c.SourcePin.RawSHA256) || !sha.MatchString(c.SourcePin.ReceiptSHA256) {
		return Plan{}, errors.New("FLEET_CAPACITY_CANDIDATE_DECODER_REQUIRED")
	}
	if len(c.ReasonCodes) > 0 {
		p.Result.ReasonCodes = append(p.Result.ReasonCodes, c.ReasonCodes...)
		return gap(p, "CAPACITY_CANDIDATE_COMPATIBILITY_UNPROVEN")
	}
	if hardware.Instance.ImageID != c.ImageID {
		return gap(p, "CAPACITY_CANDIDATE_IMAGE_COMPATIBILITY_UNPROVEN")
	}
	currentBaseline := hardware.Instance.Type == c.InstanceType
	allowed := false
	for _, typ := range model.Strings(in.Hardware, "candidate_types") {
		allowed = allowed || typ == c.InstanceType
	}
	if !allowed {
		return gap(p, "CAPACITY_CANDIDATE_NATIVE_HARDWARE_UNAVAILABLE")
	}
	// The original mapper retains the observed disk. It is safe for this
	// bounded comparison only when the selected template explicitly preserves
	// its one gp3 device and provisioned IOPS/throughput. Image defaults, multiple
	// disks, changed sizing and omitted fields remain unknown.
	devices := c.definition.Template.Data.BlockDevices
	if len(devices) != 1 || len(hardware.Volumes) != 1 || len(hardware.Instance.Devices) != 1 {
		return gap(p, "CAPACITY_CANDIDATE_STORAGE_COMPATIBILITY_UNPROVEN")
	}
	d, v := devices[0], hardware.Volumes[0]
	size, sizeErr := hardwareVolumeSize(in.HardwareEvidence.Raw, v.ID)
	if sizeErr != nil || size == nil || *size <= 0 || d.EBS == nil || d.EBS.VolumeSizeGiB == nil || *d.EBS.VolumeSizeGiB != *size || d.DeviceName != hardware.Instance.Devices[0].Device || d.VirtualName != "" || d.NoDevicePresent || d.EBS.VolumeType != "gp3" || v.Type != "gp3" || d.EBS.IOPS == nil || v.IOPS == nil || *d.EBS.IOPS != *v.IOPS || d.EBS.ThroughputMiB == nil || v.ThroughputMiBps == nil || *d.EBS.ThroughputMiB != *v.ThroughputMiBps {
		return gap(p, "CAPACITY_CANDIDATE_STORAGE_COMPATIBILITY_UNPROVEN")
	}
	forMapping := document(in.Hardware)
	forMapping["candidate_types"] = []string{c.InstanceType}
	var mapping native.CapacityMapping
	if currentBaseline {
		mapping, e = native.BuildCurrentCapacityModelInput(population, in.Profile, forMapping)
	} else {
		mapping, e = native.BuildCapacityModelInput(population, in.Profile, forMapping)
	}
	if e != nil {
		return Plan{}, e
	}
	p.Result.HardwareMapping = &mapping
	if mapping.Request == nil {
		p.Result.ReasonCodes = append(p.Result.ReasonCodes, mapping.ReasonCodes...)
		for _, reasons := range mapping.CandidateReasons {
			p.Result.ReasonCodes = append(p.Result.ReasonCodes, reasons...)
		}
		return gap(p, "CAPACITY_MEMBER_MAPPING_UNAVAILABLE")
	}
	if len(mapping.Request.Candidates) != 1 || mapping.Request.Candidates[0].ID != c.InstanceType || mapping.Request.Candidates[0].Count != 1 {
		return Plan{}, errors.New("FLEET_CAPACITY_CANDIDATE_MAPPING_INVALID")
	}
	p.Request, e = frozen(mapping.Request)
	if e != nil {
		return Plan{}, e
	}
	p.Result.ModelRequested = true
	p.Result.InputKind = "MODEL_REQUEST"
	if currentBaseline {
		if telemetry.Hash(p.Request.Current) != telemetry.Hash(p.Request.Candidates[0]) {
			return Plan{}, errors.New("FLEET_CAPACITY_BASELINE_CATALOG_CHANGED")
		}
		p.Result.InputKind = "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST"
		p.Result.ReasonCodes = append(p.Result.ReasonCodes, "CURRENT_CONFIGURATION_BASELINE_ONLY")
	}
	p.Result.InputHash = telemetry.Hash(p.Request)
	p.Result.DemandMeaning = native.CapacityRequestProxyRole
	p.Result, e = finish(p.Result)
	return p, e
}

func Evaluate(ctx context.Context, p Plan, calculator Calculator, now time.Time) (MemberResult, error) {
	if p.Result.ID != resultID(p.Result) || ValidateScope(p.Result.Scope) != nil || p.Result.ExecutionAuthorized || p.Result.GroupCapacityAuthorized || p.Result.VerifiedSaving != nil || p.Result.EstimatedSaving != nil || p.Result.ChangePlanID != nil || p.Result.CompletedBusinessWorkPreserved != nil {
		return MemberResult{}, errors.New("FLEET_CAPACITY_PLAN_INVALID")
	}
	if p.Request == nil {
		return finish(p.Result)
	}
	baseline := p.Result.InputKind == "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST"
	if baseline && (len(p.Request.Candidates) != 1 || p.Result.CandidateTemplate == nil || p.Result.CandidateTemplate.InstanceType != p.Request.Current.ID || telemetry.Hash(p.Request.Current) != telemetry.Hash(p.Request.Candidates[0]) || !containsBaselineReason(p.Result.ReasonCodes)) {
		return MemberResult{}, errors.New("FLEET_CAPACITY_BASELINE_CATALOG_CHANGED")
	}
	if !baseline && (containsBaselineReason(p.Result.ReasonCodes) || len(p.Request.Candidates) == 1 && p.Request.Candidates[0].ID == p.Request.Current.ID) {
		return MemberResult{}, errors.New("FLEET_CAPACITY_BASELINE_MARKER_CHANGED")
	}
	if !p.Result.ModelRequested || p.Result.ModelEvaluated || p.Result.ModelEvaluation != nil || p.Result.CapacitySuitable != nil || p.Result.InputHash != telemetry.Hash(p.Request) || (p.Result.InputKind != "MODEL_REQUEST" && !baseline) || p.Result.Binding == nil || p.Request.Binding != *p.Result.Binding || p.Request.AsOf.Before(now.Add(-2*time.Minute)) || p.Request.AsOf.After(now.Add(5*time.Second)) {
		return MemberResult{}, errors.New("FLEET_CAPACITY_MODEL_INPUT_CHANGED")
	}
	r := p.Result
	if calculator == nil {
		r.Status = "UNAVAILABLE"
		r.ReasonCodes = append(r.ReasonCodes, "CAPACITY_MODEL_NOT_CONFIGURED")
		return finish(r)
	}
	raw, e := calculator.Calculate(ctx, *p.Request)
	if e != nil {
		r.Status = "UNAVAILABLE"
		r.ReasonCodes = append(r.ReasonCodes, "CAPACITY_MODEL_UNAVAILABLE")
		return finish(r)
	}
	calculated, e := native.DecodeCapacityModelResult(raw, *p.Request)
	if e != nil {
		r.Status = "UNAVAILABLE"
		r.ReasonCodes = append(r.ReasonCodes, "CAPACITY_MODEL_RESPONSE_REJECTED")
		return finish(r)
	}
	if len(calculated.Candidates) != 1 {
		return MemberResult{}, errors.New("FLEET_CAPACITY_MODEL_CANDIDATE_CHANGED")
	}
	r.ModelEvaluated = true
	r.ModelEvaluation = &calculated
	if calculated.Candidates[0].Status == "INSUFFICIENT_OBSERVATION" {
		r.Status = "UNAVAILABLE"
	} else {
		suitable := calculated.Candidates[0].CapacitySuitable
		r.CapacitySuitable = &suitable
	}
	r.ReasonCodes = append(r.ReasonCodes, calculated.ReasonCodes...)
	r.ReasonCodes = append(r.ReasonCodes, calculated.Candidates[0].ReasonCodes...)
	return finish(r)
}

func containsBaselineReason(reasons []string) bool {
	for _, reason := range reasons {
		if reason == "CURRENT_CONFIGURATION_BASELINE_ONLY" {
			return true
		}
	}
	return false
}

func Summarize(scope Scope, members []MemberResult) (BatchResult, error) {
	r := BatchResult{SchemaVersion: "1", Scope: scope, Members: []MemberReference{}, Coverage: "UNAVAILABLE", Status: "BLOCKED", ReasonCodes: []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE", "GROUP_HISTORICAL_INTERVAL_OWNERSHIP_UNPROVEN", "COMPLETED_BUSINESS_WORK_PRESERVATION_UNPROVEN"}}
	invalid := errors.New("FLEET_CAPACITY_COMPLETE_POPULATION_REQUIRED")
	if ValidateScope(scope) != nil || len(members) != len(scope.CurrentMemberIDs) {
		return r, invalid
	}
	allowed := map[string]bool{}
	for _, id := range scope.CurrentMemberIDs {
		allowed[id] = true
	}
	seen := map[string]bool{}
	for _, m := range members {
		if !allowed[m.InstanceID] || seen[m.InstanceID] || m.ID != resultID(m) || fleetbilling.Hash(m.Scope) != fleetbilling.Hash(scope) || m.ExecutionAuthorized || m.GroupCapacityAuthorized || m.CompletedBusinessWorkPreserved != nil || m.VerifiedSaving != nil || m.EstimatedSaving != nil || m.ChangePlanID != nil {
			return r, invalid
		}
		seen[m.InstanceID] = true
		r.Members = append(r.Members, MemberReference{InstanceID: m.InstanceID, ResultID: m.ID, SHA256: fleetbilling.Hash(m), Status: m.Status, ModelEvaluated: m.ModelEvaluated, CapacitySuitable: m.CapacitySuitable})
	}
	return SummarizeReferences(scope, r.Members)
}

// SummarizeReferences consumes bounded metadata selected from the private
// repository. Complete must compare every reference to its issued member row;
// these hashes do not authenticate caller-uploaded results. This lets workers
// resume a full roster without retaining every model response in memory.
func SummarizeReferences(scope Scope, members []MemberReference) (BatchResult, error) {
	r := BatchResult{SchemaVersion: "1", Scope: scope, Members: append([]MemberReference{}, members...), Coverage: "UNAVAILABLE", Status: "BLOCKED", ReasonCodes: []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE", "GROUP_HISTORICAL_INTERVAL_OWNERSHIP_UNPROVEN", "COMPLETED_BUSINESS_WORK_PRESERVATION_UNPROVEN"}}
	if ValidateScope(scope) != nil || len(members) != len(scope.CurrentMemberIDs) {
		return r, errors.New("FLEET_CAPACITY_COMPLETE_POPULATION_REQUIRED")
	}
	allowed, seen := map[string]bool{}, map[string]bool{}
	for _, id := range scope.CurrentMemberIDs {
		allowed[id] = true
	}
	evaluated := 0
	for _, m := range members {
		if !allowed[m.InstanceID] || seen[m.InstanceID] || !sha.MatchString(m.SHA256) || !strings.HasPrefix(m.ResultID, "fleet-capacity-member-") || !sha.MatchString(strings.TrimPrefix(m.ResultID, "fleet-capacity-member-")) || (m.Status != "BLOCKED" && m.Status != "UNAVAILABLE") || (!m.ModelEvaluated && m.CapacitySuitable != nil) {
			return r, errors.New("FLEET_CAPACITY_COMPLETE_POPULATION_REQUIRED")
		}
		seen[m.InstanceID] = true
		if m.ModelEvaluated {
			evaluated++
		}
	}
	sort.Slice(r.Members, func(i, j int) bool { return r.Members[i].InstanceID < r.Members[j].InstanceID })
	if scope.PopulationStatus == "OBSERVED_POINT" {
		if len(members) == 0 {
			r.Coverage = "EMPTY_POINT"
			r.ReasonCodes = append(r.ReasonCodes, "CAPACITY_ORIGINAL_MEMBERSHIP_EMPTY")
		} else if evaluated == len(members) {
			r.Coverage = "ALL_MEMBER_RESULTS_OBSERVED"
		} else {
			r.Coverage = "PARTIAL"
		}
	}
	r.ReasonCodes = unique(r.ReasonCodes)
	return frozen(r)
}
