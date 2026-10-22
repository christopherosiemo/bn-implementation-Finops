package fleetcapacity

import (
	"encoding/xml"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

func decodeMembership(e NativeEvidence, selected g.Selection, now time.Time) (provider.FleetGroup, fleetbilling.GroupNativePin, error) {
	var group provider.FleetGroup
	pin, err := nativePin(e, selected, "AWS_FLEET_MEMBERSHIP", now)
	if err != nil {
		return group, pin, err
	}
	invalid := errors.New("FLEET_CAPACITY_MEMBERSHIP_NATIVE_INVALID")
	wantBinding := model.Document{"tenant_id": selected.Target.TenantID, "workload_id": selected.Target.WorkloadID, "provider": selected.Target.Provider, "account_id": selected.Target.AccountID, "region": selected.Target.Region}
	if model.String(e.Receipt, "history_registration_id") != selected.Registration.ID || model.Number(e.Receipt, "history_registration_version") != selected.Registration.Version || model.String(e.Receipt, "history_registration_hash") != selected.Registration.SHA256 || fleetbilling.Hash(e.Receipt["binding"]) != fleetbilling.Hash(wantBinding) {
		return group, pin, invalid
	}
	parts := strings.SplitN(selected.Target.ASGARN, ":autoScalingGroupName/", 2)
	if len(parts) != 2 {
		return group, pin, invalid
	}
	items, err := pages(e.Raw)
	if err != nil {
		return group, pin, err
	}
	groups := []provider.FleetGroup{}
	next := ""
	tokens := map[string]bool{}
	for n, p := range items {
		v := p.selector
		if v.Get("Action") != "DescribeAutoScalingGroups" || v.Get("Version") != "2011-01-01" || v.Get("MaxRecords") != "100" || v.Get("NextToken") != next || v.Get("AutoScalingGroupNames.member.1") != parts[1] {
			return group, pin, invalid
		}
		for key := range v {
			if key != "Action" && key != "Version" && key != "MaxRecords" && key != "NextToken" && key != "AutoScalingGroupNames.member.1" {
				return group, pin, invalid
			}
		}
		var response struct {
			XMLName xml.Name
			Result  struct {
				Groups []provider.FleetGroup `xml:"AutoScalingGroups>member"`
				Next   string                `xml:"NextToken"`
			} `xml:"DescribeAutoScalingGroupsResult"`
		}
		if xml.Unmarshal(p.body, &response) != nil || response.XMLName.Local != "DescribeAutoScalingGroupsResponse" {
			return group, pin, invalid
		}
		for _, g := range response.Result.Groups {
			if g.Members == nil {
				g.Members = []provider.FleetMember{}
			}
			groups = append(groups, g)
		}
		next = response.Result.Next
		if next == "" && n != len(items)-1 || next != "" && tokens[next] {
			return group, pin, invalid
		}
		tokens[next] = true
	}
	if next != "" || len(groups) != 1 || fleetbilling.Hash(groups) != fleetbilling.Hash(e.Receipt["groups"]) {
		return group, pin, invalid
	}
	group = groups[0]
	if group.ARN != selected.Target.ASGARN || group.Name != parts[1] || len(group.Members) > MaximumMembers {
		return group, pin, invalid
	}
	seen := map[string]bool{}
	for _, m := range group.Members {
		if !instance.MatchString(m.InstanceID) || seen[m.InstanceID] {
			return group, pin, invalid
		}
		seen[m.InstanceID] = true
	}
	return group, pin, nil
}

// ScopeHash is a versioned content hash of the immutable scope document. The
// repository repeats it after resolving actual selected issued rows, before
// publication. It is not authentication or a fresh input-authority token.
func ScopeHash(c ScopeCapture) string { c.Scope.SnapshotSHA256 = ""; return fleetbilling.Hash(c) }

// CaptureScope authenticates the archived membership/template components of a
// private scope selection. Missing candidate membership never erases a known
// original roster. Current repository/source/profile checks remain mandatory
// before this immutable snapshot is issued and before each observed member.
func CaptureScope(in ScopeInput, now time.Time) (ScopeCapture, error) {
	out := ScopeCapture{SchemaVersion: "1", RequestID: in.RequestID, Scope: Scope{Selection: in.Selection, PopulationStatus: "UNAVAILABLE", ObservedAt: now.UTC(), MembershipPins: []fleetbilling.GroupNativePin{}, CurrentMemberIDs: []string{}}, SourcePins: []fleetbilling.GroupNativePin{}, ReasonCodes: []string{"GROUP_HISTORICAL_INTERVAL_OWNERSHIP_UNPROVEN", "EXECUTION_AUTHORITY_NOT_GRANTED"}}
	if in.RequestID == "" || now.IsZero() || fleetbilling.ValidateGroupSelection(in.Selection.Groups) != nil || in.Selection.SafetyProfile.ID == "" || in.Selection.SafetyProfile.Version < 1 || !sha.MatchString(in.Selection.SafetyProfile.SHA256) || len(in.Templates) > 2 {
		return out, errors.New("FLEET_CAPACITY_SCOPE_SELECTION_INVALID")
	}
	if in.OldMembership == nil {
		out.ReasonCodes = append(out.ReasonCodes, "CAPACITY_ORIGINAL_MEMBERSHIP_UNAVAILABLE")
	} else {
		old, pin, e := decodeMembership(*in.OldMembership, in.Selection.Groups.Binding.Old, now)
		if e != nil {
			return out, e
		}
		out.Scope.PopulationStatus = "OBSERVED_POINT"
		out.Scope.ObservedAt, _ = time.Parse(time.RFC3339Nano, model.String(in.OldMembership.Receipt, "collected_at"))
		out.Scope.MembershipPins = append(out.Scope.MembershipPins, pin)
		out.SourcePins = append(out.SourcePins, pin)
		for _, m := range old.Members {
			out.Scope.CurrentMemberIDs = append(out.Scope.CurrentMemberIDs, m.InstanceID)
		}
		sort.Strings(out.Scope.CurrentMemberIDs)
	}
	var candidate *provider.FleetGroup
	if in.CandidateMembership == nil {
		out.ReasonCodes = append(out.ReasonCodes, "CAPACITY_CANDIDATE_MEMBERSHIP_UNAVAILABLE")
	} else {
		group, pin, e := decodeMembership(*in.CandidateMembership, in.Selection.Groups.Binding.Candidate, now)
		if e != nil {
			return out, e
		}
		candidate = &group
		out.Scope.MembershipPins = append(out.Scope.MembershipPins, pin)
		out.SourcePins = append(out.SourcePins, pin)
	}
	for _, e := range in.Templates {
		selected := in.Selection.Groups.Binding.Old
		if model.String(e.Receipt, "source_id") == in.Selection.Groups.Binding.Candidate.SourceID {
			selected = in.Selection.Groups.Binding.Candidate
		}
		pin, err := nativePin(e, selected, "AWS_FLEET_LAUNCH_TEMPLATES", now)
		if err != nil {
			return out, err
		}
		out.SourcePins = append(out.SourcePins, pin)
		if candidate == nil || candidate.MixedPolicy != nil || selected.SourceID != in.Selection.Groups.Binding.Candidate.SourceID {
			continue
		}
		var requests []provider.FleetTemplateRequest
		if decode(e.Receipt["requests"], &requests) != nil {
			return out, errors.New("FLEET_CAPACITY_TEMPLATE_REQUEST_INVALID")
		}
		matching := false
		for _, r := range requests {
			matching = matching || r.ID == candidate.LaunchTemplate.ID && candidate.LaunchTemplate.Version == formatVersion(r.Version)
		}
		if !matching {
			continue
		}
		decoded, err := DecodeCandidateTemplate(e, in.Selection.Groups.Binding.Candidate, candidate.LaunchTemplate, now)
		if err != nil {
			return out, err
		}
		// A native selector can legitimately describe dynamic requirements or
		// effective options this bounded physical mapper cannot resolve. Keep
		// the issued point and its reasons, without issuing a concrete candidate
		// that the repository could mistake for a model-ready configuration.
		if len(decoded.ReasonCodes) > 0 {
			out.ReasonCodes = append(out.ReasonCodes, decoded.ReasonCodes...)
			continue
		}
		if out.CandidateTemplate != nil && out.CandidateTemplate.DefinitionSHA256 != decoded.DefinitionSHA256 {
			return out, errors.New("FLEET_CAPACITY_TEMPLATE_AMBIGUOUS")
		}
		out.CandidateTemplate = decoded
	}
	if out.CandidateTemplate == nil {
		out.ReasonCodes = append(out.ReasonCodes, "CAPACITY_CANDIDATE_NATIVE_TEMPLATE_UNAVAILABLE")
	}
	seen := map[string]bool{}
	for _, pin := range out.SourcePins {
		if seen[pin.ReceiptID] {
			return out, errors.New("FLEET_CAPACITY_SCOPE_PIN_DUPLICATE")
		}
		seen[pin.ReceiptID] = true
	}
	out.ReasonCodes = unique(out.ReasonCodes)
	out.Scope.SnapshotSHA256 = ScopeHash(out)
	if ValidateScope(out.Scope) != nil {
		return out, errors.New("FLEET_CAPACITY_SCOPE_INVALID")
	}
	return out, nil
}

func formatVersion(v uint64) string { return strconv.FormatUint(v, 10) }
