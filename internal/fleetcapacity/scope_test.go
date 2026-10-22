package fleetcapacity

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

func membershipEvidence(t *testing.T, selected g.Selection, ids []string, now time.Time) NativeEvidence {
	t.Helper()
	name := strings.Split(selected.Target.ASGARN, ":autoScalingGroupName/")[1]
	members := ""
	for _, id := range ids {
		members += "<member><InstanceId>" + id + "</InstanceId><LifecycleState>InService</LifecycleState></member>"
	}
	body := `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups><member><AutoScalingGroupName>` + name + `</AutoScalingGroupName><AutoScalingGroupARN>` + selected.Target.ASGARN + `</AutoScalingGroupARN><Instances>` + members + `</Instances><LaunchTemplate><LaunchTemplateId>lt-0123456789abcdef0</LaunchTemplateId><Version>2</Version></LaunchTemplate></member></AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`
	selector := url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "AutoScalingGroupNames.member.1": {name}}.Encode()
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
	raw.WriteString(selector)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.WriteString(body)
	var response struct {
		Groups []provider.FleetGroup `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	if xml.Unmarshal([]byte(body), &response) != nil {
		t.Fatal("bad test XML")
	}
	for i := range response.Groups {
		if response.Groups[i].Members == nil {
			response.Groups[i].Members = []provider.FleetMember{}
		}
	}
	ref := model.Document{"bucket": "fixture-raw", "key": "tenant/tenant/group/" + name, "version_id": "receipt-version", "body_sha256": fleetbilling.BytesHash(raw.Bytes())}
	rr := document(ref)
	rr["version_id"] = "revision-version"
	id := name + "-membership"
	receipt := model.Document{"id": id, "revision_id": id + "-revision", "source_id": selected.SourceID, "kind": "AWS_FLEET_MEMBERSHIP", "writer_role": "finops_ingester", "registration_version": selected.SourceRegistrationVersion, "config_hash": selected.SourceConfigSHA256, "collected_at": now.Format(time.RFC3339Nano), "raw_object": ref, "history_registration_id": selected.Registration.ID, "history_registration_version": selected.Registration.Version, "history_registration_hash": selected.Registration.SHA256, "groups": response.Groups, "binding": model.Document{"tenant_id": selected.Target.TenantID, "workload_id": selected.Target.WorkloadID, "provider": "AWS", "account_id": selected.Target.AccountID, "region": selected.Target.Region}}
	revision := model.Document{"id": id + "-revision", "source_id": selected.SourceID, "kind": "AWS_FLEET_MEMBERSHIP", "writer_role": "finops_ingester", "registration_version": selected.SourceRegistrationVersion, "config_hash": selected.SourceConfigSHA256, "raw_object": rr}
	return NativeEvidence{Receipt: receipt, Revision: revision, Raw: raw.Bytes(), RevisionRaw: append([]byte{}, raw.Bytes()...)}
}

func TestScopeRetainsOriginalRosterWhenCandidateEvidenceIsMissing(t *testing.T) {
	s, now := capacityScope()
	old := membershipEvidence(t, s.Selection.Groups.Binding.Old, s.CurrentMemberIDs, now)
	c, e := CaptureScope(ScopeInput{RequestID: "request", Selection: s.Selection, OldMembership: &old}, now)
	if e != nil || c.Scope.PopulationStatus != "OBSERVED_POINT" || len(c.Scope.CurrentMemberIDs) != 2 || len(c.Scope.MembershipPins) != 1 || c.CandidateTemplate != nil || c.Scope.SnapshotSHA256 != ScopeHash(c) {
		t.Fatal("old roster collapsed with missing candidate", e)
	}
	originalHash := c.Scope.SnapshotSHA256
	c.ReasonCodes = append(c.ReasonCodes, "TAMPERED")
	if ScopeHash(c) == originalHash {
		t.Fatal("outer immutable selection not covered")
	}
	old.Receipt = document(old.Receipt)
	old.Receipt["history_registration_hash"] = strings.Repeat("f", 64)
	if _, e = CaptureScope(ScopeInput{RequestID: "request", Selection: s.Selection, OldMembership: &old}, now); e == nil {
		t.Fatal("foreign registration accepted")
	}
}

func TestScopeAuthenticatesActualEmptyGroupAndConcreteCandidate(t *testing.T) {
	s, now := capacityScope()
	old := membershipEvidence(t, s.Selection.Groups.Binding.Old, nil, now)
	candidate := membershipEvidence(t, s.Selection.Groups.Binding.Candidate, nil, now)
	template, _ := templateEvidence(t, s, now, "")
	c, e := CaptureScope(ScopeInput{RequestID: "request", Selection: s.Selection, OldMembership: &old, CandidateMembership: &candidate, Templates: []NativeEvidence{template}}, now)
	if e != nil || c.Scope.PopulationStatus != "OBSERVED_POINT" || len(c.Scope.CurrentMemberIDs) != 0 || c.CandidateTemplate == nil || c.CandidateTemplate.Version != "2" || len(c.SourcePins) != 3 {
		t.Fatal("real empty native point lost", e)
	}
	r, e := SummarizeReferences(c.Scope, nil)
	if e != nil || r.Coverage != "EMPTY_POINT" {
		t.Fatal("empty point turned unavailable", e)
	}
	if _, e = CaptureScope(ScopeInput{RequestID: "request", Selection: s.Selection, OldMembership: &old}, now.Add(6*time.Minute)); e == nil {
		t.Fatal("stale point captured")
	}
}

func TestCandidateVersionRemainsExactBeyondBrowserIntegerRange(t *testing.T) {
	s, now := capacityScope()
	e, w := templateEvidence(t, s, now, "")
	oldRaw := e.Raw
	// Reframe the genuine native response and selector with one exact large version.
	nativePages, err := pages(oldRaw)
	if err != nil {
		t.Fatal(err)
	}
	p := nativePages[0]
	p.selector.Set("LaunchTemplateVersion.1", "9007199254740993")
	body := strings.ReplaceAll(string(p.body), "<versionNumber>2</versionNumber>", "<versionNumber>9007199254740993</versionNumber>")
	var raw bytes.Buffer
	selector := p.selector.Encode()
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
	raw.WriteString(selector)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.WriteString(body)
	var response struct {
		Items []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	if xml.Unmarshal([]byte(body), &response) != nil {
		t.Fatal("XML")
	}
	e.Receipt = document(e.Receipt)
	e.Revision = document(e.Revision)
	e.Receipt["requests"] = []provider.FleetTemplateRequest{{ID: w.ID, Version: 9007199254740993}}
	e.Receipt["templates"] = response.Items
	for _, d := range []model.Document{e.Receipt, e.Revision} {
		ref := document(d["raw_object"])
		ref["body_sha256"] = fleetbilling.BytesHash(raw.Bytes())
		d["raw_object"] = ref
	}
	e.Raw = raw.Bytes()
	e.RevisionRaw = append([]byte{}, raw.Bytes()...)
	w.Version = "9007199254740993"
	c, err := DecodeCandidateTemplate(e, s.Selection.Groups.Binding.Candidate, w, now)
	if err != nil || c.Version != w.Version {
		t.Fatal("native version rounded", err)
	}
}

func TestUnsupportedNativeTemplateKeepsTheIssuedRosterAndExplicitGaps(t *testing.T) {
	s, now := capacityScope()
	old := membershipEvidence(t, s.Selection.Groups.Binding.Old, s.CurrentMemberIDs, now)
	candidate := membershipEvidence(t, s.Selection.Groups.Binding.Candidate, nil, now)
	for _, extra := range []string{`<instanceRequirements><vCpuCount><min>1</min></vCpuCount></instanceRequirements>`, `<cpuOptions><coreCount>1</coreCount></cpuOptions>`} {
		template, _ := templateEvidence(t, s, now, extra)
		capture, e := CaptureScope(ScopeInput{RequestID: "request", Selection: s.Selection, OldMembership: &old, CandidateMembership: &candidate, Templates: []NativeEvidence{template}}, now)
		if e != nil || capture.CandidateTemplate != nil || len(capture.SourcePins) != 3 || len(capture.Scope.CurrentMemberIDs) != 2 || capture.Scope.PopulationStatus != "OBSERVED_POINT" || capture.Scope.SnapshotSHA256 != ScopeHash(capture) {
			t.Fatal("unsupported native candidate lost complete point", e)
		}
		reasons := strings.Join(capture.ReasonCodes, ",")
		if !strings.Contains(reasons, "CAPACITY_CANDIDATE_NATIVE_TEMPLATE_UNAVAILABLE") || (!strings.Contains(reasons, "CAPACITY_CANDIDATE_CPU_OPTIONS_UNSUPPORTED") && !strings.Contains(reasons, "CAPACITY_CANDIDATE_EXPLICIT_TYPE_IMAGE_REQUIRED")) {
			t.Fatal("native incompatibility reasons disappeared")
		}
		members := []MemberResult{}
		for _, id := range capture.Scope.CurrentMemberIDs {
			member, e := Unavailable(capture.Scope, "request", id, "CAPACITY_CANDIDATE_NATIVE_TEMPLATE_UNAVAILABLE", now)
			if e != nil || member.ModelRequested || member.ModelEvaluated || member.CapacitySuitable != nil || member.CandidateTemplate != nil {
				t.Fatal("unsupported candidate fabricated model", e)
			}
			members = append(members, member)
		}
		summary, e := Summarize(capture.Scope, members)
		if e != nil || len(summary.Members) != 2 || summary.Coverage != "PARTIAL" {
			t.Fatal("unsupported candidate became missing population", e)
		}
	}
}
