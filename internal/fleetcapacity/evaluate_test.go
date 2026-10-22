package fleetcapacity

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

func capacityScope() (Scope, time.Time) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	selection := func(name, suffix string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + suffix + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: strings.Repeat("a", 64)}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: strings.Repeat("b", 64)}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: strings.Repeat("c", 64)}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: strings.Repeat("d", 64)}
	}
	s := Scope{Selection: fleetassessment.Selection{Groups: fleetbilling.GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: strings.Repeat("e", 64)}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: strings.Repeat("f", 64)}, Binding: g.Binding{Old: selection("old", "1"), Candidate: selection("candidate", "2")}}, SafetyProfile: g.VersionedRef{ID: "profile", Version: 1, SHA256: strings.Repeat("a", 64)}}, SnapshotSHA256: strings.Repeat("b", 64), PopulationStatus: "OBSERVED_POINT", ObservedAt: now, CurrentMemberIDs: []string{"i-0123456789abcdef0", "i-22222222222222222"}, MembershipPins: []fleetbilling.GroupNativePin{}}
	for _, name := range []string{"old", "candidate"} {
		s.MembershipPins = append(s.MembershipPins, fleetbilling.GroupNativePin{ReceiptID: name + "-membership", RevisionID: name + "-revision", ReceiptSHA256: strings.Repeat("a", 64), RawSHA256: strings.Repeat("b", 64), ReceiptVersionID: "receipt-version", RevisionVersionID: "revision-version"})
	}
	return s, now
}

func TestMissingMappingAndLateRevocationKeepTheCompleteOriginalPopulation(t *testing.T) {
	s, now := capacityScope()
	p, e := Prepare(MemberInput{BatchID: "batch", Scope: s, InstanceID: s.CurrentMemberIDs[0]}, now)
	if e != nil || p.Request != nil || p.Result.Status != "UNAVAILABLE" || p.Result.ModelRequested || p.Result.Binding != nil {
		t.Fatal("missing individual mapping became a request", e)
	}
	first, e := Evaluate(context.Background(), p, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	late, e := Unavailable(s, "batch", s.CurrentMemberIDs[1], "CAPACITY_SOURCE_REVOKED", now.Add(48*time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if late.InputKind != "UNAVAILABLE" || late.Status != "UNAVAILABLE" || late.Binding != nil || late.ResourceID != "" || late.Hardware != nil || late.Telemetry != nil || late.CandidateTemplate != nil || late.HardwareMapping != nil || late.ModelEvaluation != nil || late.CapacitySuitable != nil || late.ModelRequested || late.ModelEvaluated {
		t.Fatal("late gap manufactured fresh evidence")
	}
	full, e := Summarize(s, []MemberResult{late, first})
	if e != nil || len(full.Members) != 2 || full.Coverage != "PARTIAL" || full.ExecutionAuthorized || full.GroupCapacityAuthorized || full.VerifiedSaving != nil || full.CompletedBusinessWorkPreserved != nil {
		t.Fatal("complete unknown results became group authority", e)
	}
	for _, rows := range [][]MemberResult{{first}, {first, first}, {first, late, late}} {
		if _, e := Summarize(s, rows); e == nil {
			t.Fatal("missing or duplicate original member accepted")
		}
	}
	// Returned observations are immutable even when later repository maps/slices
	// change. The original point remains historical, not continuous ownership.
	s.CurrentMemberIDs[0] = "i-aaaaaaaaaaaaaaaaa"
	s.MembershipPins[0].ReceiptID = "changed"
	if first.Scope.CurrentMemberIDs[0] != "i-0123456789abcdef0" || first.Scope.MembershipPins[0].ReceiptID != "old-membership" {
		t.Fatal("returned result aliases caller inputs")
	}
}

func TestEmptyNativePointAndMissingMembershipRemainDistinct(t *testing.T) {
	s, _ := capacityScope()
	s.CurrentMemberIDs = []string{}
	observed, e := Summarize(s, nil)
	if e != nil || observed.Coverage != "EMPTY_POINT" {
		t.Fatal("real empty point lost", e)
	}
	s.PopulationStatus = "UNAVAILABLE"
	s.MembershipPins = nil
	missing, e := Summarize(s, nil)
	if e != nil || missing.Coverage != "UNAVAILABLE" {
		t.Fatal("missing membership became empty observed fleet", e)
	}
	s.CurrentMemberIDs = []string{"i-0123456789abcdef0"}
	if ValidateScope(s) == nil {
		t.Fatal("unobserved membership carried member identities")
	}
}

func templateEvidence(t *testing.T, s Scope, now time.Time, extra string) (NativeEvidence, provider.FleetLaunchTemplate) {
	t.Helper()
	id := "lt-0123456789abcdef0"
	want := provider.FleetLaunchTemplate{ID: id, Version: "2"}
	body := `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet><item><launchTemplateId>` + id + `</launchTemplateId><versionNumber>2</versionNumber><launchTemplateData><instanceType>m6i.large</instanceType><imageId>ami-0123456789abcdef0</imageId><placement><tenancy>default</tenancy></placement><blockDeviceMappingSet><item><deviceName>/dev/sda1</deviceName><ebs><volumeType>gp3</volumeType><volumeSize>64</volumeSize><iops>3000</iops><throughput>125</throughput></ebs></item></blockDeviceMappingSet>` + extra + `</launchTemplateData></item></launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`
	v := url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {id}, "LaunchTemplateVersion.1": {"2"}}
	var raw bytes.Buffer
	selector := v.Encode()
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
	raw.WriteString(selector)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.WriteString(body)
	var parsed struct {
		Items []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	if xml.Unmarshal([]byte(body), &parsed) != nil {
		t.Fatal("test fixture malformed")
	}
	ref := model.Document{"bucket": "fixture-raw", "key": "tenant/tenant/group/template", "version_id": "receipt-version", "body_sha256": fleetbilling.BytesHash(raw.Bytes())}
	revisionRef := document(ref)
	revisionRef["version_id"] = "revision-version"
	d := model.Document{"id": "template-receipt", "revision_id": "template-revision", "source_id": "source", "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "writer_role": "finops_ingester", "config_hash": s.Selection.Groups.Binding.Candidate.SourceConfigSHA256, "registration_version": int64(1), "collected_at": now.Format(time.RFC3339Nano), "raw_object": ref, "requests": []provider.FleetTemplateRequest{{ID: id, Version: 2}}, "templates": parsed.Items}
	r := model.Document{"id": "template-revision", "source_id": "source", "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "writer_role": "finops_ingester", "config_hash": s.Selection.Groups.Binding.Candidate.SourceConfigSHA256, "registration_version": int64(1), "raw_object": revisionRef}
	return NativeEvidence{Receipt: d, Revision: r, Raw: raw.Bytes(), RevisionRaw: append([]byte{}, raw.Bytes()...)}, want
}

func TestCandidateRequiresExactNativeSelectorAndBothImmutableRawVersions(t *testing.T) {
	s, now := capacityScope()
	e, want := templateEvidence(t, s, now, "")
	c, err := DecodeCandidateTemplate(e, s.Selection.Groups.Binding.Candidate, want, now)
	if err != nil || c.InstanceType != "m6i.large" || c.Version != "2" || len(c.ReasonCodes) != 0 || c.SourcePin.ReceiptVersionID != "receipt-version" || c.SourcePin.RevisionVersionID != "revision-version" || c.definition.Template.Data.BlockDevices[0].EBS.VolumeSizeGiB == nil {
		t.Fatal("exact native candidate unavailable", err)
	}
	for _, mutate := range []func(*NativeEvidence, *provider.FleetLaunchTemplate){func(e *NativeEvidence, _ *provider.FleetLaunchTemplate) {
		e.RevisionRaw = []byte("other immutable version")
	}, func(_ *NativeEvidence, w *provider.FleetLaunchTemplate) { w.Version = "$Latest" }, func(e *NativeEvidence, _ *provider.FleetLaunchTemplate) {
		e.Raw = append(append([]byte{}, e.Raw...), 0)
	}, func(e *NativeEvidence, _ *provider.FleetLaunchTemplate) {
		e.Receipt = document(e.Receipt)
		e.Receipt["source_id"] = "foreign"
	}, func(e *NativeEvidence, _ *provider.FleetLaunchTemplate) {
		e.Receipt = document(e.Receipt)
		r := document(e.Receipt["raw_object"])
		r["version_id"] = "null"
		e.Receipt["raw_object"] = r
	}, func(e *NativeEvidence, _ *provider.FleetLaunchTemplate) {
		e.Receipt = document(e.Receipt)
		e.Receipt["templates"] = []provider.FleetTemplateVersion{}
	}} {
		bad := e
		w := want
		mutate(&bad, &w)
		if _, err := DecodeCandidateTemplate(bad, s.Selection.Groups.Binding.Candidate, w, now); err == nil {
			t.Fatal("unbound raw/selector/canonical candidate accepted")
		}
	}
	if _, err := DecodeCandidateTemplate(e, s.Selection.Groups.Binding.Candidate, want, now.Add(6*time.Minute)); err == nil {
		t.Fatal("stale native candidate admitted as current")
	}
}

func TestCandidateEffectiveOptionsAreUnknownRatherThanSilentlyIgnored(t *testing.T) {
	s, now := capacityScope()
	for _, extra := range []string{`<cpuOptions><coreCount>1</coreCount></cpuOptions>`, `<instanceMarketOptions><marketType>spot</marketType></instanceMarketOptions>`, `<networkInterfaceSet><item><subnetId>subnet-0123456789abcdef0</subnetId></item></networkInterfaceSet>`} {
		e, want := templateEvidence(t, s, now, extra)
		c, err := DecodeCandidateTemplate(e, s.Selection.Groups.Binding.Candidate, want, now)
		if err != nil || len(c.ReasonCodes) == 0 {
			t.Fatal("effective native option vanished from compatibility", err)
		}
	}
}
