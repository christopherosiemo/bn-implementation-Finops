package source

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

func historyNativeFixture(t *testing.T, now time.Time) (fleethistory.Registration, provider.FleetInventoryEvidence) {
	t.Helper()
	p := sourceFleetPlan("history-tenant")
	g := nativeFleetGroup(p, p.Old, 2)
	g.ARN = "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:01234567-89ab-cdef-0123-456789abcdef:autoScalingGroupName/asg-blue"
	r := fleethistory.Registration{SchemaVersion: "1", ID: "history", Version: 1, FleetID: "fleet-blue", Binding: fleethistory.Binding{TenantID: p.Binding.TenantID, WorkloadID: p.Binding.WorkloadID, Provider: "AWS", AccountID: p.Binding.AccountID, Region: p.Binding.Region}, ASGARN: g.ARN, SourceID: "source", SourceSystem: "AWS_SOURCE_CONNECTION", SourceRegistrationVersion: 1, SourceConfigHash: ConfigurationHash(FixtureRegistration(p.Binding.TenantID, "source")), CadenceSeconds: 60, MaxGapSeconds: 120}
	return r, historyFramedFixture(t, []provider.FleetGroup{g}, now)
}

func historyFramedFixture(t *testing.T, groups []provider.FleetGroup, now time.Time) provider.FleetInventoryEvidence {
	t.Helper()
	var response struct {
		XMLName xml.Name
		Result  struct {
			Groups []provider.FleetGroup `xml:"AutoScalingGroups>member"`
		} `xml:"DescribeAutoScalingGroupsResult"`
	}
	response.XMLName.Local = "DescribeAutoScalingGroupsResponse"
	response.Result.Groups = groups
	body, err := xml.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	selector := url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "AutoScalingGroupNames.member.1": {"asg-blue"}}.Encode()
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
	raw.WriteString(selector)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.Write(body)
	return provider.FleetInventoryEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", CollectedAt: now, Groups: groups, Raw: raw.Bytes(), RawSHA256: BytesHash(raw.Bytes())}
}

func TestHistoryMembershipRequiresNativeSingleGroupClosureAndKeepsUnknownIncarnation(t *testing.T) {
	now := time.Now().UTC()
	r, native := historyNativeFixture(t, now)
	// Health and scaling configuration do not erase observed membership.
	native.Groups[0].Members[0].Health = "Unhealthy"
	native.Groups[0].Members[0].Lifecycle = "Terminating"
	native = historyFramedFixture(t, native.Groups, now)
	members, err := historyMembers(r, native, now)
	if err != nil || len(members) != 2 {
		t.Fatal("native point membership unavailable", err)
	}
	for _, member := range members {
		if member.LaunchTime != nil || member.Hardware != nil || member.ResourceID != "" || member.LaunchTemplateVersion != 1 {
			t.Fatal("unknown incarnation or inventory mapping was manufactured")
		}
	}
	copyBefore := append([]provider.FleetMember{}, native.Groups[0].Members...)
	_, _ = historyMembers(r, native, now)
	if !reflect.DeepEqual(copyBefore, native.Groups[0].Members) {
		t.Fatal("projection rewrote native member order")
	}
	for name, change := range map[string]func(*fleethistory.Registration, *provider.FleetInventoryEvidence){
		"wrong account": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) { n.AccountID = "999900001111" },
		"wrong region":  func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) { n.Region = "us-east-1" },
		"future time": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.CollectedAt = now.Add(6 * time.Second)
		},
		"historical time": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.CollectedAt = now.Add(-61 * time.Second)
		},
		"missing time":         func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) { n.CollectedAt = time.Time{} },
		"invalid registration": func(r *fleethistory.Registration, _ *provider.FleetInventoryEvidence) { r.ASGARN = "unknown" },
		"native typed alteration": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.Groups[0].Members[0].InstanceID = "i-fffffffffffffffff"
		},
		"native bytes alteration": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) { n.Raw[len(n.Raw)-2] ^= 1 },
		"wrong ARN": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.Groups[0].ARN += "-other"
			*n = historyFramedFixture(t, n.Groups, now)
		},
		"extra group": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.Groups = append(n.Groups, n.Groups[0])
			*n = historyFramedFixture(t, n.Groups, now)
		},
		"duplicate member": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.Groups[0].Members = append(n.Groups[0].Members, n.Groups[0].Members[0])
			*n = historyFramedFixture(t, n.Groups, now)
		},
		"unknown template": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			n.Groups[0].Members[0].LaunchTemplate.Version = "$Latest"
			*n = historyFramedFixture(t, n.Groups, now)
		},
		"extra native selector": func(_ *fleethistory.Registration, n *provider.FleetInventoryEvidence) {
			length := binary.BigEndian.Uint32(n.Raw[:4])
			selector, err := url.ParseQuery(string(n.Raw[4 : 4+length]))
			if err != nil {
				t.Fatal(err)
			}
			selector.Set("AutoScalingGroupNames.member.2", "unregistered-group")
			var raw bytes.Buffer
			_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector.Encode())))
			raw.WriteString(selector.Encode())
			raw.Write(n.Raw[4+length:])
			n.Raw, n.RawSHA256 = raw.Bytes(), BytesHash(raw.Bytes())
		},
	} {
		t.Run(name, func(t *testing.T) {
			registration, changed := historyNativeFixture(t, now)
			change(&registration, &changed)
			if _, err := historyMembers(registration, changed, now); err == nil {
				t.Fatal("unbound or altered history was accepted")
			}
		})
	}
}

func TestHistoryRegistrationProjectionRejectsCallerShapedMissingEnvelope(t *testing.T) {
	r, _ := historyNativeFixture(t, time.Now().UTC())
	if got, err := historyRegistration(model.Document{"registration": r}); err != nil || got != r {
		t.Fatal("immutable registration wrapper could not be read", err)
	}
	if _, err := historyRegistration(Object(r)); err == nil {
		t.Fatal("authoritative registration was read from an unwrapped upload")
	}
}
