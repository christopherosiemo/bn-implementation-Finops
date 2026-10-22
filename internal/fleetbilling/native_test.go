package fleetbilling

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

const account = "111122223333"
const oldInstance = "i-0123456789abcdef0"
const candidateInstance = "i-11111111111111111"
const imageID = "ami-0123456789abcdef0"
const templateID = "lt-0123456789abcdef0"

func frame(pages []page) []byte {
	var b bytes.Buffer
	for _, p := range pages {
		s := p.selector.Encode()
		_ = binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
		_ = binary.Write(&b, binary.BigEndian, uint64(len(p.body)))
		b.Write(p.body)
	}
	return b.Bytes()
}
func testHardware(t *testing.T, instance, kind string, now time.Time) (model.Document, []byte) {
	t.Helper()
	pages := []page{
		{url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "InstanceId.1": {instance}}, []byte(fmt.Sprintf(`<DescribeInstancesResponse><reservationSet><item><ownerId>%s</ownerId><instancesSet><item><instanceId>%s</instanceId><instanceType>%s</instanceType><imageId>%s</imageId><subnetId>subnet-0123456789abcdef0</subnetId><vpcId>vpc-0123456789abcdef0</vpcId><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><placement><availabilityZone>eu-west-1a</availabilityZone><tenancy>default</tenancy></placement><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0123456789abcdef0</volumeId></ebs></item></blockDeviceMapping></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`, account, instance, kind, imageID))},
		{url.Values{"Action": {"DescribeInstanceTypes"}, "Version": {"2016-11-15"}, "IncludeUnsupportedInRegion": {"false"}, "InstanceType.1": {kind}}, []byte(`<DescribeInstanceTypesResponse><instanceTypeSet><item><instanceType>` + kind + `</instanceType></item></instanceTypeSet></DescribeInstanceTypesResponse>`)},
		{url.Values{"Action": {"DescribeInstanceTypeOfferings"}, "Version": {"2016-11-15"}, "LocationType": {"availability-zone"}, "Filter.1.Name": {"instance-type"}, "Filter.1.Value.1": {kind}, "Filter.2.Name": {"location"}, "Filter.2.Value.1": {"eu-west-1a"}, "MaxResults": {"1000"}}, []byte(`<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet><item><instanceType>` + kind + `</instanceType><locationType>availability-zone</locationType><location>eu-west-1a</location></item></instanceTypeOfferingSet></DescribeInstanceTypeOfferingsResponse>`)},
		{url.Values{"Action": {"DescribeVolumes"}, "Version": {"2016-11-15"}, "VolumeId.1": {"vol-0123456789abcdef0"}}, []byte(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-0123456789abcdef0</volumeId><availabilityZone>eu-west-1a</availabilityZone><attachmentSet><item><instanceId>` + instance + `</instanceId><device>/dev/sda1</device><status>attached</status></item></attachmentSet></item></volumeSet></DescribeVolumesResponse>`)},
		{url.Values{"Action": {"DescribeImages"}, "Version": {"2016-11-15"}, "ImageId.1": {imageID}}, []byte(`<DescribeImagesResponse><imagesSet><item><imageId>` + imageID + `</imageId><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><productCodes/></item></imagesSet></DescribeImagesResponse>`)},
	}
	raw := frame(pages)
	native, e := provider.ParseHardwareEvidence(raw, account, "eu-west-1", instance, []string{kind}, now)
	if e != nil {
		t.Fatal(e)
	}
	d := model.Document{"id": "hardware-" + instance, "kind": "AWS_EC2_HARDWARE", "writer_role": "finops_ingester", "binding": model.Document{"tenant_id": "tenant", "resource_id": "resource-" + instance, "provider_resource_id": instance, "account_id": account, "region": "eu-west-1"}, "candidate_types": []string{kind}, "native": object(native), "collected_at": now.Format(time.RFC3339Nano), "raw_object": model.Document{"body_sha256": BytesHash(raw)}}
	return d, raw
}
func testTemplates(tenancy string) (model.Document, []byte) {
	body := `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>`
	for _, v := range []int{1, 2} {
		kind := "m6i.xlarge"
		if v == 2 {
			kind = "m6i.large"
		}
		body += fmt.Sprintf(`<item><launchTemplateId>%s</launchTemplateId><versionNumber>%d</versionNumber><launchTemplateData><instanceType>%s</instanceType><imageId>%s</imageId><placement><tenancy>%s</tenancy></placement></launchTemplateData></item>`, templateID, v, kind, imageID, tenancy)
	}
	body += `</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`
	raw := frame([]page{{url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {templateID}, "LaunchTemplateVersion.1": {"1"}, "LaunchTemplateVersion.2": {"2"}}, []byte(body)}})
	var decoded struct {
		Items []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	_ = xml.Unmarshal([]byte(body), &decoded)
	d := model.Document{"id": "templates", "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "writer_role": "finops_ingester", "requests": []provider.FleetTemplateRequest{{ID: templateID, Version: 1}, {ID: templateID, Version: 2}}, "templates": decoded.Items, "raw_object": model.Document{"body_sha256": BytesHash(raw)}}
	return d, raw
}
func testTarget() Target {
	return Target{Binding: fleet.Binding{TenantID: "tenant", ResourceID: "fleet-resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "blue", AccountID: account, Region: "eu-west-1"}, SourceID: "source", OldASG: "blue", CandidateASG: "green"}
}
func testMembership(target Target) (model.Document, []byte) {
	body := `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups>`
	for _, name := range []string{target.OldASG, target.CandidateASG} {
		v, count := 1, 1
		member := fmt.Sprintf(`<member><InstanceId>%s</InstanceId><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate></member>`, oldInstance, templateID)
		if name == target.CandidateASG {
			v, count, member = 2, 0, ""
		}
		body += fmt.Sprintf(`<member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>arn:aws:autoscaling:eu-west-1:%s:autoScalingGroup:fixed:autoScalingGroupName/%s</AutoScalingGroupARN><VPCZoneIdentifier>subnet-0123456789abcdef0</VPCZoneIdentifier><DesiredCapacity>%d</DesiredCapacity><MinSize>%d</MinSize><MaxSize>%d</MaxSize><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%d</Version></LaunchTemplate><Instances>%s</Instances><Tags><member><Key>finops:tenant</Key><Value>%s</Value></member><member><Key>finops:environment</Key><Value>NON_PRODUCTION</Value></member></Tags></member>`, name, account, name, count, count, count, templateID, v, member, target.Binding.TenantID)
	}
	body += `</AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`
	raw := frame([]page{{url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "AutoScalingGroupNames.member.1": {"blue"}, "AutoScalingGroupNames.member.2": {"green"}}, []byte(body)}})
	var parsed struct {
		Groups []provider.FleetGroup `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	_ = xml.Unmarshal([]byte(body), &parsed)
	for n := range parsed.Groups {
		if parsed.Groups[n].Members == nil {
			parsed.Groups[n].Members = []provider.FleetMember{}
		}
	}
	d := model.Document{"id": "membership", "kind": "AWS_FLEET_MEMBERSHIP", "writer_role": "finops_ingester", "binding": object(target.Binding), "old_asg": target.OldASG, "candidate_asg": target.CandidateASG, "groups": parsed.Groups, "raw_object": model.Document{"body_sha256": BytesHash(raw)}}
	return d, raw
}

func TestNativeRawImageTemplateAndMembershipBindings(t *testing.T) {
	now := time.Now().UTC()
	d, raw := testHardware(t, oldInstance, "m6i.xlarge", now)
	got, e := parseHardware(d, raw, account, "eu-west-1")
	if e != nil || got.Platform != "Linux/UNIX" || got.Tenancy != "default" {
		t.Fatal(got, e)
	}
	d2, r2 := testTemplates("default")
	tpl, e := parseTemplates(d2, r2)
	if e != nil || tpl[templateID+":2"].InstanceType != "m6i.large" {
		t.Fatal(tpl, e)
	}
	target := testTarget()
	d3, r3 := testMembership(target)
	old, candidate, e := parseMembership(d3, r3, target)
	if e != nil || len(old.Members) != 1 || len(candidate.Members) != 0 {
		t.Fatal(old, candidate, e)
	}
}
func TestMissingRawNativeDimensionsOrChangedSelectorsAreUnavailable(t *testing.T) {
	now := time.Now().UTC()
	for _, remove := range []string{"<platformDetails>Linux/UNIX</platformDetails>", "<tenancy>default</tenancy>", "<usageOperation>RunInstances</usageOperation>", "<subnetId>subnet-0123456789abcdef0</subnetId>", "<vpcId>vpc-0123456789abcdef0</vpcId>"} {
		t.Run(remove, func(t *testing.T) {
			d, raw := testHardware(t, oldInstance, "m6i.xlarge", now)
			pages, _ := nativePages(raw)
			pages[4].body = []byte(strings.ReplaceAll(string(pages[4].body), remove, ""))
			pages[0].body = []byte(strings.ReplaceAll(string(pages[0].body), remove, ""))
			raw = frame(pages)
			d["raw_object"] = model.Document{"body_sha256": BytesHash(raw)}
			native, e := provider.ParseHardwareEvidence(raw, account, "eu-west-1", oldInstance, []string{"m6i.xlarge"}, now)
			if e == nil {
				d["native"] = object(native)
			}
			if _, e = parseHardware(d, raw, account, "eu-west-1"); e == nil {
				t.Fatal("missing native fields inferred")
			}
		})
	}
	d, raw := testHardware(t, oldInstance, "m6i.xlarge", now)
	pages, _ := nativePages(raw)
	pages[4].selector.Set("ImageId.1", "ami-99999999999999999")
	raw = frame(pages)
	d["raw_object"] = model.Document{"body_sha256": BytesHash(raw)}
	native := object(d["native"])
	native["raw_sha256"] = BytesHash(raw)
	d["native"] = native
	if _, e := parseHardware(d, raw, account, "eu-west-1"); e == nil {
		t.Fatal("different image selector accepted")
	}
	d, raw = testTemplates("")
	if _, e := parseTemplates(d, raw); e == nil {
		t.Fatal("LT default tenancy inferred from absence")
	}
	d, raw = testTemplates("default")
	d["requests"] = []provider.FleetTemplateRequest{{ID: templateID, Version: 3}}
	if _, e := parseTemplates(d, raw); e == nil {
		t.Fatal("template version substitution accepted")
	}
	target := testTarget()
	d, raw = testMembership(target)
	target.Binding.AccountID = "999900001111"
	if _, _, e := parseMembership(d, raw, target); e == nil {
		t.Fatal("cross account native membership accepted")
	}
}

func TestRawTemplateSpotReservationsLicensesAndImplicitNetworkRemainUnavailable(t *testing.T) {
	for _, extra := range []string{`<instanceMarketOptions><marketType>spot</marketType></instanceMarketOptions>`, `<capacityReservationSpecification><capacityReservationPreference>open</capacityReservationPreference></capacityReservationSpecification>`, `<licenseSet><item><licenseConfigurationArn>arn:aws:license-manager:eu-west-1:111122223333:license-configuration/native-response</licenseConfigurationArn></item></licenseSet>`, `<licenseSpecifications><item><licenseConfigurationArn>arn:aws:license-manager:eu-west-1:111122223333:license-configuration/unknown</licenseConfigurationArn></item></licenseSpecifications>`, `<networkInterfaceSet><item><subnetId>subnet-99999999999999999</subnetId></item></networkInterfaceSet>`, `<placement><hostId>h-12345</hostId></placement>`} {
		t.Run(extra, func(t *testing.T) {
			d, raw := testTemplates("default")
			pages, _ := nativePages(raw)
			pages[0].body = []byte(strings.ReplaceAll(string(pages[0].body), `</launchTemplateData>`, extra+`</launchTemplateData>`))
			raw = frame(pages)
			d["raw_object"] = model.Document{"body_sha256": BytesHash(raw)}
			if _, e := parseTemplates(d, raw); e == nil {
				t.Fatal("unsupported purchase/license/network model borrowed regular OnDemand price")
			}
		})
	}
	target := testTarget()
	d, raw := testMembership(target)
	pages, _ := nativePages(raw)
	pages[0].body = []byte(strings.ReplaceAll(string(pages[0].body), `<VPCZoneIdentifier>subnet-0123456789abcdef0</VPCZoneIdentifier>`, ``))
	raw = frame(pages)
	d["raw_object"] = model.Document{"body_sha256": BytesHash(raw)}
	if _, _, e := parseMembership(d, raw, target); e == nil {
		t.Fatal("missing ASG network scope inferred")
	}
	if inSubnets("subnet-99999999999999999", []string{"subnet-0123456789abcdef0"}) {
		t.Fatal("different VPC/subnet reference authorized shared target tenancy")
	}
}
