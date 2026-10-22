package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func fleetTemplateXML(id string, version uint64, extra string) string {
	return fmt.Sprintf(`<item><launchTemplateId>%s</launchTemplateId><launchTemplateName>native-template</launchTemplateName><versionNumber>%d</versionNumber><createdBy>arn:aws:iam::999900001111:role/metadata-not-account-authority</createdBy><launchTemplateData><imageId>ami-0123456789abcdef0</imageId><instanceType>m6i.2xlarge</instanceType>%s</launchTemplateData></item>`, id, version, extra)
}
func TestNativeFleetTemplatesPinVersionsPreserveUnknownStorageAndCompleteRawPages(t *testing.T) {
	const id = "lt-0123456789abcdef0"
	calls := 0
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != "ec2.eu-west-1.amazonaws.com" || !strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/ec2/aws4_request") {
			t.Error("template request lost fixed region or SigV4 identity")
		}
		raw, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(raw))
		if v.Get("Action") != "DescribeLaunchTemplateVersions" || v.Get("Version") != "2016-11-15" || v.Get("LaunchTemplateId") != id || v.Get("LaunchTemplateVersion.1") != "1" || v.Get("LaunchTemplateVersion.2") != "2" || v.Get("ResolveAlias") != "false" {
			t.Error("unscoped or mutating template query")
		}
		item := fleetTemplateXML(id, 1, `<blockDeviceMappingSet><item><deviceName>/dev/xvda</deviceName><ebs><volumeType>gp3</volumeType><volumeSize>8</volumeSize></ebs></item></blockDeviceMappingSet>`)
		next := "<nextToken>page-2</nextToken>"
		if v.Get("NextToken") == "page-2" {
			item = fleetTemplateXML(id, 2, `<blockDeviceMappingSet><item><deviceName>/dev/xvda</deviceName><ebs><encrypted>false</encrypted><deleteOnTermination>true</deleteOnTermination><iops>0</iops><throughput>125</throughput><snapshotId>snap-0123456789abcdef0</snapshotId></ebs></item><item><deviceName>/dev/sdb</deviceName><noDevice/></item></blockDeviceMappingSet>`)
			next = ""
		}
		_, _ = io.WriteString(w, `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>`+item+`</launchTemplateVersionSet>`+next+`</DescribeLaunchTemplateVersionsResponse>`)
	})
	e, e2 := a.FleetTemplateVersions(context.Background(), "eu-west-1", "111122223333", []FleetTemplateRequest{{id, 2}, {id, 1}})
	if e2 != nil {
		t.Fatal(e2)
	}
	sum := sha256.Sum256(e.Raw)
	if calls != 2 || len(e.Templates) != 2 || e.RawSHA256 != hex.EncodeToString(sum[:]) || !strings.Contains(string(e.Raw), "<noDevice/>") {
		t.Fatal("native pinned response provenance lost")
	}
	first := e.Templates[0].Data.BlockDevices[0].EBS
	second := e.Templates[1].Data.BlockDevices[0].EBS
	if first.Encrypted != nil || first.DeleteOnTermination != nil || first.IOPS != nil || second.Encrypted == nil || *second.Encrypted || second.IOPS == nil || *second.IOPS != 0 || !e.Templates[1].Data.BlockDevices[1].NoDevicePresent {
		t.Fatal("unknown EBS settings became false/zero or native values changed")
	}
	if e.Templates[0].CreatedBy == "" || e.AccountID != "111122223333" {
		t.Fatal("CreatedBy metadata replaced approved account binding")
	}
}
func TestNativeFleetTemplatesRejectMissingUnexpectedUnpinnedAndAmbiguousData(t *testing.T) {
	const id = "lt-0123456789abcdef0"
	base := fleetTemplateXML(id, 1, "")
	for name, body := range map[string]string{"missing-version": "", "wrong-template": fleetTemplateXML("lt-fedcba98765432100", 1, ""), "wrong-version": fleetTemplateXML(id, 2, ""), "duplicate": base + base, "missing-instance-type": strings.Replace(base, "<instanceType>m6i.2xlarge</instanceType>", "", 1), "instance-requirements": fleetTemplateXML(id, 1, "<instanceRequirements/>"), "image-alias": strings.Replace(base, "ami-0123456789abcdef0", "resolve:ssm:latest", 1), "contradictory-block-mapping": fleetTemplateXML(id, 1, `<blockDeviceMappingSet><item><deviceName>/dev/sdb</deviceName><noDevice/><ebs><encrypted>true</encrypted></ebs></item></blockDeviceMappingSet>`)} {
		t.Run(name, func(t *testing.T) {
			a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>`+body+`</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`)
			})
			if _, e := a.FleetTemplateVersions(context.Background(), "eu-west-1", "111122223333", []FleetTemplateRequest{{id, 1}}); e == nil {
				t.Fatal("incomplete or conflicting native template accepted")
			}
		})
	}
	calls := 0
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://other.invalid/")
		w.WriteHeader(302)
	})
	for _, request := range [][]FleetTemplateRequest{{{id, 0}}, {{id, 1}, {id, 1}}, {{"not-a-template", 1}}} {
		if _, e := a.FleetTemplateVersions(context.Background(), "eu-west-1", "111122223333", request); e == nil {
			t.Fatal("unbounded pin accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid query reached transport")
	}
	if _, e := a.FleetTemplateVersions(context.Background(), "eu-west-1", "111122223333", []FleetTemplateRequest{{id, 1}}); e == nil || calls != 1 {
		t.Fatal("signed request followed provider redirect")
	}
}
func TestNativeFleetTemplatesKeepAbsentBlockMappingsUnknown(t *testing.T) {
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>`+fleetTemplateXML("lt-0123456789abcdef0", 1, "")+`</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`)
	})
	e, err := a.FleetTemplateVersions(context.Background(), "eu-west-1", "111122223333", []FleetTemplateRequest{{"lt-0123456789abcdef0", 1}})
	if err != nil || e.Templates[0].Data.BlockDevices != nil {
		t.Fatal("absent AMI-derived mappings became an observed empty storage list", err)
	}
}
