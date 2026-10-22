package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var ebsTestScope = EBSScope{TenantID: "tenant-ebs", AccountID: "111122223333", Region: "eu-west-1"}

const ebsTestVolumeID = "vol-0123456789abcdef0"
const ebsTestInstanceID = "i-0123456789abcdef0"

func ebsTestPage(action, collection, body, token string) string {
	if token != "" {
		token = "<nextToken>" + token + "</nextToken>"
	}
	return "<" + action + "Response><requestId>test-request</requestId><" + collection + ">" + body + "</" + collection + ">" + token + "</" + action + "Response>"
}
func ebsTestVolume(attached bool) string {
	a := ""
	if attached {
		a = "<item><volumeId>" + ebsTestVolumeID + "</volumeId><instanceId>" + ebsTestInstanceID + "</instanceId><device>/dev/sda1</device><status>attached</status><attachTime>2026-01-01T00:00:00Z</attachTime><deleteOnTermination>true</deleteOnTermination></item>"
	}
	return "<item><volumeId>" + ebsTestVolumeID + "</volumeId><size>100</size><snapshotId>snap-0123456789abcdef0</snapshotId><availabilityZone>eu-west-1a</availabilityZone><status>in-use</status><createTime>2026-01-01T00:00:00Z</createTime><volumeType>gp2</volumeType><iops>300</iops><encrypted>true</encrypted><multiAttachEnabled>false</multiAttachEnabled><attachmentSet>" + a + "</attachmentSet><tagSet/></item>"
}
func ebsTestNative(t *testing.T, r *http.Request, body string) (string, int) {
	t.Helper()
	v, _ := url.ParseQuery(body)
	action := v.Get("Action")
	if r.URL.Scheme != "https" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatal("unbounded protocol")
	}
	switch action {
	case "GetCallerIdentity":
		return rdsTestIdentity(), 200
	case "DescribeVolumes":
		return ebsTestPage(action, "volumeSet", ebsTestVolume(true), ""), 200
	case "DescribeSnapshots":
		if v.Get("Owner.1") != "self" {
			t.Fatal("snapshot scope not owned")
		}
		return ebsTestPage(action, "snapshotSet", "<item><snapshotId>snap-0123456789abcdef0</snapshotId><volumeId>"+ebsTestVolumeID+"</volumeId><ownerId>111122223333</ownerId><status>completed</status><volumeSize>100</volumeSize><encrypted>true</encrypted><storageTier>standard</storageTier><tagSet/></item>", ""), 200
	case "DescribeImages":
		return ebsTestPage(action, "imagesSet", "<item><imageId>ami-0123456789abcdef0</imageId><imageOwnerId>111122223333</imageOwnerId><imageState>available</imageState><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><snapshotId>snap-0123456789abcdef0</snapshotId></ebs></item></blockDeviceMapping></item>", ""), 200
	case "DescribeFastSnapshotRestores":
		return ebsTestPage(action, "fastSnapshotRestoreSet", "", ""), 200
	case "DescribeSnapshotTierStatus":
		return ebsTestPage(action, "snapshotTierStatusSet", "", ""), 200
	case "DescribeLockedSnapshots":
		return ebsTestPage(action, "snapshotSet", "", ""), 200
	case "DescribeVolumesModifications":
		return ebsTestPage(action, "volumeModificationSet", "<item><volumeId>"+ebsTestVolumeID+"</volumeId><modificationState>optimizing</modificationState><targetVolumeType>gp3</targetVolumeType><targetIops>3000</targetIops></item>", ""), 200
	case "DescribeVolumeStatus":
		return ebsTestPage(action, "volumeStatusSet", "<item><volumeId>"+ebsTestVolumeID+"</volumeId><volumeStatus><status>ok</status></volumeStatus></item>", ""), 200
	case "DescribeSnapshotAttribute":
		return "<DescribeSnapshotAttributeResponse><snapshotId>snap-0123456789abcdef0</snapshotId><createVolumePermission><item><userId>444455556666</userId></item></createVolumePermission></DescribeSnapshotAttributeResponse>", 200
	case "DescribeInstances":
		if v.Get("InstanceId.1") != ebsTestInstanceID {
			t.Fatal("instance selector not exact attachment")
		}
		return ebsTestPage(action, "reservationSet", "<item><ownerId>111122223333</ownerId><instancesSet><item><instanceId>"+ebsTestInstanceID+"</instanceId><instanceType>m6i.large</instanceType><rootDeviceName>/dev/sda1</rootDeviceName><rootDeviceType>ebs</rootDeviceType><ebsOptimized>true</ebsOptimized><monitoring><state>disabled</state></monitoring><placement><availabilityZone>eu-west-1a</availabilityZone></placement><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>"+ebsTestVolumeID+"</volumeId><status>attached</status><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping></item></instancesSet></item>", ""), 200
	case "DescribeInstanceTypes":
		return ebsTestPage(action, "instanceTypeSet", "<item><instanceType>m6i.large</instanceType><currentGeneration>true</currentGeneration><hypervisor>nitro</hypervisor><ebsInfo><ebsOptimizedSupport>default</ebsOptimizedSupport><ebsOptimizedInfo><baselineBandwidthInMbps>650</baselineBandwidthInMbps><baselineThroughputInMBps>81.25</baselineThroughputInMBps><baselineIops>3600</baselineIops><maximumBandwidthInMbps>10000</maximumBandwidthInMbps><maximumThroughputInMBps>1250</maximumThroughputInMBps><maximumIops>40000</maximumIops></ebsOptimizedInfo></ebsInfo></item>", ""), 200
	case "GetMetricStatistics":
		start, _ := time.Parse(time.RFC3339, v.Get("StartTime"))
		p := v.Get("Period")
		maximum := ""
		if v.Get("Statistics.member.3") == "Maximum" {
			maximum = "<Maximum>0</Maximum>"
		}
		stat := v.Get("Statistics.member.1")
		return "<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints><member><Timestamp>" + start.Format(time.RFC3339) + "</Timestamp><" + stat + ">0</" + stat + ">" + maximum + "<Unit>" + v.Get("Unit") + "</Unit><SampleCount>5</SampleCount></member></Datapoints><Label>" + p + "</Label></GetMetricStatisticsResult></GetMetricStatisticsResponse>", 200
	}
	t.Fatalf("unexpected native action %s", action)
	return "", 500
}

func TestEBSNativeDiscoveryScopeDependenciesAndRawFrames(t *testing.T) {
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) { return ebsTestNative(t, r, b) })
	got, e := a.EBSDiscover(context.Background(), ebsTestScope)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Volumes) != 1 || len(got.Snapshots) != 1 || len(got.OwnedImages) != 1 || len(got.Instances) != 1 || len(got.InstanceTypes) != 1 || len(got.SnapshotPermissions) != 1 {
		t.Fatalf("native population mismatch: %#v", got)
	}
	v := got.Volumes[0]
	if v["throughput_mibps"] != nil || model.String(v, "provider_resource_id") != ebsTestVolumeID {
		t.Fatal("missing native throughput fabricated")
	}
	if v["attachments"].([]model.Document)[0]["delete_on_termination"] != true {
		t.Fatal("root deletion semantics lost")
	}
	caps := got.InstanceTypes[0]["ebs"].(model.Document)["optimized_info"].(model.Document)
	if model.String(caps, "baseline_iops") == model.String(caps, "maximum_iops") {
		t.Fatal("instance burst maximum substituted for baseline")
	}
	pages, e := EBSCaptureFrames(got.Raw)
	if e != nil || len(pages) < 12 || got.RawSHA256 != rdsSHA(got.Raw) {
		t.Fatal("raw framing lost")
	}
	raw, e := json.Marshal(got)
	if e != nil || strings.Contains(string(raw), "offline-secret") || strings.Contains(string(raw), "<Describe") {
		t.Fatal("canonical leaked raw/secret")
	}
}
func TestEBSForeignAccountAndDuplicateSingletonRefused(t *testing.T) {
	for _, kind := range []string{"caller", "volume", "snapshot"} {
		t.Run(kind, func(t *testing.T) {
			a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
				raw, status := ebsTestNative(t, r, b)
				v, _ := url.ParseQuery(b)
				if kind == "caller" && v.Get("Action") == "GetCallerIdentity" {
					raw = strings.ReplaceAll(raw, "111122223333", "999988887777")
				}
				if kind == "volume" && v.Get("Action") == "DescribeVolumes" {
					raw = strings.Replace(raw, "<size>100</size>", "<size>100</size><size>1</size>", 1)
				}
				if kind == "snapshot" && v.Get("Action") == "DescribeSnapshots" {
					raw = strings.ReplaceAll(raw, "<ownerId>111122223333</ownerId>", "<ownerId>999988887777</ownerId>")
				}
				return raw, status
			})
			got, e := a.EBSDiscover(context.Background(), ebsTestScope)
			if kind == "snapshot" {
				if e != nil || got.Snapshots != nil {
					t.Fatal("foreign snapshot must be unavailable, not an owned empty population")
				}
			} else if e == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}
func TestEBSBoundedPaginationThrottleAndDependencyDenial(t *testing.T) {
	attempts := 0
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		if v.Get("Action") == "DescribeVolumes" {
			attempts++
			if attempts < 3 {
				return "<Response><Errors><Error><Code>RequestLimitExceeded</Code></Error></Errors></Response>", 400
			}
		}
		if v.Get("Action") == "DescribeImages" {
			return "<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>", 403
		}
		return ebsTestNative(t, r, b)
	})
	got, e := a.EBSDiscover(context.Background(), ebsTestScope)
	if e != nil || attempts != 3 || got.OwnedImages != nil || len(got.Volumes) != 1 {
		t.Fatal("bounded throttle/partial dependencies failed", e)
	}
	a = rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		if v.Get("Action") == "DescribeVolumes" {
			return ebsTestPage("DescribeVolumes", "volumeSet", "", "loop"), 200
		}
		return ebsTestNative(t, r, b)
	})
	if _, e = a.EBSDiscover(context.Background(), ebsTestScope); e == nil {
		t.Fatal("pagination loop accepted")
	}
}
func TestEBSMetricsNativePeriodsCountsAndUnknown(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Hour)
	selection := EBSMetricSelection{VolumeID: ebsTestVolumeID, Start: end.Add(-10 * time.Minute), End: end, PeriodSeconds: 300}
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		raw, status := ebsTestNative(t, r, b)
		if v.Get("Action") == "GetMetricStatistics" && v.Get("MetricName") == "VolumeReadOps" {
			raw = strings.Replace(raw, "<SampleCount>5</SampleCount>", "", 1)
		}
		return raw, status
	})
	got, e := a.EBSMetrics(context.Background(), ebsTestScope, selection)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Metrics) == 0 {
		t.Fatal("no actual samples")
	}
	found := false
	for _, row := range got.Metrics {
		if row["metric"] == "VolumeReadOps" {
			found = true
			if row["value"] != "0" || row["sample_count"] != nil || model.Number(row, "period_seconds") != 300 || model.Number(row, "native_cadence_seconds") != 60 || row["native_maximum"] != "0" || row["native_maximum_expected"] != true {
				t.Fatal("observed zero or unknown count altered")
			}
		}
	}
	if !found {
		t.Fatal("ops missing")
	}
	for _, c := range got.Coverage {
		if c["metric"] == "VolumeReadOps" && (c["status"] != "INCOMPLETE_OR_UNKNOWN_SAMPLES" || model.Number(c, "missing_points") != 1) {
			t.Fatal("missing bins converted to coverage")
		}
	}
	selection.PeriodSeconds = 1
	if _, e = a.EBSMetrics(context.Background(), ebsTestScope, selection); e == nil {
		t.Fatal("unsupported native period accepted")
	}
}
func TestEBSCapabilitiesVersionedLimitsAndNoShrinkAuthority(t *testing.T) {
	d := EBSCapabilities()
	if d["source_excerpt_sha256"] != rdsSHA(EBSCapabilityAsset()) || d["basis"] != "AWS_DOCUMENTED_EBS_CAPABILITIES_V1" {
		t.Fatal("asset provenance differs")
	}
	gp3 := d["volume_types"].(map[string]any)["gp3"].(map[string]any)
	if gp3["max_iops"] != "80000" || gp3["max_throughput_mibps"] != "2000" || gp3["max_size_gib"] != "65536" {
		t.Fatal("stale limits")
	}
	m := d["modification"].(map[string]any)
	if m["size_decrease_supported"] != false || m["latest_modification_does_not_prove_24h_count"] != true || d["execution_allowed"] != false {
		t.Fatal("native inventory promoted to authority")
	}
	d["basis"] = "changed"
	if EBSCapabilities()["basis"] == "changed" {
		t.Fatal("mutable global asset")
	}
}
func TestEBSMetricApplicabilityUnattachedMultiAttachAndXen(t *testing.T) {
	v := model.Document{"volume_id": ebsTestVolumeID, "volume_type": "io2", "attachments": []model.Document{}, "multi_attach_enabled": false}
	s, c := ebsVolumeSpecs(v, nil, nil)
	if len(s) != 0 || len(c) == 0 {
		t.Fatal("unattached missing metrics invented")
	}
	v["attachments"] = []model.Document{{"instance_id": ebsTestInstanceID}}
	v["multi_attach_enabled"] = true
	s, _ = ebsVolumeSpecs(v, []model.Document{{"instance_id": ebsTestInstanceID, "instance_type": "m4.large", "monitoring_state": "disabled"}}, []model.Document{{"instance_type": "m4.large", "hypervisor": "xen"}})
	for _, x := range s {
		if x.name == "VolumeTotalReadTime" || x.name == "VolumeIdleTime" || x.name == "VolumeIOPSExceededCheck" {
			t.Fatal("unsupported metric fabricated", x.name)
		}
		if x.name == "VolumeQueueLength" && x.statistic != "Average" {
			t.Fatal("unsupported Xen maximum")
		}
	}
}
func TestEBSFramingAndIdentityBounds(t *testing.T) {
	for _, raw := range [][]byte{[]byte("EBS_READ_V1\n\x00"), []byte("RDS_READ_V1\n"), make([]byte, ebsRawLimit+1)} {
		if _, e := EBSCaptureFrames(raw); e == nil {
			t.Fatal("invalid framed evidence accepted")
		}
	}
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) { return ebsTestNative(t, r, b) })
	for _, scope := range []EBSScope{{TenantID: "", AccountID: ebsTestScope.AccountID, Region: ebsTestScope.Region}, {TenantID: "t", AccountID: "bad", Region: ebsTestScope.Region}, {TenantID: "t", AccountID: ebsTestScope.AccountID, Region: "us-gov-west-1"}} {
		if _, e := a.EBSDiscover(context.Background(), scope); e == nil {
			t.Fatal(fmt.Sprintf("invalid scope accepted %#v", scope))
		}
	}
}
