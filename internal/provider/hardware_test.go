package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type hardwareTransport func(*http.Request) (*http.Response, error)

func (f hardwareTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// HardwareFixtureResponse contains provider-shaped native XML, including units
// and explicit configured CPU options. It is for offline adapter acceptance.
func HardwareFixtureResponse(v url.Values) string {
	switch v.Get("Action") {
	case "DescribeInstances":
		return `<DescribeInstancesResponse><reservationSet><item><ownerId>111122223333</ownerId><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceType>m6i.xlarge</instanceType><imageId>ami-0123456789abcdef0</imageId><architecture>x86_64</architecture><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><virtualizationType>hvm</virtualizationType><rootDeviceType>ebs</rootDeviceType><ebsOptimized>true</ebsOptimized><enaSupport>true</enaSupport><cpuOptions><coreCount>1</coreCount><threadsPerCore>2</threadsPerCore></cpuOptions><placement><availabilityZone>eu-west-1a</availabilityZone><tenancy>default</tenancy></placement><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0123456789abcdef0</volumeId></ebs></item></blockDeviceMapping></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
	case "DescribeInstanceTypes":
		var b strings.Builder
		b.WriteString(`<DescribeInstanceTypesResponse><instanceTypeSet>`)
		for j := 1; v.Get(fmt.Sprintf("InstanceType.%d", j)) != ""; j++ {
			name := v.Get(fmt.Sprintf("InstanceType.%d", j))
			cpu, mem := 4, 16384
			if name == "m6i.large" {
				cpu, mem = 2, 8192
			}
			fmt.Fprintf(&b, `<item><instanceType>%s</instanceType><vCpuInfo><defaultVCpus>%d</defaultVCpus><defaultCores>%d</defaultCores><defaultThreadsPerCore>2</defaultThreadsPerCore></vCpuInfo><memoryInfo><sizeInMiB>%d</sizeInMiB></memoryInfo><processorInfo><manufacturer>Intel</manufacturer><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><instanceStorageSupported>false</instanceStorageSupported><burstablePerformanceSupported>false</burstablePerformanceSupported><bareMetal>false</bareMetal><hypervisor>nitro</hypervisor><supportedRootDeviceTypes><item>ebs</item></supportedRootDeviceTypes><supportedUsageClasses><item>on-demand</item></supportedUsageClasses><supportedVirtualizationTypes><item>hvm</item></supportedVirtualizationTypes><networkInfo><enaSupport>required</enaSupport><networkCards><item><networkCardIndex>0</networkCardIndex><baselineBandwidthInGbps>0.781</baselineBandwidthInGbps><peakBandwidthInGbps>12.5</peakBandwidthInGbps></item></networkCards></networkInfo><ebsInfo><ebsOptimizedInfo><baselineIops>3600</baselineIops><baselineThroughputInMBps>81.25</baselineThroughputInMBps><maximumIops>40000</maximumIops><maximumThroughputInMBps>1250</maximumThroughputInMBps></ebsOptimizedInfo></ebsInfo></item>`, name, cpu, cpu/2, mem)
		}
		b.WriteString(`</instanceTypeSet></DescribeInstanceTypesResponse>`)
		return b.String()
	case "DescribeInstanceTypeOfferings":
		var b strings.Builder
		b.WriteString(`<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet>`)
		for j := 1; v.Get(fmt.Sprintf("Filter.1.Value.%d", j)) != ""; j++ {
			fmt.Fprintf(&b, `<item><instanceType>%s</instanceType><locationType>availability-zone</locationType><location>eu-west-1a</location></item>`, v.Get(fmt.Sprintf("Filter.1.Value.%d", j)))
		}
		b.WriteString(`</instanceTypeOfferingSet></DescribeInstanceTypeOfferingsResponse>`)
		return b.String()
	case "DescribeVolumes":
		return `<DescribeVolumesResponse><volumeSet><item><volumeId>vol-0123456789abcdef0</volumeId><volumeType>gp3</volumeType><availabilityZone>eu-west-1a</availabilityZone><iops>3000</iops><throughput>125</throughput><attachmentSet><item><instanceId>i-0123456789abcdef0</instanceId><device>/dev/sda1</device><status>attached</status></item></attachmentSet></item></volumeSet></DescribeVolumesResponse>`
	case "DescribeImages":
		return `<DescribeImagesResponse><imagesSet><item><imageId>ami-0123456789abcdef0</imageId><architecture>x86_64</architecture><virtualizationType>hvm</virtualizationType><rootDeviceType>ebs</rootDeviceType><imageState>available</imageState><enaSupport>true</enaSupport></item></imagesSet></DescribeImagesResponse>`
	}
	return ""
}
func TestHardwareReadPreservesNativeBytesConfiguredCPUAndExactSelectors(t *testing.T) {
	requests := 0
	a := &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("offline-fixture", "offline-fixture", "")}, client: &http.Client{Transport: hardwareTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != "https://ec2.eu-west-1.amazonaws.com/" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("native request scope or signing changed")
		}
		body, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(body))
		if v.Get("Version") != "2016-11-15" {
			t.Fatal("native query version missing")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(HardwareFixtureResponse(v)))}, nil
	})}}
	out, err := a.HardwareInventory(context.Background(), "eu-west-1", "111122223333", "i-0123456789abcdef0", []string{"m6i.large"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 5 || out.Instance.CPU.Cores == nil || *out.Instance.CPU.Cores != 1 || *out.Types[1].VCPU.Default != 4 || len(out.Raw) == 0 || len(out.RawSHA256) != 64 {
		t.Fatal("native configured/default capacities or raw provenance lost")
	}
	if err = ValidateHardwareEvidence(out, out.Instance.ID, []string{"m6i.large"}); err != nil {
		t.Fatal(err)
	}
	out.Types[0].Memory.MiB = new(int64)
	*out.Types[0].Memory.MiB = 999999
	if ValidateHardwareEvidence(out, out.Instance.ID, []string{"m6i.large"}) == nil {
		t.Fatal("typed hardware substituted without native bytes")
	}
}
func TestHardwareReadRejectsAccountAndNativeSelectorSubstitution(t *testing.T) {
	for _, mode := range []string{"wrong-owner", "wrong-type", "unknown-volume", "redirect", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			a := &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("offline-fixture", "offline-fixture", "")}, client: &http.Client{Transport: hardwareTransport(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				v, _ := url.ParseQuery(string(body))
				raw := HardwareFixtureResponse(v)
				status := 200
				if mode == "wrong-owner" {
					raw = strings.ReplaceAll(raw, "111122223333", "999900001111")
				}
				if mode == "wrong-type" && v.Get("Action") == "DescribeInstanceTypes" {
					raw = strings.ReplaceAll(raw, "m6i.large", "r6i.large")
				}
				if mode == "unknown-volume" && v.Get("Action") == "DescribeVolumes" {
					raw = strings.ReplaceAll(raw, "vol-0123456789abcdef0", "vol-aaaaaaaaaaaaaaaaa")
				}
				if mode == "redirect" {
					status = 302
				}
				if mode == "oversized" {
					raw = strings.Repeat("x", (8<<20)+1)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(raw))}, nil
			})}}
			if _, err := a.HardwareInventory(context.Background(), "eu-west-1", "111122223333", "i-0123456789abcdef0", []string{"m6i.large"}); err == nil {
				t.Fatal("invalid native hardware evidence accepted")
			}
		})
	}
}
