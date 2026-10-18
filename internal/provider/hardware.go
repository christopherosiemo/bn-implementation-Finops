package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// HardwareEvidence preserves native query selectors and response bytes. The
// source ingester must archive/read back Raw before issuing a source receipt.
// Optional fields remain optional; a missing limit never becomes zero.
type HardwareEvidence struct {
	SchemaVersion string             `json:"schema_version"`
	Provider      string             `json:"provider"`
	AccountID     string             `json:"account_id"`
	Region        string             `json:"region"`
	CollectedAt   time.Time          `json:"collected_at"`
	RawSHA256     string             `json:"raw_sha256"`
	Instance      HardwareInstance   `json:"instance"`
	Types         []HardwareType     `json:"types"`
	Offerings     []HardwareOffering `json:"offerings"`
	Volumes       []HardwareVolume   `json:"volumes"`
	Image         HardwareImage      `json:"image"`
	Raw           []byte             `json:"-"`
}
type HardwareInstance struct {
	ID              string `xml:"instanceId" json:"id"`
	Type            string `xml:"instanceType" json:"instance_type"`
	ImageID         string `xml:"imageId" json:"image_id"`
	Architecture    string `xml:"architecture" json:"architecture"`
	PlatformDetails string `xml:"platformDetails" json:"platform_details"`
	UsageOperation  string `xml:"usageOperation" json:"usage_operation"`
	Virtualization  string `xml:"virtualizationType" json:"virtualization_type"`
	RootDevice      string `xml:"rootDeviceType" json:"root_device_type"`
	EBSOptimized    *bool  `xml:"ebsOptimized" json:"ebs_optimized"`
	ENA             *bool  `xml:"enaSupport" json:"ena_support"`
	Lifecycle       string `xml:"instanceLifecycle" json:"lifecycle"`
	CPU             struct {
		Cores   *int `xml:"coreCount" json:"core_count"`
		Threads *int `xml:"threadsPerCore" json:"threads_per_core"`
	} `xml:"cpuOptions" json:"cpu_options"`
	Placement struct {
		Zone    string `xml:"availabilityZone" json:"zone"`
		Tenancy string `xml:"tenancy" json:"tenancy"`
	} `xml:"placement" json:"placement"`
	Devices []struct {
		Device   string `xml:"deviceName" json:"device"`
		VolumeID string `xml:"ebs>volumeId" json:"volume_id"`
	} `xml:"blockDeviceMapping>item" json:"devices"`
}
type HardwareType struct {
	Name string `xml:"instanceType" json:"name"`
	VCPU struct {
		Default *int `xml:"defaultVCpus" json:"default_vcpus"`
		Cores   *int `xml:"defaultCores" json:"default_cores"`
		Threads *int `xml:"defaultThreadsPerCore" json:"default_threads_per_core"`
	} `xml:"vCpuInfo" json:"vcpu"`
	Memory struct {
		MiB *int64 `xml:"sizeInMiB" json:"size_in_mib"`
	} `xml:"memoryInfo" json:"memory"`
	Architectures    []string `xml:"processorInfo>supportedArchitectures>item" json:"architectures"`
	Manufacturer     string   `xml:"processorInfo>manufacturer" json:"manufacturer"`
	StorageSupported *bool    `xml:"instanceStorageSupported" json:"instance_storage_supported"`
	Burstable        *bool    `xml:"burstablePerformanceSupported" json:"burstable_performance_supported"`
	BareMetal        *bool    `xml:"bareMetal" json:"bare_metal"`
	Hypervisor       string   `xml:"hypervisor" json:"hypervisor"`
	RootDevices      []string `xml:"supportedRootDeviceTypes>item" json:"root_device_types"`
	UsageClasses     []string `xml:"supportedUsageClasses>item" json:"usage_classes"`
	Virtualizations  []string `xml:"supportedVirtualizationTypes>item" json:"virtualization_types"`
	ENASupport       string   `xml:"networkInfo>enaSupport" json:"ena_support"`
	NetworkCards     []struct {
		Index    *int   `xml:"networkCardIndex" json:"index"`
		Baseline string `xml:"baselineBandwidthInGbps" json:"baseline_gbps"`
		Peak     string `xml:"peakBandwidthInGbps" json:"peak_gbps"`
	} `xml:"networkInfo>networkCards>item" json:"network_cards"`
	EBS struct {
		BaselineIOPS *int64 `xml:"baselineIops" json:"baseline_iops"`
		BaselineMBps string `xml:"baselineThroughputInMBps" json:"baseline_mbps"`
		MaximumIOPS  *int64 `xml:"maximumIops" json:"maximum_iops"`
		MaximumMBps  string `xml:"maximumThroughputInMBps" json:"maximum_mbps"`
	} `xml:"ebsInfo>ebsOptimizedInfo" json:"ebs"`
	GPUs []struct {
		Count *int   `xml:"count" json:"count"`
		Name  string `xml:"name" json:"name"`
	} `xml:"gpuInfo>gpus>item" json:"gpus"`
	FPGAs []struct {
		Count *int `xml:"count" json:"count"`
	} `xml:"fpgaInfo>fpgas>item" json:"fpgas"`
	Inference []struct {
		Count *int `xml:"count" json:"count"`
	} `xml:"inferenceAcceleratorInfo>accelerators>item" json:"inference_accelerators"`
}
type HardwareOffering struct {
	Type         string `xml:"instanceType" json:"instance_type"`
	LocationType string `xml:"locationType" json:"location_type"`
	Location     string `xml:"location" json:"location"`
}
type HardwareVolume struct {
	ID              string `xml:"volumeId" json:"id"`
	Type            string `xml:"volumeType" json:"volume_type"`
	Zone            string `xml:"availabilityZone" json:"zone"`
	IOPS            *int64 `xml:"iops" json:"iops"`
	ThroughputMiBps *int64 `xml:"throughput" json:"throughput_mibps"`
	Attachments     []struct {
		InstanceID string `xml:"instanceId" json:"instance_id"`
		Device     string `xml:"device" json:"device"`
		State      string `xml:"status" json:"state"`
	} `xml:"attachmentSet>item" json:"attachments"`
}
type HardwareImage struct {
	ID             string `xml:"imageId" json:"id"`
	Architecture   string `xml:"architecture" json:"architecture"`
	Virtualization string `xml:"virtualizationType" json:"virtualization_type"`
	RootDevice     string `xml:"rootDeviceType" json:"root_device_type"`
	State          string `xml:"imageState" json:"state"`
	ENASupport     *bool  `xml:"enaSupport" json:"ena_support"`
}
type HardwarePage struct {
	Selector string
	Body     []byte
}

var hardwareTypeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
var hardwareVolumeID = regexp.MustCompile(`^vol-[a-f0-9]{8}([a-f0-9]{9})?$`)
var hardwareImageID = regexp.MustCompile(`^ami-[a-f0-9]{8}([a-f0-9]{9})?$`)

func HardwareTypeNames(names []string) ([]string, error) {
	if len(names) < 1 || len(names) > 100 {
		return nil, errors.New("HARDWARE_CANDIDATE_LIMIT")
	}
	seen := map[string]bool{}
	out := append([]string{}, names...)
	for _, name := range out {
		if len(name) > 128 || !hardwareTypeName.MatchString(name) || seen[name] {
			return nil, errors.New("HARDWARE_INSTANCE_TYPE_INVALID")
		}
		seen[name] = true
	}
	sort.Strings(out)
	return out, nil
}

func (a *AWS) hardwareRead(ctx context.Context, region string, values url.Values) ([]byte, error) {
	values.Set("Version", "2016-11-15")
	body := values.Encode()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ec2."+region+".amazonaws.com/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept-Encoding", "identity")
	creds, err := a.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("HARDWARE_READ_IDENTITY_UNAVAILABLE")
	}
	sum := sha256.Sum256([]byte(body))
	if err = v4.NewSigner().SignHTTP(ctx, creds, r, hex.EncodeToString(sum[:]), "ec2", region, time.Now()); err != nil {
		return nil, err
	}
	client := *a.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(r)
	if err != nil {
		return nil, errors.New("HARDWARE_NATIVE_READ_UNAVAILABLE")
	}
	defer response.Body.Close()
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("HARDWARE_NATIVE_ENCODING_UNSUPPORTED")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return nil, errors.New("HARDWARE_NATIVE_RESPONSE_LIMIT")
	}
	if response.StatusCode != 200 {
		return nil, &QueryRejection{Action: values.Get("Action"), Code: "ProviderRejected", StatusCode: response.StatusCode}
	}
	return raw, nil
}

// HardwareInventory queries only exact current inventory and operator-approved
// candidate identifiers. Candidate prices and execution permission are absent.
func (a *AWS) HardwareInventory(ctx context.Context, region, account, instance string, candidates []string) (HardwareEvidence, error) {
	out := HardwareEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: account, Region: region, Types: []HardwareType{}, Offerings: []HardwareOffering{}, Volumes: []HardwareVolume{}}
	if region != "eu-west-1" || !fleetAccount.MatchString(account) || !fleetInstance.MatchString(instance) {
		return out, errors.New("HARDWARE_SCOPE_INVALID")
	}
	names, err := HardwareTypeNames(candidates)
	if err != nil {
		return out, err
	}
	pages := []HardwarePage{}
	read := func(v url.Values) ([]byte, error) {
		raw, e := a.hardwareRead(ctx, region, v)
		if e == nil {
			pages = append(pages, HardwarePage{v.Encode(), raw})
		}
		return raw, e
	}
	raw, err := read(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {instance}})
	if err != nil {
		return out, err
	}
	i, err := parseHardwareInstance(raw, account, instance)
	if err != nil {
		return out, err
	}
	out.Instance = i
	if !containsHardware(names, i.Type) {
		names = append(names, i.Type)
		names, err = HardwareTypeNames(names)
		if err != nil {
			return out, err
		}
	}
	v := url.Values{"Action": {"DescribeInstanceTypes"}, "IncludeUnsupportedInRegion": {"false"}}
	for j, name := range names {
		v.Set(fmt.Sprintf("InstanceType.%d", j+1), name)
	}
	for p := 0; p < 100; p++ {
		raw, err = read(v)
		if err != nil {
			return out, err
		}
		var page struct {
			XMLName xml.Name
			Types   []HardwareType `xml:"instanceTypeSet>item"`
			Next    string         `xml:"nextToken"`
		}
		if xml.Unmarshal(raw, &page) != nil || page.XMLName.Local != "DescribeInstanceTypesResponse" {
			return out, errors.New("HARDWARE_TYPES_NATIVE_INVALID")
		}
		out.Types = append(out.Types, page.Types...)
		if page.Next == "" {
			break
		}
		if p == 99 || page.Next == v.Get("NextToken") {
			return out, errors.New("HARDWARE_TYPES_PAGINATION_INVALID")
		}
		v.Set("NextToken", page.Next)
	}
	v = url.Values{"Action": {"DescribeInstanceTypeOfferings"}, "LocationType": {"availability-zone"}, "Filter.1.Name": {"instance-type"}, "Filter.2.Name": {"location"}, "Filter.2.Value.1": {i.Placement.Zone}, "MaxResults": {"1000"}}
	for j, name := range names {
		v.Set(fmt.Sprintf("Filter.1.Value.%d", j+1), name)
	}
	for p := 0; p < 100; p++ {
		raw, err = read(v)
		if err != nil {
			return out, err
		}
		var page struct {
			XMLName   xml.Name
			Offerings []HardwareOffering `xml:"instanceTypeOfferingSet>item"`
			Next      string             `xml:"nextToken"`
		}
		if xml.Unmarshal(raw, &page) != nil || page.XMLName.Local != "DescribeInstanceTypeOfferingsResponse" {
			return out, errors.New("HARDWARE_OFFERINGS_NATIVE_INVALID")
		}
		out.Offerings = append(out.Offerings, page.Offerings...)
		if page.Next == "" {
			break
		}
		if p == 99 || page.Next == v.Get("NextToken") {
			return out, errors.New("HARDWARE_OFFERINGS_PAGINATION_INVALID")
		}
		v.Set("NextToken", page.Next)
	}
	volumeIDs := []string{}
	for _, device := range i.Devices {
		if !hardwareVolumeID.MatchString(device.VolumeID) {
			return out, errors.New("HARDWARE_VOLUME_IDENTITY_UNKNOWN")
		}
		volumeIDs = append(volumeIDs, device.VolumeID)
	}
	if len(volumeIDs) < 1 || len(volumeIDs) > 32 {
		return out, errors.New("HARDWARE_VOLUME_LIMIT")
	}
	sort.Strings(volumeIDs)
	v = url.Values{"Action": {"DescribeVolumes"}}
	for j, id := range volumeIDs {
		v.Set(fmt.Sprintf("VolumeId.%d", j+1), id)
	}
	raw, err = read(v)
	if err != nil {
		return out, err
	}
	var volumes struct {
		XMLName xml.Name
		Volumes []HardwareVolume `xml:"volumeSet>item"`
		Next    string           `xml:"nextToken"`
	}
	if xml.Unmarshal(raw, &volumes) != nil || volumes.XMLName.Local != "DescribeVolumesResponse" || volumes.Next != "" {
		return out, errors.New("HARDWARE_VOLUME_NATIVE_INVALID")
	}
	out.Volumes = volumes.Volumes
	if !hardwareImageID.MatchString(i.ImageID) {
		return out, errors.New("HARDWARE_IMAGE_IDENTITY_UNKNOWN")
	}
	raw, err = read(url.Values{"Action": {"DescribeImages"}, "ImageId.1": {i.ImageID}})
	if err != nil {
		return out, err
	}
	var images struct {
		XMLName xml.Name
		Images  []HardwareImage `xml:"imagesSet>item"`
	}
	if xml.Unmarshal(raw, &images) != nil || images.XMLName.Local != "DescribeImagesResponse" || len(images.Images) != 1 {
		return out, errors.New("HARDWARE_IMAGE_NATIVE_INVALID")
	}
	out.Image = images.Images[0]
	var framed bytes.Buffer
	for _, page := range pages {
		_ = binary.Write(&framed, binary.BigEndian, uint32(len(page.Selector)))
		framed.WriteString(page.Selector)
		_ = binary.Write(&framed, binary.BigEndian, uint64(len(page.Body)))
		framed.Write(page.Body)
	}
	if framed.Len() > 32<<20 {
		return out, errors.New("HARDWARE_NATIVE_RESPONSE_LIMIT")
	}
	out.Raw = framed.Bytes()
	sum := sha256.Sum256(out.Raw)
	out.RawSHA256 = hex.EncodeToString(sum[:])
	out.CollectedAt = time.Now().UTC()
	if err = ValidateHardwareEvidence(out, instance, names); err != nil {
		return out, err
	}
	return out, nil
}
func containsHardware(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
func parseHardwareInstance(raw []byte, account, instance string) (HardwareInstance, error) {
	var response struct {
		XMLName      xml.Name
		Reservations []struct {
			Owner     string             `xml:"ownerId"`
			Instances []HardwareInstance `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
		Next string `xml:"nextToken"`
	}
	if xml.Unmarshal(raw, &response) != nil || response.XMLName.Local != "DescribeInstancesResponse" || response.Next != "" || len(response.Reservations) != 1 || response.Reservations[0].Owner != account || len(response.Reservations[0].Instances) != 1 || response.Reservations[0].Instances[0].ID != instance {
		return HardwareInstance{}, errors.New("HARDWARE_NATIVE_INSTANCE_BINDING_INVALID")
	}
	return response.Reservations[0].Instances[0], nil
}
