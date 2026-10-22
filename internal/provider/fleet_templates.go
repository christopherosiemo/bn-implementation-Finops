package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type FleetTemplateRequest struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}
type FleetTemplateEvidence struct {
	SchemaVersion string                 `json:"schema_version"`
	Provider      string                 `json:"provider"`
	AccountID     string                 `json:"account_id"`
	Region        string                 `json:"region"`
	RawSHA256     string                 `json:"raw_sha256"`
	CollectedAt   time.Time              `json:"collected_at"`
	Raw           []byte                 `json:"-"`
	Templates     []FleetTemplateVersion `json:"templates"`
}
type FleetTemplateVersion struct {
	ID        string            `xml:"launchTemplateId" json:"id"`
	Name      string            `xml:"launchTemplateName" json:"name"`
	Version   uint64            `xml:"versionNumber" json:"version"`
	CreatedBy string            `xml:"createdBy" json:"created_by"`
	Data      FleetTemplateData `xml:"launchTemplateData" json:"data"`
}
type FleetTemplateData struct {
	InstanceType         string                     `json:"instance_type"`
	ImageID              string                     `json:"image_id"`
	InstanceRequirements bool                       `json:"instance_requirements"`
	BlockDevices         []FleetTemplateBlockDevice `json:"block_devices"`
}
type FleetTemplateBlockDevice struct {
	DeviceName      string            `json:"device_name"`
	VirtualName     string            `json:"virtual_name"`
	NoDevicePresent bool              `json:"no_device_present"`
	EBS             *FleetTemplateEBS `json:"ebs"`
}
type FleetTemplateEBS struct {
	Encrypted           *bool  `xml:"encrypted" json:"encrypted"`
	DeleteOnTermination *bool  `xml:"deleteOnTermination" json:"delete_on_termination"`
	VolumeSizeGiB       *int64 `xml:"volumeSize" json:"volume_size_gib"`
	VolumeType          string `xml:"volumeType" json:"volume_type"`
	IOPS                *int64 `xml:"iops" json:"iops"`
	ThroughputMiB       *int64 `xml:"throughput" json:"throughput_mib"`
	SnapshotID          string `xml:"snapshotId" json:"snapshot_id"`
	KMSKeyID            string `xml:"kmsKeyId" json:"kms_key_id"`
}

func (d *FleetTemplateData) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var raw struct {
		InstanceType string    `xml:"instanceType"`
		ImageID      string    `xml:"imageId"`
		Requirements *struct{} `xml:"instanceRequirements"`
		BlockDevices *struct {
			Items []FleetTemplateBlockDevice `xml:"item"`
		} `xml:"blockDeviceMappingSet"`
	}
	if e := decoder.DecodeElement(&raw, &start); e != nil {
		return e
	}
	d.InstanceType, d.ImageID, d.InstanceRequirements = raw.InstanceType, raw.ImageID, raw.Requirements != nil
	d.BlockDevices = nil
	if raw.BlockDevices != nil {
		d.BlockDevices = raw.BlockDevices.Items
		if d.BlockDevices == nil {
			d.BlockDevices = []FleetTemplateBlockDevice{}
		}
	}
	return nil
}
func (d *FleetTemplateBlockDevice) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var raw struct {
		DeviceName  string            `xml:"deviceName"`
		VirtualName string            `xml:"virtualName"`
		NoDevice    *string           `xml:"noDevice"`
		EBS         *FleetTemplateEBS `xml:"ebs"`
	}
	if e := decoder.DecodeElement(&raw, &start); e != nil {
		return e
	}
	d.DeviceName, d.VirtualName, d.NoDevicePresent, d.EBS = raw.DeviceName, raw.VirtualName, raw.NoDevice != nil, raw.EBS
	return nil
}

var fleetTemplateID = regexp.MustCompile(`^lt-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var fleetAMI = regexp.MustCompile(`^ami-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var fleetInstanceType = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)

func (a *AWS) fleetTemplateRead(ctx context.Context, region string, values url.Values) ([]byte, error) {
	values.Set("Action", "DescribeLaunchTemplateVersions")
	values.Set("Version", "2016-11-15")
	body := values.Encode()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://ec2."+region+".amazonaws.com/", strings.NewReader(body))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept-Encoding", "identity")
	credentials, e := a.cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return nil, errors.New("FLEET_TEMPLATE_READ_IDENTITY_UNAVAILABLE")
	}
	sum := sha256.Sum256([]byte(body))
	if e = v4.NewSigner().SignHTTP(ctx, credentials, request, hex.EncodeToString(sum[:]), "ec2", region, time.Now()); e != nil {
		return nil, e
	}
	client := *a.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := client.Do(request)
	if e != nil {
		return nil, errors.New("FLEET_TEMPLATE_READ_UNAVAILABLE")
	}
	defer response.Body.Close()
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("FLEET_TEMPLATE_ENCODING_UNSUPPORTED")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if e != nil || len(raw) > 16<<20 {
		return nil, errors.New("FLEET_TEMPLATE_RESPONSE_LIMIT")
	}
	if response.StatusCode != 200 {
		return nil, &QueryRejection{Action: "DescribeLaunchTemplateVersions", Code: "ProviderRejected", StatusCode: response.StatusCode}
	}
	return raw, nil
}

// FleetTemplateVersions fetches exact numbered versions under the caller's
// separately approved account read-role binding. CreatedBy is retained metadata,
// never account identity. Absent AMI-derived block mappings/EBS flags stay null;
// this read cannot prove statelessness or effective attached storage.
// Query wire contract: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeLaunchTemplateVersions.html
func (a *AWS) FleetTemplateVersions(ctx context.Context, region, account string, requests []FleetTemplateRequest) (FleetTemplateEvidence, error) {
	out := FleetTemplateEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: account, Region: region, Templates: []FleetTemplateVersion{}}
	if region != "eu-west-1" || !fleetAccount.MatchString(account) || len(requests) < 1 || len(requests) > 32 {
		return out, errors.New("FLEET_TEMPLATE_SCOPE_INVALID")
	}
	wanted := map[string]map[uint64]bool{}
	for _, r := range requests {
		if !fleetTemplateID.MatchString(r.ID) || r.Version == 0 {
			return out, errors.New("FLEET_TEMPLATE_PIN_REQUIRED")
		}
		if wanted[r.ID] == nil {
			wanted[r.ID] = map[uint64]bool{}
		}
		if wanted[r.ID][r.Version] {
			return out, errors.New("FLEET_TEMPLATE_DUPLICATE_REQUEST")
		}
		wanted[r.ID][r.Version] = true
	}
	ids := []string{}
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var raw bytes.Buffer
	for _, id := range ids {
		versions := []uint64{}
		for version := range wanted[id] {
			versions = append(versions, version)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
		values := url.Values{"LaunchTemplateId": {id}, "MaxResults": {"100"}, "ResolveAlias": {"false"}}
		for i, version := range versions {
			values.Set("LaunchTemplateVersion."+strconv.Itoa(i+1), strconv.FormatUint(version, 10))
		}
		seen := map[uint64]bool{}
		tokens := map[string]bool{}
		finished := false
		for page := 0; page < 100; page++ {
			body, e := a.fleetTemplateRead(ctx, region, values)
			if e != nil {
				return out, e
			}
			var response struct {
				XMLName   xml.Name
				Templates []FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
				Next      string                 `xml:"nextToken"`
			}
			if xml.Unmarshal(body, &response) != nil || response.XMLName.Local != "DescribeLaunchTemplateVersionsResponse" {
				return out, errors.New("FLEET_TEMPLATE_RESPONSE_INVALID")
			}
			selector := values.Encode()
			_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
			raw.WriteString(selector)
			_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
			raw.Write(body)
			if raw.Len() > 32<<20 {
				return out, errors.New("FLEET_TEMPLATE_RESPONSE_LIMIT")
			}
			for _, v := range response.Templates {
				if v.ID != id || !wanted[id][v.Version] || seen[v.Version] || v.Name == "" || len(v.Name) > 128 || v.Data.InstanceRequirements || !fleetInstanceType.MatchString(v.Data.InstanceType) || len(v.Data.InstanceType) > 128 || !fleetAMI.MatchString(v.Data.ImageID) {
					return out, errors.New("FLEET_TEMPLATE_EXACT_VERSION_OR_DATA_MISMATCH")
				}
				seen[v.Version] = true
				devices := map[string]bool{}
				if len(v.Data.BlockDevices) > 64 {
					return out, errors.New("FLEET_TEMPLATE_BLOCK_MAPPING_INVALID")
				}
				for _, b := range v.Data.BlockDevices {
					if b.DeviceName == "" || len(b.DeviceName) > 255 || devices[b.DeviceName] || b.NoDevicePresent && (b.EBS != nil || b.VirtualName != "") || b.VirtualName != "" && b.EBS != nil {
						return out, errors.New("FLEET_TEMPLATE_BLOCK_MAPPING_INVALID")
					}
					devices[b.DeviceName] = true
					if b.EBS != nil {
						for _, value := range []*int64{b.EBS.VolumeSizeGiB, b.EBS.IOPS, b.EBS.ThroughputMiB} {
							if value != nil && *value < 0 {
								return out, errors.New("FLEET_TEMPLATE_BLOCK_MAPPING_INVALID")
							}
						}
					}
				}
				out.Templates = append(out.Templates, v)
			}
			if response.Next == "" {
				if len(seen) != len(versions) {
					return out, errors.New("FLEET_TEMPLATE_VERSION_NOT_OBSERVED")
				}
				finished = true
				break
			}
			if tokens[response.Next] {
				return out, errors.New("FLEET_TEMPLATE_PAGINATION_CONFLICT")
			}
			tokens[response.Next] = true
			values.Set("NextToken", response.Next)
		}
		if !finished {
			return out, errors.New("FLEET_TEMPLATE_PAGINATION_LIMIT")
		}
	}
	sort.Slice(out.Templates, func(i, j int) bool {
		if out.Templates[i].ID == out.Templates[j].ID {
			return out.Templates[i].Version < out.Templates[j].Version
		}
		return out.Templates[i].ID < out.Templates[j].ID
	})
	out.Raw = append([]byte{}, raw.Bytes()...)
	sum := sha256.Sum256(out.Raw)
	out.RawSHA256 = hex.EncodeToString(sum[:])
	out.CollectedAt = time.Now().UTC()
	return out, nil
}
