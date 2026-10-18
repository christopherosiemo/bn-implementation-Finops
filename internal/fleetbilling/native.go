package fleetbilling

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

type page struct {
	selector url.Values
	body     []byte
}

func nativePages(raw []byte) ([]page, error) {
	if len(raw) == 0 || len(raw) > 32<<20 {
		return nil, errors.New("PRICE_NATIVE_RAW_LIMIT")
	}
	r := bytes.NewReader(raw)
	out := []page{}
	for r.Len() > 0 {
		var n uint32
		var size uint64
		if binary.Read(r, binary.BigEndian, &n) != nil || n == 0 || n > 65536 || uint64(n) > uint64(r.Len()) {
			return nil, errors.New("PRICE_NATIVE_FRAMING_INVALID")
		}
		s := make([]byte, n)
		_, _ = io.ReadFull(r, s)
		v, e := url.ParseQuery(string(s))
		if e != nil || v.Encode() != string(s) {
			return nil, errors.New("PRICE_NATIVE_SELECTOR_INVALID")
		}
		for _, vs := range v {
			if len(vs) != 1 {
				return nil, errors.New("PRICE_NATIVE_SELECTOR_INVALID")
			}
		}
		if binary.Read(r, binary.BigEndian, &size) != nil || size == 0 || size > 16<<20 || size > uint64(r.Len()) {
			return nil, errors.New("PRICE_NATIVE_FRAMING_INVALID")
		}
		body := make([]byte, int(size))
		_, _ = io.ReadFull(r, body)
		out = append(out, page{v, body})
		if len(out) > 3200 {
			return nil, errors.New("PRICE_NATIVE_PAGE_LIMIT")
		}
	}
	return out, nil
}
func exactKeys(v url.Values, keys ...string) bool {
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return false
		}
	}
	return true
}

// NativeMachine is derived only after exact archived selectors are reparsed.
// It is not a public registration or an authoritative caller DTO.
type NativeMachine struct{ InstanceID, InstanceType, ImageID, Platform, Operation, Tenancy, HardwareReceiptID, SubnetID, VPCID string }
type nativeGroup struct {
	provider.FleetGroup
	Subnets []string
}

var subnetPattern = regexp.MustCompile(`^subnet-[a-f0-9]{8}(?:[a-f0-9]{9})?$`)
var vpcPattern = regexp.MustCompile(`^vpc-[a-f0-9]{8}(?:[a-f0-9]{9})?$`)

func inSubnets(subnet string, subnets []string) bool {
	for _, s := range subnets {
		if s == subnet {
			return true
		}
	}
	return false
}

type NativeTemplate struct {
	ID                             string
	Version                        uint64
	InstanceType, ImageID, Tenancy string
}

func parseHardware(receipt model.Document, raw []byte, account, region string) (NativeMachine, error) {
	native := object(receipt["native"])
	binding := object(receipt["binding"])
	ref := object(receipt["raw_object"])
	if model.String(receipt, "kind") != "AWS_EC2_HARDWARE" || model.String(receipt, "writer_role") != "finops_ingester" || model.String(native, "raw_sha256") != model.String(ref, "body_sha256") || BytesHash(raw) != model.String(ref, "body_sha256") || model.String(binding, "account_id") != account || model.String(binding, "region") != region {
		return NativeMachine{}, errors.New("PRICE_HARDWARE_RECEIPT_BINDING_INVALID")
	}
	parsed, e := provider.ParseHardwareEvidence(raw, account, region, model.String(binding, "provider_resource_id"), model.Strings(receipt, "candidate_types"), stamp(receipt, "collected_at"))
	if e != nil {
		return NativeMachine{}, e
	}
	// Both the original typed receipt and the extended image attributes must
	// agree with the same bytes, not a replacement model supplied by a caller.
	var typed provider.HardwareEvidence
	if decode(native, &typed) != nil || Hash(parsed) != Hash(typed) {
		return NativeMachine{}, errors.New("PRICE_HARDWARE_TYPED_RAW_MISMATCH")
	}
	pages, e := nativePages(raw)
	if e != nil {
		return NativeMachine{}, e
	}
	var image struct {
		XMLName xml.Name
		Items   []struct {
			ID        string `xml:"imageId"`
			Platform  string `xml:"platformDetails"`
			Operation string `xml:"usageOperation"`
			Products  []struct {
				ID string `xml:"productCode"`
			} `xml:"productCodes>item"`
		} `xml:"imagesSet>item"`
	}
	found := false
	for _, p := range pages {
		if p.selector.Get("Action") == "DescribeImages" {
			if found || xml.Unmarshal(p.body, &image) != nil || image.XMLName.Local != "DescribeImagesResponse" || len(image.Items) != 1 {
				return NativeMachine{}, errors.New("PRICE_IMAGE_NATIVE_INVALID")
			}
			found = true
		}
	}
	i := parsed.Instance
	if !found || image.Items[0].ID != i.ImageID || image.Items[0].Platform != "Linux/UNIX" || image.Items[0].Operation != "RunInstances" || len(image.Items[0].Products) != 0 || i.PlatformDetails != "Linux/UNIX" || i.UsageOperation != "RunInstances" || i.Placement.Tenancy != "default" || i.Lifecycle != "" {
		return NativeMachine{}, errors.New("PRICE_NATIVE_LINUX_SHARED_LICENSE_REQUIRED")
	}
	var network struct {
		Items []struct {
			Subnet string `xml:"subnetId"`
			VPC    string `xml:"vpcId"`
		} `xml:"reservationSet>item>instancesSet>item"`
	}
	if xml.Unmarshal(pages[0].body, &network) != nil || len(network.Items) != 1 || !subnetPattern.MatchString(network.Items[0].Subnet) || !vpcPattern.MatchString(network.Items[0].VPC) {
		return NativeMachine{}, errors.New("PRICE_NATIVE_VPC_SUBNET_UNAVAILABLE")
	}
	return NativeMachine{i.ID, i.Type, i.ImageID, i.PlatformDetails, i.UsageOperation, i.Placement.Tenancy, model.String(receipt, "id"), network.Items[0].Subnet, network.Items[0].VPC}, nil
}

func parseTemplates(receipt model.Document, raw []byte) (map[string]NativeTemplate, error) {
	if model.String(receipt, "kind") != "AWS_FLEET_LAUNCH_TEMPLATES" || model.String(receipt, "writer_role") != "finops_ingester" || BytesHash(raw) != model.String(object(receipt["raw_object"]), "body_sha256") {
		return nil, errors.New("PRICE_TEMPLATE_RAW_BINDING_INVALID")
	}
	var requests []provider.FleetTemplateRequest
	if decode(receipt["requests"], &requests) != nil || len(requests) < 1 || len(requests) > 2 {
		return nil, errors.New("PRICE_TEMPLATE_REQUEST_INVALID")
	}
	wanted := map[string][]uint64{}
	for _, r := range requests {
		if r.Version == 0 {
			return nil, errors.New("PRICE_TEMPLATE_CONCRETE_VERSION_REQUIRED")
		}
		wanted[r.ID] = append(wanted[r.ID], r.Version)
	}
	for k := range wanted {
		sort.Slice(wanted[k], func(i, j int) bool { return wanted[k][i] < wanted[k][j] })
	}
	pages, e := nativePages(raw)
	if e != nil {
		return nil, e
	}
	next, done := map[string]string{}, map[string]bool{}
	out := map[string]NativeTemplate{}
	typed := []provider.FleetTemplateVersion{}
	for _, p := range pages {
		v := p.selector
		id := v.Get("LaunchTemplateId")
		versions, ok := wanted[id]
		if !ok || done[id] || v.Get("Action") != "DescribeLaunchTemplateVersions" || v.Get("Version") != "2016-11-15" || v.Get("ResolveAlias") != "false" || v.Get("MaxResults") != "100" || v.Get("NextToken") != next[id] {
			return nil, errors.New("PRICE_TEMPLATE_SELECTOR_MISMATCH")
		}
		allowed := []string{"Action", "Version", "LaunchTemplateId", "ResolveAlias", "MaxResults", "NextToken"}
		for n, ver := range versions {
			key := "LaunchTemplateVersion." + strconv.Itoa(n+1)
			allowed = append(allowed, key)
			if v.Get(key) != strconv.FormatUint(ver, 10) {
				return nil, errors.New("PRICE_TEMPLATE_SELECTOR_MISMATCH")
			}
		}
		if !exactKeys(v, allowed...) {
			return nil, errors.New("PRICE_TEMPLATE_SELECTOR_MISMATCH")
		}
		var base struct {
			XMLName xml.Name
			Items   []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
			Next    string                          `xml:"nextToken"`
		}
		var extended struct {
			Items []struct {
				ID      string `xml:"launchTemplateId"`
				Version uint64 `xml:"versionNumber"`
				Data    struct {
					Type                string     `xml:"instanceType"`
					Image               string     `xml:"imageId"`
					Tenancy             string     `xml:"placement>tenancy"`
					Market              *struct{}  `xml:"instanceMarketOptions"`
					CapacityReservation *struct{}  `xml:"capacityReservationSpecification"`
					Licenses            []struct{} `xml:"licenseSpecifications>item"`
					NativeLicenses      []struct{} `xml:"licenseSet>item"`
					HostID              string     `xml:"placement>hostId"`
					HostResourceGroup   string     `xml:"placement>hostResourceGroupArn"`
					Interfaces          []struct {
						Subnet string `xml:"subnetId"`
					} `xml:"networkInterfaceSet>item"`
				} `xml:"launchTemplateData"`
			} `xml:"launchTemplateVersionSet>item"`
		}
		if xml.Unmarshal(p.body, &base) != nil || base.XMLName.Local != "DescribeLaunchTemplateVersionsResponse" || xml.Unmarshal(p.body, &extended) != nil {
			return nil, errors.New("PRICE_TEMPLATE_NATIVE_INVALID")
		}
		for _, i := range extended.Items {
			key := i.ID + ":" + strconv.FormatUint(i.Version, 10)
			want := false
			for _, ver := range versions {
				want = want || ver == i.Version
			}
			if i.ID != id || !want || out[key].ID != "" || i.Data.Type == "" || !strings.HasPrefix(i.Data.Image, "ami-") || i.Data.Tenancy != "default" {
				return nil, errors.New("PRICE_TEMPLATE_EXPLICIT_SHARED_TENANCY_REQUIRED")
			}
			if i.Data.Market != nil || i.Data.CapacityReservation != nil || len(i.Data.Licenses) > 0 || len(i.Data.NativeLicenses) > 0 || i.Data.HostID != "" || i.Data.HostResourceGroup != "" {
				return nil, errors.New("PRICE_TEMPLATE_PURCHASE_OR_LICENSE_MODEL_UNSUPPORTED")
			}
			for _, network := range i.Data.Interfaces {
				if network.Subnet != "" {
					return nil, errors.New("PRICE_TEMPLATE_EMBEDDED_SUBNET_UNSUPPORTED")
				}
			}
			out[key] = NativeTemplate{i.ID, i.Version, i.Data.Type, i.Data.Image, i.Data.Tenancy}
		}
		typed = append(typed, base.Items...)
		next[id] = base.Next
		done[id] = base.Next == ""
	}
	for id := range wanted {
		if !done[id] {
			return nil, errors.New("PRICE_TEMPLATE_INCOMPLETE")
		}
	}
	if len(out) != len(requests) {
		return nil, errors.New("PRICE_TEMPLATE_INCOMPLETE")
	}
	sort.Slice(typed, func(i, j int) bool {
		if typed[i].ID == typed[j].ID {
			return typed[i].Version < typed[j].Version
		}
		return typed[i].ID < typed[j].ID
	})
	if Hash(typed) != Hash(receipt["templates"]) {
		return nil, errors.New("PRICE_TEMPLATE_TYPED_RAW_MISMATCH")
	}
	return out, nil
}

func parseMembership(receipt model.Document, raw []byte, target Target) (nativeGroup, nativeGroup, error) {
	fail := func() (nativeGroup, nativeGroup, error) {
		return nativeGroup{}, nativeGroup{}, errors.New("PRICE_MEMBERSHIP_NATIVE_INVALID")
	}
	if model.String(receipt, "kind") != "AWS_FLEET_MEMBERSHIP" || model.String(receipt, "writer_role") != "finops_ingester" || Hash(receipt["binding"]) != Hash(target.Binding) || model.String(receipt, "old_asg") != target.OldASG || model.String(receipt, "candidate_asg") != target.CandidateASG || BytesHash(raw) != model.String(object(receipt["raw_object"]), "body_sha256") {
		return fail()
	}
	pages, e := nativePages(raw)
	if e != nil {
		return fail()
	}
	names := []string{target.OldASG, target.CandidateASG}
	sort.Strings(names)
	next := ""
	groups := []provider.FleetGroup{}
	networks := map[string][]string{}
	for n, p := range pages {
		v := p.selector
		if v.Get("Action") != "DescribeAutoScalingGroups" || v.Get("Version") != "2011-01-01" || v.Get("MaxRecords") != "100" || v.Get("NextToken") != next || v.Get("AutoScalingGroupNames.member.1") != names[0] || v.Get("AutoScalingGroupNames.member.2") != names[1] || !exactKeys(v, "Action", "Version", "MaxRecords", "NextToken", "AutoScalingGroupNames.member.1", "AutoScalingGroupNames.member.2") {
			return fail()
		}
		var response struct {
			XMLName xml.Name
			Result  struct {
				Groups []provider.FleetGroup `xml:"AutoScalingGroups>member"`
				Next   string                `xml:"NextToken"`
			} `xml:"DescribeAutoScalingGroupsResult"`
		}
		if xml.Unmarshal(p.body, &response) != nil || response.XMLName.Local != "DescribeAutoScalingGroupsResponse" {
			return fail()
		}
		var extra struct {
			Items []struct {
				Name    string `xml:"AutoScalingGroupName"`
				Subnets string `xml:"VPCZoneIdentifier"`
			} `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
		}
		if xml.Unmarshal(p.body, &extra) != nil {
			return fail()
		}
		for _, g := range extra.Items {
			if _, exists := networks[g.Name]; exists {
				return fail()
			}
			seenSubnets := map[string]bool{}
			subnets := strings.Split(g.Subnets, ",")
			if len(subnets) > 16 {
				return fail()
			}
			for _, s := range subnets {
				if !subnetPattern.MatchString(s) || seenSubnets[s] {
					return fail()
				}
				seenSubnets[s] = true
			}
			sort.Strings(subnets)
			networks[g.Name] = subnets
		}
		for _, g := range response.Result.Groups {
			if g.Members == nil {
				g.Members = []provider.FleetMember{}
			}
			groups = append(groups, g)
		}
		next = response.Result.Next
		if next == "" && n != len(pages)-1 {
			return fail()
		}
	}
	if next != "" || len(groups) != 2 {
		return fail()
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	if Hash(groups) != Hash(receipt["groups"]) {
		return fail()
	}
	var old, candidate nativeGroup
	seen := map[string]bool{}
	for _, g := range groups {
		if seen[g.Name] || g.LaunchTemplate.ID == "" || g.MixedPolicy != nil || !strings.HasPrefix(g.ARN, "arn:aws:autoscaling:"+target.Binding.Region+":"+target.Binding.AccountID+":autoScalingGroup:") || !strings.HasSuffix(g.ARN, ":autoScalingGroupName/"+g.Name) {
			return fail()
		}
		seen[g.Name] = true
		tags := map[string]string{}
		for _, tag := range g.Tags {
			if _, exists := tags[tag.Key]; exists {
				return fail()
			}
			tags[tag.Key] = tag.Value
		}
		if tags["finops:tenant"] != target.Binding.TenantID || tags["finops:environment"] != "NON_PRODUCTION" {
			return fail()
		}
		if g.Name == target.OldASG {
			old = nativeGroup{g, networks[g.Name]}
		} else if g.Name == target.CandidateASG {
			candidate = nativeGroup{g, networks[g.Name]}
		} else {
			return fail()
		}
	}
	if len(old.Members) < 1 || len(old.Members) > 256 {
		return fail()
	}
	return old, candidate, nil
}

func BytesHash(raw []byte) string { return rawHash(raw) }
func fresh(t, now time.Time, age time.Duration) bool {
	return !t.IsZero() && !t.After(now.Add(30*time.Second)) && !t.Before(now.Add(-age))
}
