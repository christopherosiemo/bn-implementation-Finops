package fleetcapacity

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)
var instance = regexp.MustCompile(`^i-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var instanceType = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)

type nativePage struct {
	selector url.Values
	body     []byte
}

func pages(raw []byte) ([]nativePage, error) {
	invalid := errors.New("FLEET_CAPACITY_NATIVE_FRAMING_INVALID")
	if len(raw) == 0 || len(raw) > 32<<20 {
		return nil, invalid
	}
	r := bytes.NewReader(raw)
	out := []nativePage{}
	for r.Len() > 0 {
		var n uint32
		var size uint64
		if binary.Read(r, binary.BigEndian, &n) != nil || n == 0 || n > 65536 || uint64(n) > uint64(r.Len()) {
			return nil, invalid
		}
		selector := make([]byte, n)
		if _, e := io.ReadFull(r, selector); e != nil {
			return nil, invalid
		}
		v, e := url.ParseQuery(string(selector))
		if e != nil || v.Encode() != string(selector) {
			return nil, invalid
		}
		for _, values := range v {
			if len(values) != 1 {
				return nil, invalid
			}
		}
		if binary.Read(r, binary.BigEndian, &size) != nil || size == 0 || size > 16<<20 || size > uint64(r.Len()) {
			return nil, invalid
		}
		body := make([]byte, int(size))
		if _, e = io.ReadFull(r, body); e != nil {
			return nil, invalid
		}
		out = append(out, nativePage{v, body})
		if len(out) > 3200 {
			return nil, invalid
		}
	}
	return out, nil
}

func document(v any) model.Document {
	raw, _ := json.Marshal(v)
	out := model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&out)
	return out
}
func decode(v any, out any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if e = decoder.Decode(out); e != nil {
		return e
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("FLEET_CAPACITY_DOCUMENT_INVALID")
	}
	return nil
}
func unique(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		if s != "" {
			m[s] = true
		}
	}
	out := []string{}
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func nativePin(e NativeEvidence, selected g.Selection, kind string, now time.Time) (fleetbilling.GroupNativePin, error) {
	invalid := errors.New("FLEET_CAPACITY_NATIVE_PIN_INVALID")
	d, r := e.Receipt, e.Revision
	ref, rr := document(d["raw_object"]), document(r["raw_object"])
	observed, err := time.Parse(time.RFC3339Nano, model.String(d, "collected_at"))
	if err != nil || observed.Before(now.Add(-5*time.Minute)) || observed.After(now.Add(5*time.Second)) || model.String(d, "kind") != kind || model.String(r, "kind") != kind || model.String(d, "writer_role") != "finops_ingester" || model.String(r, "writer_role") != "finops_ingester" || model.String(d, "id") == "" || model.String(r, "id") != model.String(d, "revision_id") || model.String(d, "source_id") != selected.SourceID || model.String(r, "source_id") != selected.SourceID || model.String(d, "config_hash") != selected.SourceConfigSHA256 || model.String(r, "config_hash") != selected.SourceConfigSHA256 || model.Number(d, "registration_version") != selected.SourceRegistrationVersion || model.Number(r, "registration_version") != selected.SourceRegistrationVersion {
		return fleetbilling.GroupNativePin{}, invalid
	}
	for _, key := range []string{"bucket", "key", "body_sha256"} {
		if model.String(ref, key) == "" || model.String(ref, key) != model.String(rr, key) {
			return fleetbilling.GroupNativePin{}, invalid
		}
	}
	if !strings.HasPrefix(model.String(ref, "key"), "tenant/"+selected.Target.TenantID+"/") || strings.ContainsAny(model.String(ref, "key"), "\\\x00\r\n") || strings.Contains(model.String(ref, "key"), "..") || !sha.MatchString(model.String(ref, "body_sha256")) {
		return fleetbilling.GroupNativePin{}, invalid
	}
	for _, o := range []model.Document{ref, rr} {
		if v := model.String(o, "version_id"); v == "" || v == "null" {
			return fleetbilling.GroupNativePin{}, invalid
		}
	}
	if fleetbilling.BytesHash(e.Raw) != model.String(ref, "body_sha256") {
		return fleetbilling.GroupNativePin{}, invalid
	}
	if model.String(ref, "version_id") != model.String(rr, "version_id") && !bytes.Equal(e.Raw, e.RevisionRaw) {
		return fleetbilling.GroupNativePin{}, invalid
	}
	return fleetbilling.GroupNativePin{ReceiptID: model.String(d, "id"), RevisionID: model.String(r, "id"), ReceiptSHA256: fleetbilling.Hash(d), RawSHA256: model.String(ref, "body_sha256"), ReceiptVersionID: model.String(ref, "version_id"), RevisionVersionID: model.String(rr, "version_id")}, nil
}

type candidateDefinition struct {
	Template   provider.FleetTemplateVersion
	Pin        fleetbilling.GroupNativePin
	Tenancy    string
	CPUOptions *struct{} `xml:"-"`
	Reasons    []string
}

// DecodeCandidateTemplate replays exact native selectors and canonical issued
// template facts. Unsupported effective options remain explicit unknowns; the
// v1 canonical hardware serializer and old hashes are never extended.
func DecodeCandidateTemplate(e NativeEvidence, selected g.Selection, want provider.FleetLaunchTemplate, now time.Time) (*CandidateTemplate, error) {
	pin, err := nativePin(e, selected, "AWS_FLEET_LAUNCH_TEMPLATES", now)
	if err != nil {
		return nil, err
	}
	invalid := errors.New("FLEET_CAPACITY_CANDIDATE_TEMPLATE_INVALID")
	version, err := strconv.ParseUint(want.Version, 10, 64)
	if err != nil || version == 0 || want.ID == "" {
		return nil, invalid
	}
	var requests []provider.FleetTemplateRequest
	if decode(e.Receipt["requests"], &requests) != nil || len(requests) < 1 || len(requests) > 2 {
		return nil, invalid
	}
	wanted := map[string][]uint64{}
	for _, r := range requests {
		if r.ID == "" || r.Version == 0 {
			return nil, invalid
		}
		for _, v := range wanted[r.ID] {
			if v == r.Version {
				return nil, invalid
			}
		}
		wanted[r.ID] = append(wanted[r.ID], r.Version)
	}
	for id := range wanted {
		sort.Slice(wanted[id], func(i, j int) bool { return wanted[id][i] < wanted[id][j] })
	}
	items, err := pages(e.Raw)
	if err != nil {
		return nil, err
	}
	next, done := map[string]string{}, map[string]bool{}
	typed := []provider.FleetTemplateVersion{}
	seen := map[string]bool{}
	var target *CandidateTemplate
	for _, p := range items {
		v := p.selector
		id := v.Get("LaunchTemplateId")
		versions, ok := wanted[id]
		if !ok || done[id] || v.Get("Action") != "DescribeLaunchTemplateVersions" || v.Get("Version") != "2016-11-15" || v.Get("ResolveAlias") != "false" || v.Get("MaxResults") != "100" || v.Get("NextToken") != next[id] {
			return nil, invalid
		}
		allowed := map[string]bool{}
		for _, k := range []string{"Action", "Version", "LaunchTemplateId", "ResolveAlias", "MaxResults", "NextToken"} {
			allowed[k] = true
		}
		for n, w := range versions {
			k := "LaunchTemplateVersion." + strconv.Itoa(n+1)
			allowed[k] = true
			if v.Get(k) != strconv.FormatUint(w, 10) {
				return nil, invalid
			}
		}
		for k := range v {
			if !allowed[k] {
				return nil, invalid
			}
		}
		var response struct {
			XMLName xml.Name
			Items   []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
			Next    string                          `xml:"nextToken"`
		}
		var extra struct {
			Items []struct {
				ID      string `xml:"launchTemplateId"`
				Version uint64 `xml:"versionNumber"`
				Data    struct {
					Tenancy        string     `xml:"placement>tenancy"`
					CPU            *struct{}  `xml:"cpuOptions"`
					Market         *struct{}  `xml:"instanceMarketOptions"`
					Reservation    *struct{}  `xml:"capacityReservationSpecification"`
					Host           string     `xml:"placement>hostId"`
					HostGroup      string     `xml:"placement>hostResourceGroupArn"`
					Licenses       []struct{} `xml:"licenseSpecifications>item"`
					NativeLicenses []struct{} `xml:"licenseSet>item"`
					Interfaces     []struct{} `xml:"networkInterfaceSet>item"`
				} `xml:"launchTemplateData"`
			} `xml:"launchTemplateVersionSet>item"`
		}
		if xml.Unmarshal(p.body, &response) != nil || response.XMLName.Local != "DescribeLaunchTemplateVersionsResponse" || xml.Unmarshal(p.body, &extra) != nil || len(response.Items) != len(extra.Items) {
			return nil, invalid
		}
		for n, t := range response.Items {
			k := t.ID + ":" + strconv.FormatUint(t.Version, 10)
			valid := false
			for _, w := range versions {
				valid = valid || w == t.Version
			}
			if t.ID != id || !valid || seen[k] {
				return nil, invalid
			}
			seen[k] = true
			if t.ID == want.ID && t.Version == version {
				x := extra.Items[n]
				if x.ID != t.ID || x.Version != t.Version {
					return nil, invalid
				}
				why := []string{}
				if !instanceType.MatchString(t.Data.InstanceType) || !regexp.MustCompile(`^ami-[a-f0-9]{8}(?:[a-f0-9]{9})?$`).MatchString(t.Data.ImageID) || t.Data.InstanceRequirements {
					why = append(why, "CAPACITY_CANDIDATE_EXPLICIT_TYPE_IMAGE_REQUIRED")
				}
				if x.Data.Tenancy != "default" {
					why = append(why, "CAPACITY_CANDIDATE_SHARED_TENANCY_UNPROVEN")
				}
				if x.Data.CPU != nil {
					why = append(why, "CAPACITY_CANDIDATE_CPU_OPTIONS_UNSUPPORTED")
				}
				if x.Data.Market != nil || x.Data.Reservation != nil || x.Data.Host != "" || x.Data.HostGroup != "" || len(x.Data.Licenses) > 0 || len(x.Data.NativeLicenses) > 0 || len(x.Data.Interfaces) > 0 {
					why = append(why, "CAPACITY_CANDIDATE_SPECIAL_CONFIGURATION_UNPROVEN")
				}
				definition := candidateDefinition{Template: t, Pin: pin, Tenancy: x.Data.Tenancy, CPUOptions: x.Data.CPU, Reasons: unique(why)}
				target = &CandidateTemplate{ID: t.ID, Version: strconv.FormatUint(t.Version, 10), InstanceType: t.Data.InstanceType, ImageID: t.Data.ImageID, SourcePin: pin, DefinitionSHA256: fleetbilling.Hash(definition), ReasonCodes: unique(why), definition: definition}
			}
		}
		typed = append(typed, response.Items...)
		next[id] = response.Next
		done[id] = response.Next == ""
	}
	for id, versions := range wanted {
		if !done[id] {
			return nil, invalid
		}
		for _, v := range versions {
			if !seen[id+":"+strconv.FormatUint(v, 10)] {
				return nil, invalid
			}
		}
	}
	if target == nil || fleetbilling.Hash(typed) != fleetbilling.Hash(e.Receipt["templates"]) {
		return nil, invalid
	}
	return target, nil
}

func hardwareVolumeSize(raw []byte, id string) (*int64, error) {
	items, e := pages(raw)
	if e != nil {
		return nil, e
	}
	var size *int64
	seen := false
	for _, p := range items {
		if p.selector.Get("Action") != "DescribeVolumes" {
			continue
		}
		var result struct {
			XMLName xml.Name
			Volumes []struct {
				ID   string `xml:"volumeId"`
				Size *int64 `xml:"size"`
			} `xml:"volumeSet>item"`
		}
		if xml.Unmarshal(p.body, &result) != nil || result.XMLName.Local != "DescribeVolumesResponse" {
			return nil, errors.New("FLEET_CAPACITY_VOLUME_NATIVE_INVALID")
		}
		for _, v := range result.Volumes {
			if v.ID == id {
				if seen {
					return nil, errors.New("FLEET_CAPACITY_VOLUME_NATIVE_AMBIGUOUS")
				}
				seen = true
				size = v.Size
			}
		}
	}
	return size, nil
}
