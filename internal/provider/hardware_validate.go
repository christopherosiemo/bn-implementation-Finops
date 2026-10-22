package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"time"
)

// ValidateHardwareEvidence reparses all exact native response bytes and request
// selectors. A typed result cannot be substituted while retaining a raw hash.
func ValidateHardwareEvidence(e HardwareEvidence, instance string, candidates []string) error {
	return validateHardwareEvidence(e, instance, candidates, nil)
}

// ParseHardwareEvidence is a pure archived-byte decoder, not an authority or
// ingestion endpoint. Scope and receive-time are supplied by a private reader.
func ParseHardwareEvidence(raw []byte, account, region, instance string, candidates []string, collectedAt time.Time) (HardwareEvidence, error) {
	sum := sha256.Sum256(raw)
	e := HardwareEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: account, Region: region, CollectedAt: collectedAt, Raw: raw, RawSHA256: hex.EncodeToString(sum[:])}
	var parsed HardwareEvidence
	err := validateHardwareEvidence(e, instance, candidates, &parsed)
	return parsed, err
}

func validateHardwareEvidence(e HardwareEvidence, instance string, candidates []string, parsedOut *HardwareEvidence) error {
	if e.SchemaVersion != "1" || e.Provider != "AWS" || e.Region != "eu-west-1" || !fleetAccount.MatchString(e.AccountID) || !fleetInstance.MatchString(instance) || e.CollectedAt.IsZero() || len(e.Raw) == 0 || len(e.Raw) > 32<<20 {
		return errors.New("HARDWARE_NATIVE_BINDING_INVALID")
	}
	sum := sha256.Sum256(e.Raw)
	if hex.EncodeToString(sum[:]) != e.RawSHA256 {
		return errors.New("HARDWARE_NATIVE_HASH_MISMATCH")
	}
	reader := bytes.NewReader(e.Raw)
	pages := []HardwarePage{}
	for reader.Len() > 0 {
		var n uint32
		if binary.Read(reader, binary.BigEndian, &n) != nil || n == 0 || n > 32768 || uint64(n) > uint64(reader.Len()) {
			return errors.New("HARDWARE_RAW_FRAMING_INVALID")
		}
		selector := make([]byte, n)
		_, _ = io.ReadFull(reader, selector)
		var size uint64
		if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || size > 8<<20 || size > uint64(reader.Len()) {
			return errors.New("HARDWARE_RAW_FRAMING_INVALID")
		}
		body := make([]byte, int(size))
		_, _ = io.ReadFull(reader, body)
		pages = append(pages, HardwarePage{string(selector), body})
		if len(pages) > 203 {
			return errors.New("HARDWARE_RAW_PAGINATION_LIMIT")
		}
	}
	if len(pages) < 5 {
		return errors.New("HARDWARE_RAW_INCOMPLETE")
	}
	selector := func(page HardwarePage, expected url.Values) error {
		v, err := url.ParseQuery(page.Selector)
		expected.Set("Version", "2016-11-15")
		if err != nil || v.Encode() != page.Selector || v.Encode() != expected.Encode() {
			return errors.New("HARDWARE_NATIVE_SELECTOR_MISMATCH")
		}
		return nil
	}
	if err := selector(pages[0], url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {instance}}); err != nil {
		return err
	}
	i, err := parseHardwareInstance(pages[0].Body, e.AccountID, instance)
	if err != nil {
		return err
	}
	names := append([]string{}, candidates...)
	if !containsHardware(names, i.Type) {
		names = append(names, i.Type)
	}
	names, err = HardwareTypeNames(names)
	if err != nil {
		return err
	}
	parsed := HardwareEvidence{Instance: i, Types: []HardwareType{}, Offerings: []HardwareOffering{}, Volumes: []HardwareVolume{}}
	at := 1
	next := ""
	seenTokens := map[string]bool{}
	for {
		if at >= len(pages) {
			return errors.New("HARDWARE_RAW_INCOMPLETE")
		}
		v := url.Values{"Action": {"DescribeInstanceTypes"}, "IncludeUnsupportedInRegion": {"false"}}
		for j, name := range names {
			v.Set(fmt.Sprintf("InstanceType.%d", j+1), name)
		}
		if next != "" {
			v.Set("NextToken", next)
		}
		if err = selector(pages[at], v); err != nil {
			return err
		}
		var page struct {
			XMLName xml.Name
			Types   []HardwareType `xml:"instanceTypeSet>item"`
			Next    string         `xml:"nextToken"`
		}
		if xml.Unmarshal(pages[at].Body, &page) != nil || page.XMLName.Local != "DescribeInstanceTypesResponse" {
			return errors.New("HARDWARE_TYPES_NATIVE_INVALID")
		}
		parsed.Types = append(parsed.Types, page.Types...)
		at++
		next = page.Next
		if next == "" {
			break
		}
		if seenTokens[next] {
			return errors.New("HARDWARE_NATIVE_PAGINATION_CONFLICT")
		}
		seenTokens[next] = true
	}
	next = ""
	seenTokens = map[string]bool{}
	for {
		if at >= len(pages) {
			return errors.New("HARDWARE_RAW_INCOMPLETE")
		}
		v := url.Values{"Action": {"DescribeInstanceTypeOfferings"}, "LocationType": {"availability-zone"}, "Filter.1.Name": {"instance-type"}, "Filter.2.Name": {"location"}, "Filter.2.Value.1": {i.Placement.Zone}, "MaxResults": {"1000"}}
		for j, name := range names {
			v.Set(fmt.Sprintf("Filter.1.Value.%d", j+1), name)
		}
		if next != "" {
			v.Set("NextToken", next)
		}
		if err = selector(pages[at], v); err != nil {
			return err
		}
		var page struct {
			XMLName   xml.Name
			Offerings []HardwareOffering `xml:"instanceTypeOfferingSet>item"`
			Next      string             `xml:"nextToken"`
		}
		if xml.Unmarshal(pages[at].Body, &page) != nil || page.XMLName.Local != "DescribeInstanceTypeOfferingsResponse" {
			return errors.New("HARDWARE_OFFERINGS_NATIVE_INVALID")
		}
		parsed.Offerings = append(parsed.Offerings, page.Offerings...)
		at++
		next = page.Next
		if next == "" {
			break
		}
		if seenTokens[next] {
			return errors.New("HARDWARE_NATIVE_PAGINATION_CONFLICT")
		}
		seenTokens[next] = true
	}
	if len(pages) != at+2 {
		return errors.New("HARDWARE_RAW_ACTION_SEQUENCE_INVALID")
	}
	ids := []string{}
	devices := map[string]string{}
	for _, device := range i.Devices {
		if !hardwareVolumeID.MatchString(device.VolumeID) || devices[device.VolumeID] != "" || device.Device == "" {
			return errors.New("HARDWARE_VOLUME_MAPPING_INVALID")
		}
		devices[device.VolumeID] = device.Device
		ids = append(ids, device.VolumeID)
	}
	if len(ids) < 1 || len(ids) > 32 {
		return errors.New("HARDWARE_VOLUME_LIMIT")
	}
	sort.Strings(ids)
	v := url.Values{"Action": {"DescribeVolumes"}}
	for j, id := range ids {
		v.Set(fmt.Sprintf("VolumeId.%d", j+1), id)
	}
	if err = selector(pages[at], v); err != nil {
		return err
	}
	var volumes struct {
		XMLName xml.Name
		Volumes []HardwareVolume `xml:"volumeSet>item"`
		Next    string           `xml:"nextToken"`
	}
	if xml.Unmarshal(pages[at].Body, &volumes) != nil || volumes.XMLName.Local != "DescribeVolumesResponse" || volumes.Next != "" {
		return errors.New("HARDWARE_VOLUME_NATIVE_INVALID")
	}
	parsed.Volumes = volumes.Volumes
	at++
	if !hardwareImageID.MatchString(i.ImageID) {
		return errors.New("HARDWARE_IMAGE_IDENTITY_UNKNOWN")
	}
	if err = selector(pages[at], url.Values{"Action": {"DescribeImages"}, "ImageId.1": {i.ImageID}}); err != nil {
		return err
	}
	var images struct {
		XMLName xml.Name
		Images  []HardwareImage `xml:"imagesSet>item"`
	}
	if xml.Unmarshal(pages[at].Body, &images) != nil || images.XMLName.Local != "DescribeImagesResponse" || len(images.Images) != 1 || images.Images[0].ID != i.ImageID {
		return errors.New("HARDWARE_IMAGE_NATIVE_INVALID")
	}
	parsed.Image = images.Images[0]
	seen := map[string]bool{}
	for _, typ := range parsed.Types {
		if !containsHardware(names, typ.Name) || seen[typ.Name] {
			return errors.New("HARDWARE_TYPE_IDENTITY_MISMATCH")
		}
		seen[typ.Name] = true
	}
	if len(seen) != len(names) {
		return errors.New("HARDWARE_TYPES_INCOMPLETE")
	}
	seen = map[string]bool{}
	for _, o := range parsed.Offerings {
		if !containsHardware(names, o.Type) || o.LocationType != "availability-zone" || o.Location != i.Placement.Zone || seen[o.Type] {
			return errors.New("HARDWARE_OFFERING_SCOPE_INVALID")
		}
		seen[o.Type] = true
	}
	seen = map[string]bool{}
	for _, volume := range parsed.Volumes {
		if devices[volume.ID] == "" || seen[volume.ID] || volume.Zone != i.Placement.Zone || len(volume.Attachments) != 1 || volume.Attachments[0].InstanceID != instance || volume.Attachments[0].Device != devices[volume.ID] || volume.Attachments[0].State != "attached" {
			return errors.New("HARDWARE_VOLUME_BINDING_INVALID")
		}
		seen[volume.ID] = true
	}
	if len(seen) != len(ids) {
		return errors.New("HARDWARE_VOLUMES_INCOMPLETE")
	}
	if parsedOut != nil {
		parsed.SchemaVersion, parsed.Provider, parsed.AccountID, parsed.Region = e.SchemaVersion, e.Provider, e.AccountID, e.Region
		parsed.CollectedAt, parsed.RawSHA256, parsed.Raw = e.CollectedAt, e.RawSHA256, append([]byte{}, e.Raw...)
		*parsedOut = parsed
		return nil
	}
	want := struct {
		Instance  HardwareInstance
		Types     []HardwareType
		Offerings []HardwareOffering
		Volumes   []HardwareVolume
		Image     HardwareImage
	}{e.Instance, e.Types, e.Offerings, e.Volumes, e.Image}
	actual := struct {
		Instance  HardwareInstance
		Types     []HardwareType
		Offerings []HardwareOffering
		Volumes   []HardwareVolume
		Image     HardwareImage
	}{parsed.Instance, parsed.Types, parsed.Offerings, parsed.Volumes, parsed.Image}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(actual)
	if !bytes.Equal(a, b) {
		return errors.New("HARDWARE_NATIVE_TYPED_RAW_MISMATCH")
	}
	return nil
}
