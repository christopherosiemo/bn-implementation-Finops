package provider

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
)

const HardwareIdentityDecoderV2 = "ec2-hardware-identity-v2"

// HardwareIdentityV2 is a NEW interpretation of archived native bytes. It is
// never embedded in HardwareEvidence v1: doing so would change issued hashes.
// LastStartTime is EC2's latest start, not VM creation. An ENI attachment is
// also not an assertion of creation, complete incarnation or interval ownership.
type HardwareIdentityV2 struct {
	SchemaVersion  string              `json:"schema_version"`
	DecoderVersion string              `json:"decoder_version"`
	Provider       string              `json:"provider"`
	AccountID      string              `json:"account_id"`
	Region         string              `json:"region"`
	InstanceID     string              `json:"instance_id"`
	CollectedAt    time.Time           `json:"collected_at"`
	RawSHA256      string              `json:"raw_sha256"`
	LastStartTime  *time.Time          `json:"last_start_time"`
	PrimaryENI     *HardwarePrimaryENI `json:"primary_eni"`
	ReasonCodes    []string            `json:"reason_codes"`
}

type HardwarePrimaryENI struct {
	NetworkInterfaceID string     `json:"network_interface_id"`
	AttachmentID       string     `json:"attachment_id"`
	DeviceIndex        int        `json:"device_index"`
	NetworkCardIndex   *int       `json:"network_card_index"`
	AttachTime         *time.Time `json:"attach_time"`
	AttachmentStatus   *string    `json:"attachment_status"`
	CreatorAccountID   *string    `json:"creator_account_id"`
}

var identityENI = regexp.MustCompile(`^eni-[a-f0-9]{8}([a-f0-9]{9})?$`)
var identityAttachment = regexp.MustCompile(`^eni-attach-[a-f0-9]{8}([a-f0-9]{9})?$`)

type identityNativeAttachment struct {
	IDs    []string `xml:"attachmentId"`
	Times  []string `xml:"attachTime"`
	Device []int    `xml:"deviceIndex"`
	Card   []int    `xml:"networkCardIndex"`
	Status []string `xml:"status"`
}
type identityNativeInterface struct {
	IDs         []string                   `xml:"networkInterfaceId"`
	Owners      []string                   `xml:"ownerId"`
	Attachments []identityNativeAttachment `xml:"attachment"`
}

func identityTimestamp(values []string, collected time.Time) (*time.Time, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, errors.New("HARDWARE_IDENTITY_TIMESTAMP_AMBIGUOUS")
	}
	v, err := time.Parse(time.RFC3339Nano, values[0])
	if err != nil || v.IsZero() || v.After(collected.Add(5*time.Second)) {
		return nil, errors.New("HARDWARE_IDENTITY_TIMESTAMP_INVALID")
	}
	v = v.UTC()
	return &v, nil
}

// DecodeHardwareIdentityV2 validates the entire v1 framed capture and typed
// projection first, then decodes fields v1 intentionally did not serialize.
// It performs no provider call and accepts no claimed identity/completeness flag.
func DecodeHardwareIdentityV2(parent HardwareEvidence, instance string, candidates []string) (HardwareIdentityV2, error) {
	out := HardwareIdentityV2{SchemaVersion: "2", DecoderVersion: HardwareIdentityDecoderV2, Provider: "AWS", AccountID: parent.AccountID, Region: parent.Region, InstanceID: instance, CollectedAt: parent.CollectedAt.UTC(), RawSHA256: parent.RawSHA256, ReasonCodes: []string{}}
	if err := ValidateHardwareEvidence(parent, instance, candidates); err != nil {
		return out, err
	}
	// Bounds/selectors for every frame have already been verified above.
	r := bytes.NewReader(parent.Raw)
	var selectorSize uint32
	_ = binary.Read(r, binary.BigEndian, &selectorSize)
	_, _ = r.Seek(int64(selectorSize), io.SeekCurrent)
	var bodySize uint64
	_ = binary.Read(r, binary.BigEndian, &bodySize)
	body := make([]byte, int(bodySize))
	_, _ = io.ReadFull(r, body)
	var response struct {
		XMLName xml.Name
		Rows    []struct {
			Owners    []string `xml:"ownerId"`
			Instances []struct {
				IDs        []string                  `xml:"instanceId"`
				Starts     []string                  `xml:"launchTime"`
				Interfaces []identityNativeInterface `xml:"networkInterfaceSet>item"`
			} `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
	}
	if xml.Unmarshal(body, &response) != nil || len(response.Rows) != 1 || len(response.Rows[0].Owners) != 1 || response.Rows[0].Owners[0] != parent.AccountID || len(response.Rows[0].Instances) != 1 || len(response.Rows[0].Instances[0].IDs) != 1 || response.Rows[0].Instances[0].IDs[0] != instance {
		return out, errors.New("HARDWARE_IDENTITY_NATIVE_BINDING_INVALID")
	}
	i := response.Rows[0].Instances[0]
	var err error
	out.LastStartTime, err = identityTimestamp(i.Starts, parent.CollectedAt)
	if err != nil {
		return out, err
	}
	if out.LastStartTime == nil {
		out.ReasonCodes = append(out.ReasonCodes, "LAST_START_TIME_UNOBSERVED")
	}
	if len(i.Interfaces) > 256 {
		return out, errors.New("HARDWARE_IDENTITY_INTERFACE_LIMIT")
	}
	possible, unknownIndex := []HardwarePrimaryENI{}, false
	seen := map[string]bool{}
	ambiguous := false
	for _, ni := range i.Interfaces {
		if len(ni.IDs) != 1 || !identityENI.MatchString(ni.IDs[0]) || len(ni.Owners) > 1 || len(ni.Attachments) != 1 {
			ambiguous = true
			continue
		}
		if seen[ni.IDs[0]] {
			ambiguous = true
		}
		seen[ni.IDs[0]] = true
		a := ni.Attachments[0]
		at, e := identityTimestamp(a.Times, parent.CollectedAt)
		if e != nil {
			return out, e
		}
		if len(a.Device) == 0 {
			unknownIndex = true
			continue
		}
		if len(a.Device) != 1 || a.Device[0] < 0 || a.Device[0] > 255 || len(a.Card) > 1 || len(a.Card) == 1 && (a.Card[0] < 0 || a.Card[0] > 255) {
			return out, errors.New("HARDWARE_IDENTITY_DEVICE_INDEX_INVALID")
		}
		if a.Device[0] != 0 {
			continue
		}
		if len(a.IDs) != 1 || !identityAttachment.MatchString(a.IDs[0]) || len(a.Status) > 1 {
			ambiguous = true
			continue
		}
		p := HardwarePrimaryENI{NetworkInterfaceID: ni.IDs[0], AttachmentID: a.IDs[0], DeviceIndex: 0, AttachTime: at}
		if len(a.Card) == 1 {
			card := a.Card[0]
			p.NetworkCardIndex = &card
		}
		if len(a.Status) == 1 {
			switch a.Status[0] {
			case "attaching", "attached", "detaching", "detached":
				p.AttachmentStatus = &a.Status[0]
			default:
				return out, errors.New("HARDWARE_IDENTITY_ATTACHMENT_STATUS_INVALID")
			}
		}
		if len(ni.Owners) == 1 {
			if !fleetAccount.MatchString(ni.Owners[0]) {
				return out, errors.New("HARDWARE_IDENTITY_INTERFACE_OWNER_INVALID")
			}
			p.CreatorAccountID = &ni.Owners[0]
		}
		possible = append(possible, p)
	}
	if ambiguous || len(possible) > 1 {
		out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_AMBIGUOUS")
	} else if unknownIndex {
		out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_DEVICE_INDEX_UNOBSERVED")
	} else if len(possible) == 0 {
		out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_UNOBSERVED")
	} else if possible[0].NetworkCardIndex != nil && *possible[0].NetworkCardIndex != 0 {
		out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_CARD_INDEX_AMBIGUOUS")
	} else {
		out.PrimaryENI = &possible[0]
		if out.PrimaryENI.AttachTime == nil {
			out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_ATTACH_TIME_UNOBSERVED")
		}
		if out.PrimaryENI.NetworkCardIndex == nil {
			out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_CARD_INDEX_UNOBSERVED")
		}
		if out.PrimaryENI.AttachmentStatus == nil || *out.PrimaryENI.AttachmentStatus != "attached" {
			out.ReasonCodes = append(out.ReasonCodes, "PRIMARY_ENI_ATTACHMENT_NOT_CONFIRMED")
		}
	}
	sort.Strings(out.ReasonCodes)
	return out, nil
}
