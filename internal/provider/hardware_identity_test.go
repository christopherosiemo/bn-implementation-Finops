package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func identityFixture(t *testing.T, extra string) HardwareEvidence {
	t.Helper()
	raw, err := os.ReadFile("testdata/hardware_capture.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	var selectorSize uint32
	_ = binary.Read(r, binary.BigEndian, &selectorSize)
	selector := make([]byte, int(selectorSize))
	_, _ = r.Read(selector)
	var n uint64
	_ = binary.Read(r, binary.BigEndian, &n)
	body := make([]byte, int(n))
	_, _ = r.Read(body)
	modified := strings.Replace(string(body), "</item></instancesSet>", extra+"</item></instancesSet>", 1)
	if modified == string(body) && extra != "" {
		t.Fatal("identity fixture insertion marker unavailable")
	}
	var framed bytes.Buffer
	_ = binary.Write(&framed, binary.BigEndian, selectorSize)
	_, _ = framed.Write(selector)
	_ = binary.Write(&framed, binary.BigEndian, uint64(len(modified)))
	_, _ = framed.WriteString(modified)
	_, _ = framed.Write(raw[len(raw)-r.Len():])
	e, err := ParseHardwareEvidence(framed.Bytes(), "111122223333", "eu-west-1", "i-0123456789abcdef0", []string{"m6i.large"}, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal("native fixture invalid", err)
	}
	return e
}

func identityENIXML(index, card, attach string) string {
	return `<networkInterfaceSet><item><networkInterfaceId>eni-0123456789abcdef0</networkInterfaceId><ownerId>999900001111</ownerId><attachment><attachmentId>eni-attach-0123456789abcdef0</attachmentId>` + index + card + attach + `<status>attached</status></attachment></item></networkInterfaceSet>`
}

func TestHardwareIdentityV2KeepsStartAndAttachmentDistinctAndV1Unchanged(t *testing.T) {
	eni := identityENIXML("<deviceIndex>0</deviceIndex>", "<networkCardIndex>0</networkCardIndex>", "<attachTime>2026-09-01T00:00:00Z</attachTime>")
	first := identityFixture(t, "<launchTime>2026-09-15T00:00:00Z</launchTime>"+eni)
	before, _ := json.Marshal(first)
	id, err := DecodeHardwareIdentityV2(first, first.Instance.ID, []string{"m6i.large"})
	if err != nil || id.LastStartTime == nil || id.PrimaryENI == nil || id.PrimaryENI.AttachTime == nil || id.PrimaryENI.NetworkCardIndex == nil || *id.PrimaryENI.NetworkCardIndex != 0 || id.PrimaryENI.CreatorAccountID == nil || *id.PrimaryENI.CreatorAccountID != "999900001111" {
		t.Fatal("native identity facts or explicit zero lost", id, err)
	}
	after, _ := json.Marshal(first)
	if !bytes.Equal(before, after) || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("decoding new fields rewrote issued v1 evidence")
	}
	var old map[string]json.RawMessage
	_ = json.Unmarshal(before, &old)
	var instance map[string]json.RawMessage
	_ = json.Unmarshal(old["instance"], &instance)
	keys := []string{}
	for key := range instance {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"architecture", "cpu_options", "devices", "ebs_optimized", "ena_support", "id", "image_id", "instance_type", "lifecycle", "placement", "platform_details", "root_device_type", "usage_operation", "virtualization_type"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatal("old HardwareInstance JSON projection changed", keys)
	}
	second := identityFixture(t, "<launchTime>2026-09-25T00:00:00Z</launchTime>"+eni)
	next, err := DecodeHardwareIdentityV2(second, second.Instance.ID, []string{"m6i.large"})
	if err != nil || !next.LastStartTime.After(*id.LastStartTime) || !next.PrimaryENI.AttachTime.Equal(*id.PrimaryENI.AttachTime) {
		t.Fatal("latest restart was mistaken for a new attachment or creation", next, err)
	}
	// An attachment initiation may follow last start; neither value can be
	// silently constrained into an invented VM-creation relationship.
	jitter := identityFixture(t, "<launchTime>2026-09-15T00:00:00Z</launchTime>"+identityENIXML("<deviceIndex>0</deviceIndex>", "", "<attachTime>2026-09-15T00:00:01Z</attachTime>"))
	if _, err = DecodeHardwareIdentityV2(jitter, jitter.Instance.ID, []string{"m6i.large"}); err != nil {
		t.Fatal("invented ordering between distinct native timestamps", err)
	}
}

func TestHardwareIdentityV2MissingAndAmbiguousPrimaryRemainNull(t *testing.T) {
	for _, test := range []struct{ name, xml, reason string }{
		{"absent", "", "PRIMARY_ENI_UNOBSERVED"},
		{"missing-index", identityENIXML("", "", ""), "PRIMARY_ENI_DEVICE_INDEX_UNOBSERVED"},
		{"multiple-zero", strings.ReplaceAll(identityENIXML("<deviceIndex>0</deviceIndex>", "", ""), "</networkInterfaceSet>", strings.TrimPrefix(identityENIXML("<deviceIndex>0</deviceIndex>", "", ""), "<networkInterfaceSet>")), "PRIMARY_ENI_AMBIGUOUS"},
		{"other-card-zero", identityENIXML("<deviceIndex>0</deviceIndex>", "<networkCardIndex>1</networkCardIndex>", ""), "PRIMARY_ENI_CARD_INDEX_AMBIGUOUS"},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := identityFixture(t, test.xml)
			out, err := DecodeHardwareIdentityV2(parent, parent.Instance.ID, []string{"m6i.large"})
			if err != nil || out.PrimaryENI != nil || out.LastStartTime != nil || !containsHardware(out.ReasonCodes, test.reason) || !containsHardware(out.ReasonCodes, "LAST_START_TIME_UNOBSERVED") {
				t.Fatal("unknown identity converted into an observed zero/first interface", out, err)
			}
		})
	}
	parent := identityFixture(t, identityENIXML("<deviceIndex>0</deviceIndex>", "", ""))
	out, err := DecodeHardwareIdentityV2(parent, parent.Instance.ID, []string{"m6i.large"})
	if err != nil || out.PrimaryENI == nil || out.PrimaryENI.AttachTime != nil || out.PrimaryENI.NetworkCardIndex != nil || !containsHardware(out.ReasonCodes, "PRIMARY_ENI_ATTACH_TIME_UNOBSERVED") {
		t.Fatal("missing optional native fields became zero/time", out, err)
	}
}

func TestHardwareIdentityV2RejectsMalformedNativeTimeAndScope(t *testing.T) {
	for _, extra := range []string{
		"<launchTime>not-a-time</launchTime>",
		"<launchTime>2026-10-02T00:00:00Z</launchTime>",
		"<launchTime>2026-09-15T00:00:00Z</launchTime><launchTime>2026-09-15T00:00:00Z</launchTime>",
		identityENIXML("<deviceIndex>0</deviceIndex>", "", "<attachTime>broken</attachTime>"),
		identityENIXML("<deviceIndex>0</deviceIndex><deviceIndex>0</deviceIndex>", "", ""),
		identityENIXML("<deviceIndex>-1</deviceIndex>", "", ""),
	} {
		p := identityFixture(t, extra)
		if _, err := DecodeHardwareIdentityV2(p, p.Instance.ID, []string{"m6i.large"}); err == nil {
			t.Fatal("malformed/ambiguous native value accepted", extra)
		}
	}
	p := identityFixture(t, "")
	for _, mode := range []string{"account", "instance", "rawhash", "selector", "typed"} {
		t.Run(mode, func(t *testing.T) {
			x := p
			instance := p.Instance.ID
			switch mode {
			case "account":
				x.AccountID = "999900001111"
			case "instance":
				instance = "i-aaaaaaaaaaaaaaaaa"
			case "rawhash":
				x.RawSHA256 = strings.Repeat("0", 64)
			case "selector":
				x.Raw = bytes.ReplaceAll(p.Raw, []byte("InstanceId.1"), []byte("InstanceId.2"))
				x.RawSHA256 = fmt.Sprintf("%x", sha256.Sum256(x.Raw))
			case "typed":
				x.Instance.Type = "r6i.large"
			}
			if _, err := DecodeHardwareIdentityV2(x, instance, []string{"m6i.large"}); err == nil {
				t.Fatal("identity decoder bypassed unchanged v1 raw/selector checks")
			}
		})
	}
}
