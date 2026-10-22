package fleetbilling

import (
	"bytes"
	"context"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

// Repository and native transports are unit doubles. The actual broker repeats
// framed provider decoding, immutable versions, full CUR and final currentness.
func groupCurrentBaselineFixture(t *testing.T) (*GroupNativeBroker, *groupRepositoryFixture) {
	t.Helper()
	broker, repository, archive, _ := groupNativeFixture(t)
	// Keep exactly one authentic selected point member and its actual hardware;
	// the native template has the same observed type, with a distinct version.
	d, raw := groupMembershipFixture(repository.value.Selection.Binding.Old, []string{oldInstance})
	member := &repository.value.Memberships[0]
	member.Receipt = model.Clone(member.Receipt)
	member.Revision = model.Clone(member.Revision)
	member.Receipt["groups"] = d["groups"]
	ref := archiveRef(archive, "tenant", "group-native", raw)
	member.Receipt["raw_object"], member.Revision["raw_object"] = ref, ref
	repository.value.Hardware = repository.value.Hardware[:1]
	template := &repository.value.Templates[0]
	template.Receipt = model.Clone(template.Receipt)
	template.Revision = model.Clone(template.Revision)
	oldRef := object(template.Receipt["raw_object"])
	archived, err := archive.ReadPinned(context.Background(), "tenant", oldRef)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := nativePages(archived.Body)
	if err != nil || len(pages) != 1 {
		t.Fatal("unit native template frame unavailable", err)
	}
	pages[0].body = bytes.ReplaceAll(pages[0].body, []byte("m6i.large"), []byte("m6i.xlarge"))
	raw = frame(pages)
	// Preserve the receipt's ordinary typed projection by changing only the
	// exact selected second native template type along with its archived XML.
	var parsed struct {
		Items []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	if xml.Unmarshal(pages[0].body, &parsed) != nil || len(parsed.Items) != 2 {
		t.Fatal("unit native template population differs")
	}
	document := model.Clone(template.Receipt)
	document["templates"] = parsed.Items
	ref = archiveRef(archive, "tenant", "group-native", raw)
	document["raw_object"] = ref
	template.Receipt = document
	template.Revision["raw_object"] = ref
	return broker, repository
}

func TestGroupNativeCurrentBaselineRetainsClosureWithoutCounterfactualMoney(t *testing.T) {
	broker, repository := groupCurrentBaselineFixture(t)
	value, err := captureGroup(broker)
	if err != nil || value.Status != "UNAVAILABLE" || len(value.CurrentMemberIDs) != 1 || value.CurrentMemberIDs[0] != oldInstance || len(value.SourcePins) != 4 || len(value.BillingSourceRefs) != 1 || value.Baseline.End.Sub(value.Baseline.Start) != 14*24*time.Hour || value.Old.ObservedHourlyRate != nil || value.Candidate.ObservedHourlyRate != nil || value.ExecutionAuthorized || value.VerifiedSaving != nil || value.HardSpendCap {
		t.Fatal("current baseline acquired money or lost actual complete closure", err, value.ReasonCodes)
	}
	if !strings.Contains(strings.Join(value.ReasonCodes, "|"), "CURRENT_CONFIGURATION_BASELINE_NO_COUNTERFACTUAL_ECONOMICS") || repository.calls != 2 {
		t.Fatal("baseline did not repeat final currentness or name its analytical limit")
	}
	ordinary, _, _, _ := groupNativeFixture(t)
	control, err := captureGroup(ordinary)
	if err != nil || control.Status != "OBSERVED_CONDITIONAL" || control.Old.ObservedHourlyRate == nil || *control.Old.ObservedHourlyRate != "0.2" {
		t.Fatal("ordinary different-type broker behavior changed", err)
	}
}

func TestGroupNativeCurrentBaselineStillRefusesFinalSourceChange(t *testing.T) {
	broker, repository := groupCurrentBaselineFixture(t)
	repository.after = func(snapshot *GroupNativeSnapshot) { snapshot.Registrations["source"]["version"] = 2 }
	value, err := captureGroup(broker)
	if err != nil || value.Status != "UNAVAILABLE" || !strings.Contains(strings.Join(value.ReasonCodes, "|"), "GROUP_PRICE_SELECTION_OR_SOURCE_CHANGED") {
		t.Fatal("current baseline bypassed actual final source check", err, value.ReasonCodes)
	}
}
