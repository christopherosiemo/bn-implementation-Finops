package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// Actual acquisition and replay HTTP are both local provider-shaped transport
// doubles. These tests never call AWS or establish native customer history.
func controllerReplayFixture(t *testing.T, rotate bool) ControllerDiscoveryEvidence {
	t.Helper()
	pages := 0
	a := controllerFixtureAWS(t, &controllerFixtureCredentials{rotate: rotate}, func(action string, v url.Values) *http.Response {
		if action == "GetCallerIdentity" {
			return controllerFixtureResponse(controllerFixtureIdentity(controllerFixtureAccount))
		}
		pages++
		next := ""
		if rotate && pages == 1 {
			next = "second"
		}
		return controllerFixtureResponse(controllerFixturePage(action, "", next))
	})
	e, err := a.ControllerDiscovery(context.Background(), "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func controllerReplayClone(t *testing.T, e ControllerDiscoveryEvidence) ControllerDiscoveryEvidence {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var clone ControllerDiscoveryEvidence
	if json.Unmarshal(raw, &clone) != nil {
		t.Fatal("clone failed")
	}
	clone.Raw = append([]byte{}, e.Raw...)
	return clone
}

func TestControllerDiscoveryRawReparseRetainsCompleteAbsenceAndCredentialRenewal(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		e := controllerReplayFixture(t, rotate)
		if err := ValidateControllerDiscoveryEvidence(context.Background(), e, "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne}); err != nil {
			t.Fatal("exact acquisition pages failed replay", err)
		}
		if e.Memberships[0].Status != "NO_ASG_MEMBERSHIP_OBSERVED" || len(e.UnsupportedControllerKinds) != 3 {
			t.Fatal("ASG absence became all-controller absence")
		}
		if rotate && len(e.Callers) != 2 {
			t.Fatal("renewed identity was not retained")
		}
	}
}

func TestControllerDiscoveryRawReparseRetainsObservedASGAndFullGroup(t *testing.T) {
	a := controllerFixtureAWS(t, &controllerFixtureCredentials{}, func(action string, _ url.Values) *http.Response {
		if action == "GetCallerIdentity" {
			return controllerFixtureResponse(controllerFixtureIdentity(controllerFixtureAccount))
		}
		if action == "DescribeAutoScalingInstances" {
			return controllerFixtureResponse(controllerFixturePage(action, controllerFixtureInstance(controllerFixtureOne, "blue"), ""))
		}
		return controllerFixtureResponse(controllerFixturePage(action, controllerFixtureGroup("blue", controllerFixtureAccount, controllerFixtureGroupMember(controllerFixtureOne)), ""))
	})
	e, err := a.ControllerDiscovery(context.Background(), "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne})
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateControllerDiscoveryEvidence(context.Background(), e, "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne}); err != nil {
		t.Fatal("native association/group chain failed replay", err)
	}
	if len(e.Groups) != 1 || e.Memberships[0].Status != "ASG_MEMBER_OBSERVED" || !bytes.Contains(e.Raw, []byte("UnprojectedNativeField")) {
		t.Fatal("complete group raw data was reduced to a point flag")
	}
}

func TestControllerDiscoveryRawReparseRefusesCounterfeitsAndIncompleteChains(t *testing.T) {
	control := controllerReplayFixture(t, false)
	for _, name := range []string{"typed_membership", "typed_reasons", "typed_scope", "foreign_sts", "missing_sts", "extra_frames", "truncated_body", "wrong_expected_scope"} {
		t.Run(name, func(t *testing.T) {
			e := controllerReplayClone(t, control)
			expected := []string{controllerFixtureOne}
			switch name {
			case "typed_membership":
				e.Memberships[0].Status = "ASG_MEMBER_OBSERVED"
			case "typed_reasons":
				e.UnsupportedControllerKinds = []string{}
			case "typed_scope":
				e.RegisteredInstanceIDs = []string{controllerFixtureTwo}
			case "foreign_sts":
				e.Raw = bytes.ReplaceAll(e.Raw, []byte(controllerFixtureAccount), []byte("999900001111"))
				e.RawSHA256 = controllerSHA(e.Raw)
			case "missing_sts":
				selector := int(binary.BigEndian.Uint32(e.Raw[:4]))
				body := int(binary.BigEndian.Uint64(e.Raw[4+selector : 12+selector]))
				e.Raw = e.Raw[12+selector+body:]
				e.RawSHA256 = controllerSHA(e.Raw)
			case "extra_frames":
				e.Raw = append(e.Raw, e.Raw...)
				e.RawSHA256 = controllerSHA(e.Raw)
			case "truncated_body":
				e.Raw = e.Raw[:len(e.Raw)-1]
				e.RawSHA256 = controllerSHA(e.Raw)
			case "wrong_expected_scope":
				expected = []string{controllerFixtureTwo}
			}
			if err := ValidateControllerDiscoveryEvidence(context.Background(), e, "eu-west-1", controllerFixtureAccount, expected); err == nil {
				t.Fatal("counterfeit or incomplete native chain accepted")
			}
		})
	}
}
