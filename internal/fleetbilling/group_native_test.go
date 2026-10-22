package fleetbilling

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// Explicit repository/native-transport doubles. Native framed responses and
// CUR rows are reparsed, but this suite earns no PostgreSQL or AWS-origin claim.
type groupRepositoryFixture struct {
	value GroupNativeSnapshot
	calls int
	after func(*GroupNativeSnapshot)
}
type groupPinnedReadFunc func(context.Context, string, model.Document) (PinnedObject, error)

func (f groupPinnedReadFunc) ReadPinned(ctx context.Context, tenant string, ref model.Document) (PinnedObject, error) {
	return f(ctx, tenant, ref)
}

func (r *groupRepositoryFixture) ResolveGroupNative(_ context.Context, _, _, _ string) (GroupNativeSnapshot, error) {
	r.calls++
	if r.calls > 1 && r.after != nil {
		r.after(&r.value)
	}
	return r.value, nil
}
func groupSelectionFixture(reg model.Document) GroupSelection {
	makeSelection := func(name string, n int) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: account, Region: "eu-west-1", FleetID: name, ASGARN: fmt.Sprintf("arn:aws:autoscaling:eu-west-1:%s:autoScalingGroup:00000000-0000-4000-8000-%012d:autoScalingGroupName/%s", account, n, name)}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: strings.Repeat(fmt.Sprint(n), 64)}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: strings.Repeat("c", 64)}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: strings.Repeat("d", 64)}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: source.ConfigurationHash(reg)}
	}
	return GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: strings.Repeat("a", 64)}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: strings.Repeat("b", 64)}, Binding: g.Binding{Old: makeSelection("old", 1), Candidate: makeSelection("candidate", 2)}}
}
func groupMembershipFixture(selection g.Selection, instances []string) (model.Document, []byte) {
	version := "1"
	if selection.Target.FleetID == "candidate" {
		version = "2"
	}
	members := ""
	for _, instance := range instances {
		members += fmt.Sprintf(`<member><InstanceId>%s</InstanceId><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%s</Version></LaunchTemplate></member>`, instance, templateID, version)
	}
	body := fmt.Sprintf(`<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups><member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>%s</AutoScalingGroupARN><VPCZoneIdentifier>subnet-0123456789abcdef0</VPCZoneIdentifier><DesiredCapacity>%d</DesiredCapacity><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%s</Version></LaunchTemplate><Instances>%s</Instances></member></AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`, selection.Target.FleetID, selection.Target.ASGARN, len(instances), templateID, version, members)
	raw := frame([]page{{url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "AutoScalingGroupNames.member.1": {selection.Target.FleetID}}, []byte(body)}})
	var response struct {
		Groups []provider.FleetGroup `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	_ = xml.Unmarshal([]byte(body), &response)
	for n := range response.Groups {
		if response.Groups[n].Members == nil {
			response.Groups[n].Members = []provider.FleetMember{}
		}
	}
	d := model.Document{"id": "membership-" + selection.Target.FleetID, "kind": "AWS_FLEET_MEMBERSHIP", "history_registration_id": selection.Registration.ID, "history_registration_version": selection.Registration.Version, "history_registration_hash": selection.Registration.SHA256, "binding": model.Document{"tenant_id": "tenant", "workload_id": "workload", "provider": "AWS", "account_id": account, "region": "eu-west-1"}, "groups": response.Groups}
	return d, raw
}
func groupBillingFixture(reg model.Document, records []model.Document, start, end time.Time) GroupNativeBillingRevision {
	version := "native-version"
	raw := model.Document{"source_id": "source", "source_version": version, "records": records}
	canonical := []model.Document{}
	for _, r := range records {
		cost := r["line_item_unblended_cost"]
		if model.String(r, "line_item_net_unblended_cost") != "" {
			cost = r["line_item_net_unblended_cost"]
		}
		canonical = append(canonical, model.Document{"x_SourceRecordId": r["identity_line_item_id"], "x_SourceId": "source", "x_SourceVersion": version, "x_ProviderFields": r, "SubAccountId": r["line_item_usage_account_id"], "ResourceId": r["line_item_resource_id"], "RegionId": r["product_region_code"], "BillingCurrency": r["line_item_currency_code"], "BillingAccountId": r["bill_payer_account_id"], "ChargePeriodStart": r["line_item_usage_start_date"], "ChargePeriodEnd": r["line_item_usage_end_date"], "BilledCost": cost})
	}
	can := model.Document{"records": canonical}
	cfg := source.ConfigurationHash(reg)
	proof := model.Document{"receipt_id": "billing-receipt", "revision_id": "billing-revision", "manifest_hash": strings.Repeat("e", 64), "payer_account_id": account, "usage_account_ids": []string{account}, "region": "eu-west-1", "currency": "USD", "invoice_entity": "AWS EMEA", "period_start": start.Format(time.RFC3339Nano), "period_end": end.Format(time.RFC3339Nano), "billing_period_start": start.Format(time.RFC3339Nano), "state": "COMPLETE", "object_count": 1, "verified_object_count": 1, "row_count": len(records), "verified_row_count": len(records)}
	receipt := model.Document{"id": "billing-receipt", "tenant_id": "tenant", "kind": "AWS_CUR2", "writer_role": "finops_ingester", "source_id": "source", "registration_id": "source", "revision_id": "billing-revision", "ingestion_job_id": "billing-job", "source_version": version, "config_hash": cfg, "raw_hash": Hash(raw), "canonical_hash": Hash(can), "source_proof": proof}
	revision := model.Document{"id": "billing-revision", "writer_role": "finops_ingester", "source_id": "source", "config_hash": cfg, "raw_hash": Hash(raw), "canonical_hash": Hash(can)}
	job := model.Document{"id": "billing-job", "status": "PERSISTED", "source_id": "source", "source_registration_id": "source", "source_receipt_id": "billing-receipt", "source_revision_id": "billing-revision", "source_provenance": "AWS_CUR2_AUTHENTICATED", "raw": raw, "canonical": can}
	return GroupNativeBillingRevision{receipt, revision, job, "billing-receipt"}
}
func groupNativeFixture(t *testing.T) (*GroupNativeBroker, *groupRepositoryFixture, memoryArchive, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	reg := source.FixtureRegistration("tenant", "source")
	reg["version"], reg["status"], reg["last_sync_at"] = 1, "HEALTHY", now.Format(time.RFC3339Nano)
	selection := groupSelectionFixture(reg)
	archive := memoryArchive{}
	snapshot := GroupNativeSnapshot{Selection: selection, Registrations: map[string]model.Document{"source": reg}, BillingSourceID: "source"}
	pin := func(d model.Document, raw []byte) GroupNativeReceipt {
		d["tenant_id"], d["source_id"], d["config_hash"], d["registration_version"], d["read_role_binding_id"], d["collected_at"], d["writer_role"] = "tenant", "source", source.ConfigurationHash(reg), 1, reg["read_role_binding_id"], now.Format(time.RFC3339Nano), "finops_ingester"
		d["revision_id"] = "revision-" + model.String(d, "id")
		d["raw_object"] = archiveRef(archive, "tenant", "group-native", raw)
		revision := model.Document{"id": d["revision_id"], "kind": d["kind"], "writer_role": "finops_ingester", "source_id": "source", "config_hash": d["config_hash"], "registration_version": 1, "raw_object": d["raw_object"]}
		return GroupNativeReceipt{d, revision}
	}
	second := "i-22222222222222222"
	for _, pair := range []struct {
		s   g.Selection
		ids []string
	}{{selection.Binding.Old, []string{oldInstance, second}}, {selection.Binding.Candidate, []string{}}} {
		d, raw := groupMembershipFixture(pair.s, pair.ids)
		snapshot.Memberships = append(snapshot.Memberships, pin(d, raw))
	}
	d, raw := testTemplates("default")
	snapshot.Templates = []GroupNativeReceipt{pin(d, raw)}
	for _, pair := range []struct{ id, kind string }{{oldInstance, "m6i.xlarge"}, {second, "m6i.xlarge"}, {candidateInstance, "m6i.large"}} {
		d, raw := testHardware(t, pair.id, pair.kind, now)
		binding := object(d["binding"])
		binding["workload_id"], binding["provider"] = "workload", "AWS"
		d["binding"] = binding
		snapshot.Hardware = append(snapshot.Hardware, pin(d, raw))
	}
	end := now.Truncate(24 * time.Hour)
	start := end.AddDate(0, 0, -14)
	records := []model.Document{}
	for day := 0; day < 14; day++ {
		left := start.AddDate(0, 0, day)
		for _, id := range []string{oldInstance, second} {
			records = append(records, usage(id, "m6i.xlarge", "OLD-NATIVE-SKU", "4.8", "0.2", left, left.Add(24*time.Hour)))
		}
	}
	records = append(records, usage(candidateInstance, "m6i.large", "CANDIDATE-NATIVE-SKU", "2.88", "0.12", end.Add(-24*time.Hour), end))
	snapshot.Billing = []GroupNativeBillingRevision{groupBillingFixture(reg, records, start, end)}
	scope := model.Document{"receipt_id": "commitment", "payer_account_id": account, "usage_account_ids": []string{account}, "observed_at": now.Format(time.RFC3339Nano), "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0}
	snapshot.Commitment = model.Document{"id": "commitment", "kind": "AWS_COMMITMENT", "writer_role": "finops_ingester", "source_id": "source", "config_hash": source.ConfigurationHash(reg), "commitment_scope": scope}
	repository := &groupRepositoryFixture{value: snapshot}
	return &GroupNativeBroker{Repository: repository, Archive: archive, Now: func() time.Time { return now }}, repository, archive, now
}
func captureGroup(b *GroupNativeBroker) (GroupNativeEvidence, error) {
	return b.Capture(context.Background(), "tenant", "old-proposal", "candidate-proposal")
}

func TestGroupNativeTwoMemberStoredProofRatesAndReplay(t *testing.T) {
	b, r, _, _ := groupNativeFixture(t)
	before := Hash(r.value)
	e, err := captureGroup(b)
	if err != nil || e.Status != "OBSERVED_CONDITIONAL" {
		t.Fatalf("conditional native rates: %+v %v", e.ReasonCodes, err)
	}
	if *e.Old.ObservedHourlyRate != "0.2" || *e.Candidate.ObservedHourlyRate != "0.12" || *e.Old.ObservedComputeCost != "134.4" || e.Old.MemberCount != 2 || len(e.CurrentMemberIDs) != 2 || e.Candidate.Dimensions.CostBasis != "UNBLENDED" || e.ExecutionAuthorized || e.VerifiedSaving != nil || e.HardSpendCap {
		t.Fatal("native scope, decimal or authority changed", e)
	}
	again, err := captureGroup(b)
	if err != nil || again.ID != e.ID || Hash(r.value) != before {
		t.Fatal("replay or input mutation", err)
	}
	if object(r.value.Memberships[0].Receipt["binding"])["resource_id"] != nil {
		t.Fatal("invented group inventory resource")
	}
}
func TestGroupNativeBindingRevisionAndMissingProofsRemainUnavailable(t *testing.T) {
	cases := map[string]func(*groupRepositoryFixture){
		"foreign tenant":     func(r *groupRepositoryFixture) { r.value.Selection.Binding.Candidate.Target.TenantID = "other" },
		"different workload": func(r *groupRepositoryFixture) { r.value.Selection.Binding.Candidate.Target.WorkloadID = "other" },
		"same group": func(r *groupRepositoryFixture) {
			r.value.Selection.Binding.Candidate.Target.ASGARN = r.value.Selection.Binding.Old.Target.ASGARN
		},
		"source revoked": func(r *groupRepositoryFixture) { r.value.Registrations["source"]["revoked"] = true },
		"source syncing": func(r *groupRepositoryFixture) { r.value.Registrations["source"]["status"] = "SYNCING" },
		"source stale": func(r *groupRepositoryFixture) {
			r.value.Registrations["source"]["last_sync_at"] = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339Nano)
		},
		"registration revision":        func(r *groupRepositoryFixture) { r.value.Memberships[0].Receipt["history_registration_version"] = 2 },
		"native revision":              func(r *groupRepositoryFixture) { r.value.Hardware[0].Revision["id"] = "forged" },
		"billing source":               func(r *groupRepositoryFixture) { r.value.Billing[0].Receipt["source_id"] = "other-source" },
		"billing config":               func(r *groupRepositoryFixture) { r.value.Billing[0].Receipt["config_hash"] = strings.Repeat("f", 64) },
		"billing revision ID":          func(r *groupRepositoryFixture) { r.value.Billing[0].Revision["id"] = "other-revision" },
		"registration map alias":       func(r *groupRepositoryFixture) { r.value.Registrations["source"]["id"] = "different-native-source" },
		"native issuer":                func(r *groupRepositoryFixture) { r.value.Hardware[0].Receipt["writer_role"] = "finops_api" },
		"native configuration":         func(r *groupRepositoryFixture) { r.value.Hardware[0].Receipt["config_hash"] = strings.Repeat("f", 64) },
		"missing member":               func(r *groupRepositoryFixture) { r.value.Hardware = r.value.Hardware[1:] },
		"missing candidate dimensions": func(r *groupRepositoryFixture) { r.value.Hardware = r.value.Hardware[:2] },
		"missing template":             func(r *groupRepositoryFixture) { r.value.Templates = nil },
		"wrong exact-period head":      func(r *groupRepositoryFixture) { r.value.Billing[0].CurrentReceiptID = "old-correction" },
		"missing commitment":           func(r *groupRepositoryFixture) { r.value.Commitment = nil },
		"commitment present": func(r *groupRepositoryFixture) {
			scope := object(r.value.Commitment["commitment_scope"])
			scope["savings_plan_count"] = 1
			r.value.Commitment["commitment_scope"] = scope
		},
		"receipt duplicate": func(r *groupRepositoryFixture) { r.value.Hardware = append(r.value.Hardware, r.value.Hardware[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, r, _, _ := groupNativeFixture(t)
			mutate(r)
			got, err := captureGroup(b)
			if err != nil || got.Status != "UNAVAILABLE" || got.ID != "" {
				t.Fatal("invalid group proof promoted", got.Status, got.ReasonCodes, err)
			}
		})
	}
}
func TestGroupNativeArchiveReadbackAndFinalCurrentness(t *testing.T) {
	for _, which := range []string{"hash", "version", "foreign-prefix"} {
		t.Run(which, func(t *testing.T) {
			b, r, a, _ := groupNativeFixture(t)
			ref := object(r.value.Hardware[0].Receipt["raw_object"])
			key := model.String(ref, "body_sha256")
			v := a[key]
			switch which {
			case "hash":
				v.Body = append(append([]byte{}, v.Body...), 'x')
				a[key] = v
			case "version":
				v.VersionID = "another-version"
				a[key] = v
			case "foreign-prefix":
				ref["key"] = "tenant/other/foreign"
				r.value.Hardware[0].Receipt["raw_object"] = ref
			}
			got, err := captureGroup(b)
			if err != nil || got.Status != "UNAVAILABLE" {
				t.Fatal("unpinned readback accepted", err)
			}
		})
	}
	for _, which := range []string{"source", "selection", "invoice"} {
		t.Run("during-read-"+which, func(t *testing.T) {
			b, r, _, _ := groupNativeFixture(t)
			r.after = func(s *GroupNativeSnapshot) {
				switch which {
				case "source":
					s.Registrations["source"]["revoked"] = true
				case "selection":
					s.Selection.OldProposal.SHA256 = strings.Repeat("f", 64)
				case "invoice":
					s.Billing[0].CurrentReceiptID = "corrected"
				}
			}
			got, err := captureGroup(b)
			if err != nil || got.Status != "UNAVAILABLE" {
				t.Fatal("capture crossed changed source head", err)
			}
		})
	}
}
func TestGroupNativeRawBindingsAndEconomicAmbiguity(t *testing.T) {
	for _, which := range []string{"wrong-arn", "selector", "duplicate-member", "currency", "missing-net", "payer-credit", "candidate-rate-variation"} {
		t.Run(which, func(t *testing.T) {
			b, r, a, now := groupNativeFixture(t)
			if which == "wrong-arn" || which == "selector" || which == "duplicate-member" {
				pin := &r.value.Memberships[0]
				ref := object(pin.Receipt["raw_object"])
				native := a[model.String(ref, "body_sha256")]
				pages, _ := nativePages(native.Body)
				switch which {
				case "wrong-arn":
					pages[0].body = []byte(strings.ReplaceAll(string(pages[0].body), r.value.Selection.Binding.Old.Target.ASGARN, r.value.Selection.Binding.Candidate.Target.ASGARN))
				case "selector":
					pages[0].selector.Set("AutoScalingGroupNames.member.1", "foreign")
				case "duplicate-member":
					pages[0].body = []byte(strings.ReplaceAll(string(pages[0].body), "i-22222222222222222", oldInstance))
				}
				raw := frame(pages)
				newRef := archiveRef(a, "tenant", "mutated-native", raw)
				pin.Receipt["raw_object"], pin.Revision["raw_object"] = newRef, newRef
			} else {
				records := rows(object(r.value.Billing[0].Job["raw"])["records"])
				last := records[len(records)-1]
				switch which {
				case "currency":
					last["line_item_currency_code"] = "GBP"
				case "missing-net":
					delete(last, "line_item_net_unblended_cost")
				case "payer-credit":
					credit := usage("i-99999999999999999", "m6i.large", "CREDIT", "-1", "0.1", now.Truncate(24*time.Hour).Add(-24*time.Hour), now.Truncate(24*time.Hour))
					credit["line_item_line_item_type"] = "Credit"
					records = append(records, credit)
				case "candidate-rate-variation":
					extra := model.Clone(last)
					extra["identity_line_item_id"] = "another-native-line"
					extra["line_item_unblended_rate"], extra["line_item_unblended_cost"] = "0.13", "3.12"
					records = append(records, extra)
				}
				p := r.value.Billing[0].Receipt["source_proof"].(model.Document)
				r.value.Billing[0] = groupBillingFixture(r.value.Registrations["source"], records, stamp(p, "period_start"), stamp(p, "period_end"))
			}
			got, err := captureGroup(b)
			if err != nil || got.Status != "UNAVAILABLE" {
				t.Fatal("invalid raw or economics accepted", got, err)
			}
		})
	}
}
func TestGroupNativeSelectionHasNoPublicMoneyOrFixtureRealm(t *testing.T) {
	b, r, _, _ := groupNativeFixture(t)
	raw, _ := json.Marshal(r.value.Selection)
	if strings.Contains(string(raw), "resource_id") || strings.Contains(string(raw), "fixture_profile") || strings.Contains(string(raw), "realm") {
		t.Fatal("group selector acquired individual or fixture authority")
	}
	if _, err := captureGroup(b); err != nil {
		t.Fatal(err)
	}
}

func TestGroupNativeSameByteRecaptureAuthenticatesBothIssuedVersions(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprint("matching-linked-version-", valid), func(t *testing.T) {
			b, r, archive, _ := groupNativeFixture(t)
			pin := &r.value.Memberships[0]
			original := object(pin.Revision["raw_object"])
			revisionVersion := "independent-original-version"
			original["version_id"] = revisionVersion
			pin.Revision["raw_object"] = original
			if valid {
				b.Archive = groupPinnedReadFunc(func(ctx context.Context, tenant string, ref model.Document) (PinnedObject, error) {
					got, e := archive.ReadPinned(ctx, tenant, ref)
					if model.String(ref, "version_id") == revisionVersion {
						got.VersionID = revisionVersion
					}
					return got, e
				})
			}
			got, e := captureGroup(b)
			if e != nil {
				t.Fatal(e)
			}
			if !valid {
				if got.Status != "UNAVAILABLE" || got.Old.ObservedHourlyRate != nil {
					t.Fatal("unread linked revision promoted", got.Status, got.ReasonCodes)
				}
				return
			}
			if got.Status != "OBSERVED_CONDITIONAL" || got.SourcePins[0].RevisionVersionID != revisionVersion || got.SourcePins[0].ReceiptVersionID == revisionVersion {
				t.Fatal("genuine same-byte recapture lost exact versions", got.Status, got.ReasonCodes)
			}
		})
	}
}

func TestGroupNativeHardwareGapCannotShrinkObservedMembership(t *testing.T) {
	b, repository, _, _ := groupNativeFixture(t)
	// Both old members remain in the genuine ASG response, but the second
	// member has no issued hardware receipt. Rate support must fail without
	// claiming that the remaining first member is the whole population.
	kept := []GroupNativeReceipt{}
	for _, pin := range repository.value.Hardware {
		binding := object(pin.Receipt["binding"])
		if model.String(binding, "provider_resource_id") != "i-22222222222222222" {
			kept = append(kept, pin)
		}
	}
	repository.value.Hardware = kept
	got, err := captureGroup(b)
	if err != nil || got.Status != "UNAVAILABLE" || len(got.CurrentMemberIDs) != 2 || got.Old.ObservedHourlyRate != nil {
		t.Fatal("hardware gap hid a native member", got.Status, got.CurrentMemberIDs, err)
	}
}

func TestGroupNativeNetRatesAndCandidateDayNoDoubleCounting(t *testing.T) {
	b, r, _, _ := groupNativeFixture(t)
	records := rows(object(r.value.Billing[0].Job["raw"])["records"])
	for _, row := range records {
		row["line_item_net_unblended_cost"], row["line_item_net_unblended_rate"] = row["line_item_unblended_cost"], row["line_item_unblended_rate"]
		if model.String(row, "product_instance_type") == "m6i.xlarge" {
			row["line_item_net_unblended_cost"], row["line_item_net_unblended_rate"], row["discount_total_discount"] = "3.6", "0.15", "1.2"
		}
	}
	proof := object(r.value.Billing[0].Receipt["source_proof"])
	r.value.Billing[0] = groupBillingFixture(r.value.Registrations["source"], records, stamp(proof, "period_start"), stamp(proof, "period_end"))
	got, e := captureGroup(b)
	if e != nil || got.Status != "OBSERVED_CONDITIONAL" || *got.Old.ObservedHourlyRate != "0.15" || *got.Old.ObservedComputeCost != "100.8" || got.Old.Dimensions.CostBasis != "NET_UNBLENDED" || got.Candidate.Dimensions.CostBasis != "NET_UNBLENDED" {
		t.Fatal("exact native net rate unavailable", got.Status, got.ReasonCodes, e)
	}
	duplicate := model.Clone(records[len(records)-1])
	duplicate["identity_line_item_id"] = "another-native-id-same-instance-day"
	records = append(records, duplicate)
	r.value.Billing[0] = groupBillingFixture(r.value.Registrations["source"], records, stamp(proof, "period_start"), stamp(proof, "period_end"))
	got, e = captureGroup(b)
	if e != nil || got.Status != "UNAVAILABLE" || got.Old.ObservedHourlyRate != nil || got.Candidate.ObservedHourlyRate != nil {
		t.Fatal("overlapping candidate usage double-counted or failed gate leaked money", got.Status, got.ReasonCodes, e)
	}
}
