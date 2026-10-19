package commitmentportfolio

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"testing"
	"time"
)

// These are typed contract tests. Actual native issuance and restricted SQL
// principal/currentness proof remain separate connected acceptance gates.
func issuedFixture() Resolved {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	reg := model.Document{"id": "source", "tenant_id": "tenant-a", "version": int64(1), "kind": "AWS_CUR2", "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "region": "eu-west-1", "bucket": "billing-native", "bucket_owner": "111122223333", "prefix": "cur/", "read_role_binding_id": "read-role", "export_arn": "arn:aws:bcm-data-exports:us-east-1:111122223333:export/native", "enabled": true, "revoked": false, "status": "HEALTHY"}
	scope := model.Document{"receipt_id": "inventory", "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "observed_at": now.Format(time.RFC3339Nano), "reserved_instance_count": int64(1), "savings_plan_count": int64(1), "native_snapshots": []model.Document{{"account_id": "111122223333", "reserved_instances": []model.Document{{"id": "ri-one", "state": "active", "region": "eu-west-1", "end": "2027-01-01T00:00:00Z", "currency": "USD", "offering_class": "convertible", "fixed_price": "10"}}, "savings_plans": []model.Document{{"SavingsPlanArn": "arn:aws:savingsplans::111122223333:savingsplan/00000000-0000-4000-8000-000000000001", "SavingsPlanType": "Compute", "State": "active", "Currency": "USD", "Commitment": "2.00", "Start": "2026-01-01T00:00:00Z", "End": "2027-01-01T00:00:00Z", "UpfrontPaymentAmount": "0", "RecurringPaymentAmount": "2"}}}}}
	receipt := model.Document{"id": "inventory", "source_id": "source", "tenant_id": "tenant-a", "kind": "AWS_COMMITMENT", "writer_role": "finops_ingester", "config_hash": source.ConfigurationHash(reg), "observed_at": now.Format(time.RFC3339Nano), "commitment_scope": scope, "native_hash": source.Hash(scope)}
	return Resolved{TenantID: "tenant-a", RequestID: "request", Selection: Selection{"source", "inventory", []string{}, Period{now.Add(-24 * time.Hour), now}}, Registration: reg, Checkpoint: model.Document{"commitment_receipt_id": "inventory"}, Commitment: receipt, Billing: []BillingRevision{}}
}
func TestIssuedInventoryPreservesLegacyRIGapsAndSavingsPlanClass(t *testing.T) {
	r := issuedFixture()
	in, e := Prepare(r, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal(e)
	}
	if len(in.Positions) != 2 || in.InventoryStatus != "COMPLETE_POINT_IN_TIME" || in.BillingStatus != "UNAVAILABLE" {
		t.Fatal("inventory population changed")
	}
	var ri, sp Position
	for _, p := range in.Positions {
		if p.Class == "EC2_RI_UNCLASSIFIED" {
			ri = p
		} else {
			sp = p
		}
	}
	if ri.Currency != nil || ri.UpfrontAmount != nil || ri.TermSeconds != nil {
		t.Fatal("unissued extra RI fields acquired meaning")
	}
	if sp.Class != "COMPUTE_SAVINGS_PLAN" || sp.Currency == nil || *sp.Currency != "USD" || sp.TermSeconds == nil || *sp.TermSeconds != "31536000" {
		t.Fatal("native SP class/term lost")
	}
	if len(in.OptimizationOrder) != 0 {
		t.Fatal("stage authority fabricated")
	}
}
func TestMissingScopeAndUnknownClassCannotBecomeKnownZeroOrCompute(t *testing.T) {
	r := issuedFixture()
	scope := document(r.Commitment["commitment_scope"])
	delete(scope, "reserved_instance_count")
	r.Commitment["commitment_scope"] = scope
	r.Commitment["native_hash"] = source.Hash(scope)
	if _, e := Prepare(r, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)); e == nil {
		t.Fatal("missing count became observed zero")
	}
	r = issuedFixture()
	scope = document(r.Commitment["commitment_scope"])
	snap := documents(scope["native_snapshots"])
	plans := documents(snap[0]["savings_plans"])
	plans[0]["SavingsPlanType"] = "FutureClass"
	snap[0]["savings_plans"] = plans
	scope["native_snapshots"] = snap
	r.Commitment["commitment_scope"] = scope
	r.Commitment["native_hash"] = source.Hash(scope)
	in, e := Prepare(r, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range in.Positions {
		if p.ID == model.String(plans[0], "SavingsPlanArn") && p.Class != "UNSUPPORTED_SAVINGS_PLAN" {
			t.Fatal("unknown class treated as fungible compute")
		}
	}
}
func TestIssuedInputRefusesForeignRoleCurrentHeadCurrencyTamperAndScope(t *testing.T) {
	changes := []func(*Resolved){func(r *Resolved) { r.Commitment["writer_role"] = "finops_api" }, func(r *Resolved) { r.Checkpoint["commitment_receipt_id"] = "other" }, func(r *Resolved) { r.Registration["revoked"] = true }, func(r *Resolved) { r.TenantID = "tenant-b" }, func(r *Resolved) { r.Commitment["native_hash"] = "bad" }, func(r *Resolved) { r.Commitment["observed_at"] = "2026-09-01T00:00:00Z" }}
	for _, change := range changes {
		r := issuedFixture()
		change(&r)
		if _, e := Prepare(r, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)); e == nil {
			t.Fatal("issued binding violation accepted")
		}
	}
}
func TestSelectionRequiresBoundedWholeUTCWindowAndExactIDs(t *testing.T) {
	r := issuedFixture()
	now := r.Selection.Period.End
	if ValidateSelection(r.Selection, now) != nil {
		t.Fatal("valid selection")
	}
	for _, change := range []func(*Selection){func(s *Selection) { s.BillingReceiptIDs = nil }, func(s *Selection) { s.BillingReceiptIDs = []string{"one", "one"} }, func(s *Selection) { s.Period.Start = s.Period.Start.Add(time.Second) }, func(s *Selection) { s.Period.Start = s.Period.End.Add(-32 * 24 * time.Hour) }, func(s *Selection) { s.Period.End = s.Period.End.Add(time.Hour) }} {
		s := r.Selection
		change(&s)
		if ValidateSelection(s, now) == nil {
			t.Fatal("invalid public selection accepted")
		}
	}
}
