package evidence

import (
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func v3Proof() (model.Document, model.Document, model.Document) {
	r, job := sourceFixture()
	b := V3Binding("tenant", r, "111122223333", "AWS EMEA", "GBP")
	proof := model.Document{"receipt_id": "receipt", "revision_id": "revision", "manifest_hash": strings.Repeat("a", 64), "payer_account_id": b["payer_account_id"], "usage_account_id": b["account_id"], "region": b["region"], "currency": b["currency"], "invoice_entity": b["invoice_entity"], "period_start": "2026-09-01T00:00:00Z", "period_end": "2026-10-01T00:00:00Z", "state": "COMPLETE", "object_count": 1, "verified_object_count": 1, "row_count": 336, "verified_row_count": 336}
	proof["source_id"], proof["source_version"] = "source", "v2"
	rows := Rows(Object(job["canonical"])["records"])
	rows[0]["BillingAccountId"], rows[0]["InvoiceIssuerName"] = b["payer_account_id"], b["invoice_entity"]
	rows[0]["x_ProviderFields"] = model.Document{"line_item_unblended_cost": "0.48"}
	rows[0]["x_PricingBasis"], rows[0]["x_NativeComputeCost"] = "UNBLENDED", "0.480000000000"
	job["canonical"], job["source_proof"], job["source_receipt_id"] = model.Document{"records": rows}, proof, "receipt"
	return r, job, b
}

func TestV3SourceNeedsResolvedReceiptAndNativePrice(t *testing.T) {
	r, job, binding := v3Proof()
	b, records, e := SourceV3(job, r, "tenant")
	if e != nil || len(records) != 1 || !SameBindingV3(b, binding) {
		t.Fatalf("valid v3 source rejected: %v", e)
	}
	for _, key := range []string{"source_receipt_id", "source_proof"} {
		copy := model.Clone(job)
		delete(copy, key)
		if _, _, e := SourceV3(copy, r, "tenant"); e == nil {
			t.Fatalf("missing %s accepted", key)
		}
	}
	for _, key := range []string{"source_id", "source_version"} {
		copy := model.Clone(job)
		proof := Object(copy["source_proof"])
		proof[key] = "other"
		copy["source_proof"] = proof
		if _, _, err := SourceV3(copy, r, "tenant"); err == nil {
			t.Fatalf("wrong receipt %s accepted", key)
		}
	}
	copy := model.Clone(job)
	can := Object(copy["canonical"])
	rows := Rows(can["records"])
	rows[0]["x_NativeComputeCost"] = "999"
	can["records"], copy["canonical"] = rows, can
	if _, _, e := SourceV3(copy, r, "tenant"); e == nil {
		t.Fatal("modified native price accepted")
	}
}

func TestV3NativePriceNeverInventsContractedCost(t *testing.T) {
	basis, cost, err := NativePricingBasisV3(model.Document{"line_item_net_unblended_cost": "0", "line_item_unblended_cost": "10", "ContractedCost": "999"})
	if err != nil || basis != "NET_UNBLENDED" || cost != "0" {
		t.Fatalf("native basis: %s %s %v", basis, cost, err)
	}
	if _, _, err = NativePricingBasisV3(model.Document{"ContractedCost": "0.1", "EffectiveCost": "0.1"}); err == nil {
		t.Fatal("synthetic price accepted")
	}
	for _, value := range []string{"100000000000000000000000000", "0.1234567890123", "1e2", "NaN"} {
		if _, _, err := NativePricingBasisV3(model.Document{"line_item_unblended_cost": value}); err == nil {
			t.Fatalf("invalid decimal %s accepted", value)
		}
	}
}

func TestV3ProofRejectsPartialUnfinalizedAndWrongScope(t *testing.T) {
	_, job, binding := v3Proof()
	proof := Object(job["source_proof"])
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	if ValidateSourceProofV3(proof, binding, start, end, true) == nil {
		t.Fatal("provisional absence proof accepted")
	}
	for _, key := range []string{"payer_account_id", "usage_account_id", "region", "currency", "invoice_entity", "manifest_hash", "verified_object_count", "verified_row_count"} {
		copy := model.Clone(proof)
		copy[key] = "wrong"
		if ValidateSourceProofV3(copy, binding, start, end, false) == nil {
			t.Fatalf("invalid %s accepted", key)
		}
	}
}

func TestV3CommitmentRequiresFullPayerScope(t *testing.T) {
	_, _, binding := v3Proof()
	proof := model.Document{"receipt_id": "commitment", "payer_account_id": binding["payer_account_id"], "usage_account_ids": []string{model.String(binding, "account_id")}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0}
	if e := ValidateCommitmentScopeV3(proof, binding); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"receipt_id", "usage_account_ids", "reserved_instance_count", "savings_plan_count"} {
		copy := model.Clone(proof)
		delete(copy, key)
		if ValidateCommitmentScopeV3(copy, binding) == nil {
			t.Fatalf("unknown %s treated as zero", key)
		}
	}
	proof["savings_plan_count"] = 1
	if ValidateCommitmentScopeV3(proof, binding) == nil {
		t.Fatal("covered portfolio accepted")
	}
}
