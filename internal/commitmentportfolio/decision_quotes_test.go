package commitmentportfolio

import (
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Explicit SDK/acquisition doubles for private quote decoding, not native
// pricing issuance. Every malformed control is resealed to reach the array
// admission rather than fail an unrelated outer hash check.
func decisionQuotesEmptyPlanFixture(now time.Time) (model.Document, model.Document, Input) {
	offering := model.Document{"offeringId": "offering-a", "currency": "USD", "durationSeconds": 31536000, "paymentOption": "No Upfront", "planType": "Compute"}
	page := model.Document{"operation": "DescribeSavingsPlansOfferings", "ordinal": 1, "request": model.Document{}, "response": model.Document{"searchResults": []model.Document{offering}}}
	digest := Hash(page)
	page["sha256"] = digest
	native := model.Document{"native_projection": "AWS_SAVINGS_PLAN_RATE_QUOTES_V1", "serialization": "SDK_PROJECTION", "authenticated_account_id": "111122223333", "complete": true, "pages": []model.Document{page}, "ordered_page_sha256s": []string{digest}, "offerings": []model.Document{{"native": offering, "page_sha256": digest}}, "offering_rates": []model.Document{}, "existing_plan_rates": []model.Document{}, "selection": model.Document{"plan_type": "Compute", "payment_option": "No Upfront", "duration_seconds": 31536000, "currency": "USD", "existing_plan_ids": []string{}}}
	receipt := model.Document{"id": "offer-receipt", "kind": "AWS_SAVINGS_PLAN_OFFER", "source_id": "source", "revision_id": "quote-revision", "writer_role": "finops_ingester", "projection": "AWS_SAVINGS_PLAN_RATE_QUOTES_V1", "native_offering_id": "offering-a", "collected_at": now.Format(time.RFC3339Nano)}
	revision := model.Document{"id": "quote-revision", "source_id": "source", "writer_role": "finops_ingester", "native": native, "revision_hash": Hash(native), "raw_object": model.Document{"body_sha256": Hash(native), "version_id": "immutable-version"}}
	return receipt, revision, Input{PayerAccountID: "111122223333", Positions: []Position{}}
}

func TestDecisionQuotesEmptyExistingPlanSetPreservesArrayAdmission(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	receipt, revision, inventory := decisionQuotesEmptyPlanFixture(now)
	got, err := prepareDecisionQuotes(receipt, revision, inventory, nil, now)
	if err != nil || got.Offer == nil || len(got.ContractPlanIDs) != 0 || got.ContractStatus != "COMPLETE_NATIVE_PLAN_RATE_SETS" {
		t.Fatal("complete issued empty plan set was refused", err)
	}
	for name, mutate := range map[string]func(model.Document){
		"missing":    func(selection model.Document) { delete(selection, "existing_plan_ids") },
		"null":       func(selection model.Document) { selection["existing_plan_ids"] = nil },
		"scalar":     func(selection model.Document) { selection["existing_plan_ids"] = "plan-a" },
		"non-string": func(selection model.Document) { selection["existing_plan_ids"] = []any{1} },
		"mixed":      func(selection model.Document) { selection["existing_plan_ids"] = []any{"plan-a", 1} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := model.Clone(revision)
			native := document(bad["native"])
			selection := document(native["selection"])
			mutate(selection)
			native["selection"] = selection
			bad["native"] = native
			bad["revision_hash"] = Hash(native)
			archive := document(bad["raw_object"])
			archive["body_sha256"] = Hash(native)
			bad["raw_object"] = archive
			if _, err := prepareDecisionQuotes(receipt, bad, inventory, nil, now); err == nil {
				t.Fatal("non-array/unknown plan set became an observed empty set")
			}
		})
	}
}
