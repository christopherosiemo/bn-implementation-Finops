package commitmentportfolio

import (
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestNativeAllocationUsesChargeKindBeforePresentUnrelatedZeroColumns(t *testing.T) {
	for _, tc := range []struct{ kind, amount, basis string }{
		{"SavingsPlanCoveredUsage", "0", "NET_SP_EFFECTIVE"},
		{"DiscountedUsage", "0.1", "NET_RI_EFFECTIVE"},
	} {
		raw := model.Document{"line_item_line_item_type": tc.kind,
			"savings_plan_net_savings_plan_effective_cost": "0",
			"savings_plan_savings_plan_effective_cost":     "99",
			"reservation_net_effective_cost":               "0.1",
			"reservation_effective_cost":                   "88"}
		amount, basis, e := nativeAllocatedCost(raw)
		if e != nil || amount == nil || *amount != tc.amount || basis == nil || *basis != tc.basis {
			t.Fatal("native allocation borrowed another charge family's cost", tc.kind)
		}
	}
	for _, kind := range []string{"SavingsPlanRecurringFee", "SavingsPlanNegation", "RIFee", "Credit", "Unknown"} {
		amount, basis, e := nativeAllocatedCost(model.Document{"line_item_line_item_type": kind, "savings_plan_savings_plan_effective_cost": "5", "reservation_effective_cost": "6"})
		if e != nil || amount != nil || basis != nil {
			t.Fatal("non-covered charge acquired allocation", kind)
		}
	}
}
