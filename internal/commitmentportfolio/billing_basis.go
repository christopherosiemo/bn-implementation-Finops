package commitmentportfolio

import "github.com/christopherosiemo/bn-implementation-Finops/internal/model"

func nativeAllocatedCost(raw model.Document) (*string, *string, error) {
	choices := []struct {
		basis string
		names []string
	}{
		{"NET_SP_EFFECTIVE", []string{"savings_plan_net_savings_plan_effective_cost", "savingsPlan/NetSavingsPlanEffectiveCost"}},
		{"SP_EFFECTIVE", []string{"savings_plan_savings_plan_effective_cost", "savingsPlan/SavingsPlanEffectiveCost"}},
		{"NET_RI_EFFECTIVE", []string{"reservation_net_effective_cost", "reservation/NetEffectiveCost"}},
		{"RI_EFFECTIVE", []string{"reservation_effective_cost", "reservation/EffectiveCost"}},
	}
	// Complete CUR exports may carry zero-valued fields from another charge
	// family. The actual charge kind, rather than column presence, selects the
	// permitted native effective-cost basis.
	switch first(raw, "line_item_line_item_type", "lineItem/LineItemType") {
	case "SavingsPlanCoveredUsage":
		choices = choices[:2]
	case "DiscountedUsage":
		choices = choices[2:]
	default:
		return nil, nil, nil
	}
	for _, choice := range choices {
		for _, name := range choice.names {
			if value, exists := raw[name]; exists && value != nil && value != "" {
				text, okay := value.(string)
				if !okay {
					return nil, nil, ErrEvidence
				}
				amount, e := decimalValue(text)
				if e != nil {
					return nil, nil, e
				}
				basis := choice.basis
				return amount, &basis, nil
			}
		}
	}
	return nil, nil, nil
}
