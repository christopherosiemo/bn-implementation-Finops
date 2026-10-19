package commitmentportfolio

import (
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type DecisionUsageEvidence struct {
	Status      string      `json:"status"`
	Hours       []UsageHour `json:"hours"`
	PAYGBasis   []PAYGBasis `json:"payg_basis"`
	InputRefs   []Ref       `json:"input_refs"`
	ReasonCodes []string    `json:"reason_codes"`
}

// PrepareDecisionUsage reconstructs the immutable selected portfolio at its
// issued observation time, then retains actual ordinary Usage and covered rows.
// The resolver separately authenticates current financial heads and exact
// historical ownership. The private reconstruction clock makes neither claim.
func PrepareDecisionUsage(r Resolved, scope DecisionScope, now time.Time) (DecisionUsageEvidence, error) {
	original, err := PrepareDecisionSnapshot(r, now)
	if err != nil {
		return DecisionUsageEvidence{}, err
	}
	out := DecisionUsageEvidence{Status: "PARTIAL", Hours: []UsageHour{}, PAYGBasis: []PAYGBasis{}, InputRefs: original.InputRefs, ReasonCodes: []string{}}
	if scope.TenantID != r.TenantID || scope.PayerAccountID != original.PayerAccountID || Hash(scope.UsageAccountIDs) != Hash(original.UsageAccountIDs) || !scope.HistoryPeriod.Start.Equal(r.Selection.Period.Start) || !scope.HistoryPeriod.End.Equal(r.Selection.Period.End) || !shaPattern.MatchString(scope.SHA256) || scope.Currency == "" || scope.ResourceIDs == nil || len(scope.ResourceIDs) > 10000 {
		return out, ErrEvidence
	}
	resources := map[string]bool{}
	for _, id := range scope.ResourceIDs {
		if id == "" || resources[id] {
			return out, ErrEvidence
		}
		resources[id] = true
	}
	accounts := map[string]bool{}
	for _, id := range original.UsageAccountIDs {
		accounts[id] = true
	}
	seen := map[string]bool{}
	for _, b := range r.Billing {
		native := map[string]model.Document{}
		for _, row := range documents(document(b.Job["raw"])["records"]) {
			native[first(row, "identity_line_item_id", "identity/LineItemId")] = row
		}
		for _, row := range documents(document(b.Job["canonical"])["records"]) {
			raw := document(row["x_ProviderFields"])
			id := first(row, "x_SourceRecordId")
			// Validate even records without commitment ARN; the old analysis correctly
			// omitted them, while a coverage denominator cannot omit ordinary Usage.
			if native[id] == nil || Hash(native[id]) != Hash(raw) || seen[id] {
				return out, ErrEvidence
			}
			seen[id] = true
			kind := first(raw, "line_item_line_item_type", "lineItem/LineItemType")
			if kind != "Usage" && kind != "SavingsPlanCoveredUsage" && kind != "DiscountedUsage" {
				continue
			}
			resource := first(raw, "line_item_resource_id", "lineItem/ResourceId")
			if !resources[resource] {
				continue
			}
			if first(raw, "bill_payer_account_id", "bill/PayerAccountId") != scope.PayerAccountID || !accounts[first(raw, "line_item_usage_account_id", "lineItem/UsageAccountId")] {
				return out, ErrEvidence
			}
			start, end := date(first(raw, "line_item_usage_start_date", "lineItem/UsageStartDate")), date(first(raw, "line_item_usage_end_date", "lineItem/UsageEndDate"))
			if start == nil || end == nil {
				return out, ErrEvidence
			}
			if !start.Before(scope.HistoryPeriod.End) || !end.After(scope.HistoryPeriod.Start) {
				continue
			}
			if start.Before(scope.HistoryPeriod.Start) || end.After(scope.HistoryPeriod.End) || end.Sub(*start) != time.Hour || !start.Equal(start.Truncate(time.Hour)) {
				return out, ErrEvidence
			}
			dimensions := Dimensions{AccountID: first(raw, "line_item_usage_account_id", "lineItem/UsageAccountId"), ServiceCode: first(raw, "product_servicecode", "product/servicecode"), ProductType: "EC2", UsageType: first(raw, "line_item_usage_type", "lineItem/UsageType"), Operation: first(raw, "line_item_operation", "lineItem/Operation"), Region: first(raw, "product_region_code", "product/regionCode"), InstanceType: nullable(first(raw, "product_instance_type", "product/instanceType")), InstanceFamily: nullable(first(raw, "product_instance_family", "product/instanceFamily")), ProductDescription: nullable(first(raw, "product_operating_system", "product/operatingSystem")), Tenancy: nullable(first(raw, "product_tenancy", "product/tenancy")), Unit: first(raw, "pricing_unit", "pricing/unit"), Currency: first(raw, "line_item_currency_code", "lineItem/CurrencyCode")}
			// AWS defines the family before the period in an exact instance type.
			// CUR's marketing category (e.g. General purpose) is not that family;
			// the original provider fields remain pinned by this row's NativeRef.
			dimensions.InstanceFamily = decisionInstanceFamily(dimensions.InstanceType)
			// Initial native offer mapping is EC2 compute only. Other compute product
			// classes require their own exact eligibility mapping, never guessed units.
			if dimensions.ServiceCode != "AmazonEC2" || first(raw, "product_product_family", "product/productFamily") != "Compute Instance" {
				out.ReasonCodes = append(out.ReasonCodes, "COMPUTE_PRODUCT_MAPPING_UNSUPPORTED")
				continue
			}
			if dimensions.Currency != scope.Currency || dimensions.UsageType == "" || dimensions.Operation == "" || dimensions.Region == "" || dimensions.Unit == "" {
				return out, ErrEvidence
			}
			quantity := first(raw, "line_item_usage_amount", "lineItem/UsageAmount")
			gross := first(raw, "line_item_unblended_cost", "lineItem/UnblendedCost")
			net := nullable(first(raw, "line_item_net_unblended_cost", "lineItem/NetUnblendedCost"))
			for _, value := range []*string{&quantity, &gross, net} {
				if _, err = numberValue(value, false, false); err != nil {
					return out, err
				}
			}
			billed, billedBasis := gross, "NATIVE_UNBLENDED_COST"
			if net != nil {
				billed, billedBasis = *net, "NATIVE_NET_UNBLENDED_COST"
			}
			allocated, basis, err := nativeAllocatedCost(raw)
			if err != nil {
				return out, err
			}
			commitment := nullable(first(raw, "savings_plan_savings_plan_a_r_n", "savings_plan_savings_plan_arn", "savingsPlan/SavingsPlanARN"))
			if kind == "DiscountedUsage" {
				commitment = nullable(first(raw, "reservation_reservation_a_r_n", "reservation_reservation_arn", "reservation/ReservationARN"))
			}
			if kind != "Usage" && commitment == nil {
				return out, ErrEvidence
			}
			var od *string
			odBasis := "UNAVAILABLE"
			if kind == "Usage" || kind == "SavingsPlanCoveredUsage" {
				od = &gross
				odBasis = "NATIVE_UNBLENDED_ON_DEMAND_EQUIVALENT"
				if net != nil {
					od = net
					odBasis = "NATIVE_NET_ON_DEMAND_EQUIVALENT"
				}
			}
			rate := nullable(first(raw, "savings_plan_savings_plan_rate", "savingsPlan/SavingsPlanRate"))
			if _, err = numberValue(rate, false, false); err != nil {
				return out, err
			}
			out.Hours = append(out.Hours, UsageHour{ID: id, Period: Period{Start: *start, End: *end}, Dimensions: dimensions, Kind: kind, CommitmentID: commitment, UsageAmount: quantity, BilledCost: billed, BilledCostBasis: billedBasis, NetUsageCost: net, OnDemandEquivalentCost: od, OnDemandBasis: odBasis, AllocatedCost: allocated, AllocatedCostBasis: basis, ContractRate: rate, NativeRef: ref("AWS_CUR2", b.Receipt)})
			if len(out.Hours) > 100000 {
				return out, ErrEvidence
			}
		}
	}
	sort.Slice(out.Hours, func(i, j int) bool { return out.Hours[i].ID < out.Hours[j].ID })
	out.PAYGBasis = decisionPAYGBasis(out.Hours)
	if original.BillingStatus == "COMPLETE_OBSERVED_WINDOW" && len(out.ReasonCodes) == 0 {
		out.Status = "COMPLETE_OBSERVED_ELIGIBLE_WINDOW"
	}
	return out, nil
}

var decisionInstanceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}\.[a-z0-9]{1,32}$`)

func decisionInstanceFamily(instance *string) *string {
	if instance == nil || !decisionInstanceTypePattern.MatchString(*instance) {
		return nil
	}
	family := strings.SplitN(*instance, ".", 2)[0]
	return &family
}

// Latest actual ordinary-Usage hour wins per exact dimension. Missing net cost
// in that hour cannot fall back to an older or public rate. No cross-request
// cache, provider-field default, FX conversion or unbounded precision is used.
func decisionPAYGBasis(hours []UsageHour) []PAYGBasis {
	groups := map[string][]UsageHour{}
	latest := map[string]time.Time{}
	for _, h := range hours {
		if h.Kind != "Usage" {
			continue
		}
		key := Hash(h.Dimensions)
		if h.Period.End.After(latest[key]) {
			groups[key] = nil
			latest[key] = h.Period.End
		}
		if h.Period.End.Equal(latest[key]) {
			groups[key] = append(groups[key], h)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := []PAYGBasis{}
	for _, key := range keys {
		values := groups[key]
		amount, quantity := new(big.Rat), new(big.Rat)
		ids := []string{}
		refs := []Ref{}
		seenRefs := map[string]bool{}
		valid := len(values) > 0
		for _, h := range values {
			if h.NetUsageCost == nil {
				valid = false
				break
			}
			cost, e1 := numberValue(h.NetUsageCost, false, false)
			q, e2 := numberValue(&h.UsageAmount, false, false)
			if e1 != nil || e2 != nil || q.Sign() <= 0 {
				valid = false
				break
			}
			amount.Add(amount, cost)
			quantity.Add(quantity, q)
			ids = append(ids, h.ID)
			digest := Hash(h.NativeRef)
			if !seenRefs[digest] {
				refs = append(refs, h.NativeRef)
				seenRefs[digest] = true
			}
		}
		if !valid || quantity.Sign() <= 0 {
			continue
		}
		rate := new(big.Rat).Quo(amount, quantity)
		formatted := rate.FloatString(12)
		roundtrip, e := numberValue(&formatted, false, false)
		if e != nil || roundtrip.Cmp(rate) != 0 {
			continue
		}
		sort.Strings(ids)
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
		result = append(result, PAYGBasis{Dimensions: values[0].Dimensions, ObservedPeriod: values[0].Period, Rate: formatted, Basis: "CURRENT_NATIVE_NET_USAGE_COST_PER_UNIT", SourceLineIDs: ids, NativeRefs: refs})
	}
	return result
}
