package fleetbilling

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func usage(instance, kind, sku, cost, rate string, start, end time.Time) model.Document {
	return model.Document{"line_item_net_unblended_cost": "", "line_item_net_unblended_rate": "", "identity_line_item_id": instance + ":" + start.Format(time.RFC3339Nano), "line_item_resource_id": instance, "line_item_usage_account_id": "111122223333", "bill_payer_account_id": "111122223333", "line_item_currency_code": "USD", "line_item_line_item_type": "Usage", "line_item_usage_start_date": start.Format(time.RFC3339Nano), "line_item_usage_end_date": end.Format(time.RFC3339Nano), "line_item_usage_amount": fmt.Sprint(end.Sub(start).Hours()), "line_item_unblended_cost": cost, "line_item_unblended_rate": rate, "line_item_operation": "RunInstances", "line_item_usage_type": "EUW1-BoxUsage:" + kind, "pricing_term": "OnDemand", "pricing_unit": "Hrs", "product_servicecode": "AmazonEC2", "product_product_family": "Compute Instance", "product_region_code": "eu-west-1", "product_instance_type": kind, "product_operating_system": "Linux", "product_tenancy": "Shared", "product_license_model": "No License required", "product_pre_installed_sw": "NA", "product_sku": sku}
}
func rateFixture() ([]model.Document, []NativeMachine, NativeTemplate, Period) {
	end := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	p := Period{end.AddDate(0, 0, -14), end}
	m := NativeMachine{"i-0123456789abcdef0", "m6i.xlarge", "ami-0123456789abcdef0", "Linux/UNIX", "RunInstances", "default", "hardware", "subnet-0123456789abcdef0", "vpc-0123456789abcdef0"}
	template := NativeTemplate{"lt-0123456789abcdef0", 1, m.InstanceType, m.ImageID, "default"}
	data := []model.Document{}
	for day := 0; day < 14; day++ {
		s := p.Start.AddDate(0, 0, day)
		data = append(data, usage(m.InstanceID, m.InstanceType, "OLD-NATIVE-SKU", "4.8", "0.2", s, s.Add(24*time.Hour)))
	}
	return data, []NativeMachine{m}, template, p
}
func TestNativeCurrentMemberBaselineAndExactCandidateAccountRate(t *testing.T) {
	data, m, tpl, p := rateFixture()
	got, e := summarizeRates(data, m, tpl, p, "111122223333", "eu-west-1", "USD", true)
	if e != nil || got.ObservedHourlyRate == nil || *got.ObservedHourlyRate != "0.2" || *got.ObservedComputeCost != "67.2" || *got.UsageHours != "336" || got.RateBasis != RateBasis {
		t.Fatal(got, e)
	}
	if e = portfolioSafe(data, p); e != nil {
		t.Fatal(e)
	}
	cand := NativeMachine{"i-11111111111111111", "m6i.large", m[0].ImageID, "Linux/UNIX", "RunInstances", "default", "candidate-hardware", "subnet-0123456789abcdef0", "vpc-0123456789abcdef0"}
	ct := NativeTemplate{tpl.ID, 2, cand.InstanceType, cand.ImageID, "default"}
	day := Period{p.End.AddDate(0, 0, -1), p.End}
	rows := []model.Document{usage(cand.InstanceID, cand.InstanceType, "CANDIDATE-OWN-SKU", "2.4", "0.1", day.Start, day.End)}
	r, e := summarizeRates(rows, []NativeMachine{cand}, ct, day, "111122223333", "eu-west-1", "USD", false)
	if e != nil || *r.ObservedHourlyRate != "0.1" || r.Dimensions.SKU == got.Dimensions.SKU {
		t.Fatal(r, e)
	}
}
func TestMissingOrConfoundedNativeRatesNeverManufacturePrices(t *testing.T) {
	cases := map[string]func([]model.Document, []NativeMachine, *NativeTemplate){
		"omitted net columns": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			delete(r[0], "line_item_net_unblended_cost")
			delete(r[0], "line_item_net_unblended_rate")
		},
		"unallocated discount": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["discount_total_discount"] = "0.5"
		},
		"missing native dimension": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			delete(r[0], "product_operating_system")
		},
		"public rate only": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["pricing_public_on_demand_rate"] = "0.2"
			delete(r[0], "line_item_unblended_rate")
		},
		"wrong currency": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["line_item_currency_code"] = "GBP"
		},
		"discounted pair incomplete": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["line_item_net_unblended_cost"] = "4.0"
		},
		"rounding unresolved": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["line_item_unblended_cost"] = "4.800000000001"
		},
		"sku changed": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) { r[1]["product_sku"] = "DIFFERENT" },
		"gap": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[1]["line_item_usage_start_date"] = stamp(r[1], "line_item_usage_start_date").Add(time.Hour).Format(time.RFC3339)
		},
		"overlap": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[1]["line_item_usage_start_date"] = stamp(r[0], "line_item_usage_start_date").Format(time.RFC3339)
		},
		"AMI unknown":      func(_ []model.Document, m []NativeMachine, _ *NativeTemplate) { m[0].ImageID = "" },
		"tenancy implicit": func(_ []model.Document, _ []NativeMachine, t *NativeTemplate) { t.Tenancy = "" },
		"wrong account": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["line_item_usage_account_id"] = "999900001111"
		},
		"premium software": func(r []model.Document, _ []NativeMachine, _ *NativeTemplate) {
			r[0]["product_pre_installed_sw"] = "SQL Server"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			data, m, tpl, p := rateFixture()
			mutate(data, m, &tpl)
			if _, e := summarizeRates(data, m, tpl, p, "111122223333", "eu-west-1", "USD", true); e == nil {
				t.Fatal("incomplete or conflicting evidence became rate authority")
			}
		})
	}
}
func TestNetNativeRateAndMoneyPrecisionRemainExact(t *testing.T) {
	data, m, tpl, p := rateFixture()
	for _, r := range data {
		r["line_item_net_unblended_rate"] = "0.123456789012345678"
		r["line_item_net_unblended_cost"] = "2.962962936296296272"
	}
	result, e := summarizeRates(data, m, tpl, p, "111122223333", "eu-west-1", "USD", true)
	if e != nil || *result.ObservedHourlyRate != "0.123456789012345678" || result.Dimensions.CostBasis != "NET_UNBLENDED" {
		t.Fatal(result, e)
	}
	n := new(big.Rat).SetFrac(big.NewInt(1), big.NewInt(3))
	if _, e = exactText(n); e == nil {
		t.Fatal("nonterminating rate rounded silently")
	}
}
func TestGlobalPayerCorrectionsInvalidateEconomicScope(t *testing.T) {
	data, _, _, p := rateFixture()
	original := economicHash(data, p)
	for _, kind := range []string{"RIFee", "SavingsPlanCoveredUsage", "Credit", "Refund", "Fee"} {
		r := model.Clone(data[0])
		r["line_item_resource_id"] = ""
		r["line_item_usage_account_id"] = "444455556666"
		r["product_region_code"] = "us-east-1"
		r["line_item_line_item_type"] = kind
		changed := append(append([]model.Document{}, data...), r)
		if economicHash(changed, p) == original || portfolioSafe(changed, p) == nil {
			t.Fatal("global portfolio correction ignored", kind)
		}
	}
	for _, key := range []string{"reservation_reservation_a_r_n", "reservation/ReservationARN", "savings_plan_savings_plan_a_r_n", "savingsPlan/SavingsPlanARN"} {
		r := model.Clone(data[0])
		r[key] = "arn:aws:covered"
		if portfolioSafe([]model.Document{r}, p) == nil {
			t.Fatal("native commitment ARN alias ignored", key)
		}
	}
	u := unavailable(Evidence{}, "raw SQL connection postgres://secret")
	if strings.Contains(strings.Join(u.ReasonCodes, ","), "secret") {
		t.Fatal("raw error leaked")
	}
}
