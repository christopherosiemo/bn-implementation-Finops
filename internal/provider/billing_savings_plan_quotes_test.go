package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func quoteFixtureSelection() SavingsPlanQuoteSelection {
	return SavingsPlanQuoteSelection{PlanType: "Compute", PaymentOption: "No Upfront", DurationSeconds: 31536000, Currency: "USD", ExistingPlanIDs: []string{"plan-issued-a"}}
}

// Only the native transport is doubled. Production SDK serialization, SigV4,
// STS identity, pagination and collector projection execute unchanged.
func savingsPlanQuoteFixture(t *testing.T, account string, pages map[string][]string) (*BillingAWS, map[string]int) {
	t.Helper()
	calls := map[string]int{}
	reader := billingTestAWS(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Scheme != "https" {
			t.Fatal("quote collector changed the authenticated native transport")
		}
		if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
			calls["STS"]++
			if !strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/sts/aws4_request") {
				t.Fatal("acquisition identity was not signed")
			}
			return billingResponse(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>` + account + `</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`), nil
		}
		if !strings.HasPrefix(r.URL.Host, "savingsplans.") || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/savingsplans/aws4_request") {
			t.Fatal("quote collector changed the native service or signing region")
		}
		op := strings.TrimPrefix(r.URL.Path, "/")
		if op != "DescribeSavingsPlansOfferings" && op != "DescribeSavingsPlansOfferingRates" && op != "DescribeSavingsPlanRates" {
			t.Fatal("quote collector called an API outside the three read-only operations")
		}
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		var request model.Document
		if e = json.Unmarshal(raw, &request); e != nil || model.Number(request, "maxResults") != 1000 {
			t.Fatal("native quote request or page size changed")
		}
		if op == "DescribeSavingsPlansOfferings" {
			if !reflect.DeepEqual(request["currencies"], []any{"USD"}) || !reflect.DeepEqual(request["paymentOptions"], []any{"No Upfront"}) || !reflect.DeepEqual(request["planTypes"], []any{"Compute"}) || !reflect.DeepEqual(request["durations"], []any{float64(31536000)}) {
				t.Fatal("native offering selectors changed")
			}
		}
		page := calls[op]
		if page >= len(pages[op]) || page == 0 && model.String(request, "nextToken") != "" || page > 0 && model.String(request, "nextToken") != "next" {
			t.Fatal("native quote pagination identity changed")
		}
		if op == "DescribeSavingsPlanRates" && model.String(request, "savingsPlanId") != "plan-issued-a" {
			t.Fatal("existing plan ID changed")
		}
		if op == "DescribeSavingsPlansOfferingRates" {
			ids := request["savingsPlanOfferingIds"].([]any)
			if len(ids) == 0 || ids[0] != "aaaa-bbbb" {
				t.Fatal("offering rates were not bound to the collected offering IDs")
			}
		}
		calls[op]++
		return billingResponse(pages[op][page]), nil
	})
	return reader, calls
}

func quoteNativeOffering(id string) string {
	return `{"offeringId":"` + id + `","currency":"USD","durationSeconds":31536000,"paymentOption":"No Upfront","planType":"Compute","productTypes":["EC2"],"serviceCode":"AmazonEC2","usageType":"EU-BoxUsage:m6i.large","operation":"RunInstances","properties":[{"name":"region","value":"eu-west-1"}]}`
}

func quoteNativeRate(rate string) string {
	return `{"rate":` + rate + `,"unit":"Hrs","serviceCode":"AmazonEC2","productType":"EC2","usageType":"EU-BoxUsage:m6i.large","operation":"RunInstances","properties":[{"name":"region","value":"eu-west-1"},{"name":"instanceType","value":"m6i.large"},{"name":"productDescription","value":"Linux/UNIX"},{"name":"tenancy","value":"Shared"}],"savingsPlanOffering":{"offeringId":"aaaa-bbbb","currency":"USD","durationSeconds":31536000,"paymentOption":"No Upfront","planType":"Compute"}}`
}

func TestSavingsPlanQuotesNativePagesPreserveTermsPricesAndUnknown(t *testing.T) {
	reader, calls := savingsPlanQuoteFixture(t, "111122223333", map[string][]string{
		"DescribeSavingsPlansOfferings": {
			`{"searchResults":[` + quoteNativeOffering("aaaa-bbbb") + `],"nextToken":"next"}`,
			`{"searchResults":[` + quoteNativeOffering("cccc-dddd") + `]}`,
		},
		"DescribeSavingsPlansOfferingRates": {
			`{"searchResults":[` + quoteNativeRate(`"0.012345678901"`) + `],"nextToken":"next"}`,
			`{"searchResults":[` + quoteNativeRate(`null`) + `]}`,
		},
		"DescribeSavingsPlanRates": {
			`{"savingsPlanId":"plan-issued-a","searchResults":[{"rate":"0.000000000000","currency":"USD","unit":"Hrs","serviceCode":"AmazonEC2","productType":"EC2","usageType":"EU-BoxUsage:m6i.large","operation":"RunInstances"}],"nextToken":"next"}`,
			`{"savingsPlanId":"plan-issued-a","searchResults":[{"unit":"Hrs","currency":"USD"}]}`,
		},
	})
	selection := quoteFixtureSelection()
	proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", selection)
	if err != nil || !model.Bool(proof, "complete") || model.String(proof, "native_projection") != SavingsPlanQuoteProjection || model.String(proof, "serialization") != "SDK_PROJECTION" || model.String(proof, "authenticated_account_id") != "111122223333" {
		t.Fatal("native quote projection did not complete", err)
	}
	if !reflect.DeepEqual(calls, map[string]int{"STS": 1, "DescribeSavingsPlansOfferings": 2, "DescribeSavingsPlansOfferingRates": 2, "DescribeSavingsPlanRates": 2}) {
		t.Fatal("native rate operations or pagination changed")
	}
	offers, rates, contracts := proof["offerings"].([]model.Document), proof["offering_rates"].([]model.Document), proof["existing_plan_rates"].([]model.Document)
	if len(offers) != 2 || len(rates) != 2 || len(contracts) != 2 {
		t.Fatal("native rate population was lost")
	}
	first := offers[0]["native"].(model.Document)
	if first["offeringId"] != "aaaa-bbbb" || first["currency"] != "USD" || first["paymentOption"] != "No Upfront" || first["durationSeconds"] != json.Number("31536000") || first["planType"] != "Compute" {
		t.Fatal("native offering terms were relabelled")
	}
	if rates[0]["native"].(model.Document)["rate"] != "0.012345678901" || rates[1]["native"].(model.Document)["rate"] != nil || contracts[0]["native"].(model.Document)["rate"] != "0.000000000000" || contracts[1]["native"].(model.Document)["rate"] != nil {
		t.Fatal("native lexical money, observed zero or unknown changed")
	}
	properties := rates[0]["native"].(model.Document)["properties"].([]any)
	if properties[2].(model.Document)["value"] != "Linux/UNIX" || properties[3].(model.Document)["value"] != "Shared" {
		t.Fatal("native platform or tenancy was normalized into a different SKU")
	}
	pages := proof["pages"].([]model.Document)
	hashes := proof["ordered_page_sha256s"].([]string)
	for i, page := range pages {
		body := model.Document{}
		for k, v := range page {
			if k != "sha256" {
				body[k] = v
			}
		}
		raw, _ := json.Marshal(body)
		h := sha256.Sum256(raw)
		if page["sha256"] != hex.EncodeToString(h[:]) || hashes[i] != page["sha256"] {
			t.Fatal("ordered immutable SDK page hash differs")
		}
	}
	selection.ExistingPlanIDs[0] = "caller-mutated"
	if proof["selection"].(SavingsPlanQuoteSelection).ExistingPlanIDs[0] != "plan-issued-a" {
		t.Fatal("returned source selectors retain a mutable caller alias")
	}
}

func TestSavingsPlanQuotesEmptyCatalogIsObservedWithoutInventedRates(t *testing.T) {
	reader, calls := savingsPlanQuoteFixture(t, "111122223333", map[string][]string{"DescribeSavingsPlansOfferings": {`{"searchResults":[]}`}})
	selection := quoteFixtureSelection()
	selection.ExistingPlanIDs = []string{}
	proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", selection)
	if err != nil || !model.Bool(proof, "complete") || len(proof["offerings"].([]model.Document)) != 0 || len(proof["offering_rates"].([]model.Document)) != 0 || len(proof["existing_plan_rates"].([]model.Document)) != 0 || calls["DescribeSavingsPlansOfferingRates"] != 0 || calls["DescribeSavingsPlanRates"] != 0 {
		t.Fatal("empty observed catalog was replaced by guessed rates or existing plans", err)
	}
}

func TestSavingsPlanQuotesRefuseForeignIdentityBeforeRates(t *testing.T) {
	reader, calls := savingsPlanQuoteFixture(t, "999900001111", nil)
	if proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", quoteFixtureSelection()); err == nil || proof != nil || len(calls) != 1 || calls["STS"] != 1 {
		t.Fatal("foreign acquisition identity yielded native quote evidence")
	}
}

func TestSavingsPlanQuotesRefusePartialForeignAndCyclicPages(t *testing.T) {
	for name, response := range map[string]string{
		"wrong-terms":    strings.Replace(quoteNativeOffering("aaaa-bbbb"), `"No Upfront"`, `"Partial Upfront"`, 1),
		"missing-terms":  `{"offeringId":"aaaa-bbbb","currency":"USD"}`,
		"wrong-currency": strings.Replace(quoteNativeOffering("aaaa-bbbb"), `"USD"`, `"CNY"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			reader, _ := savingsPlanQuoteFixture(t, "111122223333", map[string][]string{"DescribeSavingsPlansOfferings": {`{"searchResults":[` + response + `]}`}})
			if proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", quoteFixtureSelection()); err == nil || proof != nil {
				t.Fatal("unbound native offering produced partial evidence")
			}
		})
	}
	t.Run("cycle", func(t *testing.T) {
		reader, _ := savingsPlanQuoteFixture(t, "111122223333", map[string][]string{"DescribeSavingsPlansOfferings": {`{"searchResults":[],"nextToken":"next"}`, `{"searchResults":[],"nextToken":"next"}`}})
		if proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", quoteFixtureSelection()); err == nil || proof != nil {
			t.Fatal("cyclic native pagination became complete")
		}
	})
	t.Run("foreign-existing-plan", func(t *testing.T) {
		reader, _ := savingsPlanQuoteFixture(t, "111122223333", map[string][]string{"DescribeSavingsPlansOfferings": {`{"searchResults":[]}`}, "DescribeSavingsPlanRates": {`{"savingsPlanId":"foreign","searchResults":[]}`}})
		if proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", quoteFixtureSelection()); err == nil || proof != nil {
			t.Fatal("foreign existing-plan response became current terms")
		}
	})
	t.Run("foreign-offer-rate", func(t *testing.T) {
		reader, _ := savingsPlanQuoteFixture(t, "111122223333", map[string][]string{"DescribeSavingsPlansOfferings": {`{"searchResults":[` + quoteNativeOffering("aaaa-bbbb") + `]}`}, "DescribeSavingsPlansOfferingRates": {`{"searchResults":[` + strings.Replace(quoteNativeRate(`"1"`), "aaaa-bbbb", "eeee-ffff", 1) + `]}`}})
		if proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", quoteFixtureSelection()); err == nil || proof != nil {
			t.Fatal("rate for an uncollected offering became evidence")
		}
	})
}

func TestSavingsPlanQuoteSelectorsAndBudgetsFailClosed(t *testing.T) {
	reader := billingTestAWS(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid quote selectors contacted a provider")
		return nil, errors.New("unexpected transport")
	})
	for _, change := range []func(*SavingsPlanQuoteSelection){
		func(s *SavingsPlanQuoteSelection) { s.PlanType = "SageMaker" },
		func(s *SavingsPlanQuoteSelection) { s.Currency = "" },
		func(s *SavingsPlanQuoteSelection) { s.PaymentOption = "All Upfront" },
		func(s *SavingsPlanQuoteSelection) { s.DurationSeconds = 0 },
		func(s *SavingsPlanQuoteSelection) { s.ExistingPlanIDs = []string{"b", "a"} },
		func(s *SavingsPlanQuoteSelection) { s.ExistingPlanIDs = []string{"a", "a"} },
		func(s *SavingsPlanQuoteSelection) { s.ExistingPlanIDs = make([]string, 2001) },
	} {
		selection := quoteFixtureSelection()
		change(&selection)
		if proof, err := reader.BillingSavingsPlanQuotes(context.Background(), "111122223333", selection); err == nil || proof != nil {
			t.Fatal("invalid source selectors produced evidence")
		}
	}
	if _, err := quoteSDKDocument(model.Document{"oversize": strings.Repeat("x", (2<<20)+1)}); !errors.Is(err, errQuoteLimit) {
		t.Fatal("oversized SDK projection was accepted")
	}
	for _, b := range []*quotePages{{rows: 100000}, {bytes: 32 << 20}, {pages: make([]model.Document, 4096)}} {
		if _, err := b.append("DescribeSavingsPlanRates", model.Document{}, model.Document{}, 1); !errors.Is(err, errQuoteLimit) {
			t.Fatal("aggregate native quote budget was bypassed")
		}
	}
	if _, _, err := quoteNext(aws.String("stillnext"), map[string]bool{}, 99); !errors.Is(err, errQuoteLimit) {
		t.Fatal("truncated final page was labelled complete")
	}
	for _, token := range []string{strings.Repeat("a", 1025), "untrusted-token"} {
		if _, _, err := quoteNext(&token, map[string]bool{}, 0); !errors.Is(err, errQuoteLimit) {
			t.Fatal("invalid native continuation token was accepted")
		}
	}
}
