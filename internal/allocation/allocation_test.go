package allocation

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func allocationPolicy() Policy {
	return Policy{SchemaVersion: "1", Name: "Current ownership", Rules: []Rule{}}
}

func allocationResources() []Resource {
	return []Resource{{ID: "resource-a", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "i-native-a", WorkloadID: "workload-owner", Version: 3}}
}

func allocationRecord(id, code string, amount *string) Record {
	return Record{ID: id, SourceID: "cur-native", SourceVersion: "version-pinned-1", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", ProviderResourceID: "i-native-a", Currency: code, BilledCost: amount}
}

func allocationAmount(v string) *string { return &v }

func TestAllocationTwoMissingRegionsCannotEstablishResourceIdentity(t *testing.T) {
	resources := allocationResources()
	resources[0].Region = ""
	record := allocationRecord("regional-identity-unknown", "GBP", allocationAmount("-1.000000000001"))
	record.Region = ""
	// Even an explicit policy cannot manufacture the missing native binding.
	p := allocationPolicy()
	p.Rules = []Rule{{ResourceIDs: []string{"resource-a"}, Recipients: []Recipient{{"workload-owner", 1000000}}}}
	out, err := Evaluate(p, []Record{record}, resources, []string{"workload-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Lines) != 1 || out.Lines[0].ResourceID != nil || out.Lines[0].WorkloadID != nil || out.Lines[0].Method != "UNALLOCATED" || out.Totals[0].UnallocatedSubtotal != "-1.000000000001" {
		t.Fatal("two absent regions established an authoritative resource match")
	}
}

func requireAllocationError(t *testing.T, want string, p Policy, records []Record, resources []Resource, workloads []string) {
	t.Helper()
	if _, err := Evaluate(p, records, resources, workloads); err == nil || err.Error() != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

// Sum the public decimal strings independently with rational arithmetic. This
// catches one-unit drift without reusing the engine's scaled-integer helpers.
func allocationSum(t *testing.T, values ...string) string {
	t.Helper()
	sum := new(big.Rat)
	for _, value := range values {
		n, ok := new(big.Rat).SetString(value)
		if !ok {
			t.Fatalf("invalid output decimal %q", value)
		}
		sum.Add(sum, n)
	}
	return sum.FloatString(12)
}

func TestAllocationSignedConservationAndCurrencySeparation(t *testing.T) {
	p := allocationPolicy()
	p.Rules = []Rule{{ResourceIDs: []string{"resource-a"}, Recipients: []Recipient{{"workload-b", 666667}, {"workload-a", 333333}}}}
	records := []Record{
		allocationRecord("usage-gbp", "GBP", allocationAmount("123.123456789123")),
		allocationRecord("credit-gbp", "GBP", allocationAmount("-20.000000000001")),
		allocationRecord("usage-usd", "USD", allocationAmount("10.000000000001")),
		allocationRecord("credit-usd", "USD", allocationAmount("-1.000000000002")),
	}
	unmapped := allocationRecord("unmapped-credit", "GBP", allocationAmount("-3.000000000001"))
	unmapped.ProviderResourceID = "i-no-current-inventory"
	records = append(records, unmapped)
	out, err := Evaluate(p, records, allocationResources(), []string{"workload-owner", "workload-a", "workload-b"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Basis != "CURRENT_OWNERSHIP_VIEW" || out.ExecutionAuthorized || out.VerifiedSaving != nil || out.Status != "ALLOCATED_OBSERVATIONS" {
		t.Fatal("observations acquired authority or savings semantics")
	}
	byRecord := map[string][]string{}
	for _, line := range out.Lines {
		if line.AllocatedBilledCost == nil {
			t.Fatal("known signed amount became unavailable")
		}
		byRecord[line.RecordID] = append(byRecord[line.RecordID], *line.AllocatedBilledCost)
	}
	for _, record := range records {
		if got, want := allocationSum(t, byRecord[record.ID]...), allocationSum(t, *record.BilledCost); got != want {
			t.Fatalf("record %s did not conserve: %s != %s", record.ID, got, want)
		}
	}
	if len(out.Totals) != 2 || out.Totals[0].Currency != "GBP" || out.Totals[1].Currency != "USD" {
		t.Fatal("currencies were combined or unstable")
	}
	for i, want := range []string{"100.123456789121", "8.999999999999"} {
		total := out.Totals[i]
		if total.ObservedBilledTotal == nil || *total.ObservedBilledTotal != want || total.KnownBilledSubtotal != want || allocationSum(t, total.AllocatedSubtotal, total.UnallocatedSubtotal) != want {
			t.Fatalf("currency subtotal failed conservation: %+v", total)
		}
	}
	if out.Totals[0].UnallocatedSubtotal != "-3.000000000001" {
		t.Fatal("unmapped negative credit disappeared")
	}
}

func TestAllocationLargestRemainderAndLexicalTies(t *testing.T) {
	for _, test := range []struct {
		name, amount string
		weights      []Recipient
		want         map[string]string
	}{
		{"positive-tie", "0.000000000001", []Recipient{{"workload-b", 500000}, {"workload-a", 500000}}, map[string]string{"workload-a": "0.000000000001", "workload-b": "0.000000000000"}},
		{"negative-tie", "-0.000000000001", []Recipient{{"workload-b", 500000}, {"workload-a", 500000}}, map[string]string{"workload-a": "-0.000000000001", "workload-b": "0.000000000000"}},
		{"unequal-remainder", "0.000000000002", []Recipient{{"workload-b", 333333}, {"workload-c", 333334}, {"workload-a", 333333}}, map[string]string{"workload-a": "0.000000000001", "workload-b": "0.000000000000", "workload-c": "0.000000000001"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := allocationPolicy()
			p.Rules = []Rule{{[]string{"resource-a"}, test.weights}}
			workloads := []string{"workload-owner", "workload-a", "workload-b", "workload-c"}
			out, err := Evaluate(p, []Record{allocationRecord("smallest-unit", "GBP", allocationAmount(test.amount))}, allocationResources(), workloads)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range out.Lines {
				if line.WorkloadID == nil || line.AllocatedBilledCost == nil || *line.AllocatedBilledCost != test.want[*line.WorkloadID] {
					t.Fatalf("largest-remainder result differs: %+v", line)
				}
			}
			for left, right := 0, len(p.Rules[0].Recipients)-1; left < right; left, right = left+1, right-1 {
				p.Rules[0].Recipients[left], p.Rules[0].Recipients[right] = p.Rules[0].Recipients[right], p.Rules[0].Recipients[left]
			}
			again, err := Evaluate(p, []Record{allocationRecord("smallest-unit", "GBP", allocationAmount(test.amount))}, allocationResources(), workloads)
			if err != nil || !reflect.DeepEqual(out.Lines, again.Lines) {
				t.Fatal("recipient input order changes residual allocation", err)
			}
		})
	}
}

func TestAllocationUnavailableCostsStayDistinctFromZero(t *testing.T) {
	records := []Record{allocationRecord("unknown", "GBP", nil), allocationRecord("explicit-zero", "GBP", allocationAmount("0")), allocationRecord("known", "GBP", allocationAmount("2.50")), allocationRecord("usd-zero", "USD", allocationAmount("-0.000000000000"))}
	out, err := Evaluate(allocationPolicy(), records, allocationResources(), []string{"workload-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "PARTIAL_OBSERVATIONS" || len(out.Lines) != 4 || out.Lines[0].AllocatedBilledCost != nil || out.Lines[0].ReasonCode != "BILLED_COST_UNAVAILABLE" || out.Lines[0].WorkloadID != nil || out.Lines[1].AllocatedBilledCost == nil || *out.Lines[1].AllocatedBilledCost != "0.000000000000" {
		t.Fatal("unknown cost was invented as zero or allocated authority")
	}
	gbp, usd := out.Totals[0], out.Totals[1]
	if gbp.ObservedBilledTotal != nil || gbp.UnknownRecordCount != 1 || gbp.KnownBilledSubtotal != "2.500000000000" || usd.ObservedBilledTotal == nil || *usd.ObservedBilledTotal != "0.000000000000" || usd.UnknownRecordCount != 0 {
		t.Fatal("currency total hid unknown cost or contaminated another currency")
	}
}

func TestAllocationExactNativeBindingAndMissingOwners(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Record)
	}{
		{"unknown-resource", func(r *Record) { r.ProviderResourceID = "unknown" }},
		{"wrong-account", func(r *Record) { r.AccountID = "999900001111" }},
		{"wrong-region", func(r *Record) { r.Region = "eu-central-1" }},
		{"unknown-region", func(r *Record) { r.Region = "" }},
		{"wrong-provider", func(r *Record) { r.Provider = "GCP" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := allocationRecord("native-row", "GBP", allocationAmount("-4.25"))
			test.change(&r)
			out, err := Evaluate(allocationPolicy(), []Record{r}, allocationResources(), []string{"workload-owner"})
			if err != nil || len(out.Lines) != 1 || out.Lines[0].Method != "UNALLOCATED" || out.Lines[0].ResourceID != nil || out.Lines[0].WorkloadID != nil || out.Totals[0].UnallocatedSubtotal != "-4.250000000000" {
				t.Fatal("unmatched native binding acquired current ownership", err)
			}
		})
	}
	resources := allocationResources()
	resources[0].WorkloadID = ""
	out, err := Evaluate(allocationPolicy(), []Record{allocationRecord("no-owner", "GBP", allocationAmount("1"))}, resources, nil)
	if err != nil || out.Lines[0].ResourceID == nil || out.Lines[0].WorkloadID != nil || out.Lines[0].Method != "UNALLOCATED" || out.Lines[0].ReasonCode != "RESOURCE_OWNER_UNAVAILABLE" {
		t.Fatal("missing owner was guessed", err)
	}
	resources[0].WorkloadID = "not-in-catalog"
	requireAllocationError(t, "ALLOCATION_RESOURCE_OWNER_UNKNOWN", allocationPolicy(), nil, resources, []string{"workload-owner"})
}

func TestAllocationCanonicalDuplicatesAndCatalogAmbiguityFailClosed(t *testing.T) {
	r := allocationRecord("same-canonical-row", "GBP", allocationAmount("1"))
	requireAllocationError(t, "ALLOCATION_DUPLICATE_SOURCE_RECORD", allocationPolicy(), []Record{r, r}, allocationResources(), []string{"workload-owner"})
	changed := r
	changed.BilledCost = allocationAmount("100")
	requireAllocationError(t, "ALLOCATION_DUPLICATE_SOURCE_RECORD", allocationPolicy(), []Record{r, changed}, allocationResources(), []string{"workload-owner"})
	resources := allocationResources()
	duplicateNative := resources[0]
	duplicateNative.ID = "other-inventory-id"
	requireAllocationError(t, "ALLOCATION_RESOURCE_CATALOG_INVALID", allocationPolicy(), []Record{r}, append(resources, duplicateNative), []string{"workload-owner"})
	duplicateID := resources[0]
	duplicateID.ProviderResourceID = "different-native-id"
	requireAllocationError(t, "ALLOCATION_RESOURCE_CATALOG_INVALID", allocationPolicy(), []Record{r}, append(resources, duplicateID), []string{"workload-owner"})
	requireAllocationError(t, "ALLOCATION_WORKLOAD_CATALOG_INVALID", allocationPolicy(), []Record{r}, resources, []string{"workload-owner", "workload-owner"})
}

func TestAllocationInvalidPoliciesAndSelectors(t *testing.T) {
	validRule := func() Rule { return Rule{[]string{"resource-a"}, []Recipient{{"workload-owner", 1000000}}} }
	for name, mutate := range map[string]func(*Policy){
		"schema": func(p *Policy) { p.SchemaVersion = "2" }, "empty-name": func(p *Policy) { p.Name = "  " }, "long-name": func(p *Policy) { p.Name = strings.Repeat("x", 81) }, "nil-rules": func(p *Policy) { p.Rules = nil },
		"empty-selector": func(p *Policy) { p.Rules[0].ResourceIDs = nil }, "invalid-selector": func(p *Policy) { p.Rules[0].ResourceIDs = []string{"../resource"} }, "duplicate-selector": func(p *Policy) { p.Rules[0].ResourceIDs = []string{"resource-a", "resource-a"} },
		"overlapping-rules": func(p *Policy) { p.Rules = append(p.Rules, validRule()) }, "no-recipients": func(p *Policy) { p.Rules[0].Recipients = nil }, "zero-weight": func(p *Policy) { p.Rules[0].Recipients[0].WeightPPM = 0 }, "negative-weight": func(p *Policy) { p.Rules[0].Recipients[0].WeightPPM = -1 }, "excess-weight": func(p *Policy) { p.Rules[0].Recipients[0].WeightPPM = 1000001 }, "incomplete-weight": func(p *Policy) { p.Rules[0].Recipients[0].WeightPPM = 999999 },
		"duplicate-recipient": func(p *Policy) {
			p.Rules[0].Recipients = []Recipient{{"workload-owner", 500000}, {"workload-owner", 500000}}
		}, "invalid-recipient": func(p *Policy) { p.Rules[0].Recipients[0].WorkloadID = "../workload" },
	} {
		t.Run(name, func(t *testing.T) {
			p := allocationPolicy()
			p.Rules = []Rule{validRule()}
			mutate(&p)
			if err := ValidatePolicy(p); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	p := allocationPolicy()
	p.Rules = []Rule{validRule()}
	p.Rules[0].ResourceIDs = []string{"missing-resource"}
	requireAllocationError(t, "ALLOCATION_POLICY_RESOURCE_NOT_FOUND", p, nil, allocationResources(), []string{"workload-owner"})
	p.Rules[0] = validRule()
	p.Rules[0].Recipients[0].WorkloadID = "missing-workload"
	requireAllocationError(t, "ALLOCATION_POLICY_WORKLOAD_NOT_FOUND", p, nil, allocationResources(), []string{"workload-owner"})
}

func TestAllocationDecimalPrecisionAndTotalOverflow(t *testing.T) {
	for _, bad := range []string{"100000000000000000000000000", "-100000000000000000000000000", "0.0000000000001", "01", "1e3", "1,000", "+1", "NaN", "Infinity", " 1"} {
		t.Run(bad, func(t *testing.T) {
			requireAllocationError(t, "ALLOCATION_DECIMAL_38_12_REQUIRED", allocationPolicy(), []Record{allocationRecord("bad-decimal", "GBP", allocationAmount(bad))}, allocationResources(), []string{"workload-owner"})
		})
	}
	for _, amount := range []string{"99999999999999999999999999.999999999999", "-99999999999999999999999999.999999999999"} {
		record := allocationRecord("largest-valid", "GBP", allocationAmount(amount))
		out, err := Evaluate(allocationPolicy(), []Record{record}, allocationResources(), []string{"workload-owner"})
		if err != nil || out.Totals[0].ObservedBilledTotal == nil || *out.Totals[0].ObservedBilledTotal != amount {
			t.Fatal("exact DECIMAL(38,12) boundary lost", err)
		}
		second := record
		second.ID = "overflowing-total"
		requireAllocationError(t, "ALLOCATION_DECIMAL_TOTAL_OVERFLOW", allocationPolicy(), []Record{record, second}, allocationResources(), []string{"workload-owner"})
	}
}

func TestAllocationOutputBoundIncludesUnknownAndUnallocatedRows(t *testing.T) {
	p := allocationPolicy()
	workloads := []string{"workload-owner"}
	recipients := []Recipient{}
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("workload-%03d", i)
		workloads = append(workloads, id)
		recipients = append(recipients, Recipient{id, 10000})
	}
	p.Rules = []Rule{{[]string{"resource-a"}, recipients}}
	records := []Record{}
	for i := 0; i < MaxAllocations/len(recipients); i++ {
		records = append(records, allocationRecord(fmt.Sprintf("row-%03d", i), "GBP", allocationAmount("0.01")))
	}
	out, err := Evaluate(p, records, allocationResources(), workloads)
	if err != nil || len(out.Lines) != MaxAllocations {
		t.Fatal("exact bounded population rejected", err)
	}
	for _, kind := range []string{"allocated", "unknown-cost", "unallocated"} {
		t.Run(kind, func(t *testing.T) {
			extra := allocationRecord("one-too-many", "GBP", allocationAmount("0.01"))
			if kind == "unknown-cost" {
				extra.BilledCost = nil
			}
			if kind == "unallocated" {
				extra.ProviderResourceID = "not-in-current-inventory"
			}
			population := append(append([]Record{}, records...), extra)
			requireAllocationError(t, "ALLOCATION_OUTPUT_LIMIT", p, population, allocationResources(), workloads)
		})
	}
	tooMany := make([]Record, MaxRecords+1)
	requireAllocationError(t, "ALLOCATION_RECORD_LIMIT", allocationPolicy(), tooMany, nil, nil)
}

func TestAllocationDoesNotMutateInputAndEmptyIsUnavailable(t *testing.T) {
	p := allocationPolicy()
	p.Rules = []Rule{{[]string{"resource-a"}, []Recipient{{"workload-b", 500000}, {"workload-a", 500000}}}}
	records := []Record{allocationRecord("row", "GBP", allocationAmount("0.000000000001"))}
	resources := allocationResources()
	workloads := []string{"workload-owner", "workload-b", "workload-a"}
	input := []any{p, records, resources, workloads}
	before, _ := json.Marshal(input)
	if _, err := Evaluate(p, records, resources, workloads); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("allocation changed caller-owned policy/catalog/financial inputs")
	}
	empty, err := Evaluate(allocationPolicy(), nil, nil, nil)
	if err != nil || empty.Status != "NO_OBSERVATIONS" || len(empty.Totals) != 0 || len(empty.Lines) != 0 || empty.ExecutionAuthorized || empty.VerifiedSaving != nil {
		t.Fatal("no observations invented a financial or authority result", err)
	}
}
