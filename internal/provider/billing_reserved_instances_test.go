package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Uses the production AWS Query/SigV4 and BillingCommitments paths with native
// response-shaped bytes. The transport is synthetic; no provider is contacted.
func reservedInstanceQueryFixture(t *testing.T, regionalPages map[string][]string) (*BillingAWS, map[string]int) {
	t.Helper()
	calls := map[string]int{}
	reader := billingTestAWS(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatal("commitment collector issued a non-read API request")
		}
		switch {
		case r.URL.Host == "sts.eu-west-1.amazonaws.com":
			return billingResponse(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`), nil
		case strings.Contains(r.Header.Get("X-Amz-Target"), "DescribeOrganization"):
			out := billingResponse(`{"__type":"AWSOrganizationsNotInUseException","Message":"fixture standalone account"}`)
			out.StatusCode = http.StatusBadRequest
			return out, nil
		case strings.HasPrefix(r.URL.Host, "savingsplans."):
			if r.URL.Path != "/DescribeSavingsPlans" || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/savingsplans/aws4_request") {
				t.Fatal("wrong native Savings Plans read")
			}
			calls["savings_plans"]++
			return billingResponse(`{"savingsPlans":[]}`), nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil || values.Get("Version") != "2016-11-15" {
			t.Fatal("invalid native EC2 Query version")
		}
		region := strings.TrimSuffix(strings.TrimPrefix(r.URL.Host, "ec2."), ".amazonaws.com")
		if !strings.Contains(r.Header.Get("Authorization"), "/"+region+"/ec2/aws4_request") {
			t.Fatal("regional RI read was not signed for its region")
		}
		switch values.Get("Action") {
		case "DescribeRegions":
			calls["regions"]++
			return billingResponse(`<DescribeRegionsResponse><regionInfo><item><regionName>eu-west-1</regionName></item><item><regionName>eu-central-1</regionName></item></regionInfo></DescribeRegionsResponse>`), nil
		case "DescribeReservedInstances":
			index := calls[region]
			pages := regionalPages[region]
			if index >= len(pages) {
				t.Fatal("unexpected native RI page")
			}
			if index == 0 && values.Get("NextToken") != "" || index > 0 && values.Get("NextToken") != "next" {
				t.Fatal("native RI pagination token changed")
			}
			calls[region]++
			return billingResponse(pages[index]), nil
		default:
			t.Fatal("collector called an API outside the fixed read-only commitment path")
			return nil, nil
		}
	})
	return reader, calls
}

func reservedInstanceDocuments(t *testing.T, v any) []model.Document {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var rows []model.Document
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestNativeRIProjectionRetainsIssuedTermsAndExactPrices(t *testing.T) {
	reader, calls := reservedInstanceQueryFixture(t, map[string][]string{
		"eu-west-1": {`<DescribeReservedInstancesResponse><reservedInstancesSet><item>
<reservedInstancesId>ri-native-rich</reservedInstancesId><state>active</state>
<start>2026-01-01T00:00:00.000Z</start><end>2027-01-01T00:00:00.000Z</end><duration>31536000</duration>
<offeringClass>convertible</offeringClass><offeringType>Partial Upfront</offeringType><scope>Availability Zone</scope>
<currencyCode>USD</currencyCode><fixedPrice>1234.500000000001</fixedPrice><usagePrice>0.0</usagePrice><instanceCount>2</instanceCount>
<instanceType>m6i.large</instanceType><instanceTenancy>dedicated</instanceTenancy><productDescription>Linux/UNIX (Amazon VPC)</productDescription>
<availabilityZone>eu-west-1a</availabilityZone><availabilityZoneId>euw1-az1</availabilityZoneId>
<recurringCharges><item><frequency>Hourly</frequency><amount>0.012345678901</amount></item><item><frequency>Hourly</frequency><amount>0</amount></item></recurringCharges>
</item><item><reservedInstancesId>ri-retired</reservedInstancesId><state>retired</state></item></reservedInstancesSet><nextToken>next</nextToken></DescribeReservedInstancesResponse>`,
			`<DescribeReservedInstancesResponse><reservedInstancesSet><item><reservedInstancesId>ri-missing</reservedInstancesId><state>payment-pending</state><end>2027-02-01T00:00:00Z</end></item></reservedInstancesSet></DescribeReservedInstancesResponse>`},
		"eu-central-1": {`<DescribeReservedInstancesResponse><reservedInstancesSet><item><reservedInstancesId>ri-empty-charges</reservedInstancesId><state>active</state><recurringCharges/></item></reservedInstancesSet></DescribeReservedInstancesResponse>`},
	})
	proof, err := reader.BillingCommitments(context.Background(), "111122223333")
	if err != nil || !model.Bool(proof, "complete") || model.String(proof, "reason_code") != "COMMITMENT_SCOPE_VERIFIED" {
		t.Fatal("native account scope was not completed", err)
	}
	if !reflect.DeepEqual(calls, map[string]int{"regions": 1, "eu-west-1": 2, "eu-central-1": 1, "savings_plans": 1}) || model.Number(proof, "reserved_instance_count") != 3 {
		t.Fatal("regional pagination or original retired filtering changed")
	}
	snapshots := reservedInstanceDocuments(t, proof["native_snapshots"])
	if len(snapshots) != 1 || model.String(snapshots[0], "account_id") != "111122223333" {
		t.Fatal("issued native account binding was lost")
	}
	rows := reservedInstanceDocuments(t, snapshots[0]["reserved_instances"])
	want := model.Document{
		"id": "ri-native-rich", "state": "active", "region": "eu-west-1", "end": "2027-01-01T00:00:00.000Z",
		"native_projection": "AWS_EC2_DESCRIBE_RESERVED_INSTANCES_V2",
		"offering_class":    "convertible", "offering_type": "Partial Upfront", "scope": "Availability Zone",
		"start": "2026-01-01T00:00:00.000Z", "duration_seconds": "31536000", "currency_code": "USD",
		"fixed_price": "1234.500000000001", "usage_price": "0.0", "instance_count": "2",
		"instance_type": "m6i.large", "instance_tenancy": "dedicated", "product_description": "Linux/UNIX (Amazon VPC)",
		"availability_zone": "eu-west-1a", "availability_zone_id": "euw1-az1",
		"recurring_charges": []any{map[string]any{"frequency": "Hourly", "amount": "0.012345678901"}, map[string]any{"frequency": "Hourly", "amount": "0"}},
	}
	if len(rows) != 3 || !reflect.DeepEqual(rows[0], want) {
		t.Fatal("issued native RI terms, units, precision or legacy fields changed")
	}
	for _, key := range []string{"offering_class", "offering_type", "scope", "start", "duration_seconds", "currency_code", "fixed_price", "usage_price", "instance_count", "instance_type", "instance_tenancy", "product_description", "availability_zone", "availability_zone_id", "recurring_charges"} {
		value, exists := rows[1][key]
		if !exists || value != nil {
			t.Fatalf("absent provider field %s became an observed value", key)
		}
	}
	if charges, ok := rows[2]["recurring_charges"].([]any); !ok || len(charges) != 0 {
		t.Fatal("present empty native charge set was confused with an absent set")
	}
}

func TestNativeRIProjectionDistinguishesObservedZeroFromUnknown(t *testing.T) {
	reader, _ := reservedInstanceQueryFixture(t, map[string][]string{
		"eu-west-1":    {`<DescribeReservedInstancesResponse><reservedInstancesSet><item><reservedInstancesId>ri-zero</reservedInstancesId><state>queued</state><duration>0</duration><fixedPrice>0</fixedPrice><usagePrice>0.000000000000</usagePrice><instanceCount>0</instanceCount><recurringCharges><item><amount>0.00</amount><frequency>Hourly</frequency></item><item/></recurringCharges></item></reservedInstancesSet></DescribeReservedInstancesResponse>`},
		"eu-central-1": {`<DescribeReservedInstancesResponse><reservedInstancesSet/></DescribeReservedInstancesResponse>`},
	})
	proof, err := reader.BillingCommitments(context.Background(), "111122223333")
	if err != nil || !model.Bool(proof, "complete") {
		t.Fatal("observed native zero snapshot was discarded", err)
	}
	rows := reservedInstanceDocuments(t, reservedInstanceDocuments(t, proof["native_snapshots"])[0]["reserved_instances"])
	if len(rows) != 1 || rows[0]["fixed_price"] != "0" || rows[0]["usage_price"] != "0.000000000000" || rows[0]["instance_count"] != "0" || rows[0]["duration_seconds"] != "0" || rows[0]["currency_code"] != nil {
		t.Fatal("native zero was replaced by unknown or absent currency was defaulted")
	}
	charges := reservedInstanceDocuments(t, rows[0]["recurring_charges"])
	if len(charges) != 2 || charges[0]["amount"] != "0.00" || charges[0]["frequency"] != "Hourly" || charges[1]["amount"] != nil || charges[1]["frequency"] != nil {
		t.Fatal("native zero charge and missing amount/frequency became interchangeable")
	}
}

func TestNativeRISharedDecoderRefusesWrongResponseAndTrailingDocument(t *testing.T) {
	valid := `<DescribeReservedInstancesResponse><reservedInstancesSet><item><reservedInstancesId>ri-zero</reservedInstancesId><state>active</state><usagePrice>0</usagePrice></item></reservedInstancesSet><nextToken>second-page</nextToken></DescribeReservedInstancesResponse>`
	rows, next, err := ParseReservedInstancesResponse([]byte(valid), "eu-west-1")
	if err != nil || len(rows) != 1 || rows[0]["usage_price"] != "0" || rows[0]["fixed_price"] != nil || next != "second-page" {
		t.Fatal("shared collector decoder lost observed-zero or pagination identity", err)
	}
	for _, body := range []string{"", strings.ReplaceAll(valid, "DescribeReservedInstancesResponse", "DescribeReservedInstancesOfferingsResponse"), valid + valid, valid + "reflected-body", "<DescribeReservedInstancesResponse>", strings.Repeat(" ", (16<<20)+1)} {
		if rows, next, err := ParseReservedInstancesResponse([]byte(body), "eu-west-1"); err == nil || rows != nil || next != "" {
			t.Fatal("invalid native response produced a partial projection")
		}
	}
	if _, _, err := ParseReservedInstancesResponse([]byte(valid), "https://untrusted.example"); err == nil {
		t.Fatal("invalid native region was accepted")
	}
}
