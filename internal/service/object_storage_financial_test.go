package service

// Synthetic native-shaped component facts. Connected acceptance must still
// obtain these through CUR and catalogue readers and immutable receipts.
import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func objectStorageFinancialFixture(at ...time.Time) (time.Time, model.Document, model.Document, model.Document, []model.Document, model.Document) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if len(at) == 1 {
		now = at[0].UTC()
	}
	start, end := objectStorageFinancialDay(now)
	resource := model.Document{"tenant_id": "synthetic-tenant", "id": "bucket", "account_id": "111122223333", "region": "eu-west-1", "name": "customer display label, not the bucket name", "provider_resource_id": "arn:aws:s3:::synthetic-cost-bucket",
		"object_storage_configuration": model.Document{"name": "synthetic-cost-bucket", "arn": "arn:aws:s3:::synthetic-cost-bucket", "account_id": "111122223333", "region": "eu-west-1"}}
	receipt := model.Document{"source_receipt_id": "synthetic-receipt", "source_version": "synthetic-revision", "canonical_hash": strings.Repeat("a", 64), "payer_account_id": "111122223333",
		"source_proof": model.Document{"state": "COMPLETE", "period_start": start.Format(time.RFC3339), "period_end": end.Format(time.RFC3339)}}
	dimensions := []model.Document{}
	rows := []model.Document{}
	add := func(cls, nativeClass, component, usage, operation, unit, rate string, own bool) {
		id := "synthetic-" + cls + "-" + component
		rid := "arn:aws:s3:::synthetic-price-peer"
		if own {
			rid = model.String(resource, "provider_resource_id")
		}
		sku, code := "sku-"+id, "rate-"+id
		raw := model.Document{"product_servicecode": "AmazonS3", "product_storage_class": nativeClass, "product_sku": sku, "pricing_rate_code": code, "pricing_term": "OnDemand", "pricing_unit": unit,
			"line_item_usage_type": "EUW1-" + usage, "line_item_operation": operation, "line_item_usage_account_id": "111122223333", "product_region_code": "eu-west-1", "line_item_resource_id": rid, "line_item_line_item_type": "Usage", "line_item_currency_code": "GBP",
			"line_item_net_unblended_rate": rate, "line_item_usage_amount": "1", "line_item_net_unblended_cost": rate}
		rows = append(rows, model.Document{"x_SourceRecordId": id, "BillingAccountId": "111122223333", "SubAccountId": "111122223333", "RegionId": "eu-west-1", "ResourceId": rid, "BillingCurrency": "GBP", "BilledCost": rate,
			"ChargePeriodStart": start.Format(time.RFC3339), "ChargePeriodEnd": end.Format(time.RFC3339), "x_ProviderFields": raw})
		dimensions = append(dimensions, model.Document{"sku": sku, "rate_code": code, "begin_range": "0", "end_range": "Inf", "unit": unit, "applies_to": []string{}, "term_type": "OnDemand",
			"effective_date": start.Add(-24 * time.Hour).Format(time.RFC3339), "publication_date": start.Add(-time.Hour).Format(time.RFC3339), "attributes": model.Document{"regionCode": "eu-west-1", "servicecode": "AmazonS3", "operation": operation, "usagetype": "EUW1-" + usage}, "basis": "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"})
	}
	add("STANDARD", "Standard", "storage", "TimedStorage-ByteHrs", "StandardStorage", "GB-Mo", "0.023", true)
	add("STANDARD_IA", "Standard - Infrequent Access", "storage", "TimedStorage-SIA-ByteHrs", "StandardIAStorage", "GB-Mo", "0.0125", false)
	add("IT_FREQUENT", "Intelligent-Tiering", "storage", "TimedStorage-INT-FA-ByteHrs", "IntelligentTieringFAStorage", "GB-Mo", "0.023", false)
	add("IT_INFREQUENT", "Intelligent-Tiering", "storage", "TimedStorage-INT-IA-ByteHrs", "IntelligentTieringIAStorage", "GB-Mo", "0.0125", false)
	add("IT_ARCHIVE_INSTANT", "Intelligent-Tiering", "storage", "TimedStorage-INT-AIA-ByteHrs", "IntelligentTieringAIAStorage", "GB-Mo", "0.004", false)
	add("GLACIER_INSTANT_RETRIEVAL", "Glacier Instant Retrieval", "storage", "TimedStorage-GIR-ByteHrs", "GlacierInstantStorage", "GB-Mo", "0.004", false)
	add("GLACIER_FLEXIBLE_RETRIEVAL", "Glacier", "storage", "TimedStorage-Glacier-ByteHrs", "GlacierStorage", "GB-Mo", "0.0036", false)
	add("DEEP_ARCHIVE", "Glacier Deep Archive", "storage", "TimedStorage-GDA-ByteHrs", "DeepArchiveStorage", "GB-Mo", "0.00099", false)
	add("INTELLIGENT_TIERING", "Intelligent-Tiering", "monitoring", "Monitoring-Automation", "IntelligentTieringMonitoring", "Objects", "0.0000025", false)
	for _, pair := range []struct{ class, native string }{{"INTELLIGENT_TIERING", "Intelligent-Tiering"}, {"STANDARD_IA", "Standard - Infrequent Access"}, {"GLACIER_INSTANT_RETRIEVAL", "Glacier Instant Retrieval"}, {"GLACIER_FLEXIBLE_RETRIEVAL", "Glacier"}, {"DEEP_ARCHIVE", "Glacier Deep Archive"}} {
		add(pair.class, pair.native, "transition", "LifecycleTransition", "LifecycleTransition", "Requests", "0.00001", false)
	}
	canonical := model.Document{"pricing_dimensions": model.Document{"schema_version": "1", "scope": model.Document{"tenant_id": "synthetic-tenant", "account_id": "111122223333", "region": "eu-west-1"}, "collected_at": now.Format(time.RFC3339), "dimensions": dimensions,
		"source_ref": storageRef("AWS_S3_NATIVE_PRICING_DIMENSIONS", "synthetic-catalogue", "1", strings.Repeat("b", 64)), "basis": "NATIVE_PRICING_RANGES_WITHOUT_LIST_PRICE_SUBSTITUTION"}}
	input := model.Document{"cohorts": []model.Document{{"id": "synthetic-cohort", "object_count": "1000", "total_bytes": "1073741824000"}}}
	return now, resource, receipt, canonical, rows, input
}

func objectStorageFinancialPart(price model.Document, class, component string) model.Document {
	for _, part := range storageRows(price["components"]) {
		if part["class"] == class && part["component"] == component {
			return part
		}
	}
	return nil
}

func TestObjectStorageFinancialNativeRatesBindCurrencyDimensionsAndBucketIdentity(t *testing.T) {
	now, resource, receipt, canonical, rows, input := objectStorageFinancialFixture()
	price, ids, reasons := objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if len(reasons) != 0 || len(ids) != 1 || price["currency"] != "GBP" || price["continuing_monthly_cost"] != "0.000000000000" || len(storageRows(price["components"])) != 14 {
		t.Fatalf("valid native witnesses unavailable: %+v %+v", price, reasons)
	}
	if model.String(objectStorageFinancialPart(price, "STANDARD_IA", "storage"), "rate") != "0.012500000000" || objectStorageFinancialPart(price, "INTELLIGENT_TIERING", "monitoring") == nil {
		t.Fatal("native customer component identity lost")
	}
	// Changing a display label cannot change native resource attribution.
	resource["name"] = "synthetic-price-peer"
	_, got, _ := objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if len(got) != 1 || got[0] != ids[0] {
		t.Fatal("display label was treated as native bucket identity")
	}
	// A foreign-currency peer cannot become a GBP component, even if cheaper.
	peer := model.Clone(rows[1])
	peer["BillingCurrency"] = "USD"
	raw := storageObject(peer["x_ProviderFields"])
	raw["line_item_currency_code"] = "USD"
	peer["x_ProviderFields"] = raw
	rows[1] = peer
	price, _, reasons = objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if objectStorageFinancialPart(price, "STANDARD_IA", "storage") != nil || len(reasons) != 0 {
		t.Fatal("peer currency was relabelled or unrelated valid components lost")
	}
}

func TestObjectStorageFinancialMissingCatalogueAndMarginalBandsFailClosed(t *testing.T) {
	now, resource, receipt, canonical, rows, input := objectStorageFinancialFixture()
	price, _, _ := objectStorageNativePrices(rows, resource, receipt, now, model.Document{}, input)
	if len(storageRows(price["components"])) != 0 {
		t.Fatal("native customer rate escaped without native range/unit evidence")
	}
	for name, mutate := range map[string]func(model.Document){
		"nonzero-lower-band":   func(d model.Document) { d["begin_range"] = "51200" },
		"too-small-first-band": func(d model.Document) { d["end_range"] = "1" },
		"wrong-unit":           func(d model.Document) { d["unit"] = "Requests" },
		"conditional":          func(d model.Document) { d["applies_to"] = []string{"another-sku"} },
		"wrong-region": func(d model.Document) {
			a := storageObject(d["attributes"])
			a["regionCode"] = "us-east-1"
			d["attributes"] = a
		},
		"future-effective": func(d model.Document) { d["effective_date"] = now.Add(time.Hour).Format(time.RFC3339) },
	} {
		t.Run(name, func(t *testing.T) {
			meta := model.Clone(canonical)
			dims := storageObject(meta["pricing_dimensions"])
			parts := storageRows(dims["dimensions"])
			mutate(parts[0])
			dims["dimensions"] = parts
			meta["pricing_dimensions"] = dims
			price, _, _ := objectStorageNativePrices(rows, resource, receipt, now, meta, input)
			if objectStorageFinancialPart(price, "STANDARD", "storage") != nil {
				t.Fatal("unsupported marginal native rate accepted")
			}
		})
	}
	// A finite first storage band works only when the entire trusted payer and
	// region plus worst candidate overhead fits strictly inside its upper end.
	dims := storageObject(canonical["pricing_dimensions"])
	parts := storageRows(dims["dimensions"])
	parts[0]["end_range"] = "51200"
	dims["dimensions"] = parts
	canonical["pricing_dimensions"] = dims
	price, _, reasons := objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if objectStorageFinancialPart(price, "STANDARD", "storage") == nil || len(reasons) != 0 {
		t.Fatal("evidenced conservative first band refused", reasons)
	}
	input["cohorts"] = []model.Document{{"object_count": "1000000000000", "total_bytes": "1073741824000"}}
	price, _, _ = objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if objectStorageFinancialPart(price, "STANDARD", "storage") != nil {
		t.Fatal("small-object candidate overhead crossed bracket unnoticed")
	}
}

func TestObjectStorageFinancialContinuingUsesActualDayAndSignedCredits(t *testing.T) {
	now, resource, receipt, canonical, rows, input := objectStorageFinancialFixture()
	fee := model.Clone(rows[0])
	fee["x_SourceRecordId"] = "current-unmodelled-fee"
	fee["BilledCost"] = "-2"
	raw := storageObject(fee["x_ProviderFields"])
	raw["line_item_line_item_type"] = "Credit"
	raw["line_item_net_unblended_cost"] = "-2"
	fee["x_ProviderFields"] = raw
	old := model.Clone(fee)
	old["x_SourceRecordId"] = "old-fee"
	old["BilledCost"] = "999"
	start, end := objectStorageFinancialDay(now)
	old["ChargePeriodStart"] = start.Add(-24 * time.Hour).Format(time.RFC3339)
	old["ChargePeriodEnd"] = end.Add(-24 * time.Hour).Format(time.RFC3339)
	rows = append(rows, fee, old)
	price, _, reasons := objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if len(reasons) != 0 || price["continuing_observed_amount"] != "-2.000000000000" || price["continuing_monthly_cost"] != "-60.833333333333" || len(model.Strings(price, "continuing_record_ids")) != 1 {
		t.Fatalf("month sum, sign loss or fabricated period: %+v %+v", price, reasons)
	}
	proof := storageObject(receipt["source_proof"])
	proof["period_end"] = end.Add(-time.Hour).Format(time.RFC3339)
	receipt["source_proof"] = proof
	price, _, reasons = objectStorageNativePrices(rows, resource, receipt, now, canonical, input)
	if price["continuing_monthly_cost"] != nil || len(reasons) == 0 {
		t.Fatal("incomplete export proved absence or a complete day")
	}
}

func TestObjectStorageFinancialUnknownScopeCannotSupportMarginalUpperBound(t *testing.T) {
	now, _, receipt, _, rows, input := objectStorageFinancialFixture()
	start, end := objectStorageFinancialDay(now)
	upper, ok := objectStorageMarginalUpperBound(rows, receipt, "eu-west-1", storageRows(input["cohorts"]), start, end)
	if !ok || upper.Cmp(big.NewRat(1000, 1)) <= 0 {
		t.Fatal("full source scope and candidate overhead absent")
	}
	row := model.Clone(rows[0])
	row["RegionId"] = ""
	rows = append(rows, row)
	if _, ok = objectStorageMarginalUpperBound(rows, receipt, "eu-west-1", storageRows(input["cohorts"]), start, end); ok {
		t.Fatal("unknown regional storage scope treated as zero")
	}
}

func TestObjectStorageFinancialBucketFeesNeverRepeatAcrossPrefixCohorts(t *testing.T) {
	price := model.Document{"basis": "AWS_CUR_NET_USAGE", "currency": "GBP", "components": []model.Document{}, "continuing_monthly_cost": "10", "continuing_record_ids": []string{"native-fee"}, "continuing_observed_amount": "0.328767123288"}
	cohort := model.Document{"id": "prefix-a", "population_hash": strings.Repeat("c", 64)}
	for n := 1; n <= 2; n++ {
		out := objectStorageCohortPricing(price, cohort, model.Document{}, n)
		if out["continuing_monthly_cost"] != nil {
			t.Fatal("unattributed whole-bucket fee copied into a prefix")
		}
	}
	canonical := model.Document{"inventory": model.Document{"bucket_population_complete": true, "whole_bucket_population_hash": cohort["population_hash"]}}
	if objectStorageCohortPricing(price, cohort, canonical, 1)["continuing_monthly_cost"] != "10" {
		t.Fatal("exact whole-bucket obligation lost")
	}
	if objectStorageCohortPricing(price, cohort, canonical, 2)["continuing_monthly_cost"] != nil {
		t.Fatal("one bucket obligation appeared in two cohorts")
	}
	price["continuing_monthly_cost"] = "0" // Offsetting observed fees/credits are not an absence proof.
	if objectStorageCohortPricing(price, cohort, model.Document{}, 2)["continuing_monthly_cost"] != nil {
		t.Fatal("offsetting records became invented absence")
	}
	price["continuing_record_ids"] = []string{}
	if objectStorageCohortPricing(price, cohort, model.Document{}, 2)["continuing_monthly_cost"] != "0" {
		t.Fatal("complete native absence lost")
	}
}
