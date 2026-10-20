package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"math/big"
	"sort"
	"strings"
	"time"
)

// CurrentObjectStorageSKUs selects native catalogue identifiers, never prices,
// from the same authenticated current CUR revision used by the economics path.
// Ingestion may retain inventory when this returns an explicit billing gate.
func CurrentObjectStorageSKUs(ctx context.Context, t *store.Tx, account, region string) ([]string, error) {
	ref, records, reasons, err := objectStorageCurrentBilling(ctx, t, account, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if ref == nil || len(reasons) != 0 {
		return nil, errors.New("OBJECT_STORAGE_AUTHENTICATED_CURRENT_CUR_REQUIRED")
	}
	start, end := objectStorageFinancialDay(time.Now().UTC())
	if !objectStorageBillingPeriodComplete(ref, start, end) {
		return nil, errors.New("OBJECT_STORAGE_COMPLETE_CURRENT_BILLING_DAY_REQUIRED")
	}
	seen := map[string]bool{}
	for _, row := range records {
		raw := storageObject(row["x_ProviderFields"])
		if model.String(row, "SubAccountId") != account || model.String(row, "RegionId") != region || databaseRawString(raw, "product_servicecode") != "AmazonS3" || !objectStorageRecordInPeriod(row, start, end) || databaseRawString(raw, "line_item_usage_account_id") != account || databaseRawString(raw, "product_region_code") != region || databaseRawString(raw, "line_item_line_item_type") != "Usage" {
			continue
		}
		if sku := databaseRawString(raw, "product_sku"); sku != "" && len(sku) <= 64 && !strings.ContainsAny(sku, "\x00\r\n\t ") {
			seen[sku] = true
		}
	}
	if len(seen) > 64 {
		return nil, errors.New("OBJECT_STORAGE_CURRENT_SKU_LIMIT")
	}
	out := make([]string, 0, len(seen))
	for sku := range seen {
		out = append(out, sku)
	}
	sort.Strings(out)
	return out, nil
}

// Only native NET charge arithmetic supplies customer rates. Public prices,
// uploaded dictionaries and Inventory metadata cannot enter this projection.
func objectStorageCharge(raw model.Document) (class, component, unit string) {
	if databaseRawString(raw, "product_servicecode") != "AmazonS3" {
		return
	}
	usage := databaseRawString(raw, "line_item_usage_type")
	operation := databaseRawString(raw, "line_item_operation")
	nativeClass := databaseRawString(raw, "product_storage_class")
	if nativeClass == "" {
		nativeClass = databaseRawString(raw, "product_volume_type")
	}
	classes := map[string]string{"Standard": "STANDARD", "General Purpose": "STANDARD", "STANDARD": "STANDARD", "Standard - Infrequent Access": "STANDARD_IA", "Standard-Infrequent Access": "STANDARD_IA", "STANDARD_IA": "STANDARD_IA", "One Zone - Infrequent Access": "ONEZONE_IA", "ONEZONE_IA": "ONEZONE_IA", "Intelligent-Tiering": "INTELLIGENT_TIERING", "INTELLIGENT_TIERING": "INTELLIGENT_TIERING", "Glacier Instant Retrieval": "GLACIER_INSTANT_RETRIEVAL", "GLACIER_IR": "GLACIER_INSTANT_RETRIEVAL", "Glacier": "GLACIER_FLEXIBLE_RETRIEVAL", "GLACIER": "GLACIER_FLEXIBLE_RETRIEVAL", "Glacier Deep Archive": "DEEP_ARCHIVE", "DEEP_ARCHIVE": "DEEP_ARCHIVE"}
	class = classes[nativeClass]
	if strings.Contains(usage, "Monitoring-Automation") && (class == "" || class == "INTELLIGENT_TIERING") {
		class = "INTELLIGENT_TIERING"
	}
	if class == "" || class == "INTELLIGENT_TIERING" {
		switch {
		case strings.Contains(usage, "TimedStorage-INT-FA"):
			class = "IT_FREQUENT"
		case strings.Contains(usage, "TimedStorage-INT-IA"):
			class = "IT_INFREQUENT"
		case strings.Contains(usage, "TimedStorage-INT-AIA"):
			class = "IT_ARCHIVE_INSTANT"
		case strings.Contains(usage, "TimedStorage-INT-AA"):
			class = "IT_ARCHIVE"
		case strings.Contains(usage, "TimedStorage-INT-DAA"):
			class = "IT_DEEP_ARCHIVE"
		case strings.Contains(usage, "TimedStorage-SIA"):
			class = "STANDARD_IA"
		case strings.Contains(usage, "TimedStorage-ZIA"):
			class = "ONEZONE_IA"
		case strings.Contains(usage, "TimedStorage-GIR"):
			class = "GLACIER_INSTANT_RETRIEVAL"
		case operation == "GlacierStorage":
			class = "GLACIER_FLEXIBLE_RETRIEVAL"
		case operation == "DeepArchiveStorage":
			class = "DEEP_ARCHIVE"
		case operation == "StandardStorage":
			class = "STANDARD"
		}
	}
	switch {
	case strings.Contains(usage, "TimedStorage") || operation == "StandardStorage" || operation == "GlacierStorage" || operation == "DeepArchiveStorage":
		component = "storage"
		unit = "GiB-Mo"
	case strings.Contains(usage, "Monitoring-Automation"):
		component = "monitoring"
		unit = "Object-Mo"
	case strings.Contains(usage, "Retrieval") && !strings.Contains(usage, "Requests"):
		component = "retrieval"
		unit = "GiB"
	case strings.Contains(operation, "Transition") || strings.Contains(usage, "LifecycleTransition"):
		component = "transition"
		unit = "Request"
	case strings.Contains(operation, "Restore") || strings.Contains(usage, "RestoreRequest"):
		component = "restore_request"
		unit = "Request"
	case strings.Contains(usage, "Requests"):
		component = "request"
		unit = "Request"
	}
	return
}
func objectStorageRateUnit(raw model.Document, unit string) bool {
	u := databaseRawString(raw, "pricing_unit")
	switch unit {
	case "GiB-Mo":
		return u == "GB-Mo" || u == "GiB-Mo"
	case "GiB":
		return u == "GB" || u == "GiB"
	case "Request":
		return u == "Requests" || u == "Request"
	case "Object-Mo":
		return u == "Objects" || u == "Object-Mo"
	}
	return false
}

func objectStorageFinancialDay(now time.Time) (time.Time, time.Time) {
	end := now.UTC().Truncate(24 * time.Hour)
	return end.Add(-24 * time.Hour), end
}

func objectStorageRecordInPeriod(row model.Document, start, end time.Time) bool {
	a, ae := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
	b, be := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
	return ae == nil && be == nil && b.After(a) && !a.Before(start) && !b.After(end)
}

func objectStorageCurrentBilling(ctx context.Context, t *store.Tx, account string, now time.Time) (model.Document, []model.Document, []string, error) {
	rows, err := t.Query(ctx, "SELECT id FROM source_registrations WHERE tenant_id=$1 AND kind='AWS_CUR2' AND (document->'usage_account_ids' ? $2) ORDER BY id LIMIT 257", t.Tenant, account)
	if err != nil {
		return nil, nil, nil, err
	}
	sources := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		sources = append(sources, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(sources) > 256 {
		return nil, nil, []string{"OBJECT_STORAGE_BILLING_SOURCE_LIMIT"}, nil
	}
	start, _ := objectStorageFinancialDay(now)
	month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	var selected model.Document
	var records []model.Document
	for _, id := range sources {
		ref, data, e := (&API{}).databaseBillingMonth(ctx, t, id, month)
		if e != nil {
			if databaseDomainError(e) || errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			return nil, nil, nil, e
		}
		if selected != nil {
			return nil, nil, []string{"OBJECT_STORAGE_BILLING_SOURCE_AMBIGUOUS"}, nil
		}
		selected, records = ref, data
	}
	if selected == nil {
		return nil, nil, []string{"OBJECT_STORAGE_AUTHENTICATED_CUR_REQUIRED"}, nil
	}
	return selected, records, nil, nil
}

func objectStorageBillingPeriodComplete(receipt model.Document, start, end time.Time) bool {
	proof := storageObject(receipt["source_proof"])
	left, le := time.Parse(time.RFC3339Nano, model.String(proof, "period_start"))
	right, re := time.Parse(time.RFC3339Nano, model.String(proof, "period_end"))
	state := model.String(proof, "state")
	return le == nil && re == nil && !left.After(start) && !right.Before(end) && (state == "COMPLETE" || state == "FINAL")
}

func objectStorageNativeBucket(resource model.Document) (string, bool) {
	configuration := storageObject(resource["object_storage_configuration"])
	name, arn := model.String(configuration, "name"), model.String(resource, "provider_resource_id")
	return name, name != "" && arn == "arn:aws:s3:::"+name && model.String(configuration, "arn") == arn && configuration["account_id"] == resource["account_id"] && configuration["region"] == resource["region"]
}

// This deliberately generous upper bound sums month-equivalent native storage
// across every authenticated payer/member row in the region, not only the
// target bucket or class, then adds worst-case candidate object overhead. It
// can refuse a valid opportunity; it cannot assume an unknown cheaper bracket.
func objectStorageMarginalUpperBound(records []model.Document, receipt model.Document, region string, cohorts []model.Document, start, end time.Time) (*big.Rat, bool) {
	if !objectStorageBillingPeriodComplete(receipt, start, end) || model.String(receipt, "payer_account_id") == "" {
		return nil, false
	}
	bound := new(big.Rat)
	seen := map[string]bool{}
	for _, row := range records {
		raw := storageObject(row["x_ProviderFields"])
		if databaseRawString(raw, "product_servicecode") != "AmazonS3" || databaseRawString(raw, "line_item_line_item_type") != "Usage" || !objectStorageRecordInPeriod(row, start, end) {
			continue
		}
		_, component, _ := objectStorageCharge(raw)
		if component != "storage" {
			if strings.Contains(databaseRawString(raw, "line_item_usage_type"), "Storage") && (model.String(row, "RegionId") == "" || model.String(row, "RegionId") == region) {
				return nil, false
			}
			continue
		}
		if model.String(row, "RegionId") == "" {
			return nil, false
		}
		if model.String(row, "RegionId") != region {
			continue
		}
		quantity, ok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		id := model.String(row, "x_SourceRecordId")
		a, _ := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
		b, _ := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
		if !ok || quantity.Sign() < 0 || !objectStorageRateUnit(raw, "GiB-Mo") || id == "" || seen[id] || model.String(row, "BillingAccountId") != model.String(receipt, "payer_account_id") || model.String(row, "SubAccountId") != databaseRawString(raw, "line_item_usage_account_id") || databaseRawString(raw, "product_region_code") != region {
			return nil, false
		}
		seen[id] = true
		seconds := new(big.Rat).SetFrac(big.NewInt(b.Sub(a).Nanoseconds()), big.NewInt(int64(time.Second)))
		if seconds.Sign() <= 0 {
			return nil, false
		}
		bound.Add(bound, new(big.Rat).Quo(new(big.Rat).Mul(quantity, big.NewRat(730*3600, 1)), seconds))
	}
	if len(seen) == 0 {
		return nil, false
	}
	for _, cohort := range cohorts {
		count, cok := databaseDecimal(cohort["object_count"])
		size, sok := databaseDecimal(cohort["total_bytes"])
		if !cok || !sok || count.Sign() < 0 || size.Sign() < 0 || !count.IsInt() || !size.IsInt() {
			return nil, false
		}
		bytes := new(big.Rat).Add(size, new(big.Rat).Mul(count, big.NewRat((128+40)*1024, 1)))
		bound.Add(bound, new(big.Rat).Quo(bytes, big.NewRat(1073741824, 1)))
	}
	return bound, true
}

func objectStorageRateDimension(raw, dimensions, resource model.Document, rowStart, now time.Time, upper *big.Rat) bool {
	scope := storageObject(dimensions["scope"])
	collected, ce := time.Parse(time.RFC3339Nano, model.String(dimensions, "collected_at"))
	ref := storageObject(dimensions["source_ref"])
	if model.String(dimensions, "schema_version") != "1" || model.String(dimensions, "basis") != "NATIVE_PRICING_RANGES_WITHOUT_LIST_PRICE_SUBSTITUTION" || scope["account_id"] != resource["account_id"] || scope["region"] != resource["region"] || scope["tenant_id"] != resource["tenant_id"] || model.String(scope, "tenant_id") == "" || ce != nil || collected.After(now.Add(time.Minute)) || now.Sub(collected) > 24*time.Hour || model.String(ref, "id") == "" || model.String(ref, "version") == "" || len(model.String(ref, "sha256")) != 64 {
		return false
	}
	matches := 0
	for _, dimension := range storageRows(dimensions["dimensions"]) {
		if model.String(dimension, "sku") != databaseRawString(raw, "product_sku") || model.String(dimension, "rate_code") != databaseRawString(raw, "pricing_rate_code") {
			continue
		}
		matches++
		effective, ee := time.Parse(time.RFC3339Nano, model.String(dimension, "effective_date"))
		publication, pe := time.Parse(time.RFC3339Nano, model.String(dimension, "publication_date"))
		attrs := storageObject(dimension["attributes"])
		begin, bok := databaseDecimal(dimension["begin_range"])
		_, component, unit := objectStorageCharge(raw)
		probe := model.Document{"pricing_unit": dimension["unit"]}
		if ee != nil || pe != nil || effective.After(rowStart) || publication.After(now) || model.String(dimension, "term_type") != "OnDemand" || model.String(dimension, "basis") != "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE" || !bok || begin.Sign() != 0 || !objectStorageRateUnit(probe, unit) || attrs["regionCode"] != resource["region"] || model.String(attrs, "servicecode") != "" && model.String(attrs, "servicecode") != "AmazonS3" {
			return false
		}
		// Nonempty appliesTo contains SKU identifiers, not objects. Reject any
		// conditional dimension rather than losing it through a document decoder.
		switch values := dimension["applies_to"].(type) {
		case []any:
			if len(values) != 0 {
				return false
			}
		case []string:
			if len(values) != 0 {
				return false
			}
		default:
			return false
		}
		if value := model.String(attrs, "operation"); value != "" && value != databaseRawString(raw, "line_item_operation") {
			return false
		}
		if value := model.String(attrs, "usagetype"); value != "" && value != databaseRawString(raw, "line_item_usage_type") {
			return false
		}
		if value := model.String(attrs, "storageClass"); value != "" {
			probe := model.Clone(raw)
			probe["product_storage_class"] = value
			observed, _, _ := objectStorageCharge(raw)
			expected, _, _ := objectStorageCharge(probe)
			if observed != expected {
				return false
			}
		}
		if model.String(dimension, "end_range") != "Inf" {
			end, ok := databaseDecimal(dimension["end_range"])
			if !ok || end.Sign() <= 0 || component != "storage" || upper == nil || upper.Cmp(end) >= 0 {
				return false
			}
		}
	}
	return matches == 1
}
func objectStorageNativePrices(records []model.Document, resource, receipt model.Document, now time.Time, options ...model.Document) (model.Document, []string, []string) {
	account, region := model.String(resource, "account_id"), model.String(resource, "region")
	arn := model.String(resource, "provider_resource_id")
	name, bucketKnown := objectStorageNativeBucket(resource)
	startDay, endDay := objectStorageFinancialDay(now)
	dimensions := model.Document{}
	cohorts := []model.Document{}
	if len(options) > 0 {
		dimensions = storageObject(options[0]["pricing_dimensions"])
	}
	if len(options) > 1 {
		cohorts = storageRows(options[1]["cohorts"])
	}
	upper, upperKnown := objectStorageMarginalUpperBound(records, receipt, region, cohorts, startDay, endDay)
	if !upperKnown {
		upper = nil
	}
	parts := map[string]model.Document{}
	signatures := map[string]string{}
	conflicts := map[string]bool{}
	ids := []string{}
	currentIDs := []string{}
	currencies := map[string]bool{}
	continuing := new(big.Rat)
	continuingKnown := objectStorageBillingPeriodComplete(receipt, startDay, endDay) && bucketKnown
	latest := time.Time{}
	nativeCurrent := false
	ref := storageRef("AWS_CUR2_CANONICAL_RECORDS", model.String(receipt, "source_receipt_id"), model.String(receipt, "source_version"), model.String(receipt, "canonical_hash"))
	// Establish the target bucket's actual source currency before considering
	// peer rate witnesses. Every component must match that same currency.
	for _, row := range records {
		if model.String(row, "SubAccountId") != account || model.String(row, "RegionId") != region || !objectStorageRecordInPeriod(row, startDay, endDay) {
			continue
		}
		raw := storageObject(row["x_ProviderFields"])
		if databaseRawString(raw, "product_servicecode") != "AmazonS3" || model.String(row, "ResourceId") != arn && model.String(row, "ResourceId") != name {
			continue
		}
		cur := model.String(row, "BillingCurrency")
		if !databaseCoverageCurrency.MatchString(cur) || cur != databaseRawString(raw, "line_item_currency_code") {
			continuingKnown = false
			continue
		}
		currencies[cur] = true
	}
	currency := ""
	if len(currencies) == 1 {
		for cur := range currencies {
			currency = cur
		}
	}
	continuingIDs := []string{}
	for _, row := range records {
		if model.String(row, "SubAccountId") != account || model.String(row, "RegionId") != region {
			continue
		}
		raw := storageObject(row["x_ProviderFields"])
		if databaseRawString(raw, "product_servicecode") != "AmazonS3" {
			continue
		}
		if !objectStorageRecordInPeriod(row, startDay, endDay) {
			continue
		}
		rid := model.String(row, "ResourceId")
		if rid == "" {
			continuingKnown = false
			continue
		}
		own := rid == arn || rid == name
		start, se := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
		end, ee := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
		if se != nil || ee != nil || !end.After(start) || end.After(now) {
			if own {
				continuingKnown = false
			}
			continue
		}
		if own && end.After(latest) {
			latest = end
		}
		class, component, unit := objectStorageCharge(raw)
		billed, bok := databaseDecimal(row["BilledCost"])
		if own {
			if !bok {
				continuingKnown = false
			} else {
				if component == "" || class == "" || databaseRawString(raw, "line_item_line_item_type") != "Usage" {
					continuing.Add(continuing, billed)
					if billed.Sign() != 0 {
						continuingIDs = append(continuingIDs, model.String(row, "x_SourceRecordId"))
					}
				}
			}
		}
		if class == "" || component == "" {
			continue
		}
		if databaseRawString(raw, "line_item_line_item_type") != "Usage" {
			continue
		}
		rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
		qty, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		amount, aok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		cur := model.String(row, "BillingCurrency")
		rowID := model.String(row, "x_SourceRecordId")
		if !rok || !qok || !aok || !bok || rate.Sign() < 0 || qty.Sign() <= 0 || amount.Cmp(billed) != 0 || databaseInputMoney(new(big.Rat).Mul(rate, qty)) != databaseInputMoney(amount) || !databaseCoverageCurrency.MatchString(cur) || cur != currency || cur != databaseRawString(raw, "line_item_currency_code") || !objectStorageRateUnit(raw, unit) || databaseRawString(raw, "line_item_usage_account_id") != account || databaseRawString(raw, "product_region_code") != region || databaseRawString(raw, "line_item_resource_id") != rid || rowID == "" || !objectStorageRateDimension(raw, dimensions, resource, start, now, upper) {
			if own {
				continuingKnown = false
			}
			continue
		}
		dims := model.Document{}
		for _, key := range []string{"pricing_rate_code", "product_sku", "line_item_operation", "pricing_term"} {
			v := databaseRawString(raw, key)
			if v == "" {
				continuingKnown = false
			}
			dims[key] = v
		}
		if databaseRawString(raw, "pricing_term") != "OnDemand" {
			continue
		}
		if own {
			currentIDs = append(currentIDs, rowID)
			nativeCurrent = true
		}
		key := class + ":" + component
		signature := evidence.Hash(model.Document{"dimensions": dims, "rate": databaseInputMoney(rate), "currency": cur, "unit": unit})
		if old := signatures[key]; old != "" && old != signature {
			conflicts[key] = true
		}
		signatures[key] = signature
		parts[key] = model.Document{"class": class, "component": component, "unit": unit, "rate": databaseInputMoney(rate), "source_ref": ref}
		ids = append(ids, rowID)
	}
	components := []model.Document{}
	keys := []string{}
	for key := range parts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !conflicts[key] {
			components = append(components, parts[key])
		}
	}
	reasons := []string{}
	if currency == "" || !nativeCurrent {
		reasons = append(reasons, "OBJECT_STORAGE_CURRENT_NATIVE_BILLING_UNAVAILABLE")
	}
	if latest.IsZero() || now.Sub(latest) > 48*time.Hour {
		reasons = append(reasons, "OBJECT_STORAGE_BILLING_STALE")
	}
	if !bucketKnown {
		reasons = append(reasons, "OBJECT_STORAGE_NATIVE_BUCKET_IDENTITY_REQUIRED")
	}
	if !objectStorageBillingPeriodComplete(receipt, startDay, endDay) {
		reasons = append(reasons, "OBJECT_STORAGE_COMPLETE_CURRENT_BILLING_DAY_REQUIRED")
	}
	var continuingMonthly any
	if continuingKnown && currency != "" { // Carry observed non-modelled charges through both scenarios; no saving is attributed to them.
		continuingMonthly = databaseInputMoney(new(big.Rat).Mul(continuing, big.NewRat(730, 24)))
	}
	price := model.Document{"basis": "AWS_CUR_NET_USAGE", "currency": currency, "components": components, "continuing_monthly_cost": continuingMonthly, "source_ref": ref, "native_rate_record_ids": databaseSortedReasons(ids), "current_record_ids": databaseSortedReasons(currentIDs), "continuing_record_ids": databaseSortedReasons(continuingIDs), "continuing_observed_amount": databaseInputMoney(continuing), "continuing_observed_period": model.Document{"start": startDay.Format(time.RFC3339), "end": endDay.Format(time.RFC3339)}, "continuing_basis": "OBSERVED_COMPLETE_UTC_DAY_HELD_730H_MONTH"}
	return price, databaseSortedReasons(currentIDs), reasons
}
func (a *API) objectStorageFinancialInput(ctx context.Context, t *store.Tx, r, input model.Document, canonical ...model.Document) ([]model.Document, []string, error) {
	ref, records, reasons, e := objectStorageCurrentBilling(ctx, t, model.String(r, "account_id"), a.now())
	if e != nil || ref == nil {
		return nil, reasons, e
	}
	boundResource := model.Clone(r)
	boundResource["tenant_id"] = t.Tenant
	metadata := model.Document{}
	if len(canonical) == 1 {
		metadata = canonical[0]
	}
	price, ids, reasons := objectStorageNativePrices(records, boundResource, ref, a.now(), metadata, input)
	cohorts := storageRows(input["cohorts"])
	for j, c := range cohorts {
		c["pricing"] = objectStorageCohortPricing(price, c, metadata, len(cohorts))
		cohorts[j] = c
	}
	input["cohorts"] = cohorts
	ref["economic_record_ids"] = ids
	ref["attribution_basis"] = "BUCKET_NATIVE_CHARGES_COHORT_RATES_ARE_MODELLED"
	ref["native_rate_record_ids"] = price["native_rate_record_ids"]
	ref["continuing_record_ids"] = price["continuing_record_ids"]
	ref["continuing_observed_amount"] = price["continuing_observed_amount"]
	ref["continuing_observed_period"] = price["continuing_observed_period"]
	ref["continuing_basis"] = price["continuing_basis"]
	ref["pricing_dimensions_ref"] = storageObject(metadata["pricing_dimensions"])["source_ref"]
	return []model.Document{ref}, reasons, nil
}

func objectStorageCohortPricing(price, cohort, canonical model.Document, populationCount int) model.Document {
	out := model.Clone(price)
	// Bucket continuing fees/credits have no defensible prefix allocation.
	// Only a complete-export absence is safe for every cohort. Nonzero source
	// components (including offsetting credits) remain a bucket-level burden.
	if len(model.Strings(price, "continuing_record_ids")) != 0 {
		inventory := storageObject(canonical["inventory"])
		whole := populationCount == 1 && model.Bool(inventory, "bucket_population_complete") && model.String(cohort, "population_hash") != "" && model.String(cohort, "population_hash") == model.String(inventory, "whole_bucket_population_hash")
		if !whole {
			out["continuing_monthly_cost"] = nil
		}
	}
	for _, field := range []string{"native_rate_record_ids", "current_record_ids", "continuing_record_ids", "continuing_observed_amount", "continuing_observed_period", "continuing_basis"} {
		delete(out, field)
	}
	return out
}
