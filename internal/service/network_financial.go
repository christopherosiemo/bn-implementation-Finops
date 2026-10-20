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

// Classifies native usage dimensions, not service-wide cost guesses. Unsupported
// components remain in the all-AWS denominator and are not silently renamed.
func networkChargeKind(raw model.Document) string {
	service := databaseRawString(raw, "product_servicecode")
	usage := databaseRawString(raw, "line_item_usage_type")
	family := databaseRawString(raw, "product_product_family")
	switch service {
	case "AmazonEC2", "AmazonVPC", "AWSDataTransfer", "AWSELB":
	default:
		return ""
	}
	switch {
	case strings.Contains(usage, "NatGateway") && strings.Contains(usage, "Hours"):
		return "NAT_HOURLY"
	case strings.Contains(usage, "NatGateway") && strings.Contains(usage, "Bytes"):
		return "NAT_PROCESSING"
	case strings.Contains(usage, "PublicIPv4:"):
		return "PUBLIC_IPV4"
	case strings.Contains(usage, "VpcEndpoint") && strings.Contains(usage, "Hours"):
		return "ENDPOINT_HOURLY"
	case strings.Contains(usage, "VpcEndpoint") && strings.Contains(usage, "Bytes"):
		return "ENDPOINT_PROCESSING"
	case strings.Contains(usage, "TransitGateway"):
		return "TRANSIT_GATEWAY"
	case strings.Contains(usage, "PrivateLink"):
		return "PRIVATELINK"
	case strings.Contains(usage, "DataTransfer-Regional-Bytes") || strings.Contains(usage, "DataTransfer-xAZ") || strings.Contains(usage, "DataTransfer-AZ"):
		return "CROSS_AZ_TRANSFER"
	case strings.Contains(usage, "AWS-Out-Bytes") || strings.Contains(usage, "AWS-In-Bytes"):
		return "CROSS_REGION_TRANSFER"
	case strings.Contains(usage, "DataTransfer-Out-Bytes"):
		return "INTERNET_EGRESS"
	case service == "AWSELB" && (strings.Contains(usage, "LCUUsage") || strings.Contains(usage, "ProcessedBytes") || family == "Load Balancer"):
		return "LOAD_BALANCER_PROCESSING"
	}
	return ""
}
func networkWindow(c model.Document, now time.Time) (time.Time, time.Time) {
	selection := storageObject(storageObject(c["metrics"])["selection"])
	start, e := time.Parse(time.RFC3339Nano, model.String(selection, "start"))
	end, f := time.Parse(time.RFC3339Nano, model.String(selection, "end"))
	if e != nil || f != nil || !end.After(start) || end.Sub(start) > 90*24*time.Hour {
		end = now.UTC().Truncate(24 * time.Hour)
		start = end.Add(-14 * 24 * time.Hour)
	}
	return start, end
}
func networkCurrentMonth(ctx context.Context, t *store.Tx, account string, month time.Time) (model.Document, []model.Document, error) {
	rows, e := t.Query(ctx, "SELECT id FROM source_registrations WHERE tenant_id=$1 AND kind='AWS_CUR2' AND document->'usage_account_ids' ? $2 ORDER BY id LIMIT 65", t.Tenant, account)
	if e != nil {
		return nil, nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			break
		}
		ids = append(ids, id)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	if len(ids) > 64 {
		return nil, nil, errors.New("NETWORK_BILLING_SOURCE_LIMIT")
	}
	var ref model.Document
	var data []model.Document
	for _, id := range ids {
		candidate, records, e := (&API{}).databaseBillingMonth(ctx, t, id, month)
		if e != nil {
			if databaseDomainError(e) || errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			return nil, nil, e
		}
		if ref != nil {
			return nil, nil, errors.New("NETWORK_BILLING_SOURCE_AMBIGUOUS")
		}
		ref, data = candidate, records
	}
	return ref, data, nil
}

// CurrentNetworkSKUs returns only native identifiers from authenticated current
// billing. Catalogue calls subsequently return dimension metadata, never prices.
func CurrentNetworkSKUs(ctx context.Context, t *store.Tx, account, region string) ([]string, error) {
	now := time.Now().UTC().Add(-24 * time.Hour)
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	ref, records, e := networkCurrentMonth(ctx, t, account, month)
	if e != nil {
		return nil, e
	}
	if ref == nil {
		return nil, errors.New("NETWORK_NATIVE_BILLING_REQUIRED")
	}
	seen := map[string]bool{}
	for _, r := range records {
		raw := storageObject(r["x_ProviderFields"])
		if r["SubAccountId"] == account && r["RegionId"] == region && networkChargeKind(raw) != "" {
			if sku := databaseRawString(raw, "product_sku"); sku != "" {
				seen[sku] = true
			}
		}
	}
	if len(seen) > 32 {
		return nil, errors.New("NETWORK_SKU_BOUND_EXCEEDED")
	}
	out := []string{}
	for sku := range seen {
		out = append(out, sku)
	}
	sort.Strings(out)
	return out, nil
}
func networkFlatDimension(raw model.Document, dimensions []model.Document, at time.Time) bool {
	for _, key := range []string{"product_sku", "pricing_rate_code", "pricing_unit", "product_servicecode", "product_region_code", "line_item_usage_type"} {
		if databaseRawString(raw, key) == "" {
			return false
		}
	}
	matches := 0
	for _, d := range dimensions {
		attrs := storageObject(d["attributes"])
		effective, e := time.Parse(time.RFC3339Nano, model.String(d, "effective_date"))
		if e != nil {
			effective, e = time.Parse("2006-01-02T15:04:05Z", model.String(d, "effective_date"))
		}
		if d["sku"] == databaseRawString(raw, "product_sku") && d["rate_code"] == databaseRawString(raw, "pricing_rate_code") && d["unit"] == databaseRawString(raw, "pricing_unit") && d["service_code"] == databaseRawString(raw, "product_servicecode") && d["term_type"] == "OnDemand" && databaseRawString(raw, "pricing_term") == "OnDemand" && model.String(d, "begin_range") == "0" && model.String(d, "end_range") == "Inf" && len(model.Strings(d, "applies_to")) == 0 && e == nil && !effective.After(at) && model.String(attrs, "regionCode") == databaseRawString(raw, "product_region_code") && model.String(attrs, "usagetype") == databaseRawString(raw, "line_item_usage_type") && model.String(attrs, "operation") == databaseRawString(raw, "line_item_operation") {
			matches++
		}
	}
	return matches == 1
}
func (a *API) networkFinancial(ctx context.Context, t *store.Tx, r, canonical model.Document) (model.Document, []model.Document, []model.Document, []string, error) {
	start, end := networkWindow(canonical, a.now())
	bill := model.Document{"currency": nil, "basis": "AWS_CUR_NET_USAGE", "complete": true, "scope_complete": true, "marginal_pricing_known": true, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "source_ref": nil, "components": []model.Document{}}
	rates := []model.Document{}
	refs := []model.Document{}
	reasons := []string{}
	all := []model.Document{}
	dimensions := storageRows(canonical["price_dimensions"])
	type group struct {
		category, unit   string
		amount, quantity *big.Rat
		ids              []string
		native           bool
	}
	groups := map[string]*group{}
	currency := ""
	rateSeen := map[string]string{}
	rateBad := map[string]bool{}
	candidateRows := []model.Document{}
	for month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(end); month = month.AddDate(0, 1, 0) {
		ref, records, e := networkCurrentMonth(ctx, t, model.String(r, "account_id"), month)
		if e != nil {
			return nil, nil, nil, nil, e
		}
		if ref == nil {
			bill["complete"], bill["scope_complete"] = false, false
			continue
		}
		left, right := start, end
		if left.Before(month) {
			left = month
		}
		if next := month.AddDate(0, 1, 0); right.After(next) {
			right = next
		}
		if !objectStorageBillingPeriodComplete(ref, left, right) {
			bill["complete"] = false
		}
		ref = model.Clone(ref)
		ref["economic_record_ids"] = []string{}
		ref["record_ids"] = []string{}
		ids := []string{}
		candidateIDs := []string{}
		for _, row := range records {
			raw := storageObject(row["x_ProviderFields"])
			if row["SubAccountId"] != r["account_id"] || row["RegionId"] != r["region"] || databaseRawString(raw, "line_item_usage_account_id") != model.String(r, "account_id") || databaseRawString(raw, "product_region_code") != model.String(r, "region") || !objectStorageRecordInPeriod(row, start, end) {
				continue
			}
			category := networkChargeKind(raw)
			if category == "" {
				continue
			}
			owned := model.String(row, "ResourceId") == model.String(r, "provider_resource_id") && databaseRawString(raw, "line_item_resource_id") == model.String(r, "provider_resource_id")
			if !owned {
				if category == "ENDPOINT_HOURLY" || category == "ENDPOINT_PROCESSING" {
					candidateRows = append(candidateRows, model.Document{"record": row, "reference": ref})
					candidateIDs = append(candidateIDs, model.String(row, "x_SourceRecordId"))
				}
				continue
			}
			cur := model.String(row, "BillingCurrency")
			if !databaseCoverageCurrency.MatchString(cur) || cur != databaseRawString(raw, "line_item_currency_code") {
				bill["complete"] = false
				continue
			}
			if currency != "" && currency != cur {
				bill["complete"] = false
				reasons = append(reasons, "NETWORK_SOURCE_CURRENCIES_REQUIRE_SEPARATE_ASSESSMENT")
				continue
			}
			currency = cur
			amount, ok := databaseDecimal(model.String(row, "BilledCost"))
			if !ok {
				bill["complete"] = false
				continue
			}
			quantity, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
			if !qok {
				quantity = new(big.Rat)
				bill["marginal_pricing_known"] = false
			}
			unit := databaseRawString(raw, "pricing_unit")
			if unit == "" {
				unit = "Unknown"
			}
			if amount.Sign() < 0 {
				category = "CREDIT"
			}
			key := category + ":" + unit
			g := groups[key]
			if g == nil {
				g = &group{category: category, unit: unit, amount: new(big.Rat), quantity: new(big.Rat), ids: []string{}, native: true}
				groups[key] = g
			}
			g.amount.Add(g.amount, amount)
			g.quantity.Add(g.quantity, quantity)
			id := model.String(row, "x_SourceRecordId")
			g.ids = append(g.ids, id)
			ids = append(ids, id)
			all = append(all, row)
			net, nok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
			rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
			valid := nok && rok && qok && quantity.Sign() > 0 && rate.Sign() >= 0 && net.Cmp(amount) == 0 && databaseInputMoney(new(big.Rat).Mul(rate, quantity)) == databaseInputMoney(net) && databaseRawString(raw, "line_item_line_item_type") == "Usage" && networkFlatDimension(raw, dimensions, start)
			if !valid {
				g.native = false
				bill["marginal_pricing_known"] = false
			}
			signature := databaseRawString(raw, "pricing_rate_code") + ":" + databaseRawString(raw, "product_sku") + ":" + databaseRawString(raw, "line_item_net_unblended_rate")
			if prior := rateSeen[key]; prior != "" && prior != signature {
				rateBad[key] = true
			}
			rateSeen[key] = signature
		}
		ref["economic_record_ids"], ref["record_ids"] = ids, append(append([]string{}, ids...), candidateIDs...)
		refs = append(refs, ref)
	}
	if currency == "" || len(groups) == 0 {
		bill["complete"], bill["scope_complete"] = false, false
		reasons = append(reasons, "NETWORK_NATIVE_BILLING_UNAVAILABLE")
	}
	bill["currency"] = currency
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	components := []model.Document{}
	for _, key := range keys {
		g := groups[key]
		sort.Strings(g.ids)
		id := evidence.Hash(model.Document{"records": g.ids, "kind": g.category, "account": r["account_id"], "region": r["region"], "window_start": start, "window_end": end})
		c := model.Document{"id": id, "category": g.category, "amount": databaseInputMoney(g.amount), "quantity": databaseInputMoney(g.quantity), "unit": g.unit, "source_ref": storageRef("CANONICAL_NETWORK_CHARGE_GROUP", id, "1", evidence.Hash(model.Document{"ids": g.ids, "amount": databaseInputMoney(g.amount), "quantity": databaseInputMoney(g.quantity), "references": refs}))}
		// No global GB convention is guessed. A fully observed independent NAT
		// counter pair may resolve its own native billed unit by exact equality.
		if g.category == "NAT_PROCESSING" && g.unit == "GB" {
			if unitBytes := networkProcessingUnitBytes(canonical, g.quantity); unitBytes != "" {
				c["bytes_per_unit"] = unitBytes
			} else {
				bill["marginal_pricing_known"] = false
			}
		}
		if !g.native || rateBad[key] {
			bill["marginal_pricing_known"] = false
		}
		components = append(components, c)
	}
	if len(components) > 256 {
		reasons = append(reasons, "NETWORK_BILLING_COMPONENT_BOUND")
		components = []model.Document{}
		bill["complete"] = false
	}
	bill["components"] = components
	if len(refs) > 0 {
		bill["source_ref"] = storageRef("AUTHENTICATED_NETWORK_BILLING", model.String(r, "id"), "1", evidence.Hash(refs))
	}
	_ = all
	rates = networkCandidateRates(candidateRows, canonical, r, currency, start)
	return bill, rates, refs, databaseSortedReasons(reasons), nil
}
func networkCandidateRates(rows []model.Document, canonical, r model.Document, currency string, at time.Time) []model.Document {
	dimensions := storageRows(canonical["price_dimensions"])
	byResource := map[string]model.Document{}
	for _, item := range storageRows(storageObject(canonical["topology"])["resources"]) {
		if model.String(item, "resource_type") == "VPC_ENDPOINT" {
			byResource[model.String(item, "provider_resource_id")] = item
		}
	}
	seen := map[string]model.Document{}
	conflicts := map[string]bool{}
	for _, item := range rows {
		row := storageObject(item["record"])
		raw := storageObject(row["x_ProviderFields"])
		endpoint := byResource[model.String(row, "ResourceId")]
		ref := storageObject(item["reference"])
		if !networkCandidateScope(row, raw, endpoint, ref, r, currency) || databaseRawString(raw, "line_item_line_item_type") != "Usage" || !networkFlatDimension(raw, dimensions, at) {
			continue
		}
		rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
		qty, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		cost, cok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		billed, bok := databaseDecimal(model.String(row, "BilledCost"))
		if !rok || !qok || !cok || !bok || qty.Sign() <= 0 || rate.Sign() < 0 || cost.Cmp(billed) != 0 || databaseInputMoney(new(big.Rat).Mul(qty, rate)) != databaseInputMoney(cost) {
			continue
		}
		category := networkChargeKind(raw)
		if category != "ENDPOINT_HOURLY" && category != "ENDPOINT_PROCESSING" {
			continue
		}
		unit := databaseRawString(raw, "pricing_unit")
		if category == "ENDPOINT_HOURLY" && (unit == "Hrs" || unit == "Hours") {
			unit = "Hour"
		}
		if category == "ENDPOINT_HOURLY" && unit != "Hour" || category == "ENDPOINT_PROCESSING" && unit != "GiB" && unit != "Byte" && unit != "GB" {
			continue
		}
		key := category + ":" + model.String(endpoint, "service_name")
		candidate := model.Document{"id": evidence.Hash(model.Document{"key": key, "source": ref["source_version"]}), "component": category, "rate": databaseInputMoney(rate), "unit": unit, "currency": currency, "payer_account_id": row["BillingAccountId"], "usage_account_id": r["account_id"], "region": r["region"], "service": endpoint["service_name"], "pricing_bracket": databaseRawString(raw, "pricing_rate_code") + ":0:Inf", "pricing_bracket_resolved": true, "marginal_pricing_known": true, "source_ref": storageRef("NATIVE_CUSTOMER_NETWORK_RATE", model.String(row, "x_SourceRecordId"), model.String(ref, "source_version"), evidence.Hash(model.Document{"record": row, "reference": ref, "dimensions": dimensions}))}
		candidate["service"] = strings.TrimPrefix(model.String(endpoint, "service_name"), "com.amazonaws."+model.String(r, "region")+".")
		if unit == "GB" {
			candidate["marginal_pricing_known"] = false
		}
		if prior := seen[key]; prior != nil && (prior["rate"] != candidate["rate"] || prior["unit"] != unit || prior["pricing_bracket"] != candidate["pricing_bracket"]) {
			conflicts[key] = true
		}
		seen[key] = candidate
	}
	keys := []string{}
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []model.Document{}
	for _, key := range keys {
		if !conflicts[key] {
			out = append(out, seen[key])
		}
	}
	return out
}

func networkCandidateScope(row, raw, endpoint, ref, r model.Document, currency string) bool {
	account, region := model.String(r, "account_id"), model.String(r, "region")
	payer := model.String(ref, "payer_account_id")
	servicePrefix := "com.amazonaws." + region + "."
	return endpoint != nil && model.String(endpoint, "resource_type") == "VPC_ENDPOINT" && endpoint["account_id"] == account && endpoint["region"] == region &&
		model.String(endpoint, "endpoint_type") == "Interface" && strings.HasPrefix(model.String(endpoint, "service_name"), servicePrefix) && len(model.String(endpoint, "service_name")) > len(servicePrefix) &&
		model.String(row, "ResourceId") != "" && model.String(endpoint, "provider_resource_id") == model.String(row, "ResourceId") && databaseRawString(raw, "line_item_resource_id") == model.String(row, "ResourceId") &&
		row["SubAccountId"] == account && row["RegionId"] == region && databaseRawString(raw, "line_item_usage_account_id") == account && databaseRawString(raw, "product_region_code") == region &&
		len(payer) == 12 && model.String(row, "BillingAccountId") == payer && databaseRawString(raw, "bill_payer_account_id") == payer && model.String(row, "BillingCurrency") == currency && databaseRawString(raw, "line_item_currency_code") == currency &&
		model.String(row, "x_SourceRecordId") != "" && model.String(ref, "kind") == "AWS_CUR2_CONNECTION" && model.String(ref, "source_version") != "" && model.String(ref, "source_connection_id") != "" && model.String(ref, "source_receipt_id") != ""
}

// A unit may be resolved only by a complete, independently observed input
// counter pair. Coincidental equality to a partial series is not a unit proof.
func networkProcessingUnitBytes(canonical model.Document, quantity *big.Rat) string {
	metrics := storageObject(canonical["metrics"])
	if quantity == nil || quantity.Sign() <= 0 || !networkProjectionComplete(metrics, "BytesInFromSource", "Sum") || !networkProjectionComplete(metrics, "BytesInFromDestination", "Sum") {
		return ""
	}
	totals := storageObject(metrics["totals"])
	incoming, ok := databaseDecimal(model.String(totals, "BytesInFromSource"))
	replies, other := databaseDecimal(model.String(totals, "BytesInFromDestination"))
	if !ok || !other || incoming.Sign() < 0 || replies.Sign() < 0 {
		return ""
	}
	factor := new(big.Rat).Quo(new(big.Rat).Add(incoming, replies), quantity)
	if factor.Cmp(big.NewRat(1073741824, 1)) == 0 || factor.Cmp(big.NewRat(1000000000, 1)) == 0 {
		return factor.Num().String()
	}
	return ""
}
func (a *API) networkInput(ctx context.Context, t *store.Tx, r, canonical, policy model.Document) (model.Document, []model.Document, []string, error) {
	bill, rates, refs, reasons, e := a.networkFinancial(ctx, t, r, canonical)
	if e != nil {
		return nil, nil, nil, e
	}
	input, projectionReasons := networkProjectInput(r, canonical, policy, storageBinding(t.Tenant, r), bill, rates, a.now())
	reasons = append(reasons, projectionReasons...)
	return input, refs, databaseSortedReasons(reasons), nil
}
