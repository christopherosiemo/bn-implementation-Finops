package service

// Lambda financial projection selects the existing authenticated current CUR
// revisions. Catalogue metadata proves a dimension, never a customer price.
import (
	"context"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func lambdaChargeKind(raw model.Document) string {
	if databaseRawString(raw, "product_servicecode") != "AWSLambda" {
		return ""
	}
	u := strings.ToLower(databaseRawString(raw, "line_item_usage_type"))
	switch {
	case strings.Contains(u, "provisioned-concurrency"):
		return "PROVISIONED_CAPACITY"
	case strings.Contains(u, "provisioned-gb-second"):
		return "PROVISIONED_COMPUTE"
	case strings.Contains(u, "storage-gb-second"):
		return "EPHEMERAL_STORAGE"
	case strings.Contains(u, "gb-second") && !strings.Contains(u, "durable"):
		return "ON_DEMAND_COMPUTE"
	case strings.Contains(u, "request") && !strings.Contains(u, "durable"):
		return "REQUEST"
	case strings.Contains(u, "streaming"):
		return "STREAMING"
	case strings.Contains(u, "poller") || strings.Contains(u, "epu"):
		return "EVENT_POLLER"
	case strings.Contains(u, "snapstart"):
		return "SNAPSTART"
	default:
		return "UNSUPPORTED"
	}
}
func lambdaCurrentMonth(ctx context.Context, t *store.Tx, account string, month time.Time) (model.Document, []model.Document, error) {
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
		return nil, nil, errors.New("LAMBDA_BILLING_SOURCE_LIMIT")
	}
	var ref model.Document
	var records []model.Document
	for _, id := range ids {
		r, rs, err := (&API{}).databaseBillingMonth(ctx, t, id, month)
		if err != nil {
			if databaseDomainError(err) || errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return nil, nil, err
		}
		if ref != nil {
			return nil, nil, errors.New("LAMBDA_BILLING_SOURCE_AMBIGUOUS")
		}
		ref, records = r, rs
	}
	return ref, records, nil
}
func CurrentLambdaSKUs(ctx context.Context, t *store.Tx, account, region string) ([]string, error) {
	now := time.Now().UTC().Add(-24 * time.Hour)
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	ref, records, e := lambdaCurrentMonth(ctx, t, account, month)
	if e != nil {
		return nil, e
	}
	if ref == nil {
		return nil, errors.New("LAMBDA_NATIVE_BILLING_REQUIRED")
	}
	seen := map[string]bool{}
	for _, r := range records {
		raw := storageObject(r["x_ProviderFields"])
		if r["SubAccountId"] == account && r["RegionId"] == region && lambdaChargeKind(raw) != "" {
			if sku := databaseRawString(raw, "product_sku"); sku != "" {
				seen[sku] = true
			}
		}
	}
	if len(seen) > 64 {
		return nil, errors.New("LAMBDA_SKU_BOUND_EXCEEDED")
	}
	out := []string{}
	for sku := range seen {
		out = append(out, sku)
	}
	sort.Strings(out)
	return out, nil
}
func lambdaNativeUnit(raw model.Document, component string) bool {
	u := databaseRawString(raw, "pricing_unit")
	switch component {
	case "REQUEST":
		return u == "Requests" || u == "Request"
	case "ON_DEMAND_COMPUTE", "PROVISIONED_COMPUTE", "PROVISIONED_CAPACITY", "EPHEMERAL_STORAGE":
		return u == "Lambda-GB-Second" || u == "GB-Second" || u == "GB-s"
	}
	return false
}

// Resolve a single witnessed bracket over the entire complete payer month.
// Multiple native net rates, a free bracket or a crossed tier stays unavailable.
func lambdaDimension(raw model.Document, dimensions []model.Document, at time.Time, total *big.Rat) bool {
	if total == nil || total.Sign() < 0 {
		return false
	}
	matches := 0
	for _, d := range dimensions {
		attrs := storageObject(d["attributes"])
		effective, e := time.Parse(time.RFC3339Nano, model.String(d, "effective_date"))
		begin, bok := databaseDecimal(d["begin_range"])
		endText := model.String(d, "end_range")
		end, eok := databaseDecimal(endText)
		if !bok || (!eok && endText != "Inf") || begin.Sign() < 0 || total.Cmp(begin) < 0 || (eok && total.Cmp(end) >= 0) {
			continue
		}
		if d["sku"] == databaseRawString(raw, "product_sku") && d["rate_code"] == databaseRawString(raw, "pricing_rate_code") && d["unit"] == databaseRawString(raw, "pricing_unit") && d["service_code"] == "AWSLambda" && d["term_type"] == "OnDemand" && databaseRawString(raw, "pricing_term") == "OnDemand" && len(model.Strings(d, "applies_to")) == 0 && e == nil && !effective.After(at) && model.String(attrs, "regionCode") == databaseRawString(raw, "product_region_code") && model.String(attrs, "usagetype") == databaseRawString(raw, "line_item_usage_type") && model.String(attrs, "operation") == databaseRawString(raw, "line_item_operation") {
			matches++
		}
	}
	return matches == 1
}
func lambdaCommitmentClosure(registration, receipt model.Document, now time.Time) bool {
	if model.String(receipt, "kind") != "AWS_COMMITMENT" || receipt["id"] != registration["commitment_receipt_id"] || receipt["source_id"] != registration["id"] || receipt["config_hash"] != source.ConfigurationHash(registration) {
		return false
	}
	scope := storageObject(receipt["commitment_scope"])
	at, e := time.Parse(time.RFC3339Nano, model.String(scope, "observed_at"))
	if e != nil || at.After(now) || now.Sub(at) > 5*time.Minute || scope["complete"] != true || scope["scope"] != "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS" || scope["payer_account_id"] != registration["payer_account_id"] || !databaseSameStrings(model.Strings(scope, "usage_account_ids"), model.Strings(registration, "usage_account_ids")) {
		return false
	}
	// Empty complete inventory establishes no fixed exposure. Nonempty portfolios
	// stay visible but need a separately evidenced marginal allocation model.
	return scope["savings_plan_count"] != nil && model.Number(scope, "savings_plan_count") == 0
}
func lambdaWindow(c model.Document, now time.Time) (time.Time, time.Time) {
	p := storageObject(c["period"])
	if len(p) == 0 {
		p = storageObject(storageObject(c["metrics"])["period"])
	}
	s, se := time.Parse(time.RFC3339Nano, model.String(p, "start"))
	e, ee := time.Parse(time.RFC3339Nano, model.String(p, "end"))
	if se != nil || ee != nil || !e.After(s) || e.Sub(s) > 90*24*time.Hour {
		e = now.UTC().Truncate(24 * time.Hour)
		s = e.Add(-14 * 24 * time.Hour)
	}
	return s, e
}
func lambdaArchitecture(raw model.Document) string {
	u := strings.ToLower(databaseRawString(raw, "line_item_usage_type"))
	if strings.Contains(u, "arm") {
		return "arm64"
	}
	return "x86_64"
}

func lambdaRateBracket(raw model.Document, dimensions []model.Document, total *big.Rat) model.Document {
	if total == nil {
		return nil
	}
	for _, d := range dimensions {
		if d["sku"] == databaseRawString(raw, "product_sku") && d["rate_code"] == databaseRawString(raw, "pricing_rate_code") {
			begin, ok := databaseDecimal(d["begin_range"])
			if !ok {
				return nil
			}
			var upper any
			if model.String(d, "end_range") != "Inf" {
				end, ok := databaseDecimal(d["end_range"])
				if !ok {
					return nil
				}
				upper = databaseInputMoney(end)
			}
			return model.Document{"begin": databaseInputMoney(begin), "end": upper, "aggregate_quantity": databaseInputMoney(total), "resolved": true}
		}
	}
	return nil
}

// Complete native query delivery alone is insufficient: the all-version log
// population must reconcile independently with function-level invocation bins
// AND billed GB-seconds/requests before unqualified CUR can be allocated.
func lambdaBaseAllocationProof(r, c model.Document, records []model.Document, start, end time.Time) bool {
	config := storageObject(c["configuration"])
	base := model.String(config, "base_function_arn")
	version := model.String(config, "version")
	reports := storageObject(c["reports"])
	coverage := storageObject(reports["coverage"])
	if coverage["query_scope"] != "FUNCTION_ALL_VERSIONS" || coverage["status"] != "COMPLETE_OBSERVED" || coverage["cohort_rows_truncated"] == true || reports["truncated"] == true || model.String(coverage, "start") != start.Format(time.RFC3339) || model.String(coverage, "end") != end.Format(time.RFC3339) {
		return false
	}
	count, billed := new(big.Rat), new(big.Rat)
	seen := map[string]bool{}
	for _, row := range storageRows(reports["rows"]) {
		if model.String(row, "version") != version {
			return false
		}
		id := model.String(row, "request_id_hash")
		if id == "" {
			id = model.String(row, "cohort_id")
		}
		if id == "" || seen[id] {
			return false
		}
		seen[id] = true
		timestamp := model.String(row, "event_time")
		if timestamp == "" {
			timestamp = model.String(row, "first_event_time")
		}
		at, e := time.Parse(time.RFC3339Nano, timestamp)
		last := at
		if lastText := model.String(row, "last_event_time"); lastText != "" {
			last, e = time.Parse(time.RFC3339Nano, lastText)
		}
		if e != nil || at.Before(start) || !at.Before(end) || last.Before(at) || !last.Before(end) {
			return false
		}
		n, ok := databaseDecimal(row["count"])
		if row["count"] == nil {
			n, ok = big.NewRat(1, 1), true
		}
		ms, mok := databaseDecimal(row["billed_duration_ms"])
		memory, memok := databaseDecimal(row["memory_size_mb"])
		expected, eok := databaseDecimal(config["memory_size_mb"])
		if !ok || !mok || !memok || !eok || !n.IsInt() || n.Sign() <= 0 || memory.Cmp(expected) != 0 {
			return false
		}
		count.Add(count, n)
		billed.Add(billed, new(big.Rat).Mul(new(big.Rat).Mul(ms, memory), new(big.Rat).Quo(n, big.NewRat(1024000, 1))))
	}
	invocations := new(big.Rat)
	period := int64(0)
	bins := map[int64]bool{}
	for _, row := range storageRows(storageObject(c["function_metrics"])["rows"]) {
		if row["metric"] != "Invocations" || row["statistic"] != "Sum" {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
		p := model.Number(row, "period_seconds")
		v, vok := databaseDecimal(row["value"])
		samples, sok := databaseDecimal(row["sample_count"])
		if e != nil || p <= 0 || 86400%p != 0 || at.Before(start) || !at.Add(time.Duration(p)*time.Second).Before(end.Add(time.Nanosecond)) || (at.Unix()-start.Unix())%p != 0 || bins[at.Unix()] || row["qualified_arn"] != base || row["version"] != "ALL" || !vok || !sok || samples.Sign() <= 0 || period != 0 && period != p {
			return false
		}
		period = p
		bins[at.Unix()] = true
		invocations.Add(invocations, v)
	}
	if period == 0 || int64(len(bins)) != int64(end.Sub(start)/time.Second)/period || count.Cmp(invocations) != 0 {
		return false
	}
	requests, compute := new(big.Rat), new(big.Rat)
	for _, row := range records {
		raw := storageObject(row["x_ProviderFields"])
		if row["ResourceId"] != base || row["SubAccountId"] != r["account_id"] || row["RegionId"] != r["region"] || !objectStorageRecordInPeriod(row, start, end) || databaseRawString(raw, "line_item_line_item_type") != "Usage" {
			continue
		}
		kind := lambdaChargeKind(raw)
		if kind != "REQUEST" && kind != "ON_DEMAND_COMPUTE" && kind != "PROVISIONED_COMPUTE" {
			continue
		}
		q, ok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		if !ok || !lambdaNativeUnit(raw, kind) {
			return false
		}
		if kind == "REQUEST" {
			requests.Add(requests, q)
		} else {
			compute.Add(compute, q)
		}
	}
	return count.Sign() > 0 && requests.Cmp(count) == 0 && compute.Cmp(billed) == 0
}

// lambdaFinancialRecords is pure and bounded. It never accepts policy amounts.
func lambdaFinancialRecords(r, c, ref model.Document, records []model.Document, start, end time.Time) ([]model.Document, []string, bool) {
	config := storageObject(c["configuration"])
	target := model.String(config, "qualified_arn")
	base := model.String(config, "base_function_arn")
	dims := storageRows(c["price_dimensions"])
	reasons := []string{}
	components := []model.Document{}
	currency := ""
	freeResolved := true
	totals := map[string]*big.Rat{}
	signatures := map[string]string{}
	ambiguous := map[string]bool{}
	for _, row := range records {
		raw := storageObject(row["x_ProviderFields"])
		kind := lambdaChargeKind(raw)
		if kind == "" || row["RegionId"] != r["region"] {
			continue
		}
		if row["BillingAccountId"] != ref["payer_account_id"] || databaseRawString(raw, "bill_payer_account_id") != model.String(ref, "payer_account_id") || databaseRawString(raw, "product_region_code") != model.String(r, "region") {
			freeResolved = false
			continue
		}
		typ := databaseRawString(raw, "line_item_line_item_type")
		if typ != "Usage" {
			freeResolved = false
			continue
		}
		q, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
		if !qok || !rok || q.Sign() < 0 || rate.Sign() <= 0 {
			freeResolved = false
			continue
		}
		key := kind + ":" + lambdaArchitecture(raw)
		if totals[key] == nil {
			totals[key] = new(big.Rat)
		}
		totals[key].Add(totals[key], q)
		sig := databaseRawString(raw, "pricing_rate_code") + ":" + databaseRawString(raw, "product_sku") + ":" + databaseInputMoney(rate)
		if old := signatures[key]; old != "" && old != sig {
			ambiguous[key] = true
		}
		signatures[key] = sig
	}
	seen := map[string]bool{}
	baseAllocation := lambdaBaseAllocationProof(r, c, records, start, end)
	for _, row := range records {
		raw := storageObject(row["x_ProviderFields"])
		kind := lambdaChargeKind(raw)
		rid := model.String(row, "ResourceId")
		if kind == "" || row["SubAccountId"] != r["account_id"] || row["RegionId"] != r["region"] || !objectStorageRecordInPeriod(row, start, end) || (rid != target && rid != base) {
			continue
		}
		if rid == base && target != base && !baseAllocation {
			reasons = append(reasons, "LAMBDA_BILLING_SERVING_TARGET_UNRESOLVED")
		}
		id := model.String(row, "x_SourceRecordId")
		if id == "" || seen[id] || databaseRawString(raw, "line_item_usage_account_id") != model.String(r, "account_id") || databaseRawString(raw, "product_region_code") != model.String(r, "region") || databaseRawString(raw, "line_item_resource_id") != rid || row["BillingAccountId"] != ref["payer_account_id"] || databaseRawString(raw, "bill_payer_account_id") != model.String(ref, "payer_account_id") {
			return nil, []string{"LAMBDA_FINANCIAL_RECORD_BINDING_INVALID"}, false
		}
		seen[id] = true
		cur := model.String(row, "BillingCurrency")
		amount, aok := databaseDecimal(row["BilledCost"])
		if !databaseCoverageCurrency.MatchString(cur) || cur != databaseRawString(raw, "line_item_currency_code") || !aok || currency != "" && cur != currency {
			return nil, []string{"LAMBDA_FINANCIAL_CURRENCY_OR_AMOUNT_INVALID"}, false
		}
		currency = cur
		typ := databaseRawString(raw, "line_item_line_item_type")
		q, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
		net, nok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		effective, eok := databaseDecimal(row["EffectiveCost"])
		if amount.Sign() < 0 || typ == "Credit" || typ == "Refund" {
			kind = "CREDIT"
		}
		key := kind + ":" + lambdaArchitecture(raw)
		valid := typ == "Usage" && qok && rok && nok && q.Sign() > 0 && rate.Sign() >= 0 && net.Cmp(amount) == 0 && databaseInputMoney(new(big.Rat).Mul(q, rate)) == databaseInputMoney(amount) && lambdaNativeUnit(raw, kind) && !ambiguous[key] && lambdaDimension(raw, dims, start, totals[key])
		if kind != "CREDIT" && !valid {
			reasons = append(reasons, "LAMBDA_NATIVE_CUSTOMER_RATE_OR_TIER_UNRESOLVED")
		}
		var quantity, rateValue, effectiveValue any
		if qok {
			quantity = databaseInputMoney(q)
		}
		if rok {
			rateValue = databaseInputMoney(rate)
		}
		if eok {
			effectiveValue = databaseInputMoney(effective)
		}
		allocation := "EXACT_NATIVE_RESOURCE_ID"
		if rid == base && target != base {
			allocation = "MODELLED_SINGLE_VERSION_FUNCTION_ALLOCATION"
		}
		components = append(components, model.Document{"id": id, "component": kind, "amount": databaseInputMoney(amount), "effective_amount": effectiveValue, "quantity": quantity, "rate": rateValue, "currency": cur, "unit": databaseRawString(raw, "pricing_unit"), "architecture": lambdaArchitecture(raw), "basis": "AWS_CUR_NATIVE_NET", "marginal_pricing_known": valid, "source_ref": storageRef("AWS_CUR2_LAMBDA_COMPONENT", id, model.String(ref, "source_version"), evidence.Hash(model.Document{"record": row, "reference": ref, "dimensions": dims})), "resource_id": rid, "allocation_basis": allocation, "rate_bracket": lambdaRateBracket(raw, dims, totals[key])})
	}
	if len(components) > 256 {
		return nil, []string{"LAMBDA_FINANCIAL_COMPONENT_BOUND"}, false
	}
	return components, databaseSortedReasons(reasons), freeResolved
}
func (a *API) lambdaFinancial(ctx context.Context, t *store.Tx, r, c model.Document) (model.Document, []model.Document, []string, error) {
	start, end := lambdaWindow(c, a.now())
	bill := model.Document{"currency": nil, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "complete": true, "scope_complete": true, "marginal_pricing_known": true, "commitment_scope_known": true, "free_tier_resolved": true, "components": []model.Document{}}
	refs := []model.Document{}
	all := []model.Document{}
	reasons := []string{}
	for month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(end); month = month.AddDate(0, 1, 0) {
		ref, records, e := lambdaCurrentMonth(ctx, t, model.String(r, "account_id"), month)
		if e != nil {
			return nil, nil, nil, e
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
		registration, e := t.SourceGet(ctx, model.String(ref, "source_connection_id"))
		if e != nil {
			return nil, nil, nil, e
		}
		commit, e := t.SourceReceiptGet(ctx, model.String(registration, "commitment_receipt_id"))
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, nil, nil, e
		}
		if !lambdaCommitmentClosure(registration, commit, a.now()) {
			bill["commitment_scope_known"] = false
		}
		components, rs, free := lambdaFinancialRecords(r, c, ref, records, left, right)
		if len(rs) > 0 {
			bill["marginal_pricing_known"] = false
		}
		if !free {
			bill["free_tier_resolved"] = false
		}
		reasons = append(reasons, rs...)
		ids := []string{}
		for _, part := range components {
			cur := model.String(part, "currency")
			if bill["currency"] != nil && bill["currency"] != cur {
				return nil, nil, nil, errors.New("LAMBDA_CURRENCIES_REQUIRE_SEPARATE_ASSESSMENT")
			}
			bill["currency"] = cur
			ids = append(ids, model.String(part, "id"))
		}
		ref["economic_record_ids"], ref["record_ids"] = ids, ids
		refs = append(refs, ref)
		all = append(all, components...)
	}
	if len(all) == 0 {
		bill["complete"], bill["scope_complete"], bill["marginal_pricing_known"] = false, false, false
		reasons = append(reasons, "LAMBDA_NATIVE_BILLING_UNAVAILABLE")
	}
	bill["components"] = all
	return bill, refs, databaseSortedReasons(reasons), nil
}
