package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"math/big"
	"sort"
	"strings"
	"time"
)

// No public price catalogue is consulted here. A candidate needs a compatible
// native NET rate witness in the same customer's authenticated export revision.
type storagePricePart struct {
	rate, quantity, amount *big.Rat
	currency, dimensions   string
	ids                    []string
}

func storageChargeKind(raw model.Document) (component, kind, unit string) {
	if databaseRawString(raw, "product_servicecode") != "AmazonEC2" {
		return "", "", ""
	}
	usage := databaseRawString(raw, "line_item_usage_type")
	kind = databaseRawString(raw, "product_volume_api_name")
	for _, t := range []string{"gp2", "gp3", "io1", "io2"} {
		if strings.HasSuffix(usage, "."+t) {
			if kind != "" && kind != t {
				return "", "", ""
			}
			kind = t
		}
	}
	switch {
	case strings.Contains(usage, "EBS:VolumeUsage."):
		component, unit = "storage", "GiB-Mo"
	case strings.Contains(usage, "EBS:VolumeP-IOPS."):
		component, unit = "iops", "IOPS-Mo"
	case strings.Contains(usage, "EBS:VolumeP-Throughput."):
		component, unit = "throughput", "MiBps-Mo"
	case strings.Contains(usage, "SnapshotArchive"):
		component = "archive"
	case strings.Contains(usage, "FastSnapshotRestore"):
		component = "fast_snapshot_restore"
	case strings.Contains(usage, "EBS:SnapshotUsage"):
		component = "snapshots"
	}
	return
}
func storagePriceUnit(raw model.Document, component string) bool {
	unit := databaseRawString(raw, "pricing_unit")
	switch component {
	case "storage":
		return unit == "GB-Mo" || unit == "GiB-Mo"
	case "iops":
		return unit == "IOPS-Mo"
	case "throughput":
		return unit == "MiBps-Mo" || unit == "GiBps-mo"
	}
	return false
}
func storageCurrentRecords(records []model.Document, account, region, id string, start, end time.Time) []model.Document {
	out := []model.Document{}
	for _, r := range records {
		if model.String(r, "SubAccountId") != account || model.String(r, "RegionId") != region || model.String(r, "ResourceId") != id {
			continue
		}
		a, ae := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodStart"))
		b, be := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodEnd"))
		if ae != nil || be != nil || !b.After(a) || a.Before(start) || b.After(end) {
			continue
		}
		out = append(out, r)
	}
	return out
}
func storageNativePrice(records []model.Document, account, region, id, kind string, start, end time.Time, receipt model.Document, capability model.Document, config model.Document) (model.Document, []string, []string) {
	parts := map[string]*storagePricePart{}
	reasons := []string{}
	ids := []string{}
	currency := ""
	seen := map[string]bool{}
	for _, r := range storageCurrentRecords(records, account, region, id, start, end) {
		raw := storageObject(r["x_ProviderFields"])
		component, nativeKind, unit := storageChargeKind(raw)
		if component != "storage" && component != "iops" && component != "throughput" {
			continue
		}
		if nativeKind != kind {
			return nil, nil, []string{"STORAGE_CUR_VOLUME_TYPE_MISMATCH"}
		}
		if databaseRawString(raw, "line_item_line_item_type") != "Usage" {
			continue
		}
		if databaseRawString(raw, "line_item_usage_account_id") != account || databaseRawString(raw, "product_region_code") != region || databaseRawString(raw, "line_item_resource_id") != id || databaseRawString(raw, "pricing_term") != "OnDemand" || !storagePriceUnit(raw, component) {
			reasons = append(reasons, "STORAGE_NATIVE_RATE_DIMENSIONS_UNKNOWN")
			continue
		}
		rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
		q, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		amount, aok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		billed, bok := databaseDecimal(r["BilledCost"])
		rowID := model.String(r, "x_SourceRecordId")
		cur := model.String(r, "BillingCurrency")
		dims := databaseRawString(raw, "pricing_rate_code") + "\x00" + databaseRawString(raw, "line_item_operation") + "\x00" + databaseRawString(raw, "pricing_term") + "\x00" + databaseRawString(raw, "product_sku")
		if !rok || !qok || !aok || !bok || rate.Sign() < 0 || q.Sign() <= 0 || amount.Sign() < 0 || amount.Cmp(billed) != 0 || databaseInputMoney(new(big.Rat).Mul(rate, q)) != databaseInputMoney(amount) || rowID == "" || seen[rowID] || !databaseCoverageCurrency.MatchString(cur) || cur != databaseRawString(raw, "line_item_currency_code") {
			reasons = append(reasons, "STORAGE_NATIVE_NET_RATE_ARITHMETIC_OR_SCOPE_INVALID")
			continue
		}
		if databaseRawString(raw, "pricing_rate_code") == "" || databaseRawString(raw, "line_item_operation") == "" || databaseRawString(raw, "product_sku") == "" {
			reasons = append(reasons, "STORAGE_NATIVE_RATE_CONTRACT_DIMENSIONS_UNKNOWN")
			continue
		}
		if currency != "" && currency != cur {
			reasons = append(reasons, "STORAGE_NATIVE_CURRENCY_AMBIGUOUS")
			continue
		}
		currency = cur
		seen[rowID] = true
		// Native GiB/s-month rates and quantities are converted together. The
		// customer amount remains unchanged; this is never a 1024x cheaper rate.
		if component == "throughput" && databaseRawString(raw, "pricing_unit") == "GiBps-mo" {
			rate = new(big.Rat).Quo(rate, big.NewRat(1024, 1))
			q = new(big.Rat).Mul(q, big.NewRat(1024, 1))
		}
		p := parts[component]
		if p == nil {
			p = &storagePricePart{rate: new(big.Rat).Set(rate), quantity: new(big.Rat), amount: new(big.Rat), currency: cur, dimensions: dims}
			parts[component] = p
		} else if p.rate.Cmp(rate) != 0 || p.currency != cur || p.dimensions != dims {
			reasons = append(reasons, "STORAGE_NATIVE_RATE_TIERS_OR_CORRECTIONS_UNRESOLVED")
			continue
		}
		p.quantity.Add(p.quantity, q)
		p.amount.Add(p.amount, amount)
		p.ids = append(p.ids, rowID)
		ids = append(ids, rowID)
		_ = unit
	}
	if len(reasons) > 0 {
		return nil, ids, databaseSortedReasons(reasons)
	}
	if parts["storage"] == nil {
		return nil, ids, []string{"STORAGE_CUSTOMER_STORAGE_RATE_UNAVAILABLE"}
	}
	components := []model.Document{}
	curRef := storageRef("AWS_CUR2_CANONICAL_RECORDS", model.String(receipt, "source_receipt_id")+":"+id, model.String(receipt, "source_version"), model.String(receipt, "canonical_hash"))
	for _, component := range []string{"storage", "iops", "throughput"} {
		unit := map[string]string{"storage": "GiB-Mo", "iops": "IOPS-Mo", "throughput": "MiBps-Mo"}[component]
		p := parts[component]
		if p != nil {
			components = append(components, model.Document{"component": component, "unit": unit, "basis": "AWS_CUR_NET_USAGE", "rate": databaseInputMoney(p.rate), "quantity": databaseInputMoney(p.quantity), "amount": databaseInputMoney(p.amount), "source_ref": curRef})
			continue
		}
		// Explicit provider-included dimensions are absence proofs, not fabricated
		// zero-cost CUR records. A complete native export is checked by the caller.
		inclusive := kind == "gp2" || component == "throughput" && (kind == "io1" || kind == "io2")
		if kind == "gp3" {
			field, baseline := "iops", "baseline_iops"
			if component == "throughput" {
				field, baseline = "throughput_mib_per_second", "baseline_throughput_mib_per_second"
			}
			v, b := storageNumber(config, field), storageNumber(capability, baseline)
			inclusive = v != nil && b != nil && v.Cmp(b) <= 0
		}
		if !inclusive {
			return nil, ids, []string{"STORAGE_CUSTOMER_PAID_COMPONENT_RATE_UNAVAILABLE_" + strings.ToUpper(component)}
		}
		ref := storageRef("AWS_CUR2_COMPLETE_INCLUDED_COMPONENT_ABSENCE", model.String(receipt, "source_receipt_id")+":"+id+":"+component, model.String(receipt, "source_version"), evidence.Hash(model.Document{"receipt": receipt, "resource_id": id, "component": component, "capability": capability, "period": model.Document{"start": start, "end": end}}))
		components = append(components, model.Document{"component": component, "unit": unit, "basis": "INCLUDED_IN_NATIVE_STORAGE_RATE", "rate": "0", "quantity": "0", "amount": "0", "source_ref": ref})
	}
	return model.Document{"basis": "AWS_CUR_NET_USAGE", "volume_type": kind, "region": region, "account_id": account, "currency": currency, "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "components": components}, ids, nil
}

// Ignore an addon only when the proposed configuration has no billable units
// above its documented included baseline. Actually billed dimensions retain
// the exact native contract/technical identity as well as their NET rate.
func storagePeerPriceSignature(price, candidate, capability model.Document, records []model.Document, account, region, id string, start, end time.Time) (string, bool) {
	required := map[string]bool{"storage": true}
	for _, part := range []struct{ name, field, baseline string }{{"iops", "iops", "baseline_iops"}, {"throughput", "throughput_mib_per_second", "baseline_throughput_mib_per_second"}} {
		value, baseline := storageNumber(candidate, part.field), storageNumber(capability, part.baseline)
		if value == nil || baseline == nil {
			return "", false
		}
		required[part.name] = value.Cmp(baseline) > 0
	}
	components := model.Document{}
	for _, c := range storageRows(price["components"]) {
		name := model.String(c, "component")
		if required[name] {
			components[name] = model.Document{"rate": c["rate"], "unit": c["unit"], "basis": c["basis"]}
		}
	}
	contracts := model.Document{}
	for _, r := range storageCurrentRecords(records, account, region, id, start, end) {
		raw := storageObject(r["x_ProviderFields"])
		name, _, _ := storageChargeKind(raw)
		if !required[name] || databaseRawString(raw, "line_item_line_item_type") != "Usage" {
			continue
		}
		d := model.Document{}
		for _, key := range []string{"product_servicecode", "product_volume_api_name", "pricing_term", "pricing_rate_code", "line_item_operation", "product_sku"} {
			d[key] = databaseRawString(raw, key)
		}
		h := evidence.Hash(d)
		if old := contracts[name]; old != nil && old != h {
			return "", false
		}
		contracts[name] = h
	}
	for name, needed := range required {
		if needed && (components[name] == nil || contracts[name] == nil) {
			return "", false
		}
	}
	return evidence.Hash(model.Document{"currency": price["currency"], "account_id": account, "region": region, "components": components, "contracts": contracts}), true
}

func storageFinancialProjection(resource, canonical, input, receipt model.Document, records []model.Document, start, end time.Time) (model.Document, []string) {
	ref := model.Clone(receipt)
	account, region := model.String(resource, "account_id"), model.String(resource, "region")
	native := storageObject(resource["storage_configuration"])
	inventory := storageObject(canonical["inventory"])
	current := storageObject(input["current_configuration"])
	proof := storageObject(receipt["source_proof"])
	left, le := time.Parse(time.RFC3339Nano, model.String(proof, "period_start"))
	right, re := time.Parse(time.RFC3339Nano, model.String(proof, "period_end"))
	if le != nil || re != nil || left.After(start) || right.Before(end) || model.String(proof, "state") != "COMPLETE" && model.String(proof, "state") != "FINAL" {
		return ref, []string{"STORAGE_COMPLETE_CUSTOMER_BILLING_SCOPE_REQUIRED"}
	}
	economicIDs := []string{}
	reasons := []string{}
	caps := map[string]model.Document{}
	for _, c := range storageRows(storageObject(input["capabilities"])["entries"]) {
		caps[model.String(c, "id")] = c
	}
	currency := ""
	if model.String(resource, "resource_type") == "EBS_VOLUME" {
		price, ids, rs := storageNativePrice(records, account, region, model.String(resource, "provider_resource_id"), model.String(native, "volume_type"), start, end, receipt, caps[model.String(current, "capability_id")], current)
		input["current_pricing"] = price
		economicIDs = append(economicIDs, ids...)
		reasons = append(reasons, rs...)
		currency = model.String(price, "currency")
	}
	// Only actual native customer witnesses qualify. Different tier/rate-code
	// groups or currencies are unresolved; a public list rate is never substituted.
	candidates := storageRows(input["candidate_configurations"])
	for _, candidate := range candidates {
		var selected model.Document
		witnessIDs := []string{}
		selectedSignature := ""
		for _, peer := range storageRows(inventory["volumes"]) {
			if peer["account_id"] != account || peer["region"] != region || model.String(peer, "volume_type") != model.String(candidate, "volume_type") {
				continue
			}
			price, ids, rs := storageNativePrice(records, account, region, model.String(peer, "volume_id"), model.String(candidate, "volume_type"), start, end, receipt, caps[model.String(candidate, "capability_id")], candidate)
			if len(rs) > 0 {
				continue
			}
			signature, known := storagePeerPriceSignature(price, candidate, caps[model.String(candidate, "capability_id")], records, account, region, model.String(peer, "volume_id"), start, end)
			if !known {
				continue
			}
			if selected != nil && selectedSignature != signature {
				selected = nil
				witnessIDs = nil
				break
			}
			selected, selectedSignature = price, signature
			witnessIDs = append(witnessIDs, ids...)
		}
		candidate["pricing"] = selected
		economicIDs = append(economicIDs, witnessIDs...)
	}
	input["candidate_configurations"] = candidates
	associated := map[string]bool{model.String(resource, "provider_resource_id"): true}
	if model.String(resource, "resource_type") == "EBS_VOLUME" {
		if !storageCoverageKnown(inventory, "snapshots") {
			reasons = append(reasons, "STORAGE_ASSOCIATED_SNAPSHOT_SCOPE_UNKNOWN")
		}
		for _, s := range storageRows(inventory["snapshots"]) {
			if s["volume_id"] == native["volume_id"] {
				associated[model.String(s, "snapshot_id")] = true
			}
		}
	}
	totals := map[string]*big.Rat{"snapshots": new(big.Rat), "fast_snapshot_restore": new(big.Rat), "archive": new(big.Rat), "continuing": new(big.Rat)}
	continuingIDs := map[string][]string{}
	continuingUnknown := false
	for _, component := range []string{"snapshots", "fast_snapshot_restores", "snapshot_tiers"} {
		if !storageCoverageKnown(inventory, component) {
			continuingUnknown = true
			reasons = append(reasons, "STORAGE_CONTINUING_NATIVE_INVENTORY_SCOPE_UNKNOWN")
		}
	}
	known := map[string]bool{}
	knownSnapshots := map[string]bool{}
	for _, v := range storageRows(inventory["volumes"]) {
		if v["account_id"] == account && v["region"] == region && model.String(v, "volume_id") != "" {
			known[model.String(v, "volume_id")] = true
		}
	}
	for _, v := range storageRows(inventory["snapshots"]) {
		if v["account_id"] == account && v["region"] == region && model.String(v, "snapshot_id") != "" && (model.String(resource, "resource_type") == "EBS_SNAPSHOT" || model.String(v, "volume_id") != "") {
			known[model.String(v, "snapshot_id")] = true
			knownSnapshots[model.String(v, "snapshot_id")] = true
		}
	}
	for _, r := range records {
		a, ae := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodStart"))
		b, be := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodEnd"))
		if ae != nil || be != nil || a.Before(start) || b.After(end) || !b.After(a) {
			continue
		}
		raw := storageObject(r["x_ProviderFields"])
		component, _, _ := storageChargeKind(raw)
		potentialEBS := component != "" || databaseRawString(raw, "product_servicecode") == "AmazonEC2" && strings.Contains(databaseRawString(raw, "line_item_usage_type"), "EBS:")
		rowAccount, rowRegion, id := model.String(r, "SubAccountId"), model.String(r, "RegionId"), model.String(r, "ResourceId")
		if rowAccount != "" && rowAccount != account || rowRegion != "" && rowRegion != region {
			continue
		}
		snapshotCharge := component == "snapshots" || component == "fast_snapshot_restore" || component == "archive"
		if potentialEBS && (rowAccount == "" || rowRegion == "" || id == "" || !known[id] || snapshotCharge && !knownSnapshots[id]) {
			continuingUnknown = true
			reasons = append(reasons, "STORAGE_CONTINUING_NATIVE_RESOURCE_ATTRIBUTION_UNKNOWN")
			continue
		}
		if rowAccount != account || rowRegion != region || !associated[id] {
			continue
		}
		amount, ok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		billed, bok := databaseDecimal(r["BilledCost"])
		cur := model.String(r, "BillingCurrency")
		if !ok || !bok || amount.Cmp(billed) != 0 || !databaseCoverageCurrency.MatchString(cur) || cur != databaseRawString(raw, "line_item_currency_code") {
			continuingUnknown = true
			reasons = append(reasons, "STORAGE_CONTINUING_NATIVE_COST_UNKNOWN")
			continue
		}
		if currency == "" {
			currency = cur
		}
		if currency != cur {
			continuingUnknown = true
			reasons = append(reasons, "STORAGE_CONTINUING_CURRENCY_MISMATCH")
			continue
		}
		if component == "storage" || component == "iops" || component == "throughput" {
			if amount.Sign() >= 0 && databaseRawString(raw, "line_item_line_item_type") == "Usage" {
				continue
			}
			component = "continuing"
		}
		if totals[component] == nil {
			component = "continuing"
		}
		totals[component].Add(totals[component], amount)
		rid := model.String(r, "x_SourceRecordId")
		if rid == "" {
			continuingUnknown = true
			reasons = append(reasons, "STORAGE_CONTINUING_RECORD_ID_REQUIRED")
			continue
		}
		economicIDs = append(economicIDs, rid)
		continuingIDs[component] = append(continuingIDs[component], rid)
	}
	components := []model.Document{}
	for _, name := range []string{"snapshots", "fast_snapshot_restore", "archive", "continuing"} {
		basis := "AWS_CUR2_EXACT_ASSOCIATED_NATIVE_CHARGES"
		if len(continuingIDs[name]) == 0 {
			basis = "AWS_CUR2_COMPLETE_EXACT_RESOURCE_SCOPE_ABSENCE"
		}
		sourceRef := storageRef(basis, model.String(receipt, "source_receipt_id")+":"+model.String(resource, "provider_resource_id")+":"+name, model.String(receipt, "source_version"), evidence.Hash(model.Document{"receipt": receipt, "component": name, "resources": associated, "record_ids": continuingIDs[name], "period": model.Document{"start": start, "end": end}}))
		components = append(components, model.Document{"component": name, "amount": databaseInputMoney(totals[name]), "source_refs": []model.Document{sourceRef}})
	}
	if currency == "" || continuingUnknown {
		if currency == "" {
			reasons = append(reasons, "STORAGE_CUSTOMER_COST_CURRENCY_UNAVAILABLE")
		}
		input["continuing_costs"] = nil
	} else {
		input["continuing_costs"] = model.Document{"currency": currency, "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "components": components}
	}
	snapshots := storageRows(input["snapshots"])
	for _, snap := range snapshots {
		total := new(big.Rat)
		known := false
		for _, r := range storageCurrentRecords(records, account, region, model.String(snap, "id"), start, end) {
			value, ok := databaseDecimal(r["BilledCost"])
			if !ok || model.String(r, "BillingCurrency") != currency {
				continue
			}
			total.Add(total, value)
			known = true
		}
		if known {
			total.Mul(total, big.NewRat(730*3600, int64(end.Sub(start)/time.Second)))
			snap["monthly_cost"] = databaseInputMoney(total)
			snap["currency"] = currency
			snap["pricing_source_ref"] = storageRef("AWS_CUR2_EXACT_SNAPSHOT_COST", model.String(receipt, "source_receipt_id")+":"+model.String(snap, "id"), model.String(receipt, "source_version"), model.String(receipt, "canonical_hash"))
		}
	}
	input["snapshots"] = snapshots
	unique := map[string]bool{}
	ids := []string{}
	for _, id := range economicIDs {
		if !unique[id] {
			unique[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	ref["economic_record_ids"] = ids
	ref["economic_basis"] = "NATIVE_NET_EBS_COMPONENTS_PLUS_EXACT_ASSOCIATED_CONTINUING_CHARGES"
	ref["absence_proofs"] = components
	if continuingUnknown {
		ref["absence_proofs"] = []model.Document{}
	}
	return ref, databaseSortedReasons(reasons)
}

func (a *API) storageFinancialInput(ctx context.Context, t *store.Tx, resource, canonical, input model.Document, now time.Time) ([]model.Document, []string, error) {
	rows, e := t.Query(ctx, "SELECT id FROM source_registrations WHERE tenant_id=$1 AND kind='AWS_CUR2' AND (document->'usage_account_ids' ? $2) ORDER BY id LIMIT 257", t.Tenant, model.String(resource, "account_id"))
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
	if len(ids) > 256 {
		return nil, []string{"STORAGE_BILLING_SOURCE_LIMIT"}, nil
	}
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.Add(-24 * time.Hour)
	var selected model.Document
	var records []model.Document
	for _, id := range ids {
		reg, e := t.SourceGet(ctx, id)
		if e != nil {
			return nil, nil, e
		}
		if model.String(reg, "status") != "HEALTHY" || !model.Bool(reg, "enabled") {
			continue
		}
		if _, e = source.ParseRegistration(reg); e != nil {
			continue
		}
		month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
		ref, data, e := a.databaseBillingMonth(ctx, t, id, month)
		if e != nil {
			if databaseDomainError(e) || errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			return nil, nil, e
		}
		if selected != nil {
			return nil, []string{"STORAGE_BILLING_SOURCE_AMBIGUOUS"}, nil
		}
		selected, records = ref, data
	}
	if selected == nil {
		return nil, []string{"STORAGE_AUTHENTICATED_CUSTOMER_CUR_REQUIRED"}, nil
	}
	ref, reasons := storageFinancialProjection(resource, canonical, input, selected, records, start, end)
	return []model.Document{ref}, reasons, nil
}
