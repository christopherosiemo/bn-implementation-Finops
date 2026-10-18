package fleetbilling

import (
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

var decimalPattern = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?$`)
var reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,119}$`)

func decimal(s string) (*big.Rat, error) {
	if len(s) == 0 || len(s) > 128 || !decimalPattern.MatchString(s) {
		return nil, errors.New("PRICE_NATIVE_DECIMAL_REQUIRED")
	}
	n, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("PRICE_NATIVE_DECIMAL_REQUIRED")
	}
	return n, nil
}

// exactText never rounds a provider value or an inferred rational rate. A
// non-terminating account rate is unavailable, rather than quietly projected.
func exactText(n *big.Rat) (string, error) {
	d := new(big.Int).Set(n.Denom())
	two, five := big.NewInt(2), big.NewInt(5)
	a, b := 0, 0
	for new(big.Int).Mod(d, two).Sign() == 0 {
		d.Div(d, two)
		a++
	}
	for new(big.Int).Mod(d, five).Sign() == 0 {
		d.Div(d, five)
		b++
	}
	scale := max(a, b)
	if d.Cmp(big.NewInt(1)) != 0 || scale > 36 {
		return "", errors.New("PRICE_EXACT_DECIMAL_UNAVAILABLE")
	}
	s := n.FloatString(scale)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s, nil
}
func rawString(d model.Document, key string) string {
	if s := model.String(d, key); s != "" {
		return s
	}
	if strings.HasPrefix(key, "product_") {
		return model.String(object(d["product"]), strings.TrimPrefix(key, "product_"))
	}
	return ""
}

type pricedRow struct {
	id, instance      string
	start, end        time.Time
	dims              Dimensions
	cost, hours, rate *big.Rat
}

func dimensions(raw model.Document) (Dimensions, error) {
	d := Dimensions{AccountID: rawString(raw, "line_item_usage_account_id"), Region: rawString(raw, "product_region_code"), Currency: rawString(raw, "line_item_currency_code"), InstanceType: rawString(raw, "product_instance_type"), OperatingSystem: rawString(raw, "product_operating_system"), Tenancy: rawString(raw, "product_tenancy"), LicenseModel: rawString(raw, "product_license_model"), PreinstalledSoftware: rawString(raw, "product_pre_installed_sw"), SKU: rawString(raw, "product_sku"), Operation: rawString(raw, "line_item_operation"), UsageType: rawString(raw, "line_item_usage_type"), Unit: rawString(raw, "pricing_unit")}
	if rawString(raw, "product_servicecode") != "AmazonEC2" || rawString(raw, "product_product_family") != "Compute Instance" || rawString(raw, "line_item_line_item_type") != "Usage" || rawString(raw, "pricing_term") != "OnDemand" || d.OperatingSystem != "Linux" || d.Tenancy != "Shared" || d.LicenseModel != "No License required" || d.PreinstalledSoftware != "NA" || d.Operation != "RunInstances" || d.Unit != "Hrs" || d.InstanceType == "" || d.SKU == "" || d.UsageType == "" || len(d.Currency) != 3 {
		return d, errors.New("PRICE_NATIVE_DIMENSIONS_UNAVAILABLE")
	}
	return d, nil
}
func parsePriceRow(raw model.Document) (pricedRow, error) {
	d, e := dimensions(raw)
	if e != nil {
		return pricedRow{}, e
	}
	basis, costKey, rateKey := "UNBLENDED", "line_item_unblended_cost", "line_item_unblended_rate"
	// An omitted export column cannot establish the absence of a discount.
	if _, ok := raw["line_item_net_unblended_cost"].(string); !ok {
		return pricedRow{}, errors.New("PRICE_NATIVE_NET_COLUMNS_UNOBSERVED")
	}
	if _, ok := raw["line_item_net_unblended_rate"].(string); !ok {
		return pricedRow{}, errors.New("PRICE_NATIVE_NET_COLUMNS_UNOBSERVED")
	}
	nc, nr := rawString(raw, "line_item_net_unblended_cost"), rawString(raw, "line_item_net_unblended_rate")
	if (nc == "") != (nr == "") {
		return pricedRow{}, errors.New("PRICE_NATIVE_NET_PAIR_INCOMPLETE")
	}
	if nc != "" {
		basis, costKey, rateKey = "NET_UNBLENDED", "line_item_net_unblended_cost", "line_item_net_unblended_rate"
	}
	if nc == "" && discountPresent(raw, "") {
		return pricedRow{}, errors.New("PRICE_NATIVE_DISCOUNT_ALLOCATION_UNPROVEN")
	}
	d.CostBasis = basis
	cost, e := decimal(rawString(raw, costKey))
	if e != nil {
		return pricedRow{}, e
	}
	rate, e := decimal(rawString(raw, rateKey))
	if e != nil {
		return pricedRow{}, e
	}
	hours, e := decimal(rawString(raw, "line_item_usage_amount"))
	if e != nil {
		return pricedRow{}, e
	}
	if cost.Sign() <= 0 || rate.Sign() <= 0 || hours.Sign() <= 0 {
		return pricedRow{}, errors.New("PRICE_NATIVE_POSITIVE_USAGE_REQUIRED")
	}
	if new(big.Rat).Mul(rate, hours).Cmp(cost) != 0 {
		return pricedRow{}, errors.New("PRICE_NATIVE_RATE_ROUNDING_UNRESOLVED")
	}
	start, end := stamp(raw, "line_item_usage_start_date"), stamp(raw, "line_item_usage_end_date")
	if start.IsZero() || !start.Before(end) {
		return pricedRow{}, errors.New("PRICE_NATIVE_USAGE_PERIOD_INVALID")
	}
	return pricedRow{rawString(raw, "identity_line_item_id"), rawString(raw, "line_item_resource_id"), start, end, d, cost, hours, rate}, nil
}

// economicHash includes the full payer portfolio during the baseline. A
// cross-account/global credit, reservation or discount correction cannot be
// ignored because its resource is outside the target fleet.
func economicHash(records []model.Document, p Period) string {
	selected := []model.Document{}
	for _, raw := range records {
		s, e := stamp(raw, "line_item_usage_start_date"), stamp(raw, "line_item_usage_end_date")
		if s.Before(p.End) && e.After(p.Start) {
			selected = append(selected, raw)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return Hash(selected[i]) < Hash(selected[j]) })
	return Hash(selected)
}
func portfolioSafe(records []model.Document, p Period) error {
	for _, raw := range records {
		s, e := stamp(raw, "line_item_usage_start_date"), stamp(raw, "line_item_usage_end_date")
		if !s.Before(p.End) || !e.After(p.Start) {
			continue
		}
		kind := rawString(raw, "line_item_line_item_type")
		if kind != "Usage" && kind != "Tax" {
			return errors.New("PRICE_PAYER_ECONOMIC_CONFOUNDER")
		}
		if term := rawString(raw, "pricing_term"); term == "Reserved" || term == "SavingsPlan" || nativeCommitment(raw, "") {
			return errors.New("PRICE_PAYER_COMMITMENT_HISTORY")
		}
		if discountPresent(raw, "") && (rawString(raw, "line_item_net_unblended_cost") == "" || rawString(raw, "line_item_net_unblended_rate") == "") {
			return errors.New("PRICE_NATIVE_DISCOUNT_ALLOCATION_UNPROVEN")
		}
		for _, key := range []string{"line_item_unblended_cost", "line_item_net_unblended_cost"} {
			if v := rawString(raw, key); v != "" {
				n, e := decimal(v)
				if e != nil || n.Sign() < 0 {
					return errors.New("PRICE_PAYER_ECONOMIC_CONFOUNDER")
				}
			}
		}
	}
	return nil
}
func discountPresent(d model.Document, prefix string) bool {
	for key, v := range d {
		key = prefix + strings.ToLower(key)
		if nested, ok := v.(map[string]any); ok {
			if discountPresent(nested, key) {
				return true
			}
			continue
		}
		if nested, ok := v.(model.Document); ok {
			if discountPresent(nested, key) {
				return true
			}
			continue
		}
		if strings.Contains(key, "discount") {
			s, ok := v.(string)
			if ok && s == "" {
				continue
			}
			if !ok {
				return true
			}
			n, e := decimal(s)
			if e != nil || n.Sign() != 0 {
				return true
			}
		}
	}
	return false
}
func nativeCommitment(d model.Document, prefix string) bool {
	normalizer := strings.NewReplacer("_", "", "/", "", "-", "")
	for k, v := range d {
		key := prefix + normalizer.Replace(strings.ToLower(k))
		if nested, ok := v.(map[string]any); ok {
			if nativeCommitment(nested, key) {
				return true
			}
			continue
		}
		if nested, ok := v.(model.Document); ok {
			if nativeCommitment(nested, key) {
				return true
			}
			continue
		}
		if strings.Contains(key, "arn") && (strings.Contains(key, "reservation") || strings.Contains(key, "savingsplan")) {
			if s, ok := v.(string); !ok || s != "" {
				return true
			}
		}
	}
	return false
}
func machineMatches(m NativeMachine, t NativeTemplate) bool {
	return m.InstanceType == t.InstanceType && m.ImageID == t.ImageID && m.Tenancy == t.Tenancy && m.Platform == "Linux/UNIX" && m.Operation == "RunInstances"
}
func rowMatches(r pricedRow, m NativeMachine, account, region, currency string) bool {
	return r.instance == m.InstanceID && r.dims.AccountID == account && r.dims.Region == region && r.dims.Currency == currency && r.dims.InstanceType == m.InstanceType && r.dims.Operation == m.Operation
}

func summarizeRates(records []model.Document, machines []NativeMachine, template NativeTemplate, p Period, account, region, currency string, complete bool) (Rate, error) {
	out := Rate{InstanceType: template.InstanceType, RateBasis: RateBasis, MemberCount: len(machines)}
	ids := []string{}
	byID := map[string]NativeMachine{}
	for _, m := range machines {
		if !machineMatches(m, template) || byID[m.InstanceID].InstanceID != "" {
			return out, errors.New("PRICE_NATIVE_MACHINE_TEMPLATE_MISMATCH")
		}
		byID[m.InstanceID] = m
		ids = append(ids, m.InstanceID)
	}
	sort.Strings(ids)
	out.MemberIDsHash = Hash(ids)
	spans := map[string][]Period{}
	cost, hours := new(big.Rat), new(big.Rat)
	var selected *pricedRow
	seen := map[string]bool{}
	latest := time.Time{}
	for _, raw := range records {
		m, ok := byID[rawString(raw, "line_item_resource_id")]
		if !ok {
			continue
		}
		start, end := stamp(raw, "line_item_usage_start_date"), stamp(raw, "line_item_usage_end_date")
		if !start.Before(p.End) || !end.After(p.Start) {
			continue
		}
		r, e := parsePriceRow(raw)
		if e != nil {
			return out, e
		}
		if !rowMatches(r, m, account, region, currency) {
			return out, errors.New("PRICE_NATIVE_SCOPE_OR_CURRENCY_MISMATCH")
		}
		if r.start.Before(p.Start) || r.end.After(p.End) || r.id == "" || seen[r.id] {
			return out, errors.New("PRICE_NATIVE_COVERAGE_AMBIGUOUS")
		}
		seen[r.id] = true
		// One instance-hour unit must correspond to real elapsed usage. Daily/hourly
		// CUR rows are supported; aggregate/blended allocation is not guessed.
		elapsed := new(big.Rat).SetFrac(big.NewInt(r.end.Sub(r.start).Nanoseconds()), big.NewInt(int64(time.Hour)))
		if r.hours.Cmp(elapsed) != 0 {
			return out, errors.New("PRICE_NATIVE_USAGE_COVERAGE_UNPROVEN")
		}
		if selected != nil && (Hash(selected.dims) != Hash(r.dims) || selected.rate.Cmp(r.rate) != 0) {
			return out, errors.New("PRICE_NATIVE_RATE_VARIATION_UNRESOLVED")
		}
		rr := r
		selected = &rr
		cost.Add(cost, r.cost)
		hours.Add(hours, r.hours)
		spans[r.instance] = append(spans[r.instance], Period{r.start, r.end})
		out.SampleCount++
		if r.end.After(latest) {
			latest = r.end
		}
	}
	if selected == nil {
		return out, errors.New("PRICE_CANDIDATE_ACCOUNT_RATE_UNAVAILABLE")
	}
	if complete {
		for _, m := range machines {
			parts := spans[m.InstanceID]
			sort.Slice(parts, func(i, j int) bool { return parts[i].Start.Before(parts[j].Start) })
			cursor := p.Start
			for _, span := range parts {
				if !span.Start.Equal(cursor) {
					return out, errors.New("PRICE_CURRENT_MEMBER_BASELINE_INCOMPLETE")
				}
				cursor = span.End
			}
			if !cursor.Equal(p.End) {
				return out, errors.New("PRICE_CURRENT_MEMBER_BASELINE_INCOMPLETE")
			}
		}
	} else if latest.Before(p.End) {
		return out, errors.New("PRICE_CANDIDATE_LATEST_DAY_UNOBSERVED")
	}
	rateText, e := exactText(selected.rate)
	if e != nil {
		return out, e
	}
	hoursText, e := exactText(hours)
	if e != nil {
		return out, e
	}
	costText, e := exactText(cost)
	if e != nil {
		return out, e
	}
	out.Dimensions = &selected.dims
	out.ObservedHourlyRate = &rateText
	out.UsageHours = &hoursText
	out.ObservedComputeCost = &costText
	out.LatestUsageEnd = &latest
	return out, nil
}

func unavailable(e Evidence, reason string) Evidence {
	if !reasonCodePattern.MatchString(reason) {
		reason = "PRICE_EVIDENCE_UNAVAILABLE"
	}
	e.Status = "UNAVAILABLE"
	e.ID = ""
	e.ReasonCodes = []string{reason, "EXECUTION_AUTHORITY_NOT_GRANTED", "NO_PROVIDER_FUTURE_PRICE_GUARANTEE", "WORKLOAD_ATTRIBUTION_NOT_PROVEN"}
	return e
}
