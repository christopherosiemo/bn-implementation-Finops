package evidence

import (
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"strings"
	"time"
)

func isCompute(row model.Document) bool {
	raw := Object(row["x_ProviderFields"])
	family := strings.ReplaceAll(strings.ToLower(model.String(raw, "product_product_family")), " ", "")
	usage := model.String(raw, "line_item_usage_type")
	operation := model.String(raw, "line_item_operation")
	return model.String(row, "ServiceName") == "AmazonEC2" && (family == "computeinstance" || strings.Contains(usage, "BoxUsage:") || strings.HasPrefix(operation, "RunInstances"))
}
func retained(row model.Document) bool {
	raw := Object(row["x_ProviderFields"])
	usage := strings.ToLower(model.String(raw, "line_item_usage_type"))
	family := strings.ToLower(model.String(raw, "product_product_family"))
	return strings.Contains(usage, "ebs") || strings.Contains(family, "volume") || strings.Contains(family, "storage") || strings.Contains(family, "ip") || strings.Contains(usage, "ipv4") || strings.Contains(usage, "elasticip")
}
func chargeKey(row model.Document) string {
	raw := Object(row["x_ProviderFields"])
	return model.String(row, "ServiceName") + ":" + model.String(row, "ResourceId") + ":" + model.String(raw, "line_item_usage_type") + ":" + model.String(raw, "product_product_family") + ":" + model.String(raw, "line_item_operation")
}
func rate(row model.Document) (*big.Rat, error) {
	cost, ok := new(big.Rat).SetString(model.String(row, "EffectiveCost"))
	s, e1 := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
	e, e2 := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
	if !ok || e1 != nil || e2 != nil || !s.Before(e) {
		return nil, errors.New("UNKNOWN_INCREMENTAL_COST")
	}
	return cost.Quo(cost, new(big.Rat).SetInt64(int64(e.Sub(s)/time.Second))), nil
}

// IncrementalReferences derives extra-charge attribution from persisted native
// records. An unclassified non-compute charge cannot silently disappear from the
// saving. Continuing retained storage/IP is excluded from avoided compute only
// when its observed rate has not increased from the frozen baseline.
func IncrementalReferences(base, post, owned []model.Document) ([]string, error) {
	owners := map[string]bool{}
	for _, o := range owned {
		owners[model.String(o, "execution_id")] = true
	}
	baselineRates := map[string]*big.Rat{}
	for _, r := range base {
		if isCompute(r) || !retained(r) {
			continue
		}
		value, e := rate(r)
		if e != nil {
			return nil, e
		}
		key := chargeKey(r)
		if prior, ok := baselineRates[key]; !ok || prior.Cmp(value) < 0 {
			baselineRates[key] = value
		}
	}
	ids := []string{}
	for _, r := range post {
		if isCompute(r) {
			continue
		}
		cost, ok := new(big.Rat).SetString(model.String(r, "EffectiveCost"))
		if !ok {
			return nil, errors.New("UNKNOWN_INCREMENTAL_COST")
		}
		if cost.Sign() == 0 {
			continue
		}
		raw := Object(r["x_ProviderFields"])
		execution := model.String(raw, "finops_incremental_execution_id")
		if execution != "" {
			if !owners[execution] || retained(r) {
				return nil, errors.New("INCREMENTAL_ATTRIBUTION_INVALID")
			}
			ids = append(ids, model.String(r, "x_SourceRecordId"))
			continue
		}
		if retained(r) {
			value, e := rate(r)
			if e != nil {
				return nil, e
			}
			if before, ok := baselineRates[chargeKey(r)]; ok && value.Cmp(before) <= 0 {
				continue
			}
		}
		return nil, errors.New("UNKNOWN_INCREMENTAL_COST")
	}
	return ids, nil
}
