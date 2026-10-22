package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func CurrentAWSServiceSKUs(ctx context.Context, t *store.Tx, account, region string) ([]string, error) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-90 * 24 * time.Hour)
	seen := map[string]bool{}
	for month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(end); month = month.AddDate(0, 1, 0) {
		ref, records, e := lambdaCurrentMonth(ctx, t, account, month)
		if e != nil {
			return nil, e
		}
		if ref == nil {
			continue
		}
		for _, record := range records {
			raw := storageObject(record["x_ProviderFields"])
			if record["SubAccountId"] == account && record["RegionId"] == region && databaseRawString(raw, "product_servicecode") == "AmazonECS" {
				if sku := databaseRawString(raw, "product_sku"); sku != "" {
					seen[sku] = true
				}
			}
		}
	}
	if len(seen) > 32 {
		return nil, errors.New("AWS_SERVICE_PRICE_SKU_BOUND_EXCEEDED")
	}
	out := []string{}
	for sku := range seen {
		out = append(out, sku)
	}
	sort.Strings(out)
	return out, nil
}

// CUR2 gzip CSV encodes its resource_tags map as JSON. No inferred aliases or
// user resource tags may replace AWS-managed per-charge historical identity.
func awsServiceCURTags(value any) (model.Document, bool) {
	if text, ok := value.(string); ok {
		if len(text) > 65536 {
			return nil, false
		}
		d := json.NewDecoder(bytes.NewBufferString(text))
		token, e := d.Token()
		if e != nil || token != json.Delim('{') {
			return nil, false
		}
		out := model.Document{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return nil, false
			}
			k, ok := key.(string)
			if !ok || out[k] != nil {
				return nil, false
			}
			var v string
			if d.Decode(&v) != nil {
				return nil, false
			}
			out[k] = v
		}
		if _, e = d.Token(); e != nil {
			return nil, false
		}
		if d.Decode(new(any)) != io.EOF {
			return nil, false
		}
		return out, true
	}
	d := storageObject(value)
	if d == nil {
		return nil, false
	}
	for _, v := range d {
		if _, ok := v.(string); !ok {
			return nil, false
		}
	}
	return d, true
}

func fargateCURMatches(resource, configuration, record model.Document, tasks map[string]model.Document) (bool, bool) {
	raw := storageObject(record["x_ProviderFields"])
	id := model.String(record, "ResourceId")
	tags, ok := awsServiceCURTags(raw["resource_tags"])
	cluster := model.String(configuration, "clusterArn")
	clusterName := strings.TrimPrefix(cluster, "arn:aws:ecs:"+model.String(resource, "region")+":"+model.String(resource, "account_id")+":cluster/")
	managed := ok && tags["aws:ecs:clusterName"] == clusterName && tags["aws:ecs:serviceName"] == configuration["serviceName"]
	if tasks[id] == nil && !managed {
		return false, false
	}
	if !managed || tasks[id] == nil || databaseRawString(raw, "product_servicecode") != "AmazonECS" || databaseRawString(raw, "line_item_operation") != "FargateTask" {
		return false, true
	}
	return true, false
}

type fargateBillingInterval struct{ start, end time.Time }
type fargateBillingCoverage map[string][]fargateBillingInterval

func (coverage fargateBillingCoverage) observe(record, configuration model.Document) bool {
	raw := storageObject(record["x_ProviderFields"])
	component := awsServiceChargeComponent(raw)
	if component != "FARGATE_CPU" && component != "FARGATE_MEMORY" {
		return true
	}
	start, e1 := time.Parse(time.RFC3339Nano, model.String(record, "ChargePeriodStart"))
	end, e2 := time.Parse(time.RFC3339Nano, model.String(record, "ChargePeriodEnd"))
	quantity, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
	definition := storageObject(configuration["task_definition"])
	key := "cpu"
	if component == "FARGATE_MEMORY" {
		key = "memory"
	}
	capacity, cok := databaseDecimal(definition[key])
	if e1 != nil || e2 != nil || !end.After(start) || !qok || !cok {
		return false
	}
	expected := new(big.Rat).Mul(capacity, big.NewRat(end.Sub(start).Nanoseconds(), int64(time.Hour)))
	expected.Quo(expected, big.NewRat(1024, 1))
	if quantity.Cmp(expected) != 0 {
		return false
	}
	identity := model.String(record, "ResourceId") + "\x00" + component
	coverage[identity] = append(coverage[identity], fargateBillingInterval{start, end})
	return true
}

func (coverage fargateBillingCoverage) complete(tasks map[string]model.Document, start, end time.Time) bool {
	if len(tasks) == 0 {
		return false
	}
	for task := range tasks {
		for _, component := range []string{"FARGATE_CPU", "FARGATE_MEMORY"} {
			intervals := coverage[task+"\x00"+component]
			sort.Slice(intervals, func(i, j int) bool { return intervals[i].start.Before(intervals[j].start) })
			at := start
			for _, interval := range intervals {
				if !interval.start.Equal(at) || interval.end.After(end) {
					return false
				}
				at = interval.end
			}
			if !at.Equal(end) {
				return false
			}
		}
	}
	return true
}

func fargateCustomerDimensions(raw model.Document, dimensions []model.Document, at time.Time) bool {
	if databaseRawString(raw, "product_cpu_architecture") != "x86" || databaseRawString(raw, "product_operating_system") != "Linux" {
		return false
	}
	for _, dimension := range dimensions {
		if dimension["sku"] != databaseRawString(raw, "product_sku") || dimension["rate_code"] != databaseRawString(raw, "pricing_rate_code") {
			continue
		}
		attrs := storageObject(dimension["attributes"])
		if attrs["cpuArchitecture"] != "x86" || attrs["operatingSystem"] != "Linux" {
			return false
		}
	}
	return networkFlatDimension(raw, dimensions, at)
}

func fargateInputCohort(resource, input model.Document, start, end time.Time) (map[string]model.Document, error) {
	return awsservice.FargateHistoricalCohort(storageBinding("", resource), storageObject(input["configuration"]), start, end)
}
