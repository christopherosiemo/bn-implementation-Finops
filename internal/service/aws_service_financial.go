package service

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func awsServiceChargeComponent(raw model.Document) string {
	service := databaseRawString(raw, "product_servicecode")
	usage := strings.ToLower(databaseRawString(raw, "line_item_usage_type"))
	typ := databaseRawString(raw, "line_item_line_item_type")
	if typ == "Credit" || typ == "Refund" {
		return "CREDIT"
	}
	switch service {
	case "AmazonECS":
		switch {
		case strings.Contains(usage, "fargate") && strings.Contains(usage, "vcpu"):
			return "FARGATE_CPU"
		case strings.Contains(usage, "fargate") && strings.Contains(usage, "ephemeral"):
			return "FARGATE_EPHEMERAL"
		case strings.Contains(usage, "fargate") && strings.Contains(usage, "gb-hour"):
			return "FARGATE_MEMORY"
		}
	case "AmazonDynamoDB":
		switch {
		case strings.Contains(usage, "replicated"):
			return "CONTINUING"
		case strings.Contains(usage, "readcapacityunit"):
			return "READ_PROVISIONED"
		case strings.Contains(usage, "writecapacityunit"):
			return "WRITE_PROVISIONED"
		case strings.Contains(usage, "readrequestunit"):
			return "READ_REQUEST"
		case strings.Contains(usage, "writerequestunit"):
			return "WRITE_REQUEST"
		}
	case "AmazonElastiCache":
		if !strings.Contains(usage, "serverless") && (strings.Contains(usage, "nodeusage") || strings.Contains(usage, "cacheusage")) {
			return "CACHE_NODE"
		}
	case "AWSELB", "ElasticLoadBalancing":
		return "CONTINUING"
	}
	return "CONTINUING"
}

func awsServiceChargeUnit(component, unit string) bool {
	switch component {
	case "FARGATE_CPU":
		return unit == "vCPU-Hours" || unit == "vCPU-Hrs" || unit == "vCPU-hours"
	case "FARGATE_MEMORY", "FARGATE_EPHEMERAL":
		return unit == "GB-Hours" || unit == "GB-Hrs" || unit == "GB-hours"
	case "READ_PROVISIONED", "WRITE_PROVISIONED", "CACHE_NODE":
		return unit == "Hrs" || unit == "Hours"
	case "READ_REQUEST", "WRITE_REQUEST":
		return unit == "ReadRequestUnits" || unit == "WriteRequestUnits" || unit == "Requests"
	}
	return false
}

// Customer economics is resolved only from authenticated current CUR revisions.
// Native catalogues identify contractual dimensions/brackets, never customer
// prices. Exact amounts, source records, payer and member bindings are retained.
func (a *API) awsServiceFinancialInput(ctx context.Context, t *store.Tx, resource, snapshot, canonical, input model.Document) ([]model.Document, []string, error) {
	_ = snapshot
	period := storageObject(input["period"])
	if len(period) == 0 {
		period = storageObject(canonical["period"])
	}
	start, se := time.Parse(time.RFC3339Nano, model.String(period, "start"))
	end, ee := time.Parse(time.RFC3339Nano, model.String(period, "end"))
	if se != nil || ee != nil || !end.After(start) || end.Sub(start) > 90*24*time.Hour {
		end = a.now().UTC().Truncate(24 * time.Hour)
		start = end.Add(-14 * 24 * time.Hour)
	}
	bill := model.Document{"currency": nil, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "complete": true, "scope_complete": true, "marginal_pricing_known": true, "commitment_scope_known": true, "components": []model.Document{}, "rate_witnesses": []model.Document{}}
	refs, reasons := []model.Document{}, []string{}
	parts, witnesses := []model.Document{}, []model.Document{}
	seen := map[string]bool{}
	dimensions := storageRows(canonical["price_dimensions"])
	fargate := resource["resource_type"] == "ECS_SERVICE"
	cohort := map[string]model.Document{}
	coverage := fargateBillingCoverage{}
	configuration := storageObject(input["configuration"])
	if fargate {
		var e error
		cohort, e = fargateInputCohort(resource, input, start, end)
		if e != nil {
			bill["scope_complete"], bill["marginal_pricing_known"] = false, false
			reasons = append(reasons, "ECS_NATIVE_LONG_LIVED_TASK_COHORT_REQUIRED")
		}
		bill["attribution_basis"] = "NATIVE_CUR_MANAGED_TAGS_AND_LONG_LIVED_TASK_COHORT_V1"
		history := storageObject(storageObject(input["observations"])["service_history"])
		if history["schema_version"] == awsservice.ServiceHistoryVersion && len(model.Strings(history, "reason_codes")) == 0 && len(storageRows(history["epochs"])) == 1 {
			bill["historical_service_epoch_id"] = storageRows(history["epochs"])[0]["id"]
			bill["historical_service_evidence_refs"] = history["source_refs"]
		}
	}
	for month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(end); month = month.AddDate(0, 1, 0) {
		ref, records, e := lambdaCurrentMonth(ctx, t, model.String(resource, "account_id"), month)
		if e != nil {
			if strings.HasPrefix(e.Error(), "LAMBDA_BILLING_") {
				reasons = append(reasons, "AWS_SERVICE_BILLING_SCOPE_AMBIGUOUS")
				bill["complete"], bill["scope_complete"] = false, false
				continue
			}
			return nil, nil, e
		}
		if ref == nil {
			bill["complete"], bill["scope_complete"] = false, false
			reasons = append(reasons, "AWS_SERVICE_NATIVE_BILLING_REQUIRED")
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
			bill["complete"], bill["scope_complete"] = false, false
			reasons = append(reasons, "AWS_SERVICE_BILLING_PERIOD_INCOMPLETE")
		}
		registration, e := t.SourceGet(ctx, model.String(ref, "source_connection_id"))
		if e != nil {
			return nil, nil, e
		}
		commitment, e := t.SourceReceiptGet(ctx, model.String(registration, "commitment_receipt_id"))
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, nil, e
		}
		closure := lambdaCommitmentClosure(registration, commitment, a.now())
		// Existing SP closure does not prove absence of cache/DynamoDB reservations.
		if resource["service_family"] == "DYNAMODB" || resource["service_family"] == "ELASTICACHE" {
			closure = false
		}
		if !closure {
			bill["commitment_scope_known"] = false
			reasons = append(reasons, "AWS_SERVICE_COMMITMENT_EXPOSURE_UNRESOLVED")
		}
		ids := []string{}
		for _, record := range records {
			if record["SubAccountId"] != resource["account_id"] || record["RegionId"] != resource["region"] || !objectStorageRecordInPeriod(record, left, right) {
				continue
			}
			if fargate {
				matched, unknown := fargateCURMatches(resource, configuration, record, cohort)
				if unknown {
					bill["scope_complete"], bill["marginal_pricing_known"] = false, false
					reasons = append(reasons, "ECS_HISTORICAL_TASK_BILLING_ATTRIBUTION_UNRESOLVED")
				}
				if !matched {
					continue
				}
				if !coverage.observe(record, configuration) {
					bill["scope_complete"], bill["marginal_pricing_known"] = false, false
					reasons = append(reasons, "ECS_TASK_CONFIGURATION_BILLING_QUANTITY_MISMATCH")
				}
			} else if record["ResourceId"] != resource["provider_resource_id"] {
				continue
			}
			raw := storageObject(record["x_ProviderFields"])
			id := model.String(record, "x_SourceRecordId")
			key := databaseCoverageLineKey(ref, id)
			if id == "" || seen[key] || record["BillingAccountId"] != ref["payer_account_id"] || databaseRawString(raw, "bill_payer_account_id") != model.String(ref, "payer_account_id") || databaseRawString(raw, "line_item_usage_account_id") != model.String(resource, "account_id") || databaseRawString(raw, "product_region_code") != model.String(resource, "region") || databaseRawString(raw, "line_item_resource_id") != model.String(record, "ResourceId") {
				return nil, nil, errors.New("AWS_SERVICE_FINANCIAL_BINDING_INVALID")
			}
			seen[key] = true
			amount, ok := databaseDecimal(record["BilledCost"])
			currency := model.String(record, "BillingCurrency")
			if !ok || !databaseCoverageCurrency.MatchString(currency) || currency != databaseRawString(raw, "line_item_currency_code") {
				return nil, nil, errors.New("AWS_SERVICE_FINANCIAL_AMOUNT_OR_CURRENCY_INVALID")
			}
			if bill["currency"] != nil && bill["currency"] != currency {
				bill["scope_complete"], bill["marginal_pricing_known"] = false, false
				reasons = append(reasons, "AWS_SERVICE_CURRENCIES_REQUIRE_SEPARATE_ANALYSIS")
			} else if bill["currency"] == nil {
				bill["currency"] = currency
			}
			component := awsServiceChargeComponent(raw)
			if amount.Sign() < 0 {
				component = "CREDIT"
			}
			quantity, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
			rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
			net, nok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
			effective, eok := databaseDecimal(record["EffectiveCost"])
			valid := component != "CREDIT" && component != "CONTINUING" && databaseRawString(raw, "line_item_line_item_type") == "Usage" && qok && rok && nok && quantity.Sign() > 0 && rate.Sign() >= 0 && amount.Cmp(net) == 0 && new(big.Rat).Mul(quantity, rate).Cmp(net) == 0 && awsServiceChargeUnit(component, databaseRawString(raw, "pricing_unit")) && networkFlatDimension(raw, dimensions, left)
			if fargate {
				valid = valid && fargateCustomerDimensions(raw, dimensions, left)
			}
			var q, r, eff any
			if qok {
				q = databaseInputMoney(quantity)
			}
			if rok {
				r = databaseInputMoney(rate)
			}
			if eok {
				eff = databaseInputMoney(effective)
			}
			sourceRef := storageRef("AWS_CUR2_SERVICE_COMPONENT", id, model.String(ref, "source_version"), evidence.Hash(model.Document{"record": record, "reference": ref}))
			avoidability := "CONTINUING"
			if component == "CREDIT" {
				avoidability = "CREDIT"
			} else if valid && closure {
				avoidability = "MARGINAL"
			}
			parts = append(parts, model.Document{"id": id, "component": component, "amount": databaseInputMoney(amount), "effective_amount": eff, "quantity": q, "rate": r, "unit": databaseRawString(raw, "pricing_unit"), "currency": currency, "avoidability": avoidability, "source_ref": sourceRef})
			if component != "CREDIT" && component != "CONTINUING" && !valid {
				bill["marginal_pricing_known"] = false
				reasons = append(reasons, "AWS_SERVICE_NATIVE_RATE_OR_BRACKET_UNRESOLVED")
			}
			if valid {
				witnesses = append(witnesses, model.Document{"id": id, "component": component, "rate": r, "unit": databaseRawString(raw, "pricing_unit"), "currency": currency, "dimensions": model.Document{"payer_account_id": ref["payer_account_id"], "account_id": resource["account_id"], "region": resource["region"], "sku": databaseRawString(raw, "product_sku"), "rate_code": databaseRawString(raw, "pricing_rate_code"), "usage_type": databaseRawString(raw, "line_item_usage_type"), "operation": databaseRawString(raw, "line_item_operation"), "architecture": databaseRawString(raw, "product_processor_architecture")}, "bracket_resolved": true, "source_ref": sourceRef})
			}
			ids = append(ids, id)
			if len(parts) > 4096 {
				return nil, nil, errors.New("AWS_SERVICE_FINANCIAL_RECORD_BOUND")
			}
		}
		ref["record_ids"], ref["economic_record_ids"] = ids, ids
		refs = append(refs, ref)
	}
	if len(parts) == 0 {
		bill["complete"], bill["scope_complete"], bill["marginal_pricing_known"] = false, false, false
		reasons = append(reasons, "AWS_SERVICE_EXACT_NATIVE_RESOURCE_BILLING_UNAVAILABLE")
	}
	if fargate && !coverage.complete(cohort, start, end) {
		bill["scope_complete"], bill["marginal_pricing_known"] = false, false
		reasons = append(reasons, "ECS_COMPLETE_TASK_CPU_MEMORY_BILLING_REQUIRED")
	}
	bill["components"], bill["rate_witnesses"] = parts, witnesses
	input["billing"] = bill
	return refs, databaseSortedReasons(reasons), nil
}
