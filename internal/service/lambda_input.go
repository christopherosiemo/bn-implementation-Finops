package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func lambdaDecimalValue(v any) any {
	if v == nil {
		return nil
	}
	n, ok := databaseDecimal(v)
	if !ok {
		return nil
	}
	return databaseInputMoney(n)
}
func lambdaIntegerValue(v any) any {
	if v == nil {
		return nil
	}
	n, ok := databaseDecimal(v)
	if !ok || !n.IsInt() || !n.Num().IsInt64() || n.Sign() < 0 {
		return nil
	}
	return n.Num().Int64()
}
func lambdaReference(d model.Document) model.Document {
	if d == nil {
		return nil
	}
	out := model.Document{}
	for _, key := range []string{"kind", "id", "sha256", "binding"} {
		if v, ok := d[key]; ok {
			out[key] = v
		}
	}
	if d["version"] != nil {
		out["version"] = fmt.Sprint(d["version"])
	}
	return out
}
func lambdaMetricRows(value any) []model.Document {
	out := []model.Document{}
	for _, r := range storageRows(value) {
		d := model.Clone(r)
		d["value"], d["sample_count"] = lambdaDecimalValue(r["value"]), lambdaDecimalValue(r["sample_count"])
		d["period_seconds"] = lambdaIntegerValue(r["period_seconds"])
		out = append(out, d)
	}
	return out
}
func lambdaProjectInput(r, c, policy, binding, billing model.Document, rates []model.Document, performance model.Document, now time.Time) (model.Document, []string) {
	reasons := []string{}
	config := model.Clone(storageObject(c["configuration"]))
	if config == nil {
		config = model.Document{}
	}
	if c["resource_id"] != r["id"] || c["account_id"] != r["account_id"] || c["region"] != r["region"] || model.String(c, "config_hash") != LambdaConfigurationHash(r) {
		reasons = append(reasons, "LAMBDA_NATIVE_SCOPE_OR_CONFIGURATION_CHANGED")
	}
	for _, key := range []string{"memory_size_mb", "timeout_seconds", "ephemeral_storage_mb", "reserved_concurrency"} {
		config[key] = lambdaIntegerValue(config[key])
	}
	metrics := storageObject(c["metrics"])
	reports := model.Clone(storageObject(c["reports"]))
	if reports == nil {
		reports = model.Document{}
	}
	reportRows := []model.Document{}
	for _, raw := range storageRows(reports["rows"]) {
		d := model.Clone(raw)
		for _, key := range []string{"duration_ms", "billed_duration_ms", "memory_size_mb", "max_memory_used_mb", "init_duration_ms", "count"} {
			if v, ok := raw[key]; ok {
				d[key] = lambdaDecimalValue(v)
			}
		}
		reportRows = append(reportRows, d)
	}
	reports["rows"] = reportRows
	// ListProvisionedConcurrencyConfigs is qualified. A missing/denied collection
	// is unknown, whereas an exhausted empty native list proves no configured PC.
	pc := config["provisioned_concurrency"]
	if databaseInputArrayKnown(pc) {
		var total int64
		known := true
		for _, row := range storageRows(pc) {
			arn := model.String(row, "FunctionArn")
			if arn != model.String(config, "qualified_arn") {
				continue
			}
			v := lambdaIntegerValue(row["AllocatedProvisionedConcurrentExecutions"])
			if v == nil || model.String(row, "Status") != "READY" {
				known = false
				break
			}
			total += v.(int64)
		}
		if known {
			config["provisioned_concurrency"] = total
		} else {
			config["provisioned_concurrency"] = nil
		}
	} else if pc != nil {
		config["provisioned_concurrency"] = lambdaIntegerValue(pc)
	}
	p := model.Clone(storageObject(policy["policy"]))
	if p == nil {
		p = model.Document{}
	}
	if model.String(r, "owner") == "" || p["owner"] != r["owner"] {
		reasons = append(reasons, "LAMBDA_RESOURCE_OWNERSHIP_NOT_EVIDENCED")
	}
	if model.String(r, "configuration_authority") == "" || p["configuration_authority"] != r["configuration_authority"] {
		reasons = append(reasons, "LAMBDA_CONFIGURATION_AUTHORITY_NOT_EVIDENCED")
	}
	// A customer cap does not establish native account availability. Both bounds
	// must be known, and the smaller applies. A native reserved limit is separate.
	account := storageObject(config["account_concurrency"])
	limit := storageObject(account["AccountLimit"])
	native, nok := databaseDecimal(limit["UnreservedConcurrentExecutions"])
	if !nok || native.Sign() < 0 {
		config["account_available_concurrency"] = nil
	} else {
		config["account_available_concurrency"] = databaseInputMoney(native)
		config["account_concurrency_semantics"] = "NATIVE_UNRESERVED_QUOTA_NOT_CURRENT_UNOCCUPIED_CAPACITY"
	}
	start, end := lambdaWindow(c, now)
	refs := []model.Document{}
	for _, raw := range storageRows(c["source_refs"]) {
		if ref := lambdaReference(raw); ref != nil {
			refs = append(refs, ref)
		}
	}
	if policy != nil && model.String(policy, "id") != "" {
		refs = append(refs, storageRef("LAMBDA_POLICY", model.String(policy, "id"), strconv.FormatInt(model.Number(policy, "version"), 10), lambdaPolicyHash(policy)))
	}
	points := []model.Document{}
	for _, raw := range storageRows(performance["receipts"]) {
		d := model.Clone(raw)
		d["source_ref"] = lambdaReference(storageObject(d["source_ref"]))
		d["memory_size_mb"] = lambdaIntegerValue(d["memory_size_mb"])
		points = append(points, d)
	}
	provider := storageRows(storageObject(c["provider_recommendations"])["rows"])
	if provider == nil {
		provider = []model.Document{}
	}
	if rates == nil {
		rates = []model.Document{}
	}
	input := model.Document{"schema_version": "1", "model_version": "lambda-v1", "binding": binding, "resource_id": r["id"], "config_hash": c["config_hash"], "as_of": now.UTC().Format(time.RFC3339Nano), "configuration": config, "policy": p, "observation": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "metrics": lambdaMetricRows(metrics["rows"]), "reports": reports}, "performance": model.Document{"receipts": points}, "billing": billing, "rates": rates, "provider_recommendations": provider, "source_refs": refs}
	return input, databaseSortedReasons(reasons)
}
func (a *API) lambdaInput(ctx context.Context, t *store.Tx, r, canonical, policy, performance model.Document) (model.Document, []model.Document, []string, error) {
	bill, refs, reasons, e := a.lambdaFinancial(ctx, t, r, canonical)
	if e != nil {
		return nil, nil, nil, e
	}
	input, rs := lambdaProjectInput(r, canonical, policy, storageBinding(t.Tenant, r), bill, nil, performance, a.now())
	// Financial availability is represented inside the model, so an unpriced
	// architecture/performance review remains visible. Binding corruption is fatal.
	for _, reason := range reasons {
		if reason == "LAMBDA_FINANCIAL_RECORD_BINDING_INVALID" || reason == "LAMBDA_FINANCIAL_CURRENCY_OR_AMOUNT_INVALID" {
			rs = append(rs, reason)
		}
	}
	return input, refs, databaseSortedReasons(rs), nil
}
func lambdaUnavailableEconomics() model.Document {
	return model.Document{"status": "ECONOMICS_UNAVAILABLE", "currency": nil, "observed_billed_cost": nil, "current_effective_cost": nil, "current_request_cost": nil, "current_compute_cost": nil, "current_provisioned_capacity_cost": nil, "continuing_cost": nil, "credits": nil, "pricing_basis": "NATIVE_CUSTOMER_NET_ONLY", "components": []model.Document{}, "current_window_cost": nil, "candidate_window_cost": nil, "estimated_window_saving": nil, "estimated_monthly_saving": nil, "estimated_annual_saving": nil}
}
func lambdaBlocked(binding model.Document, reasons []string) model.Document {
	return model.Document{"schema_version": "1", "model_version": "lambda-v1", "model_kind": "LAMBDA_ASSESSMENT_V1", "binding": binding, "resource_id": binding["resource_id"], "config_hash": "", "configuration": model.Document{}, "status": "BLOCKED", "reason_codes": databaseSortedReasons(reasons), "decision_families": []model.Document{}, "candidates": []model.Document{}, "observations": model.Document{}, "economics": lambdaUnavailableEconomics(), "confidence": model.Document{"status": "UNAVAILABLE", "reasons": databaseSortedReasons(reasons)}, "provider_recommendation": []model.Document{}, "our_recommendation": []model.Document{}, "difference": "NO_PROVIDER_ADVICE", "reason_for_difference": []string{}, "configuration_authority": nil, "implementation_method": "CUSTOMER_CONFIGURATION_REVIEW", "source_refs": []model.Document{}, "proposal": model.Document{"risk_class": "R2", "executable": false, "execution_authorized": false}, "read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}
}
func lambdaBlockForEvidence(result model.Document, reasons []string) {
	result["analysed_components"], result["economically_analysed_source_record_ids"] = []model.Document{}, []string{}
	reasons = databaseSortedReasons(append(model.Strings(result, "reason_codes"), reasons...))
	result["status"], result["reason_codes"] = "BLOCKED", reasons
	econ := storageObject(result["economics"])
	econ["status"] = "ECONOMICS_UNAVAILABLE"
	for _, key := range []string{"current_window_cost", "candidate_window_cost", "estimated_window_saving", "estimated_monthly_saving", "estimated_annual_saving"} {
		econ[key] = nil
	}
	result["economics"] = econ
	result["confidence"] = model.Document{"status": "UNAVAILABLE", "reasons": reasons}
	candidates := storageRows(result["candidates"])
	for _, c := range candidates {
		c["status"], c["decision"], c["reason_codes"] = "BLOCKED", "INSUFFICIENT_EVIDENCE", reasons
		ce := storageObject(c["economics"])
		for _, key := range []string{"current_window_cost", "candidate_window_cost", "estimated_window_saving", "estimated_monthly_saving", "estimated_annual_saving"} {
			ce[key] = nil
		}
		ce["status"] = "ECONOMICS_UNAVAILABLE"
		c["economics"] = ce
		c["confidence"] = model.Document{"status": "UNAVAILABLE", "reasons": reasons}
		c["pre_execution_ready"], c["execution_authorized"], c["verified_saving"] = false, false, nil
	}
	result["candidates"] = candidates
	families := storageRows(result["decision_families"])
	for _, f := range families {
		f["status"], f["decision"], f["reason_codes"] = "BLOCKED", "INSUFFICIENT_EVIDENCE", reasons
	}
	result["decision_families"] = families
}
func validateLambdaResult(result, input model.Document) error {
	p := storageObject(result["proposal"])
	v, ok := result["verified_saving"]
	if result["schema_version"] != "1" || result["model_kind"] != "LAMBDA_ASSESSMENT_V1" || result["model_version"] != "lambda-v1" || result["read_only"] != true || result["resource_id"] != input["resource_id"] || result["config_hash"] != input["config_hash"] || evidence.Hash(result["binding"]) != evidence.Hash(input["binding"]) || p["executable"] != false || p["execution_authorized"] != false || p["risk_class"] != "R2" || !ok || v != nil || result["pre_execution_ready"] != false || result["execution_authorized"] != false {
		return errors.New("LAMBDA_ECONOMICS_RESPONSE_INVALID")
	}
	candidates := storageRows(result["candidates"])
	if len(candidates) > 128 {
		return errors.New("LAMBDA_ECONOMICS_CANDIDATE_BOUND")
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		v, ok := c["verified_saving"]
		id := model.String(c, "id")
		if id == "" || seen[id] || !ok || v != nil || c["pre_execution_ready"] != false || c["execution_authorized"] != false || c["read_only"] != true {
			return errors.New("LAMBDA_ECONOMICS_CANDIDATE_AUTHORITY_INVALID")
		}
		seen[id] = true
		switch c["status"] {
		case "RECOMMENDED", "NO_CHANGE", "BLOCKED", "OBSERVATION_ONLY":
		default:
			return errors.New("LAMBDA_ECONOMICS_CANDIDATE_STATUS_INVALID")
		}
		for _, key := range []string{"current_window_cost", "candidate_window_cost", "estimated_window_saving", "estimated_monthly_saving"} {
			if value := storageObject(c["economics"])[key]; value != nil {
				if s, ok := value.(string); !ok || !databaseCoverageDecimal.MatchString(s) {
					return errors.New("LAMBDA_ECONOMICS_DECIMAL_REQUIRED")
				}
			}
		}
		if storageObject(c["economics"])["estimated_annual_saving"] != nil {
			return errors.New("LAMBDA_ANNUAL_ESTIMATE_UNSUPPORTED")
		}
	}
	switch result["status"] {
	case "RECOMMENDED", "NO_CHANGE", "BLOCKED", "OBSERVATION_ONLY":
		return nil
	}
	return errors.New("LAMBDA_ECONOMICS_STATUS_INVALID")
}
