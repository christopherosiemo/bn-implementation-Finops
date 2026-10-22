"""Commitment advice from private, server-resolved portfolio evidence.

This evaluator checks arithmetic and scope consistency. The existing Go worker
authenticates issuers, resolves canonical records and rechecks current authority.
No output authorizes a purchase, execution or verified financial claim.
"""
from collections import defaultdict
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import json
import re

from .portfolio import EvidenceError, HASH, STAGES, analysis_hash, decimal, exact_seconds, need, stamp

POLICY = "DECIMAL80_INTERMEDIATE_HALF_EVEN_12_FINAL"
PRICE_ASSUMPTION = "HELD_CURRENT_NATIVE_NET_RATE"
OFFER_VALIDITY_BASIS = "LOCAL_READ_FRESHNESS_POLICY_NOT_PROVIDER_QUOTE_EXPIRY"
SUPPORTED_CLASSES = {"COMPUTE_SAVINGS_PLAN", "EC2_INSTANCE_SAVINGS_PLAN"}
REFERENCE_KINDS = {
    "AWS_COMMITMENT", "AWS_CUR2", "AWS_SAVINGS_PLAN_RATES",
    "AWS_SAVINGS_PLAN_OFFER", "AWS_SAVINGS_PLAN_OFFER_RATE",
    "COMMITMENT_PORTFOLIO_ANALYSIS", "HISTORICAL_OWNERSHIP",
    "OPTIMIZATION_ASSESSMENT", "OPTIMIZATION_DECISION", "OPTIMIZATION_OUTCOME",
    "POST_OPTIMIZATION_FORECAST", "FORECAST_CALIBRATION",
    "DEPLOYMENT_RECEIPT", "CONFIGURATION_ARTIFACT", "OWNERSHIP_JOURNAL", "OWNERSHIP_REVIEW",
    # Private issuers authenticate these exact immutable stage/history inputs;
    # public uploads cannot create receipts merely by choosing a kind string.
    "COMMITMENT_PREPARATION", "WORKLOAD_SAFETY_PROFILE", "SLO_OBJECTIVE",
    "WORKLOAD_SIZE_CONSTRAINT", "WORKLOAD_CONTROLLER_SCOPE", "FLEET_JOINT_DECISION",
    "AWS_CONTROLLER_DISCOVERY", "HISTORICAL_USAGE", "AWS_CUR2_REVISION", "AWS_CUR2_INGESTION_JOB",
}
DIMENSIONS = ("account_id", "service_code", "product_type", "usage_type", "operation",
              "region", "instance_type", "instance_family", "product_description",
              "tenancy", "unit", "currency")


def keys(value, expected):
    need(isinstance(value, dict) and set(value) == set(expected), "exact decision fields required")


def money(value):
    value = value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN)
    need(abs(value) < Decimal(10) ** 26, "DECIMAL(38,12) overflow")
    if value == 0:
        return "0"
    return format(value, "f").rstrip("0").rstrip(".")


def reference(value):
    keys(value, ("kind", "id", "sha256"))
    need(value["kind"] in REFERENCE_KINDS and isinstance(value["id"], str)
         and 0 < len(value["id"]) <= 128 and isinstance(value["sha256"], str)
         and HASH.fullmatch(value["sha256"]), "invalid decision reference")
    return value["kind"], value["id"], value["sha256"]


def period(value):
    keys(value, ("start", "end"))
    start, end = stamp(value["start"]), stamp(value["end"])
    need(start < end, "positive period required")
    return start, end


def dimensions(value, scope):
    keys(value, DIMENSIONS)
    for name in DIMENSIONS:
        need(value[name] is None and name in {"instance_type", "instance_family", "product_description", "tenancy"}
             or isinstance(value[name], str) and 0 < len(value[name]) <= 2048,
             "native pricing dimensions required")
    need(value["account_id"] in scope["usage_account_ids"] and value["currency"] == scope["currency"],
         "pricing dimensions outside scope")
    return tuple(value[name] for name in DIMENSIONS)


def metric(value, unit, currency, basis, span, refs, reasons=()):
    return {"status": "AVAILABLE" if value is not None else "UNAVAILABLE",
            "value": money(value) if value is not None else None,
            "unit": unit, "currency": currency, "basis": basis, "period": span,
            "reason_codes": sorted(set(reasons)), "input_refs": refs}


def _proofs(data):
    keys(data, ("schema_version", "request_id", "selection", "scope", "portfolio",
                "usage_status", "usage", "contract_rates", "contract_rate_status",
                "contract_rate_plan_ids", "contract_rate_refs", "offer", "payg_basis",
                "optimization_order", "forecast", "input_refs", "observed_at", "reason_codes"))
    need(data["schema_version"] == "2" and isinstance(data["request_id"], str)
         and 0 < len(data["request_id"]) <= 128, "decision binding required")
    keys(data["selection"], ("portfolio_analysis_request_id", "offer_receipt_id",
                             "post_optimization_assessment_id", "forecast_id"))
    need(all(isinstance(v, str) and 0 < len(v) <= 128 for v in data["selection"].values()), "IDs-only selection required")
    scope = data["scope"]
    keys(scope, ("tenant_id", "workload_id", "payer_account_id", "usage_account_ids", "resource_ids",
                 "class", "currency", "configuration_sha256", "ownership_ref", "history_period",
                 "projection_period", "sha256"))
    need(isinstance(scope["sha256"], str) and HASH.fullmatch(scope["sha256"])
         and isinstance(scope["configuration_sha256"], str) and HASH.fullmatch(scope["configuration_sha256"]), "scope hashes required")
    need(all(isinstance(scope[name], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", scope[name])
             for name in ("tenant_id", "workload_id"))
         and isinstance(scope["currency"], str) and re.fullmatch(r"[A-Z]{3}", scope["currency"]), "scoped identity and currency required")
    need(analysis_hash({**scope, "sha256": ""}) == scope["sha256"], "scope hash differs")
    need(isinstance(scope["usage_account_ids"], list) and 0 < len(scope["usage_account_ids"]) <= 2000
         and scope["usage_account_ids"] == sorted(set(scope["usage_account_ids"]))
         and all(isinstance(v, str) and re.fullmatch(r"[0-9]{12}", v) for v in scope["usage_account_ids"])
         and scope["payer_account_id"] in scope["usage_account_ids"], "payer/member scope required")
    need(isinstance(scope["resource_ids"], list) and 0 < len(scope["resource_ids"]) <= 2000
         and all(isinstance(v, str) and 0 < len(v) <= 2048 for v in scope["resource_ids"])
         and len(set(scope["resource_ids"])) == len(scope["resource_ids"]), "resource ownership scope required")
    history, projection = period(scope["history_period"]), period(scope["projection_period"])
    observed = stamp(data["observed_at"])
    need(history[1] <= observed <= projection[0], "historical and projected periods overlap")
    need((projection[1]-projection[0]).total_seconds() % 3600 == 0, "complete projected hours required")
    need(isinstance(data["input_refs"], list) and 0 < len(data["input_refs"]) <= 2048, "bounded proof set required")
    refs = {reference(v) for v in data["input_refs"]}
    need(len(refs) == len(data["input_refs"]), "duplicate proof reference")
    need(len({(kind, identity) for kind, identity, _ in refs}) == len(refs), "conflicting immutable proof revision")
    need(reference(scope["ownership_ref"]) in refs, "ownership proof absent")
    portfolio = data["portfolio"]
    need(isinstance(portfolio, dict) and portfolio["request_id"] == data["selection"]["portfolio_analysis_request_id"]
         and portfolio["id"] == analysis_hash({**portfolio, "id": ""}), "portfolio analysis differs")
    need(("COMMITMENT_PORTFOLIO_ANALYSIS", portfolio["request_id"], analysis_hash(portfolio)) in refs,
         "immutable portfolio result reference absent")
    for item in portfolio["input_refs"]:
        need(reference(item) in refs, "portfolio proof absent")
    need(portfolio["selection"]["period"] == scope["history_period"], "portfolio period differs")
    for name in ("usage", "contract_rates", "contract_rate_refs", "contract_rate_plan_ids", "payg_basis", "optimization_order", "reason_codes"):
        need(isinstance(data[name], list), "decision collection required")
    need(len(data["usage"]) <= 100000 and len(data["contract_rates"]) <= 20000, "decision population bound exceeded")
    need(len(data["reason_codes"]) <= 128 and all(isinstance(v, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", v)
                                                for v in data["reason_codes"]), "bounded reason codes required")
    return scope, refs, history, projection, observed


def _payg(data, scope, refs, history):
    by_id, latest, keys_by_row = {}, {}, {}
    for row in data["usage"]:
        keys(row, ("id", "period", "dimensions", "kind", "commitment_id", "usage_amount", "billed_cost",
                   "billed_cost_basis", "net_usage_cost", "on_demand_equivalent_cost", "on_demand_basis",
                   "allocated_cost", "allocated_cost_basis", "contract_rate", "native_ref"))
        need(row["id"] not in by_id and reference(row["native_ref"]) in refs, "duplicate or unreferenced usage")
        span = period(row["period"])
        need(history[0] <= span[0] < span[1] <= history[1] and (span[1]-span[0]).total_seconds() == 3600,
             "usage period outside complete hours")
        key = dimensions(row["dimensions"], scope)
        decimal(row["usage_amount"])
        decimal(row["billed_cost"], False)
        need(row["kind"] in {"Usage", "SavingsPlanCoveredUsage", "DiscountedUsage"}, "non-usage charge in population")
        if row["net_usage_cost"] is not None:
            decimal(row["net_usage_cost"], False)
        for name in ("on_demand_equivalent_cost", "allocated_cost", "contract_rate"):
            if row[name] is not None:
                decimal(row[name], name != "allocated_cost")
        by_id[row["id"]], keys_by_row[row["id"]] = row, key
        if row["kind"] == "Usage":
            latest[key] = max(latest.get(key, span), span)
    rates = {}
    for basis in data["payg_basis"]:
        keys(basis, ("dimensions", "observed_period", "rate", "basis", "source_line_ids", "native_refs"))
        key, span = dimensions(basis["dimensions"], scope), period(basis["observed_period"])
        need(key not in rates and basis["basis"] == "CURRENT_NATIVE_NET_USAGE_COST_PER_UNIT",
             "native net account pricing required")
        need(latest.get(key) == span and basis["source_line_ids"], "PAYG basis is not the latest observation")
        ids = basis["source_line_ids"]
        need(len(ids) == len(set(ids)) and all(i in by_id for i in ids), "PAYG source records absent")
        expected_ids = sorted(i for i, row in by_id.items() if keys_by_row[i] == key and row["kind"] == "Usage"
                              and period(row["period"]) == span)
        need(sorted(ids) == expected_ids, "PAYG basis omits latest source records")
        quantity, cost = Decimal(0), Decimal(0)
        for identity in ids:
            row = by_id[identity]
            need(row["kind"] == "Usage" and row["net_usage_cost"] is not None
                 and row["billed_cost_basis"] == "NATIVE_NET_UNBLENDED_COST", "public or gross PAYG substitution")
            quantity += decimal(row["usage_amount"])
            cost += decimal(row["net_usage_cost"])
        need(quantity > 0 and decimal(basis["rate"]) * quantity == cost, "derived PAYG rate differs")
        need(all(reference(r) in refs for r in basis["native_refs"])
             and {reference(by_id[i]["native_ref"]) for i in ids} == {reference(r) for r in basis["native_refs"]},
             "PAYG source references differ")
        rates[key] = decimal(basis["rate"])
    return by_id, rates


def _observed(data, rows):
    eligible, covered, allocated, comparison = (Decimal(0) for _ in range(4))
    coverage_known = data["usage_status"] == "COMPLETE_OBSERVED_ELIGIBLE_WINDOW"
    discount_known = coverage_known
    valuation_bases = set()
    for row in rows.values():
        # Already RI-discounted usage is not eligible for a Savings Plan.
        # It must not inflate either side of SP coverage or discount.
        if row["kind"] == "DiscountedUsage":
            continue
        value = row["on_demand_equivalent_cost"]
        if value is None or row["on_demand_basis"] not in {
                "NATIVE_UNBLENDED_ON_DEMAND_EQUIVALENT", "NATIVE_NET_ON_DEMAND_EQUIVALENT"}:
            coverage_known = False
        else:
            valuation_bases.add(row["on_demand_basis"])
            eligible += decimal(value)
            if row["kind"] != "Usage":
                covered += decimal(value)
        if row["kind"] != "Usage":
            if (row["on_demand_basis"] != "NATIVE_NET_ON_DEMAND_EQUIVALENT" or value is None
                    or row["allocated_cost"] is None or row["allocated_cost_basis"] not in {"NET_SP_EFFECTIVE", "NET_RI_EFFECTIVE"}):
                discount_known = False
            else:
                allocated += decimal(row["allocated_cost"], False)
                comparison += decimal(value)
    return (covered / eligible if coverage_known and len(valuation_bases) == 1 and eligible > 0 else None,
            Decimal(1) - allocated / comparison if discount_known and comparison > 0 else None)


def _stages(data, scope, refs, observed, expected_stages=STAGES):
    stages, last = data["optimization_order"], None
    if len(stages) != len(expected_stages):
        return None, "POST_OPTIMIZATION_ORDER_INCOMPLETE"
    for expected, item in zip(expected_stages, stages):
        keys(item, ("stage", "disposition", "decision_ref", "outcome_ref", "scope_sha256", "completed_at", "reason_codes"))
        when = stamp(item["completed_at"])
        if (item["stage"] != expected or item["disposition"] not in {"COMPLETED", "EVIDENCED_NO_CHANGE"}
                or item["scope_sha256"] != scope["sha256"] or when > observed or last is not None and when < last):
            return None, "POST_OPTIMIZATION_ORDER_INVALID"
        need(reference(item["decision_ref"]) in refs and reference(item["outcome_ref"]) in refs,
             "optimization proof absent")
        last = when
    return last, None


def _forecast(data, scope, refs, projection, last):
    from .portfolio_forecast import MODEL_SHA256
    forecast = data["forecast"]
    if forecast is None:
        return None, "POST_OPTIMIZATION_FORECAST_UNAVAILABLE"
    keys(forecast, ("id", "scope_sha256", "recalculated_at", "hours", "calibration", "native_ref"))
    need(reference(forecast["native_ref"]) in refs, "forecast reference absent")
    before_forecast = stamp(data["optimization_order"][-2]["completed_at"]) if len(data["optimization_order"]) == len(STAGES) else None
    if (forecast["id"] != data["selection"]["forecast_id"] or forecast["scope_sha256"] != scope["sha256"]
            or last is None or before_forecast is None
            or not before_forecast <= stamp(forecast["recalculated_at"]) <= last <= stamp(data["observed_at"])):
        return None, "PRE_OPTIMIZATION_FORECAST_REJECTED"
    calibration, hours = forecast["calibration"], int((projection[1]-projection[0]).total_seconds()/3600)
    if calibration is None:
        return None, "TERM_FORECAST_CALIBRATION_UNAVAILABLE"
    keys(calibration, ("target", "horizon_hours", "backtest_origin_count", "method", "model_version", "model_sha256",
                       "training_period", "holdout_period", "sample_count", "nominal_coverage", "observed_coverage",
                       "scope_sha256", "native_ref"))
    need(reference(calibration["native_ref"]) in refs, "calibration proof absent")
    training, holdout = period(calibration["training_period"]), period(calibration["holdout_period"])
    if (calibration["target"] != "TERM_UTILIZATION_AND_NET_COST" or calibration["horizon_hours"] != hours
            or calibration["method"] != "ROLLING_ORIGIN_TERM_BLOCK_V1" or calibration["model_version"] != "commitment-stable-floor-v1"
            or calibration["model_sha256"] != MODEL_SHA256 or calibration["scope_sha256"] != scope["sha256"]
            or not isinstance(calibration["backtest_origin_count"], int) or isinstance(calibration["backtest_origin_count"], bool)
            or not isinstance(calibration["sample_count"], int) or isinstance(calibration["sample_count"], bool)
            or not isinstance(calibration["horizon_hours"], int) or isinstance(calibration["horizon_hours"], bool)
            or calibration["backtest_origin_count"] < 12 or calibration["sample_count"] < calibration["backtest_origin_count"]
            or not training[1] <= holdout[0] < holdout[1] <= stamp(data["observed_at"])
            or (holdout[1]-holdout[0]).total_seconds() < hours*3600
            or not Decimal("0.9") <= decimal(calibration["nominal_coverage"]) <= decimal(calibration["observed_coverage"]) <= 1):
        return None, "TERM_FORECAST_CALIBRATION_UNSUPPORTED"
    need(isinstance(forecast["hours"], list) and 0 < len(forecast["hours"]) <= 100000, "bounded native forecast required")
    groups = defaultdict(dict)
    for item in forecast["hours"]:
        keys(item, ("period", "dimensions", "expected_usage", "lower_usage", "upper_usage"))
        span, key = period(item["period"]), dimensions(item["dimensions"], scope)
        offset = (span[0]-projection[0]).total_seconds()
        need(offset >= 0 and offset % 3600 == 0 and (span[1]-span[0]).total_seconds() == 3600
             and span[1] <= projection[1] and key not in groups[int(offset/3600)], "forecast gaps or duplicate dimensions")
        values = tuple(decimal(item[name]) for name in ("lower_usage", "expected_usage", "upper_usage"))
        need(values[0] <= values[1] <= values[2], "forecast interval order differs")
        groups[int(offset/3600)][key] = (item["dimensions"], values, span)
    need(set(groups) == set(range(hours)), "forecast has missing hours")
    expected_keys = set(groups[0])
    need(all(set(group) == expected_keys for group in groups.values()), "forecast drops eligible dimensions")
    return groups, None


def _existing(data, scope, refs, keys_needed):
    portfolio = data["portfolio"]
    if (portfolio["inventory_status"] != "COMPLETE_POINT_IN_TIME"
            or data["contract_rate_status"] != "COMPLETE_NATIVE_PLAN_RATE_SETS"):
        return None, "EXISTING_COMMITMENT_EXPOSURE_UNKNOWN"
    plans = {item["position"]["id"]: item["position"] for item in portfolio["positions"]}
    rates = {}
    for row in data["contract_rates"]:
        keys(row, ("plan_id", "dimensions", "rate", "native_ref"))
        key = dimensions(row["dimensions"], scope)
        need(row["plan_id"] in plans and reference(row["native_ref"]) in refs, "existing contract rate outside inventory")
        identity = row["plan_id"], key
        need(identity not in rates and decimal(row["rate"]) > 0, "ambiguous existing contract rate")
        rates[identity] = decimal(row["rate"])
    active_ids = set()
    for identity, plan in plans.items():
        if plan["class"] in {"DATABASE_SAVINGS_PLAN", "SAGEMAKER_SAVINGS_PLAN"}:
            continue
        if plan["end"] is not None and stamp(plan["end"]) <= stamp(scope["projection_period"]["start"]):
            continue
        if (plan["class"] not in SUPPORTED_CLASSES or plan["start"] is None or plan["end"] is None
                or plan["currency"] != scope["currency"] or plan["hourly_commitment"] is None
                or plan["state"] not in {"active", "queued"}):
            return None, "EXISTING_COMMITMENT_APPLICABILITY_UNRESOLVED"
        active_ids.add(identity)
        for key in keys_needed:
            if plan["class"] == "EC2_INSTANCE_SAVINGS_PLAN" and (plan["region"] != key[5] or plan["instance_family"] != key[7]):
                continue
            if (identity, key) not in rates:
                return None, "EXISTING_COMMITMENT_RATE_MISSING"
    need(set(data["contract_rate_plan_ids"]) == active_ids
         and len(set(data["contract_rate_plan_ids"])) == len(data["contract_rate_plan_ids"]), "existing rate plan set differs")
    need(all(reference(r) in refs for r in data["contract_rate_refs"]), "existing rate receipt absent")
    return (plans, rates, active_ids), None


def _residual(group, existing, which):
    plans, rates, active_ids = existing
    result = {}
    for key, (_, values, span) in group.items():
        possible = Decimal(0)
        for identity in active_ids:
            plan = plans[identity]
            if stamp(plan["start"]) < span[1] and stamp(plan["end"]) > span[0] and (identity, key) in rates:
                possible += decimal(plan["hourly_commitment"]) / rates[identity, key]
        # Each SKU receives the maximum potential existing coverage, including
        # sharing. This upper bound can count a plan budget more than once and
        # consequently UNDERstates new uncovered demand; it cannot overbuy.
        result[key] = max(Decimal(0), values[which]-possible)
    return result


def _benefit(usage, offer_rates, payg_rates, budget):
    used, avoided = Decimal(0), Decimal(0)
    # Worst economic ordering: no claim about the provider's future allocation.
    for key in sorted(usage, key=lambda k: (payg_rates[k]/offer_rates[k], json.dumps(k, separators=(",", ":")))):
        allocated = min(usage[key]*offer_rates[key], max(Decimal(0), budget-used))
        used += allocated
        avoided += allocated*payg_rates[key]/offer_rates[key]
    return used, avoided


def _obligations(portfolio, currency, observed_value):
    """Cash still owed differs from sunk, unamortized capital.

    Only native No Upfront SP terms establish a complete cash schedule here.
    Upfront/RI amortization needs its own native schedule, never a fabricated
    straight-line allocation. A complete empty inventory is evidenced zero.
    """
    observed = stamp(observed_value)
    if portfolio["inventory_status"] != "COMPLETE_POINT_IN_TIME":
        return None, None, ["COMPLETE_NATIVE_CASH_SCHEDULE_UNAVAILABLE"]
    owed, paid = Decimal(0), Decimal(0)
    for item in portfolio["positions"]:
        p = item["position"]
        if p["end"] is not None and stamp(p["end"]) <= observed:
            continue
        if p["currency"] is None:
            return None, None, ["NATIVE_CASH_SCHEDULE_CURRENCY_UNKNOWN"]
        if p["currency"] != currency:
            continue
        if (p["class"] not in SUPPORTED_CLASSES or p["payment_option"] != "No Upfront"
                or p["upfront_amount"] is None or decimal(p["upfront_amount"]) != 0
                or p["hourly_commitment"] is None or p["start"] is None or p["end"] is None
                or p["state"] not in {"active", "queued"}):
            return None, None, ["COMPLETE_NATIVE_CASH_AND_AMORTIZATION_SCHEDULE_UNAVAILABLE"]
        start, end = max(observed, stamp(p["start"])), stamp(p["end"])
        need(start < end, "remaining native term differs")
        # Retain native subsecond precision without floating-point currency.
        duration = exact_seconds(p["end"], p["start"]) if stamp(p["start"]) > observed else exact_seconds(p["end"], observed_value)
        owed += decimal(p["hourly_commitment"])*duration/3600
    return owed, paid, []


def evaluate(data):
    with localcontext() as context:
        context.prec = 80
        scope, refs, history, projection, observed = _proofs(data)
        rows, payg = _payg(data, scope, refs, history)
        coverage, discount = _observed(data, rows)
        result = {"schema_version": "2", "id": "", "request_id": data["request_id"], "selection": data["selection"],
                  "scope": scope, "input_refs": data["input_refs"], "status": "BLOCKED", "computation_policy": POLICY,
                  "forward_price_assumption": PRICE_ASSUMPTION, "optimization_order": data["optimization_order"],
                  "reason_codes": list(data["reason_codes"]), "observed_at": data["observed_at"],
                  "finance_approval_required": True, "purchase_authorized": False, "execution_authorized": False, "verified_saving": None}
        def put(name, value, basis, *, forward=False, unit="currency", reasons=()):
            result[name] = metric(value, unit, None if unit == "fraction" else scope["currency"], basis,
                                  scope["projection_period"] if forward else scope["history_period"], data["input_refs"], reasons)
        put("observed_coverage", coverage, "NATIVE_SP_ELIGIBLE_OD_EQUIVALENT_VALUATION_EXCLUDING_RI", unit="fraction",
            reasons=() if coverage is not None else ["COMPLETE_ELIGIBLE_DENOMINATOR_UNAVAILABLE"])
        put("observed_effective_discount", discount, "NATIVE_NET_COVERED_EQUIVALENT_VS_NET_ALLOCATED_COST", unit="fraction",
            reasons=() if discount is not None else ["MATCHING_NATIVE_NET_COMPARISON_UNAVAILABLE"])
        unused = [p["observed_unused_commitment"] for p in data["portfolio"]["partitions"] if p["currency"] == scope["currency"]]
        put("observed_unused_exposure", sum((decimal(v) for v in unused), Decimal(0)) if unused and all(v is not None for v in unused) else None,
            "OBSERVED_NATIVE_UNUSED_COMMITMENT", reasons=[] if unused else ["NATIVE_UNUSED_COMMITMENT_UNAVAILABLE"])
        for name, unit in (("expected_utilization", "fraction"), ("break_even_utilization", "fraction"),
                           ("expected_savings", "currency"), ("downside_exposure", "currency"), ("cash_requirement", "currency"),
                           ("proposed_hourly_commitment", "currency/hour"), ("proposed_term_obligation", "currency"),
                           ("remaining_contractual_obligation", "currency"), ("paid_unamortized_value", "currency")):
            put(name, None, "POST_OPTIMIZATION_CONSERVATIVE_NATIVE_ECONOMICS", forward=True, unit=unit,
                reasons=["COMPLETE_NATIVE_DECISION_PREREQUISITES_REQUIRED"])
        owed, paid, obligation_reasons = _obligations(data["portfolio"], scope["currency"], data["observed_at"])
        put("remaining_contractual_obligation", owed, "REMAINING_NATIVE_NO_UPFRONT_SP_CASH_SCHEDULE", forward=True, reasons=obligation_reasons)
        put("paid_unamortized_value", paid, "NATIVE_ZERO_UPFRONT_ONLY_NO_IMPUTED_AMORTIZATION", forward=True, reasons=obligation_reasons)
        # Remaining obligations can outlive the proposed purchase term. Show
        # the full native obligation horizon rather than labelling it one year.
        ends = [scope["projection_period"]["end"]]+[p["position"]["end"] for p in data["portfolio"]["positions"]
                if p["position"]["currency"] == scope["currency"] and p["position"]["end"] is not None]
        cash_period = {"start": data["observed_at"], "end": max(ends, key=stamp)}
        result["remaining_contractual_obligation"]["period"] = cash_period
        result["paid_unamortized_value"]["period"] = cash_period
        result["confidence"] = {"status": "UNAVAILABLE", "lower_expected_savings": None, "upper_expected_savings": None,
                                "coverage": None, "method": None, "calibration_ref": None, "reason_codes": ["TERM_FORECAST_CALIBRATION_UNAVAILABLE"]}
        result["price_change_stress"] = {"status": "UNAVAILABLE", "assumption": PRICE_ASSUMPTION,
                                         "break_even_payg_rate_drop_fraction": None,
                                         "zero_usage_loss": result["downside_exposure"], "reason_codes": ["NATIVE_PRICING_OR_FORECAST_UNAVAILABLE"]}
        last, stage_error = _stages(data, scope, refs, observed)
        forecast, forecast_error = _forecast(data, scope, refs, projection, last)
        blockers = [v for v in (stage_error, forecast_error) if v]
        if data["usage_status"] != "COMPLETE_OBSERVED_ELIGIBLE_WINDOW": blockers.append("COMPLETE_ELIGIBLE_USAGE_UNAVAILABLE")
        offer = data["offer"]
        if offer is None:
            blockers.append("NATIVE_OFFER_UNAVAILABLE")
        else:
            keys(offer, ("id", "native_offering_id", "class", "currency", "payment_option", "duration_seconds", "effective_period", "validity_basis", "rates", "native_ref"))
            need(reference(offer["native_ref"]) in refs, "offer proof absent")
            need(offer["id"] == data["selection"]["offer_receipt_id"]
                 and isinstance(offer["native_offering_id"], str) and 0 < len(offer["native_offering_id"]) <= 128,
                 "issued offer selection or native identifier differs")
            validity = period(offer["effective_period"])
            if (scope["class"] not in SUPPORTED_CLASSES or offer["class"] != scope["class"] or offer["currency"] != scope["currency"]
                    or offer["payment_option"] != "No Upfront" or decimal(offer["duration_seconds"]) != 31536000
                    # AWS exposes observed offering terms/rates, not a promised
                    # future quote-expiry interval. This server-issued window
                    # limits the age of the read at decision/review time; forward
                    # economics still state the held-current-price assumption.
                    or offer["validity_basis"] != OFFER_VALIDITY_BASIS
                    or validity[1]-validity[0] > timedelta(minutes=5)
                    or not validity[0] <= observed < validity[1]
                    or Decimal(str((projection[1]-projection[0]).total_seconds())) != decimal(offer["duration_seconds"])):
                blockers.append("OFFER_TERM_OR_SCOPE_UNSUPPORTED")
        if forecast is not None and offer is not None:
            offer_rates = {}
            for row in offer["rates"]:
                keys(row, ("dimensions", "rate", "native_ref"))
                key = dimensions(row["dimensions"], scope)
                need(reference(row["native_ref"]) in refs and key not in offer_rates and decimal(row["rate"]) > 0,
                     "ambiguous native offered rate")
                offer_rates[key] = decimal(row["rate"])
            needed = set(forecast[0])
            if not needed <= set(offer_rates) or not needed <= set(payg): blockers.append("EXACT_NATIVE_NET_PRICE_SET_UNAVAILABLE")
            existing, existing_error = _existing(data, scope, refs, needed)
            if existing_error: blockers.append(existing_error)
        else:
            existing = None
        if blockers or existing is None:
            result["reason_codes"] = sorted(set(result["reason_codes"] + blockers))
        else:
            scenarios = [[_residual(forecast[i], existing, which) for i in range(len(forecast))] for which in range(3)]
            lower_demands = sorted(sum((q*offer_rates[k] for k, q in hour.items()), Decimal(0)) for hour in scenarios[0])
            budget = lower_demands[(len(lower_demands)-1)//10]
            term_cost, summaries = budget*len(forecast), []
            for scenario in scenarios:
                used = avoided = Decimal(0)
                for hour in scenario:
                    u, a = _benefit(hour, offer_rates, payg, budget)
                    used += u; avoided += a
                summaries.append((used/term_cost if term_cost > 0 else Decimal(0), avoided-term_cost, avoided))
            lower, expected, upper = summaries
            put("proposed_hourly_commitment", budget, "CALIBRATED_LOWER_PATH_10TH_PERCENTILE_UNCOVERED_NATIVE_SP_COST", forward=True, unit="currency/hour")
            put("proposed_term_obligation", term_cost, "NATIVE_NO_UPFRONT_FIXED_HOURLY_COMMITMENT", forward=True)
            put("cash_requirement", Decimal(0), "NATIVE_NO_UPFRONT_PAYMENT_OPTION", forward=True)
            put("expected_utilization", expected[0] if budget > 0 else None, "MAXIMUM_EXISTING_COVERAGE_AND_CONSERVATIVE_NEW_ALLOCATION", forward=True, unit="fraction",
                reasons=[] if budget > 0 else ["ZERO_SAFE_INCREMENTAL_COMMITMENT"])
            worst_ratio = min(payg[k]/offer_rates[k] for k in needed)
            put("break_even_utilization", Decimal(1)/worst_ratio if worst_ratio > 0 else None,
                "NO_UPFRONT_WORST_MATCHED_NET_PAYG_TO_OFFER_RATE", forward=True, unit="fraction")
            put("expected_savings", expected[1], "INCREMENTAL_NATIVE_NET_COST_PROVISIONAL_PRICE_ASSUMPTION", forward=True)
            put("downside_exposure", term_cost, "ZERO_FUTURE_USAGE_FIXED_NATIVE_OBLIGATION", forward=True)
            result["confidence"] = {"status": "AVAILABLE", "lower_expected_savings": money(lower[1]), "upper_expected_savings": money(upper[1]),
                                    "coverage": data["forecast"]["calibration"]["observed_coverage"], "method": data["forecast"]["calibration"]["method"],
                                    "calibration_ref": data["forecast"]["calibration"]["native_ref"], "reason_codes": ["MODEL_ASSUMPTIONS_APPLY_NO_GUARANTEED_FUTURE_PRICE", "DEPENDENT_ROLLING_ORIGIN_EMPIRICAL_PATH_COVERAGE"]}
            result["price_change_stress"] = {"status": "AVAILABLE", "assumption": PRICE_ASSUMPTION,
                                             "break_even_payg_rate_drop_fraction": money(Decimal(1)-term_cost/expected[2]) if expected[2] > 0 else None,
                                             "zero_usage_loss": result["downside_exposure"], "reason_codes": []}
            result["status"] = "RECOMMEND_PURCHASE_PENDING_FINANCE" if budget > 0 and expected[1] > 0 and lower[1] > 0 and lower[0] >= Decimal("0.9") else "DO_NOT_PURCHASE"
            result["reason_codes"] = sorted(set(result["reason_codes"] + ["EXPECTED_ECONOMICS_PROVISIONAL", "EXISTING_COVERAGE_UPPER_BOUND", "FINANCE_APPROVAL_REQUIRED"]
                                                + ([] if result["status"] == "RECOMMEND_PURCHASE_PENDING_FINANCE" else ["INSUFFICIENT_SAFE_INCREMENTAL_BENEFIT"])))
        result["id"] = analysis_hash(result)
        return result
