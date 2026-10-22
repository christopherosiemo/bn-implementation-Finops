"""Private analytical evaluator. Input provenance is resolved by the Go worker.

Historical allocation is separate from recommendation, invoice finality and
avoidable cost. A checksum never authenticates an uploaded financial claim.
"""
from decimal import Decimal, InvalidOperation, localcontext
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

STAGES = ("REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND")
RI_CLASSES = {"EC2_RI_UNCLASSIFIED", "EC2_STANDARD_RI", "EC2_CONVERTIBLE_RI"}
CLASSES = RI_CLASSES | {"COMPUTE_SAVINGS_PLAN", "EC2_INSTANCE_SAVINGS_PLAN", "DATABASE_SAVINGS_PLAN", "SAGEMAKER_SAVINGS_PLAN", "UNSUPPORTED_SAVINGS_PLAN"}
HASH = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,18})?\Z")
ALLOCATION_BASES = {"NET_SP_EFFECTIVE", "SP_EFFECTIVE", "NET_RI_EFFECTIVE", "RI_EFFECTIVE"}

class EvidenceError(ValueError):
    pass

def need(ok, message):
    if not ok:
        raise EvidenceError(message)

def decimal(value, nonnegative=True):
    need(isinstance(value, str) and DECIMAL.fullmatch(value), "exact decimal string required")
    try:
        out = Decimal(value)
    except InvalidOperation as error:
        raise EvidenceError("invalid decimal") from error
    need(out.is_finite() and (not nonnegative or out >= 0), "invalid signed amount")
    return out

def amount(value):
    text = format(value, "f")
    fraction = text.partition(".")[2].rstrip("0")
    need(len(fraction) <= 12 and len(text.lstrip("-").split(".")[0]) <= 26, "amount exceeds DECIMAL(38,12)")
    return text.rstrip("0").rstrip(".") if "." in text else text

def ratio(numerator, denominator):
    return amount((numerator/denominator).quantize(Decimal("0.000000000001"))) if denominator > 0 else None

def seconds(delta):
    return Decimal(delta.days*86400+delta.seconds)+Decimal(delta.microseconds)/Decimal(1000000)

def exact_seconds(left, right):
    def parts(value):
        parsed = stamp(value)
        suffix = re.search(r"T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.([0-9]{1,12}))?(?:Z|\+00:00)$", value)
        need(suffix is not None, "unsupported timestamp precision")
        return parsed.replace(microsecond=0), Decimal("0."+(suffix.group(1) or "0"))
    a, af = parts(left)
    b, bf = parts(right)
    return seconds(a-b)+af-bf

def expiry(position, observed_value):
    observed = stamp(observed_value)
    start = stamp(position["start"]) if position["start"] is not None else None
    end = stamp(position["end"]) if position["end"] is not None else None
    if start is not None and end is not None:
        need(start < end, "commitment term is invalid")
        if position["term_seconds"] is not None:
            need(decimal(position["term_seconds"]) == exact_seconds(position["end"], position["start"]), "commitment term differs from native dates")
    if end is None:
        return {"status": "UNKNOWN", "remaining_seconds": None, "within_days": 30, "expires_within_window": None}
    difference = exact_seconds(position["end"], observed_value)
    remaining = max(Decimal(0), difference)
    return {"status": "EXPIRED" if difference <= 0 else "NOT_STARTED" if start is not None and exact_seconds(position["start"], observed_value) > 0 else "ACTIVE",
            "remaining_seconds": amount(remaining), "within_days": 30,
            "expires_within_window": Decimal(0) < difference <= Decimal(30*86400)}

def reserved_terms(position):
    terms = position["reserved_instance_terms"]
    if terms is None:
        need(position["class"] not in {"EC2_STANDARD_RI", "EC2_CONVERTIBLE_RI"}, "classified RI requires native terms")
        return
    fields = {"offering_class", "offering_type", "scope", "duration_seconds", "currency_code", "fixed_price", "usage_price", "instance_count", "instance_type", "instance_tenancy", "product_description", "availability_zone", "availability_zone_id", "recurring_charges"}
    need(position["class"] in RI_CLASSES and isinstance(terms, dict) and set(terms) == fields, "native reserved-instance terms required")
    for name in fields-{"recurring_charges"}:
        need(terms[name] is None or isinstance(terms[name], str) and 0 < len(terms[name]) <= 2048, "native RI lexical value required")
    for name in ("duration_seconds", "fixed_price", "usage_price", "instance_count"):
        if terms[name] is not None: decimal(terms[name])
    expected = {"standard": "EC2_STANDARD_RI", "convertible": "EC2_CONVERTIBLE_RI"}.get(terms["offering_class"])
    need(expected is None and position["class"] == "EC2_RI_UNCLASSIFIED" or expected == position["class"], "RI offering class differs")
    if terms["currency_code"] is not None: need(terms["currency_code"] == position["currency"], "RI currency differs")
    charges = terms["recurring_charges"]
    need(charges is None or isinstance(charges, list) and len(charges) <= 256, "native recurring charges required")
    for charge in charges or []:
        need(isinstance(charge, dict) and set(charge) == {"amount", "frequency"} and (charge["frequency"] is None or isinstance(charge["frequency"], str)), "native recurring charge fields required")
        if charge["amount"] is not None: decimal(charge["amount"])

def stamp(value):
    need(isinstance(value, str) and len(value) <= 40, "UTC timestamp required")
    try:
        out = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("invalid timestamp") from error
    need(out.tzinfo is not None and out.utcoffset() == timedelta(0), "UTC required")
    return out

def ref(value):
    need(isinstance(value, dict) and set(value) == {"kind", "id", "sha256"}, "exact reference required")
    need(value["kind"] in {"AWS_COMMITMENT", "AWS_CUR2", "OPTIMIZATION_DECISION", "OPTIMIZATION_OUTCOME"} and isinstance(value["id"], str) and 0 < len(value["id"]) <= 128 and HASH.fullmatch(value["sha256"]), "invalid reference")
    return (value["kind"], value["id"], value["sha256"])

def analysis_hash(value):
    # Match the existing Go Hash(map) contract, including native Unicode and
    # default encoding/json HTML and line-separator escaping.
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    for character, escaped in (("<", r"\u003c"), (">", r"\u003e"), ("&", r"\u0026"), ("\u2028", r"\u2028"), ("\u2029", r"\u2029")):
        raw = raw.replace(character, escaped)
    return hashlib.sha256(raw.encode()).hexdigest()

def evaluate(data):
    need(isinstance(data, dict) and set(data) == {"schema_version", "request_id", "tenant_id", "payer_account_id", "usage_account_ids", "selection", "input_refs", "inventory_status", "positions", "billing", "billing_status", "optimization_order", "observed_at"}, "exact input schema required")
    need(data["schema_version"] == "1" and isinstance(data["request_id"], str) and 0 < len(data["request_id"]) <= 128 and re.fullmatch(r"[0-9]{12}", data["payer_account_id"]), "binding required")
    refs = {ref(v) for v in data["input_refs"]}
    need(len(refs) == len(data["input_refs"]) and 1 <= len(refs) <= 128, "reference limits")
    accounts = data["usage_account_ids"]
    need(isinstance(accounts, list) and 1 <= len(accounts) <= 10000 and all(isinstance(v, str) and re.fullmatch(r"[0-9]{12}", v) for v in accounts) and len(set(accounts)) == len(accounts) and data["payer_account_id"] in accounts, "issued account scope required")
    selection = data["selection"]
    need(set(selection) == {"source_id", "commitment_receipt_id", "billing_receipt_ids", "period"}, "IDs-only selection required")
    start, end = stamp(selection["period"]["start"]), stamp(selection["period"]["end"])
    observed = stamp(data["observed_at"])
    need(start < end <= observed and end-start <= timedelta(days=31) and start.minute == start.second == start.microsecond == end.minute == end.second == end.microsecond == 0, "bounded whole-hour historical window required")
    need(data["inventory_status"] in {"COMPLETE_POINT_IN_TIME", "PARTIAL", "UNAVAILABLE"} and data["billing_status"] in {"COMPLETE_OBSERVED_WINDOW", "PARTIAL", "UNAVAILABLE"}, "evidence status required")
    need(isinstance(data["positions"], list) and len(data["positions"]) <= 2000 and isinstance(data["billing"], list) and len(data["billing"]) <= 100000, "population bounds")
    billing_ids = set()
    for line in data["billing"]:
        need(isinstance(line, dict) and set(line) == {"id", "commitment_id", "account_id", "currency", "kind", "period", "billed_cost", "allocated_cost", "allocated_cost_basis", "total_commitment", "used_commitment", "native_ref"}, "exact billing-line schema required")
        need(isinstance(line["id"], str) and line["id"] and line["id"] not in billing_ids and line["account_id"] in accounts and re.fullmatch(r"[A-Z]{3}", line["currency"]) and ref(line["native_ref"]) in refs and line["native_ref"]["kind"] == "AWS_CUR2", "billing provenance or duplicate invalid")
        billing_ids.add(line["id"])
        need((line["allocated_cost"] is None and line["allocated_cost_basis"] is None) or line["allocated_cost"] is not None and line["allocated_cost_basis"] in ALLOCATION_BASES, "native allocation pricing basis required")
        if line["allocated_cost"] is not None:
            need(line["kind"] == "SavingsPlanCoveredUsage" and line["allocated_cost_basis"] in {"NET_SP_EFFECTIVE", "SP_EFFECTIVE"} or line["kind"] == "DiscountedUsage" and line["allocated_cost_basis"] in {"NET_RI_EFFECTIVE", "RI_EFFECTIVE"}, "allocation basis differs from native charge kind")
        a, b = stamp(line["period"]["start"]), stamp(line["period"]["end"])
        need(start <= a < b <= end, "billing interval outside selected period")
        decimal(line["billed_cost"], False)
        if line["allocated_cost"] is not None: decimal(line["allocated_cost"])
    positions, ids, partitions = [], set(), {}
    with localcontext() as ctx:
        ctx.prec = 80
        for position in data["positions"]:
            need(isinstance(position, dict) and set(position) == {"id", "account_id", "class", "state", "region", "instance_family", "currency", "start", "end", "term_seconds", "hourly_commitment", "upfront_amount", "recurring_amount", "recurring_amount_unit", "payment_option", "reserved_instance_terms", "native_ref", "reason_codes"}, "exact position schema required")
            pid = position["id"]
            need(isinstance(pid, str) and 0 < len(pid) <= 2048 and pid not in ids and position["class"] in CLASSES, "position identity or class invalid")
            ids.add(pid)
            need(ref(position["native_ref"]) in refs and position["native_ref"]["kind"] == "AWS_COMMITMENT", "inventory reference mismatch")
            need(position["account_id"] in accounts, "commitment account outside issued scope")
            currency = position["currency"]
            need(currency is None or isinstance(currency, str) and re.fullmatch(r"[A-Z]{3}", currency), "currency required")
            for name in ("hourly_commitment", "upfront_amount", "recurring_amount"):
                if position[name] is not None:
                    decimal(position[name])
            reserved_terms(position)
            need(position["recurring_amount_unit"] == "PROVIDER_FIELD_UNIT_UNVERIFIED", "native recurrence cannot imply cash schedule")
            expiry_state = expiry(position, data["observed_at"])
            reasons = set(position["reason_codes"]) | {"COVERAGE_ELIGIBILITY_ALLOCATION_UNAVAILABLE", "BREAK_EVEN_RATE_MIX_UNRESOLVED", "REMAINING_VALUE_AND_CASH_SCHEDULE_UNAVAILABLE", "FORECAST_CONFIDENCE_UNAVAILABLE"}
            lines = []
            seen = set()
            for line in data["billing"]:
                if line["commitment_id"] != pid:
                    continue
                need(line["id"] not in seen and ref(line["native_ref"]) in refs and line["native_ref"]["kind"] == "AWS_CUR2", "billing provenance or duplicate invalid")
                seen.add(line["id"])
                # Currency mismatch is refused; FX is never inferred.
                need(currency is not None and line["currency"] == currency, "commitment currency differs")
                a, b = stamp(line["period"]["start"]), stamp(line["period"]["end"])
                need(start <= a < b <= end, "billing interval outside selected period")
                if line["kind"] == "SavingsPlanRecurringFee":
                    need(line["account_id"] in {position["account_id"], data["payer_account_id"]}, "commitment fee account differs")
                if line["kind"] in {"SavingsPlanRecurringFee", "SavingsPlanCoveredUsage"}:
                    need(position["class"] not in RI_CLASSES, "Savings Plan charge attached to RI")
                if line["kind"] == "DiscountedUsage":
                    need(position["class"] in RI_CLASSES, "RI charge attached to Savings Plan")
                if position["start"] is not None: need(a >= stamp(position["start"]), "billing precedes commitment term")
                if position["end"] is not None: need(b <= stamp(position["end"]), "billing follows commitment term")
                decimal(line["billed_cost"], False)
                if line["allocated_cost"] is not None:
                    decimal(line["allocated_cost"])
                lines.append((line, a, b))
            full = data["billing_status"] == "COMPLETE_OBSERVED_WINDOW"
            billed = amount(sum((decimal(v[0]["billed_cost"], False) for v in lines), Decimal(0))) if full and lines else None
            allocation = [v[0] for v in lines if v[0]["kind"] in {"SavingsPlanCoveredUsage", "DiscountedUsage"}]
            allocation_bases = {v["allocated_cost_basis"] for v in allocation}
            allocated = amount(sum((decimal(v["allocated_cost"]) for v in allocation), Decimal(0))) if full and allocation and all(v["allocated_cost"] is not None for v in allocation) and len(allocation_bases) == 1 else None
            allocation_basis = next(iter(allocation_bases)) if allocated is not None else None
            if len(allocation_bases) > 1: reasons.add("ALLOCATION_PRICING_BASIS_MISMATCH")
            committed = used = unused = utilization = downside = None
            fees = sorted((v for v in lines if v[0]["kind"] == "SavingsPlanRecurringFee"), key=lambda v: v[1])
            complete_fees = full and position["class"] not in RI_CLASSES | {"UNSUPPORTED_SAVINGS_PLAN"} and bool(fees)
            cursor = start
            total, consumed = Decimal(0), Decimal(0)
            for line, a, b in fees:
                need(a >= cursor, "hourly commitment overlap")
                if b-a != timedelta(hours=1) or a != cursor:
                    complete_fees = False
                    reasons.add("HOURLY_COMMITMENT_GAP_OR_UNSUPPORTED_INTERVAL")
                cursor = b
                if line["total_commitment"] is None or line["used_commitment"] is None:
                    complete_fees = False
                    continue
                t, u = decimal(line["total_commitment"]), decimal(line["used_commitment"])
                need(u <= t, "used commitment exceeds observed commitment")
                total += t
                consumed += u
            complete_fees = complete_fees and cursor == end
            if complete_fees:
                committed, used, unused = amount(total), amount(consumed), amount(total-consumed)
                # Observed-window zero-usage bound, not a future demand forecast.
                downside = amount(total)
                utilization = ratio(consumed, total)
                if total == 0:
                    reasons.add("ZERO_COMMITMENT_UTILIZATION_UNDEFINED")
            else:
                reasons.add("COMPLETE_HOURLY_COMMITMENT_ALLOCATION_UNAVAILABLE")
            if not full:
                reasons.add("BILLING_WINDOW_INCOMPLETE")
            result = {"position": position, "expiry": expiry_state, "observed_billed_cost": billed, "observed_allocated_cost": allocated, "allocated_cost_basis": allocation_basis, "commitment_cost_basis": "NATIVE_SP_HOURLY_TOTAL_AND_USED_COMMITMENT" if position["class"] not in RI_CLASSES | {"UNSUPPORTED_SAVINGS_PLAN"} else "UNAVAILABLE", "observed_committed_cost": committed, "observed_used_commitment": used, "observed_unused_commitment": unused, "utilization": utilization, "coverage": None, "effective_discount": None, "downside_if_zero_usage_observed_window": downside, "break_even_utilization": None, "remaining_value": None, "cash_requirement": None, "expected_utilization": None, "confidence_interval": None, "status": "OBSERVED_PARTIAL" if billed is not None or utilization is not None else "UNKNOWN", "reason_codes": sorted(reasons)}
            positions.append(result)
            key = (position["class"], currency, position["account_id"], position["region"], position["instance_family"])
            partitions.setdefault(key, []).append(result)
        # Current inventory can omit an expired or returned commitment. Keep
        # its issued charges visible without inventing native terms or usage.
        unmatched = {}
        for line in data["billing"]:
            if line["commitment_id"] not in ids:
                key = (line["commitment_id"], line["account_id"], line["currency"])
                unmatched.setdefault(key, []).append(line)
        unmatched_rows = [{"commitment_id": key[0], "account_id": key[1], "currency": key[2], "line_ids": sorted(v["id"] for v in values),
                           "observed_billed_cost": amount(sum((decimal(v["billed_cost"], False) for v in values), Decimal(0))) if data["billing_status"] == "COMPLETE_OBSERVED_WINDOW" else None,
                           "reason_codes": ["COMMITMENT_NOT_IN_SELECTED_NATIVE_POINT"]} for key, values in sorted(unmatched.items())]
        partition_rows = []
        for key, values in sorted(partitions.items(), key=lambda kv: repr(kv[0])):
            cls, cur, account, region, family = key
            complete_rates = data["inventory_status"] == "COMPLETE_POINT_IN_TIME" and cur is not None and all(v["position"]["hourly_commitment"] is not None and v["expiry"]["status"] == "ACTIVE" and v["position"]["state"] == "active" for v in values)
            hourly = sum((decimal(v["position"]["hourly_commitment"]) for v in values), Decimal(0)) if complete_rates else None
            total_field = lambda field: amount(sum((decimal(v[field], field != "observed_billed_cost") for v in values), Decimal(0))) if all(v[field] is not None for v in values) else None
            committed, used = total_field("observed_committed_cost"), total_field("observed_used_commitment")
            partition_rows.append({"class": cls, "currency": cur, "account_id": account, "region": region, "instance_family": family,
                                   "position_ids": sorted(v["position"]["id"] for v in values), "position_count": len(values),
                                   "observed_billed_cost": total_field("observed_billed_cost"), "observed_committed_cost": committed,
                                   "observed_used_commitment": used, "observed_unused_commitment": total_field("observed_unused_commitment"),
                                   "utilization": ratio(decimal(used), decimal(committed)) if committed is not None and used is not None else None,
                                   "hourly_commitment_rate": amount(hourly) if hourly is not None else None, "hourly_commitment_rate_unit": "currency/hour",
                                   "concentration_basis": "NATIVE_HOURLY_COMMITMENT_RATE",
                                   "position_shares": [{"position_id": v["position"]["id"], "share": ratio(decimal(v["position"]["hourly_commitment"]), hourly) if hourly is not None else None} for v in sorted(values, key=lambda v:v["position"]["id"])],
                                   "expiring_position_ids": sorted(v["position"]["id"] for v in values if v["expiry"]["expires_within_window"] is True)})
    # Existing issuers do not establish the complete optimization sequence.
    # Even a caller carrying plausible refs cannot grant a recommendation gate.
    need(data["optimization_order"] == [], "optimization outcome issuer not integrated")
    stages = [{"stage": name, "status": "BLOCKED", "decision_ref": None, "outcome_ref": None, "scope_sha256": None, "reason_codes": ["ISSUED_OPTIMIZATION_OUTCOME_UNAVAILABLE"]} for name in STAGES]
    result = {"schema_version": "1", "id": "", "request_id": data["request_id"], "selection": selection, "input_refs": data["input_refs"], "observed_at": data["observed_at"], "inventory_status": data["inventory_status"], "billing_status": data["billing_status"], "positions": sorted(positions, key=lambda v:v["position"]["id"]), "partitions": partition_rows, "unmatched_billing": unmatched_rows, "optimization_order": stages, "recommendation_status": "BLOCKED", "reason_codes": ["OPTIMIZATION_ORDER_UNPROVEN", "RECOMMENDATION_FORECAST_UNCALIBRATED", "NO_PURCHASE_OR_EXECUTION_AUTHORITY"], "expected_savings": None, "estimated_saving": None, "verified_saving": None, "recommendation_authorized": False, "purchase_authorized": False, "execution_authorized": False}
    result["id"] = analysis_hash(result)
    return result
