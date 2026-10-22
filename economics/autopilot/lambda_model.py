"""Read-only Event Function comparisons from authenticated, server-selected evidence.

This boundary validates arithmetic and comparable observations. It authenticates no
receipt itself and grants neither function nor experiment execution authority.
"""
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import re

from .model import EvidenceError, instant

MODEL_VERSION = "lambda-v1"
MODEL_KIND = "LAMBDA_ASSESSMENT_V1"
ROUTE = "/v11/lambda-assessment"
FAMILIES = ("MEMORY", "PROVISIONED_CONCURRENCY", "ARCHITECTURE", "PERFORMANCE", "RESERVED_CONCURRENCY")
COMPONENTS = ("REQUEST", "ON_DEMAND_COMPUTE", "PROVISIONED_CAPACITY", "PROVISIONED_COMPUTE", "EPHEMERAL_STORAGE", "STREAMING", "EVENT_POLLER", "SNAPSTART", "CONTINUING", "CREDIT", "UNSUPPORTED")
BINDING = ("tenant_id", "account_id", "region", "resource_id", "provider", "provider_resource_id", "workload_id")


def _obj(value, allowed=None):
    if not isinstance(value, dict) or allowed is not None and set(value) - set(allowed):
        raise EvidenceError("unsupported Lambda evidence fields")
    return value


def _text(value, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise EvidenceError("Lambda identity required")
    return value


def _num(value, optional=False, signed=False, integral=False):
    if value is None and optional:
        return None
    # Source decimals are never binary floats or JSON numbers. Native integer
    # configuration is handled explicitly below, not silently accepted as money.
    if not isinstance(value, str) or not re.fullmatch(r"-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?", value):
        raise EvidenceError("Lambda decimal string required")
    n = Decimal(value)
    if not signed and n < 0 or integral and n != n.to_integral_value():
        raise EvidenceError("invalid Lambda quantity")
    return n


def _integer(value, optional=False):
    if value is None and optional:
        return None
    if type(value) is not int or value < 0 or value > 1000000000:
        raise EvidenceError("Lambda integral configuration required")
    return Decimal(value)


def _money(value):
    if value is None:
        return None
    if abs(value) >= Decimal("1e26"):
        raise EvidenceError("Lambda result exceeds DECIMAL(38,12)")
    return format(value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN), "f")


def _stamp(value):
    if not isinstance(value, str) or not (value.endswith("Z") or value.endswith("+00:00")):
        raise EvidenceError("Lambda UTC timestamp required")
    return instant(value)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _ref(value, refs, binding):
    if not isinstance(value, dict):
        return False
    _obj(value, ("kind", "id", "version", "sha256", "binding"))
    for k in ("kind", "id", "version"):
        _text(value.get(k))
    if not re.fullmatch("[a-f0-9]{64}", value.get("sha256", "")):
        raise EvidenceError("Lambda immutable hash required")
    if "binding" in value and any(binding.get(k) != v for k, v in _obj(value["binding"], BINDING).items()):
        raise EvidenceError("Lambda source binding mismatch")
    key = (value["kind"], value["id"], value["version"])
    if key in refs and refs[key] != value:
        raise EvidenceError("Lambda conflicting immutable references")
    refs[key] = value
    return True


def _metrics(observation, configuration, start, end):
    rows = observation.get("metrics", [])
    if not isinstance(rows, list) or len(rows) > 100000:
        raise EvidenceError("bounded Lambda metric rows required")
    groups = {}
    for row in rows:
        _obj(row)
        name = _text(row.get("metric"))
        stat = _text(row.get("statistic"))
        at = _stamp(row.get("source_time"))
        period = _integer(row.get("period_seconds"))
        if period <= 0 or period > 86400 or Decimal(86400) % period or at < start or at + timedelta(seconds=int(period)) > end or (at - start).total_seconds() % int(period):
            raise EvidenceError("Lambda metric period outside evidence window")
        if row.get("qualified_arn") != configuration.get("qualified_arn") or str(row.get("version")) != str(configuration.get("version")):
            raise EvidenceError("Lambda metric serving version mismatch")
        units = {"Invocations": "Count", "Errors": "Count", "Throttles": "Count", "ConcurrentExecutions": "Count", "Duration": "Milliseconds", "ProvisionedConcurrentExecutions": "Count", "ProvisionedConcurrencyInvocations": "Count", "ProvisionedConcurrencySpilloverInvocations": "Count", "ProvisionedConcurrencyUtilization": "None", "IteratorAge": "Milliseconds", "AsyncEventAge": "Milliseconds", "AsyncEventsReceived": "Count", "AsyncEventsDropped": "Count", "DestinationDeliveryFailures": "Count", "DeadLetterErrors": "Count"}
        if name in units and row.get("unit") != units[name]:
            raise EvidenceError("Lambda metric unit mismatch")
        value = _num(row.get("value"), integral=units.get(name) == "Count")
        samples = _num(row.get("sample_count"), optional=True, integral=True)
        key = (name, stat)
        g = groups.setdefault(key, {"seen": set(), "period": period, "values": [], "samples": [], "unit": row.get("unit")})
        if at in g["seen"] or g["period"] != period or g["unit"] != row.get("unit"):
            raise EvidenceError("duplicate or inconsistent Lambda metric bin")
        g["seen"].add(at)
        g["values"].append(value)
        g["samples"].append(samples)
    summary = {}
    for (name, stat), g in groups.items():
        expected = int((end - start).total_seconds()) // int(g["period"])
        complete = len(g["seen"]) == expected and all(v is not None and v > 0 for v in g["samples"])
        summary[name + ":" + stat] = {"total": _money(sum(g["values"], Decimal(0))) if stat == "Sum" else None,
                                     "maximum": _money(max(g["values"])) if g["values"] else None,
                                     "complete": complete, "unit": g["unit"], "observed_bins": len(g["seen"]), "expected_bins": expected}
    return summary


def _metric(summary, name, stat="Sum", maximum=False):
    row = summary.get(name + ":" + stat, {})
    if row.get("complete") is not True:
        return None
    return _num(row.get("maximum" if maximum else "total"), optional=True)


def _reports(observation, configuration, start, end, invocations):
    reports = _obj(observation.get("reports", {}))
    rows = reports.get("rows", [])
    if not isinstance(rows, list) or len(rows) > 20000:
        raise EvidenceError("bounded Lambda report snapshot required")
    seen, billed, duration, init, memory = set(), Decimal(0), Decimal(0), Decimal(0), None
    configuration_mixed = False
    for row in rows:
        _obj(row)
        rid = _text(row.get("request_id_hash") or row.get("cohort_id"))
        at = _stamp(row.get("event_time") or row.get("first_event_time"))
        last = _stamp(row.get("last_event_time")) if row.get("last_event_time") is not None else at
        if rid in seen or at < start or at >= end or last < at or last >= end or str(row.get("version")) != str(configuration.get("version")):
            raise EvidenceError("Lambda REPORT identity or period mismatch")
        seen.add(rid)
        count = _num(row.get("count", "1"), integral=True)
        if count <= 0:
            raise EvidenceError("Lambda report multiplicity required")
        allocated = _num(row.get("memory_size_mb"), integral=True)
        used = _num(row.get("max_memory_used_mb"))
        if used > allocated:
            raise EvidenceError("Lambda REPORT memory configuration mismatch")
        if allocated != _integer(configuration.get("memory_size_mb")):
            configuration_mixed = True
        duration += _num(row.get("duration_ms")) * count
        billed += _num(row.get("billed_duration_ms")) * count
        # INIT may be included in billed duration. Never add it a second time.
        init += (_num(row.get("init_duration_ms"), optional=True) or Decimal(0)) * count
        memory = used if memory is None else max(memory, used)
    coverage = _obj(reports.get("coverage", {}))
    count = sum((_num(r.get("count", "1"), integral=True) for r in rows), Decimal(0))
    complete = not configuration_mixed and coverage.get("status") == "COMPLETE_OBSERVED" and coverage.get("start") == observation["start"] and coverage.get("end") == observation["end"] and reports.get("truncated") is not True and coverage.get("cohort_rows_truncated") is not True and invocations is not None and count == invocations
    return {"status": "COMPLETE_OBSERVED" if complete else "PARTIAL" if seen else "UNAVAILABLE", "count": int(count),
            "total_duration_ms": _money(duration) if seen else None, "total_billed_duration_ms": _money(billed) if seen else None,
            "max_memory_used_mb": _money(memory), "init_duration_ms": _money(init) if seen else None,
            "memory_semantics": "EXECUTION_ENVIRONMENT_HIGH_WATER_NOT_EXACT_PER_INVOCATION", "configuration_mixed": configuration_mixed}


def _financial(data, refs, binding):
    billing = _obj(data.get("billing", {}))
    currency = billing.get("currency")
    if currency is not None and not re.fullmatch("[A-Z]{3}", currency):
        raise EvidenceError("Lambda currency required")
    reasons, components, totals, rates = set(), [], {}, {}
    if billing.get("start") != data["observation"].get("start") or billing.get("end") != data["observation"].get("end"):
        reasons.add("LAMBDA_BILLING_OBSERVATION_WINDOW_MISMATCH")
    for field in ("complete", "scope_complete", "marginal_pricing_known", "commitment_scope_known", "free_tier_resolved"):
        if billing.get(field) is not True:
            reasons.add("LAMBDA_" + field.upper() + "_REQUIRED")
    rows = billing.get("components", [])
    if not isinstance(rows, list) or len(rows) > 256:
        raise EvidenceError("bounded Lambda financial components required")
    seen = set()
    for row in rows:
        _obj(row)
        identity, category = _text(row.get("id")), row.get("component")
        if identity in seen or category not in COMPONENTS:
            raise EvidenceError("duplicate or unsupported Lambda charge component")
        seen.add(identity)
        amount = _num(row.get("amount"), signed=True)
        effective = _num(row.get("effective_amount"), optional=True, signed=True)
        quantity = _num(row.get("quantity"), optional=True)
        rate = _num(row.get("rate"), optional=True)
        if not _ref(row.get("source_ref"), refs, binding):
            reasons.add("LAMBDA_FINANCIAL_REFERENCE_REQUIRED")
        if row.get("currency") != currency:
            raise EvidenceError("Lambda component currency mismatch")
        if category == "CREDIT":
            if amount > 0:
                reasons.add("LAMBDA_POSITIVE_CREDIT_REQUIRES_REVIEW")
        elif category == "UNSUPPORTED":
            reasons.add("LAMBDA_UNSUPPORTED_FINANCIAL_COMPONENT")
        elif amount < 0:
            raise EvidenceError("negative Lambda usage is not a credit")
        if category not in ("CREDIT", "CONTINUING", "UNSUPPORTED"):
            if quantity is None or rate is None or quantity <= 0 or _money(rate * quantity) != _money(amount) or row.get("basis") != "AWS_CUR_NATIVE_NET" or row.get("marginal_pricing_known") is not True:
                reasons.add("LAMBDA_NATIVE_COMPONENT_RATE_UNAVAILABLE:" + category)
            else:
                key = (category, row.get("architecture"))
                if key in rates and rates[key] != (rate, row.get("unit")):
                    reasons.add("LAMBDA_RATE_TIERS_UNRESOLVED")
                rates[key] = (rate, row.get("unit"))
            bracket = row.get("rate_bracket")
            if not isinstance(bracket, dict) or bracket.get("resolved") is not True:
                reasons.add("LAMBDA_RATE_BRACKET_SCOPE_UNRESOLVED")
            else:
                lower = _num(bracket.get("begin"))
                upper = _num(bracket.get("end"), optional=True)
                aggregate = _num(bracket.get("aggregate_quantity"))
                if aggregate < lower or upper is not None and aggregate >= upper:
                    reasons.add("LAMBDA_RATE_BRACKET_SCOPE_UNRESOLVED")
        totals[category] = totals.get(category, Decimal(0)) + amount
        components.append({**row, "amount": _money(amount), "effective_amount": _money(effective)})
    if currency is None or not rows:
        reasons.add("LAMBDA_NATIVE_BILLING_UNAVAILABLE")
    result = {"status": "ECONOMICS_UNAVAILABLE" if reasons else "NATIVE_CUSTOMER_ECONOMICS", "currency": currency,
              "observed_billed_cost": _money(sum(totals.values(), Decimal(0))) if rows else None,
              "current_effective_cost": _money(sum((_num(c["effective_amount"], signed=True) for c in components), Decimal(0))) if rows and all(c["effective_amount"] is not None for c in components) else None,
              "current_request_cost": _money(totals.get("REQUEST")), "current_compute_cost": _money(sum((totals.get(c, Decimal(0)) for c in ("ON_DEMAND_COMPUTE", "PROVISIONED_COMPUTE")), Decimal(0))) if any(c in totals for c in ("ON_DEMAND_COMPUTE", "PROVISIONED_COMPUTE")) else None,
              "current_provisioned_capacity_cost": _money(totals.get("PROVISIONED_CAPACITY")),
              "continuing_cost": _money(sum((totals.get(c, Decimal(0)) for c in ("CONTINUING", "EVENT_POLLER", "STREAMING", "SNAPSTART")), Decimal(0))) if rows else None,
              "credits": _money(totals.get("CREDIT", Decimal(0))) if rows else None, "pricing_basis": "NATIVE_CUSTOMER_NET_ONLY", "components": components}
    return result, reasons, rates


def _curve(performance, configuration, binding, refs, as_of):
    rows = _obj(performance).get("receipts", [])
    if not isinstance(rows, list) or len(rows) > 64:
        raise EvidenceError("bounded Lambda performance receipts required")
    out, ids = [], set()
    for row in rows:
        _obj(row)
        rid = _text(row.get("id"))
        if rid in ids:
            raise EvidenceError("duplicate Lambda performance receipt")
        ids.add(rid)
        if row.get("provenance") not in ("REGISTERED_MACHINE_BENCHMARK", "NATIVE_CONFIGURATION_EPOCH"):
            continue
        if row.get("binding") != binding:
            raise EvidenceError("Lambda performance binding mismatch")
        if _stamp(row.get("received_at")) > as_of or _stamp(row.get("measurement_end")) > as_of or _stamp(row.get("measurement_start")) >= _stamp(row.get("measurement_end")):
            raise EvidenceError("Lambda performance period invalid")
        if not _ref(row.get("source_ref"), refs, binding):
            continue
        if row.get("code_sha256") != configuration.get("code_sha256") or row.get("qualifier") != configuration.get("qualifier"):
            continue
        parsed = {key: _num(row.get(key), optional=key in ("p95_application_latency_ms", "cold_start_p95_ms")) for key in ("invocations", "successful_work", "errors", "throttles", "total_duration_ms", "total_billed_duration_ms", "p95_duration_ms", "p99_duration_ms", "max_memory_used_mb", "peak_concurrent_executions", "p95_application_latency_ms", "cold_start_p95_ms")}
        memory = _integer(row.get("memory_size_mb"))
        if parsed["successful_work"] <= 0 or parsed["invocations"] <= 0 or parsed["errors"] > parsed["invocations"] or parsed["max_memory_used_mb"] > memory or parsed["p99_duration_ms"] < parsed["p95_duration_ms"]:
            raise EvidenceError("invalid Lambda performance cohort")
        comparable = tuple(_text(row.get(k)) for k in ("comparison_fingerprint", "workload_definition_id", "workload_definition_version", "workload_mix_hash", "load_profile_hash"))
        out.append({"row": row, "values": parsed, "memory": memory, "comparable": comparable})
    return out


def _empty_economics(currency):
    return {"status": "ECONOMICS_UNAVAILABLE", "currency": currency, "current_window_cost": None, "candidate_window_cost": None,
            "estimated_window_saving": None, "estimated_monthly_saving": None, "estimated_annual_saving": None,
            "component_costs": [], "pricing_basis": "NATIVE_CUSTOMER_NET_ONLY"}


def _candidate(identity, family, decision, reasons, authority, currency):
    return {"id": identity, "family": family, "status": "BLOCKED" if reasons else "NO_CHANGE", "decision": decision,
            "memory_size_mb": None, "architecture": None, "provisioned_concurrency": None, "physical_status": "BLOCKED" if reasons else "PASS",
            "checks": [], "performance": {k: None for k in ("duration_ms", "billed_duration_ms", "p95_duration_ms", "p99_duration_ms", "max_memory_used_mb", "successful_work", "errors", "throttles", "peak_concurrency")},
            "economics": _empty_economics(currency), "reason_codes": sorted(reasons), "confidence": {"status": "UNAVAILABLE" if reasons else "LIMITED", "reasons": sorted(reasons)},
            "implementation_method": "DECLARATIVE_REMEDIATION_REVIEW" if authority in ("TERRAFORM", "CLOUDFORMATION", "SAM", "CDK", "OTHER_DECLARATIVE") else "CUSTOMER_CONFIGURATION_REVIEW",
            "read_only": True, "pre_execution_ready": False, "execution_authorized": False, "verified_saving": None}


def _evaluate(data):
    _obj(data, ("schema_version", "model_version", "binding", "resource_id", "config_hash", "as_of", "configuration", "policy", "observation", "performance", "billing", "rates", "provider_recommendations", "source_refs"))
    if data.get("schema_version") != "1" or data.get("model_version") != MODEL_VERSION:
        raise EvidenceError("unsupported Lambda model version")
    binding = _obj(data.get("binding"), BINDING)
    for key in BINDING:
        _text(binding.get(key), optional=key == "workload_id")
    if binding["provider"] != "AWS" or not re.fullmatch("[0-9]{12}", binding["account_id"]) or data.get("resource_id") != binding["resource_id"] or not re.fullmatch("[a-f0-9]{64}", data.get("config_hash", "")):
        raise EvidenceError("invalid Lambda resource binding")
    as_of = _stamp(data.get("as_of"))
    configuration, policy, obs = (_obj(data.get(k, {})) for k in ("configuration", "policy", "observation"))
    refs, reasons = {}, set()
    for ref in data.get("source_refs", []):
        _ref(ref, refs, binding)
    if not refs:
        reasons.add("LAMBDA_IMMUTABLE_NATIVE_EVIDENCE_REQUIRED")
    start, end = _stamp(obs.get("start")), _stamp(obs.get("end"))
    if end <= start or end > as_of or any((s.hour or s.minute or s.second or s.microsecond) for s in (start, end)):
        raise EvidenceError("Lambda complete UTC observation days required")
    days = Decimal(str((end - start).total_seconds())) / 86400
    minimum = 90 if policy.get("seasonal") is True else 30 if policy.get("criticality") == "PRODUCTION" else 14
    if policy.get("criticality") not in ("PRODUCTION", "NON_PRODUCTION"):
        reasons.add("LAMBDA_CRITICALITY_UNKNOWN")
    if days < minimum:
        reasons.add("INSUFFICIENT_OBSERVATION")
    if as_of - end > timedelta(hours=48):
        reasons.add("LAMBDA_OBSERVATION_STALE")
    authority = policy.get("configuration_authority")
    if not policy.get("owner") or authority in (None, "UNKNOWN"):
        reasons.add("LAMBDA_OWNERSHIP_OR_AUTHORITY_UNKNOWN")
    if configuration.get("model") != "EVENT_DEFAULT":
        reasons.add("LAMBDA_FUNCTION_MODEL_UNSUPPORTED")
    memory = _integer(configuration.get("memory_size_mb"), optional=True)
    if memory is None or not 128 <= memory <= 10240:
        reasons.add("LAMBDA_MEMORY_CAPABILITY_UNSUPPORTED")
    for key in ("qualified_arn", "qualifier", "version", "code_sha256", "architecture"):
        if configuration.get(key) is None:
            reasons.add("LAMBDA_SERVING_CONFIGURATION_UNKNOWN")
    summary = _metrics(obs, configuration, start, end)
    invocations = _metric(summary, "Invocations")
    errors, throttles = _metric(summary, "Errors"), _metric(summary, "Throttles")
    concurrent = _metric(summary, "ConcurrentExecutions", "Maximum", True)
    for name, value in (("INVOCATIONS", invocations), ("ERRORS", errors), ("THROTTLES", throttles), ("CONCURRENCY", concurrent)):
        if value is None:
            reasons.add("LAMBDA_" + name + "_EVIDENCE_INCOMPLETE")
    if errors is not None and invocations is not None and errors > invocations:
        raise EvidenceError("Lambda errors exceed invocations")
    report = _reports(obs, configuration, start, end, invocations)
    economics, financial_reasons, rates = _financial(data, refs, binding)
    curve = _curve(data.get("performance", {}), configuration, binding, refs, as_of)
    candidates = []
    current = [p for p in curve if p["memory"] == memory and p["row"].get("architecture") == configuration.get("architecture") and str(p["row"].get("executed_version")) == str(configuration.get("version"))]
    current = current[0] if len(current) == 1 else None
    memory_reasons = set(reasons)
    if current is None:
        memory_reasons.add("LAMBDA_COMPARABLE_PERFORMANCE_CURVE_REQUIRED")
    if report["max_memory_used_mb"] is None:
        memory_reasons.add("LAMBDA_TRUSTED_MEMORY_EVIDENCE_REQUIRED")
    if report["status"] != "COMPLETE_OBSERVED":
        memory_reasons.add("LAMBDA_MEMORY_OBSERVATION_INCOMPLETE")
    if policy.get("latency_sensitive") not in (True, False):
        memory_reasons.add("LAMBDA_LATENCY_POLICY_UNKNOWN")
    if invocations == 0:
        memory_reasons.add("LAMBDA_NO_WORKLOAD_FOR_PERFORMANCE_COMPARISON")
    points = [p for p in curve if current is not None and p["comparable"] == current["comparable"] and p["row"].get("architecture") == configuration.get("architecture")]
    if not points:
        candidates.append(_candidate("memory-insufficient", "MEMORY", "INSUFFICIENT_EVIDENCE", memory_reasons, authority, economics["currency"]))
    for point in points:
        rs = set(memory_reasons)
        if not 128 <= point["memory"] <= 10240:
            rs.add("LAMBDA_MEMORY_CAPABILITY_UNSUPPORTED")
        pv, cv = point["values"], current["values"]
        item = _candidate("memory-" + point["row"]["id"], "MEMORY", "KEEP_CURRENT_MEMORY", rs, authority, economics["currency"])
        item["memory_size_mb"], item["architecture"] = int(point["memory"]), point["row"]["architecture"]
        ratio = pv["total_billed_duration_ms"] / pv["successful_work"] / (cv["total_billed_duration_ms"] / cv["successful_work"]) if cv["total_billed_duration_ms"] > 0 else None
        item["performance"] = {"duration_ms": _money(pv["total_duration_ms"] / pv["invocations"]), "billed_duration_ms": _money(pv["total_billed_duration_ms"] / pv["invocations"]), "p95_duration_ms": _money(pv["p95_duration_ms"]), "p99_duration_ms": _money(pv["p99_duration_ms"]), "max_memory_used_mb": _money(pv["max_memory_used_mb"]), "successful_work": _money(pv["successful_work"]), "errors": _money(pv["errors"]), "throttles": _money(pv["throttles"]), "peak_concurrency": _money(pv["peak_concurrent_executions"]), "source_receipt_ids": [current["row"]["id"], point["row"]["id"]]}
        def check(name, observed, limit, unit):
            status = "BLOCKED" if observed is None or limit is None else "PASS" if observed <= limit else "FAIL"
            item["checks"].append({"dimension": name, "status": status, "observed": _money(observed), "limit": _money(limit), "unit": unit})
            if status != "PASS":
                rs.add("LAMBDA_CANDIDATE_" + name.upper() + "_" + status)
        reserve = _num(policy.get("memory_headroom_fraction"), optional=True)
        if reserve is not None and reserve >= 1:
            raise EvidenceError("Lambda memory headroom must be below one")
        observed_memory = _num(report["max_memory_used_mb"], optional=True)
        observed_memory = max(observed_memory, pv["max_memory_used_mb"]) if observed_memory is not None else None
        check("memory", observed_memory, point["memory"] * (1 - reserve) if reserve is not None else None, "MB")
        check("error_rate", pv["errors"] / pv["invocations"], _num(policy.get("max_error_rate"), optional=True), "Fraction")
        check("throttle_rate", pv["throttles"] / pv["invocations"], _num(policy.get("max_throttle_rate"), optional=True), "Fraction")
        if errors and pv["errors"] / pv["invocations"] > cv["errors"] / cv["invocations"]:
            rs.add("LAMBDA_ERROR_REGRESSION")
        if throttles or pv["throttles"] > cv["throttles"]:
            rs.add("LAMBDA_THROTTLING_REQUIRES_REVIEW")
        timeout = _integer(configuration.get("timeout_seconds"), optional=True)
        check("duration", pv["p99_duration_ms"], min(timeout * 1000, _num(policy.get("max_duration_ms"))) if timeout is not None and policy.get("max_duration_ms") is not None else None, "Milliseconds")
        limit = _integer(configuration.get("reserved_concurrency"), optional=True)
        if limit is None:
            limit = _num(configuration.get("account_available_concurrency"), optional=True)
            cap = _num(policy.get("available_concurrency"), optional=True)
            if limit is not None and cap is not None:
                limit = min(limit, cap)
        headroom = _num(policy.get("concurrency_headroom_fraction"), optional=True)
        demand = concurrent * ratio if concurrent is not None and ratio is not None else None
        check("concurrency", max(demand, pv["peak_concurrent_executions"]) if demand is not None else None, limit * (1 - headroom) if limit is not None and headroom is not None else None, "Count")
        if policy.get("latency_sensitive") is True:
            check("latency", pv["p95_application_latency_ms"], _num(policy.get("latency_slo_ms"), optional=True), "Milliseconds")
        if policy.get("throughput_minimum") is not None:
            elapsed = Decimal(str((_stamp(point["row"]["measurement_end"]) - _stamp(point["row"]["measurement_start"])).total_seconds()))
            throughput, minimum_throughput = pv["successful_work"] / elapsed, _num(policy["throughput_minimum"])
            passed = throughput >= minimum_throughput
            item["checks"].append({"dimension": "throughput", "status": "PASS" if passed else "FAIL", "observed": _money(throughput), "limit": _money(minimum_throughput), "unit": "Work/Second"})
            if not passed:
                rs.add("LAMBDA_CANDIDATE_THROUGHPUT_FAIL")
        for age in ("IteratorAge", "AsyncEventAge"):
            if age + ":Maximum" in summary:
                check(age, _metric(summary, age, "Maximum", True), _num(policy.get("max_queue_age_ms"), optional=True), "Milliseconds")
        econ = _empty_economics(economics["currency"])
        money_reasons = set(financial_reasons)
        if ratio is None:
            money_reasons.add("LAMBDA_BILLED_DURATION_CURVE_REQUIRED")
        if not money_reasons:
            current_cost, target_cost, parts = Decimal(0), Decimal(0), []
            for component in economics["components"]:
                amount = _num(component["amount"], signed=True)
                target = amount
                if component["component"] in ("ON_DEMAND_COMPUTE", "PROVISIONED_COMPUTE"):
                    target *= point["memory"] / memory * ratio
                elif component["component"] == "PROVISIONED_CAPACITY":
                    target *= point["memory"] / memory
                elif component["component"] == "EPHEMERAL_STORAGE":
                    target *= ratio
                elif component["component"] == "REQUEST":
                    target *= (pv["invocations"] / pv["successful_work"]) / (cv["invocations"] / cv["successful_work"])
                bracket = component.get("rate_bracket")
                if isinstance(bracket, dict) and amount > 0:
                    aggregate = _num(bracket.get("aggregate_quantity"))
                    own_quantity = _num(component.get("quantity"))
                    candidate_aggregate = aggregate + own_quantity * (target / amount - 1)
                    lower, upper = _num(bracket.get("begin")), _num(bracket.get("end"), optional=True)
                    if candidate_aggregate < lower or upper is not None and candidate_aggregate >= upper:
                        money_reasons.add("LAMBDA_CANDIDATE_PRICE_BRACKET_CROSSED")
                current_cost += amount
                target_cost += target
                parts.append({"component": component["component"], "current_cost": _money(amount), "candidate_cost": _money(target)})
            saving = current_cost - target_cost
            econ.update(status="MODELLED_NATIVE_CUSTOMER_ECONOMICS", current_window_cost=_money(current_cost), candidate_window_cost=_money(target_cost), estimated_window_saving=_money(saving), estimated_monthly_saving=_money(saving / days / 24 * 730), component_costs=parts)
            if money_reasons:
                econ = _empty_economics(economics["currency"])
        item["economics"] = econ
        if rs:
            item["decision"], item["status"] = "INSUFFICIENT_EVIDENCE", "BLOCKED"
        elif point["memory"] == memory:
            item["decision"], item["status"] = "KEEP_CURRENT_MEMORY", "NO_CHANGE"
        elif money_reasons:
            rs.update(money_reasons)
            item["decision"], item["status"] = "INSUFFICIENT_EVIDENCE", "BLOCKED"
        elif Decimal(econ["estimated_window_saving"]) > 0:
            item["decision"], item["status"] = ("REDUCE_MEMORY" if point["memory"] < memory else "INCREASE_MEMORY_FOR_LOWER_COST"), "RECOMMENDED"
        elif point["memory"] > memory and pv["p95_duration_ms"] < cv["p95_duration_ms"] and policy.get("performance_improvement_required") is True:
            item["decision"], item["status"] = "INCREASE_MEMORY_FOR_PERFORMANCE", "RECOMMENDED"
        else:
            item["decision"], item["status"] = "KEEP_CURRENT_MEMORY", "NO_CHANGE"
            rs.add("LAMBDA_CANDIDATE_NOT_CHEAPER")
        item["physical_status"] = "FAIL" if any(c["status"] == "FAIL" for c in item["checks"]) else "BLOCKED" if rs and item["status"] == "BLOCKED" else "PASS"
        item["reason_codes"] = sorted(rs)
        item["confidence"] = {"status": "MEDIUM" if item["status"] != "BLOCKED" else "UNAVAILABLE", "reasons": sorted(rs | {"CUSTOMER_BENCHMARK_NOT_TARGET_CANARY", "HISTORICAL_DEMAND_AND_RATES_HELD_CONSTANT"})}
        if item["status"] == "BLOCKED":
            item["economics"]["estimated_window_saving"] = None
            item["economics"]["estimated_monthly_saving"] = None
        candidates.append(item)

    # Provisioned capacity is paid independently of invocation duration. Use
    # observed maxima and declared reserve, never average utilization division.
    pc = configuration.get("provisioned_concurrency")
    pc_count = _integer(pc, optional=True) if pc is None or type(pc) is int else None
    pc_reasons = set(reasons)
    pc_item = _candidate("provisioned-concurrency", "PROVISIONED_CONCURRENCY", "KEEP_CURRENT", pc_reasons, authority, economics["currency"])
    if pc_count is not None and pc_count > 0:
        peak = _metric(summary, "ProvisionedConcurrentExecutions", "Maximum", True)
        spill = _metric(summary, "ProvisionedConcurrencySpilloverInvocations")
        pci = _metric(summary, "ProvisionedConcurrencyInvocations")
        utilization = _metric(summary, "ProvisionedConcurrencyUtilization", "Maximum", True)
        if any(v is None for v in (peak, spill, pci, utilization)):
            pc_reasons.add("LAMBDA_PROVISIONED_OBSERVATION_INCOMPLETE")
        if policy.get("bursts_known") is not True or policy.get("latency_sensitive") not in (True, False):
            pc_reasons.add("LAMBDA_BURST_OR_LATENCY_POLICY_UNKNOWN")
        minimum_pc = _num(policy.get("minimum_provisioned_concurrency"), optional=True, integral=True)
        reserve = _num(policy.get("concurrency_headroom_fraction"), optional=True)
        if minimum_pc is None or reserve is None or reserve >= 1:
            pc_reasons.add("LAMBDA_PROVISIONED_MINIMUM_OR_RESERVE_UNKNOWN")
        target = max(minimum_pc, (peak / (1 - reserve)).to_integral_value(rounding="ROUND_CEILING")) if peak is not None and minimum_pc is not None and reserve is not None and reserve < 1 else None
        if spill and target is not None:
            target = max(pc_count, target)
            pc_reasons.add("LAMBDA_SPILLOVER_PREVENTS_REDUCTION")
        if (policy.get("latency_sensitive") is True or policy.get("requires_warm_capacity") is True) and target == 0:
            pc_reasons.add("LAMBDA_COLD_START_SLO_REQUIRES_WARM_CAPACITY")
        pc_item["provisioned_concurrency"] = int(target) if target is not None else None
        if target is not None and not pc_reasons:
            if target < pc_count:
                pc_item["decision"] = "REMOVE_PROVISIONED_CONCURRENCY_REVIEW" if target == 0 else "REDUCE_PROVISIONED_CONCURRENCY"
                pc_item["status"] = "RECOMMENDED"
            elif target > pc_count:
                pc_item["decision"], pc_item["status"] = "INCREASE_PROVISIONED_CONCURRENCY", "RECOMMENDED"
            if not financial_reasons:
                capacity_cost = _num(economics["current_provisioned_capacity_cost"], optional=True)
                if capacity_cost is not None:
                    saving = capacity_cost * (1 - target / pc_count)
                    pc_item["economics"].update(status="MODELLED_NATIVE_CUSTOMER_ECONOMICS", current_window_cost=_money(capacity_cost), candidate_window_cost=_money(capacity_cost - saving), estimated_window_saving=_money(saving), estimated_monthly_saving=_money(saving / days / 24 * 730), component_costs=[{"component": "PROVISIONED_CAPACITY", "current_cost": _money(capacity_cost), "candidate_cost": _money(capacity_cost - saving)}])
            if pc_item["economics"]["status"] == "ECONOMICS_UNAVAILABLE" and pc_item["status"] == "RECOMMENDED":
                pc_reasons.update(financial_reasons or {"LAMBDA_PROVISIONED_CUSTOMER_RATE_UNAVAILABLE"})
        # Existing histories can identify a scheduling review; the evaluator
        # does not invent zero demand for unobserved off-hours.
        active_windows = policy.get("active_windows")
        if active_windows and obs.get("off_hours_coverage") == "COMPLETE_ZERO_OBSERVED" and policy.get("off_hours_warm_required") is False and not pc_reasons:
            scheduling = _candidate("provisioned-schedule", "PROVISIONED_CONCURRENCY", "AUTO_SCALE_PROVISIONED_CONCURRENCY_REVIEW", set(), authority, economics["currency"])
            scheduling["status"] = "RECOMMENDED"
            scheduling["reason_codes"] = ["LAMBDA_SCHEDULE_COST_REQUIRES_ALLOCATION_EPOCHS_AND_FIVE_MINUTE_ROUNDING"]
            candidates.append(scheduling)
    elif pc_count is None:
        pc_reasons.add("LAMBDA_PROVISIONED_CONFIGURATION_UNKNOWN")
    pc_item["reason_codes"] = sorted(pc_reasons)
    if pc_reasons:
        pc_item["status"], pc_item["decision"] = "BLOCKED", "INSUFFICIENT_EVIDENCE"
    candidates.append(pc_item)

    architecture_reasons = set(reasons)
    arm = _candidate("arm64-review", "ARCHITECTURE", "KEEP_CURRENT", architecture_reasons, authority, economics["currency"])
    arm["architecture"] = "arm64"
    if configuration.get("architecture") == "x86_64":
        compatibility = _obj(policy.get("architecture_compatibility", {}))
        required = ("runtime", "package", "native_dependencies", "layers", "extensions", "container_image", "customer_declaration")
        if any(compatibility.get(k) == "INCOMPATIBLE" for k in required):
            architecture_reasons.add("LAMBDA_ARM64_DEPENDENCY_INCOMPATIBLE")
        elif not all(compatibility.get(k) in ("COMPATIBLE", "NOT_APPLICABLE") for k in required):
            architecture_reasons.add("LAMBDA_ARM64_COMPATIBILITY_UNKNOWN")
        else:
            arm["decision"], arm["status"] = "ARM64_BENCHMARK_RECOMMENDED", "RECOMMENDED"
            arm["reason_codes"] = ["LAMBDA_ARM64_COMPARABLE_CUSTOMER_BENCHMARK_AND_NATIVE_RATE_REQUIRED", "FUTURE_WEIGHTED_ALIAS_CANARY_DESIGN_ONLY"]
    if architecture_reasons:
        arm["status"], arm["reason_codes"] = "BLOCKED", sorted(architecture_reasons)
    candidates.append(arm)
    performance = _candidate("performance-review", "PERFORMANCE", "KEEP_CURRENT", reasons, authority, economics["currency"])
    duration_max = _metric(summary, "Duration", "Maximum", True)
    threshold = _num(policy.get("performance_review_duration_ms"), optional=True)
    if duration_max is not None and threshold is not None and duration_max >= threshold and not reasons:
        performance["status"], performance["decision"], performance["reason_codes"] = "RECOMMENDED", "SERVERLESS_PERFORMANCE_REVIEW", ["LAMBDA_PERFORMANCE_CAUSE_UNDETERMINED"]
    candidates.append(performance)
    reserved = _candidate("reserved-concurrency-review", "RESERVED_CONCURRENCY", "KEEP_CURRENT", reasons, authority, economics["currency"])
    if throttles and not reasons:
        reserved["status"], reserved["decision"], reserved["reason_codes"] = "RECOMMENDED", "RESERVED_CONCURRENCY_POLICY_REVIEW", ["RESERVED_CONCURRENCY_HAS_NO_PAID_IDLE_CAPACITY_SAVING"]
    candidates.append(reserved)

    families = []
    for family in FAMILIES:
        members = [c for c in candidates if c["family"] == family]
        positive = [c for c in members if c["status"] == "RECOMMENDED"]
        unblocked = [c for c in members if c["status"] == "NO_CHANGE"]
        chosen = min(positive, key=lambda c: (Decimal(c["economics"]["candidate_window_cost"]) if c["economics"]["candidate_window_cost"] is not None else Decimal("1e25"), c["id"])) if positive else unblocked[0] if unblocked else members[0]
        families.append({"family": family, "status": chosen["status"], "decision": chosen["decision"], "reason_codes": chosen["reason_codes"]})
    provider = data.get("provider_recommendations", [])
    if not isinstance(provider, list) or len(provider) > 100:
        raise EvidenceError("bounded Lambda provider recommendations required")
    ours = [{"family": f["family"], "decision": f["decision"]} for f in families]
    selected_memory = next((c for c in candidates if c["family"] == "MEMORY" and c["status"] == "RECOMMENDED"), None)
    provider_sizes = set()
    for advice in provider:
        options = advice.get("memorySizeRecommendationOptions", [])
        if isinstance(options, list):
            for option in options:
                if isinstance(option, dict) and type(option.get("memorySize")) is int:
                    provider_sizes.add(option["memorySize"])
    difference = "NO_PROVIDER_ADVICE" if not provider else "AGREES" if selected_memory is not None and selected_memory["memory_size_mb"] in provider_sizes else "DIFFERS"
    status = "RECOMMENDED" if any(c["status"] == "RECOMMENDED" for c in candidates) else "BLOCKED" if all(f["status"] == "BLOCKED" for f in families) else "NO_CHANGE"
    analysed = set()
    for candidate in candidates:
        if candidate["status"] in ("RECOMMENDED", "NO_CHANGE") and candidate["economics"]["status"] == "MODELLED_NATIVE_CUSTOMER_ECONOMICS":
            analysed.update(part["component"] for part in candidate["economics"]["component_costs"])
    analysed_components = [{"component": name, "source_record_ids": sorted(c["id"] for c in economics["components"] if c["component"] == name)} for name in sorted(analysed)]
    output = {"schema_version": "1", "model_version": MODEL_VERSION, "model_kind": MODEL_KIND, "binding": binding, "resource_id": data["resource_id"], "config_hash": data["config_hash"], "configuration": configuration,
              "status": status, "reason_codes": sorted(reasons), "decision_families": families, "candidates": candidates,
              "observations": {"start": obs["start"], "end": obs["end"], "history_days": _money(days), "metrics_summary": summary, "report_summary": report},
              "economics": economics, "confidence": {"status": "UNAVAILABLE" if status == "BLOCKED" else "MEDIUM" if report["status"] == "COMPLETE_OBSERVED" and len(points)>1 and not financial_reasons else "LIMITED", "reasons": ["OBSERVED_COMPARABLE_COHORT_SCREEN_NOT_CALIBRATED_PROBABILITY", "PROVIDER_ADVICE_IS_SUPPORTING_EVIDENCE_ONLY", "INVOCATION_VOLUME:" + (_money(invocations) if invocations is not None else "UNKNOWN"), "HISTORY_DAYS:" + _money(days), "MEMORY_COVERAGE:" + report["status"], "COMPARABLE_MEMORY_POINTS:" + str(len(points))]},
              "provider_recommendation": provider, "our_recommendation": ours, "difference": difference,
              "reason_for_difference": ["INDEPENDENT_MEMORY_PERFORMANCE_SAFETY_AND_NATIVE_CUSTOMER_ECONOMICS"] if provider else ["PROVIDER_ADVICE_UNAVAILABLE_DOES_NOT_EXCLUDE_FUNCTION"],
              "configuration_authority": authority, "implementation_method": candidates[0]["implementation_method"], "source_refs": sorted(refs.values(), key=lambda r: (r["kind"], r["id"], r["version"])),
              "analysed_components": analysed_components, "economically_analysed_source_record_ids": sorted({identity for component in analysed_components for identity in component["source_record_ids"]}),
              "proposal": {"risk_class": "R2", "executable": False, "execution_authorized": False}, "read_only": True, "pre_execution_ready": False, "execution_authorized": False, "verified_saving": None}
    output["assessment_hash"] = _hash(output)
    return output


def evaluate_lambda(data):
    with localcontext() as ctx:
        ctx.prec = 60
        return _evaluate(data)
