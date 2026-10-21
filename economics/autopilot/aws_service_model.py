"""Bounded read-only AWS service decisions from server-selected native evidence.

This private worker validates evidence interpretation and exact arithmetic. It
does not authenticate AWS, enable instrumentation, purchase or mutate resources.
"""
from datetime import timedelta
from decimal import Decimal, ROUND_CEILING, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import re

from .model import EvidenceError, instant

MODEL_KIND = "AWS_SERVICE_ASSESSMENT_V1"
MODEL_VERSION = "aws-service-v1"
ROUTE = "/v12/aws-service-assessment"
BINDING = {"tenant_id", "provider", "account_id", "region", "resource_id", "provider_resource_id", "workload_id"}
FAMILIES = {"ECS", "DYNAMODB", "ELASTICACHE", "ELB"}


def _obj(value, allowed=None):
    if not isinstance(value, dict) or allowed is not None and set(value) - set(allowed):
        raise EvidenceError("unsupported AWS service fields")
    return value


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise EvidenceError("AWS service identity required")
    return value


def _num(value, optional=False, signed=False):
    if optional and value in (None, ""):
        return None
    if not isinstance(value, str) or not re.fullmatch(r"-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?", value):
        raise EvidenceError("AWS service decimal string required")
    result = Decimal(value)
    if not signed and result < 0:
        raise EvidenceError("AWS service negative quantity")
    return result


def _native(value, optional=False):
    if optional and value is None:
        return None
    if type(value) is int and value >= 0:
        return Decimal(value)
    return _num(value, optional)


def _money(value):
    if value is None:
        return None
    if abs(value) >= Decimal("1e26"):
        raise EvidenceError("AWS service amount outside DECIMAL(38,12)")
    return format(value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN), "f")


def _stamp(value):
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        raise EvidenceError("UTC AWS service timestamp required")
    return instant(value)


def _ref(value, binding):
    _obj(value)
    for key in ("kind", "id", "version"):
        _text(value.get(key))
    if not re.fullmatch("[a-f0-9]{64}", value.get("sha256", "")):
        raise EvidenceError("immutable AWS service reference required")
    if "binding" in value and any(binding.get(k) != v for k, v in _obj(value["binding"], BINDING).items()):
        raise EvidenceError("AWS service source binding mismatch")


def _history(data, policy):
    obs = _obj(data.get("observations", {}))
    end, supplied_start, now = _stamp(obs.get("end")), _stamp(obs.get("start")), _stamp(data.get("now"))
    days = 90 if policy.get("seasonal") is True else 14 if policy.get("criticality") == "NON_PRODUCTION" else 30
    start = end - timedelta(days=days)
    reasons = []
    if end > now or end.hour or end.minute or end.second or end.microsecond or now - end > timedelta(hours=48):
        reasons.append("AWS_SERVICE_OBSERVATION_WINDOW_STALE_OR_INCOMPLETE")
    if supplied_start > start or supplied_start >= end:
        reasons.append("AWS_SERVICE_INSUFFICIENT_OBSERVATION_HISTORY")
    rows = obs.get("metrics", [])
    if not isinstance(rows, list) or len(rows) > 100000:
        raise EvidenceError("bounded AWS service metric samples required")
    groups = {}
    for row in rows:
        _obj(row)
        at = _stamp(row.get("source_time"))
        if at < supplied_start or at >= end:
            raise EvidenceError("AWS service metric outside acquired window")
        if row.get("provider_resource_id") != data["binding"]["provider_resource_id"]:
            raise EvidenceError("AWS service metric resource mismatch")
        period = row.get("period_seconds")
        if type(period) is not int or period < 1 or period > 86400 or 86400 % period:
            raise EvidenceError("AWS service native metric period required")
        value, count = _num(row.get("value")), _num(row.get("sample_count"))
        if count <= 0:
            raise EvidenceError("observed native sample count required")
        metric, statistic, unit = (_text(row.get(k)) for k in ("metric", "statistic", "unit"))
        if statistic not in ("Maximum", "Minimum", "Sum", "Average"):
            raise EvidenceError("unsupported aggregated AWS statistic")
        dimensions = _obj(row.get("dimensions", {}))
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in dimensions.items()):
            raise EvidenceError("native metric dimensions required")
        if at < start:
            continue
        if at + timedelta(seconds=period) > end or (at-start).total_seconds() % period:
            raise EvidenceError("AWS service metric bin misaligned")
        identity = (metric, statistic, json.dumps(dimensions, sort_keys=True))
        g = groups.setdefault(identity, {"metric": metric, "statistic": statistic, "unit": unit, "period": period,
                                         "dimensions": dimensions, "values": [], "seen": set(), "sample_count": Decimal(0)})
        if at in g["seen"] or period != g["period"] or unit != g["unit"]:
            raise EvidenceError("conflicting AWS service metric bin")
        g["seen"].add(at)
        g["values"].append(value)
        g["sample_count"] += count
    summary = []
    for identity in sorted(groups):
        g = groups[identity]
        expected = days * 86400 // g["period"]
        complete = len(g["seen"]) == expected and supplied_start <= start
        summary.append({"metric": g["metric"], "statistic": g["statistic"], "unit": g["unit"], "dimensions": g["dimensions"],
                        "period_seconds": g["period"], "observed_bins": len(g["seen"]), "expected_bins": expected,
                        "coverage": "COMPLETE_OBSERVED" if complete else "UNKNOWN_GAPS", "sample_count": _money(g["sample_count"]),
                        "maximum": _money(max(g["values"])), "minimum": _money(min(g["values"])),
                        "total": _money(sum(g["values"], Decimal(0))) if g["statistic"] == "Sum" else None,
                        "semantics": "NATIVE_PERIOD_STATISTIC_NOT_RAW_EVENT_PERCENTILE"})
    expected_series=obs.get("expected_series",[])
    if not isinstance(expected_series,list) or len(expected_series)>512:raise EvidenceError("bounded native metric selectors required")
    for selector in expected_series:
        _obj(selector)
        identity=(_text(selector.get("metric")),_text(selector.get("statistic")),json.dumps(_obj(selector.get("dimensions",{})),sort_keys=True))
        if identity not in groups:
            period=selector.get("period_seconds")
            if type(period) is not int or period<1 or period>86400 or 86400%period:raise EvidenceError("native metric selector period required")
            summary.append({"metric":identity[0],"statistic":identity[1],"unit":_text(selector.get("unit")),"dimensions":selector.get("dimensions",{}),"period_seconds":period,"observed_bins":0,"expected_bins":days*86400//period,"coverage":"UNKNOWN_GAPS","sample_count":None,"maximum":None,"minimum":None,"total":None,"semantics":"MISSING_SERIES_NOT_ZERO"})
    return start, end, summary, reasons


def _metric(summary, name, statistic="Maximum", aggregate="max", unit=None):
    rows = [r for r in summary if r["metric"] == name and r["statistic"] == statistic]
    if not rows or any(r["coverage"] != "COMPLETE_OBSERVED" or unit is not None and r["unit"] != unit for r in rows):
        return None
    values = [_num(r["total"] if aggregate == "sum" else r["minimum"] if aggregate == "min" else r["maximum"]) for r in rows]
    return sum(values, Decimal(0)) if aggregate == "sum" else min(values) if aggregate == "min" else max(values)


def _financial(data, start, end):
    b = _obj(data.get("billing", {}))
    reasons, components, rates = [], [], []
    if any(b.get(k) is not True for k in ("complete", "scope_complete", "marginal_pricing_known", "commitment_scope_known")):
        reasons.append("AWS_SERVICE_NATIVE_CUSTOMER_ECONOMICS_OR_COMMITMENT_SCOPE_UNAVAILABLE")
    if not b.get("start") or not b.get("end") or _stamp(b["start"]) != start or _stamp(b["end"]) != end:
        reasons.append("AWS_SERVICE_FINANCIAL_WINDOW_MISMATCH")
    currency = b.get("currency")
    if currency is not None and (not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency)):
        raise EvidenceError("AWS service currency invalid")
    if currency is None:
        reasons.append("AWS_SERVICE_CURRENCY_UNAVAILABLE")
    seen, currencies = set(), set()
    units = {"FARGATE_CPU":{"vCPU-Hours","vCPU-Hrs","vCPU-hours"},"FARGATE_MEMORY":{"GB-Hours","GB-Hrs","GB-hours"},"FARGATE_EPHEMERAL":{"GB-Hours","GB-Hrs","GB-hours"},"READ_PROVISIONED":{"Hrs","Hours"},"WRITE_PROVISIONED":{"Hrs","Hours"},"READ_REQUEST":{"ReadRequestUnits","Requests"},"WRITE_REQUEST":{"WriteRequestUnits","Requests"},"CACHE_NODE":{"Hrs","Hours"}}
    for row in b.get("components", []):
        _obj(row)
        identity = _text(row.get("id"))
        if identity in seen:
            raise EvidenceError("duplicate canonical AWS service charge")
        seen.add(identity)
        amount = _num(row.get("amount"), signed=True)
        effective = _num(row.get("effective_amount"), optional=True, signed=True)
        component = _text(row.get("component"))
        units = {"FARGATE_CPU":{"vCPU-Hours","vCPU-Hrs","vCPU-hours"},"FARGATE_MEMORY":{"GB-Hours","GB-Hrs","GB-hours"},"FARGATE_EPHEMERAL":{"GB-Hours","GB-Hrs","GB-hours"},"READ_PROVISIONED":{"Hrs","Hours"},"WRITE_PROVISIONED":{"Hrs","Hours"},"READ_REQUEST":{"ReadRequestUnits","Requests"},"WRITE_REQUEST":{"WriteRequestUnits","Requests"},"CACHE_NODE":{"Hrs","Hours"}}
        if row.get("avoidability") == "MARGINAL" and row.get("unit") not in units.get(component,set()):
            raise EvidenceError("native customer charge unit mismatch")
        row_currency = row.get("currency")
        if row_currency is not None:
            currencies.add(row_currency)
        _ref(row.get("source_ref"), data["binding"])
        quantity, rate = _num(row.get("quantity"), optional=True), _num(row.get("rate"), optional=True)
        if row.get("avoidability") == "MARGINAL" and (quantity is None or rate is None or quantity * rate != amount or amount < 0):
            raise EvidenceError("altered native customer rate arithmetic")
        components.append({**row, "_amount": amount, "_effective": effective, "_quantity": quantity, "_rate": rate, "component": component})
    if len(currencies) > 1 or currencies and currencies != {currency}:
        reasons.append("AWS_SERVICE_CURRENCY_SCOPE_MISMATCH")
    if not components:
        reasons.append("AWS_SERVICE_CANONICAL_BILLING_REQUIRED")
    for rate in b.get("rate_witnesses", []):
        _obj(rate)
        value = _num(rate.get("rate"))
        _ref(rate.get("source_ref"), data["binding"])
        if rate.get("currency") != currency or rate.get("bracket_resolved") is not True:
            reasons.append("AWS_SERVICE_RATE_DIMENSIONS_OR_BRACKET_UNRESOLVED")
        if rate.get("component") in units and rate.get("unit") not in units[rate["component"]]:
            raise EvidenceError("native customer rate unit mismatch")
        rates.append({**rate, "_rate": value})
    return {"currency": currency, "components": components, "rates": rates, "reasons": sorted(set(reasons)),
            "current": sum((r["_amount"] for r in components), Decimal(0)) if currency and currencies == {currency} else None,
            "hours": Decimal(str((end-start).total_seconds()))/Decimal(3600)}


def _rate(fin, component, candidate_key=None):
    matches = [r for r in fin["rates"] if r.get("component") == component and (candidate_key is None or r.get("candidate_key") == candidate_key)]
    values = {r["_rate"] for r in matches}
    return next(iter(values)) if len(values) == 1 and all(r.get("bracket_resolved") is True for r in matches) else None


def _econ(fin, replacement=None, conditional=None):
    reasons = list(fin["reasons"])
    candidate = None
    if replacement is not None:
        current_replaced = [r for r in fin["components"] if r["component"] in replacement]
        if not current_replaced or any(r.get("avoidability") != "MARGINAL" for r in current_replaced):
            reasons.append("AWS_SERVICE_AVOIDABLE_EXPOSURE_UNPROVEN")
        if any(v is None for v in replacement.values()):
            reasons.append("AWS_SERVICE_CANDIDATE_CUSTOMER_RATE_REQUIRED")
        if not reasons and fin["current"] is not None:
            candidate = fin["current"] - sum((r["_amount"] for r in current_replaced), Decimal(0)) + sum(replacement.values(), Decimal(0))
    return {"status": "NATIVE_CUSTOMER_ECONOMICS" if candidate is not None else "ECONOMICS_UNAVAILABLE", "currency": fin["currency"],
            "observed_billed_window_cost": _money(fin["current"]), "current_window_cost": _money(fin["current"]),
            "candidate_window_cost": _money(candidate), "estimated_window_saving": _money(fin["current"]-candidate) if candidate is not None else None,
            "conditional_monthly_run_rate": None, "basis": "MODELLED_NATIVE_CUSTOMER_MARGINAL_COMPARISON" if candidate is not None else "UNAVAILABLE",
            "reason_codes": sorted(set(reasons)), "assumptions": conditional or [], "credits_and_continuing_costs_retained": True}


def _candidate(identity, kind, current, proposed, reasons, economics, decision=None, review=False):
    if reasons:
        status, decision = "BLOCKED", decision or "INSUFFICIENT_EVIDENCE"
        economics = {**economics, "status": "ECONOMICS_UNAVAILABLE", "candidate_window_cost": None, "estimated_window_saving": None}
    elif review:
        status, decision = "RECOMMENDED", decision or "HUMAN_REVIEW_REQUIRED"
    elif economics["estimated_window_saving"] is None:
        status, decision = "BLOCKED", decision or "CUSTOMER_ECONOMICS_UNAVAILABLE"
        reasons = economics["reason_codes"] or ["AWS_SERVICE_CUSTOMER_ECONOMICS_UNAVAILABLE"]
    elif Decimal(economics["estimated_window_saving"]) > 0:
        status, decision = "RECOMMENDED", decision or "ECONOMICALLY_JUSTIFIED_READ_ONLY_PROPOSAL"
    else:
        status, decision = "NO_CHANGE", decision or "KEEP_CURRENT_NEGATIVE_OR_ZERO_OUTCOME"
    return {"id": identity, "recommendation_kind": kind, "status": status, "decision_code": decision, "reason_codes": sorted(set(reasons)),
            "current_configuration": current, "proposed_configuration": proposed, "economics": economics,
            "confidence": {"status": "UNAVAILABLE" if reasons else "BOUNDED_EVIDENCE", "reason_codes": sorted(set(reasons))},
            "risk_class": "R3", "read_only": True, "pre_execution_ready": False, "execution_authorized": False, "verified_saving": None}


def _limits(policy):
    constraints = _obj(policy.get("service_constraints", {}))
    values = {}
    for key, value in constraints.items():
        if value is not None and type(value) not in (bool, str, dict, int):
            raise EvidenceError("invalid AWS service policy type")
        values[key] = value
    return values


def _required_constraints(limits, names):
    return ["AWS_SERVICE_POLICY_"+name.upper()+"_REQUIRED" for name in names if limits.get(name) is None]


def _application_guards(summary, limits):
    reasons=[]
    if limits.get("max_latency_ms") is not None:
        latency=_metric(summary,"ApplicationLatency",unit="Milliseconds")
        if latency is None:reasons.append("AWS_SERVICE_APPLICATION_LATENCY_EVIDENCE_REQUIRED")
        elif latency>_num(limits["max_latency_ms"]):reasons.append("AWS_SERVICE_APPLICATION_HARD_LATENCY_SLO_BREACH")
    if limits.get("max_error_rate") is not None:
        errors=_metric(summary,"ApplicationErrors","Sum","sum","Count")
        success=_metric(summary,"SuccessfulWork","Sum","sum","Count")
        if errors is None or success is None:reasons.append("AWS_SERVICE_SUCCESS_AND_ERROR_EVIDENCE_REQUIRED")
        elif (errors/(errors+success) if errors+success else Decimal(0)) > _num(limits["max_error_rate"]):reasons.append("AWS_SERVICE_APPLICATION_ERROR_SLO_BREACH")
    if limits.get("max_queue_age_ms") is not None:
        age=_metric(summary,"QueueAge",unit="Milliseconds")
        if age is None:reasons.append("AWS_SERVICE_QUEUE_DELAY_EVIDENCE_REQUIRED")
        elif age>_num(limits["max_queue_age_ms"]):reasons.append("AWS_SERVICE_QUEUE_DELAY_SLO_BREACH")
    return reasons


def _ecs(data, summary, fin, base):
    c, limits = data["configuration"], _limits(data["policy"])
    # Resource utilisation and a current SLO probe do not establish historical
    # demand. All ECS decisions retain the independently observed work window.
    activity = _activity(data, summary)
    base = list(base)
    if activity is None:
        base.append("ECS_INDEPENDENT_WORKLOAD_ACTIVITY_REQUIRED")
    task = _obj(c.get("task_definition", {}))
    cpu, memory = _native(task.get("cpu"), True), _native(task.get("memory"), True)
    replicas = _native(c.get("runningCount"), True)
    max_replicas = _metric(summary, "RunningTaskCount", "Maximum", unit="Count")
    min_replicas = _metric(summary, "RunningTaskCount", "Minimum", "min", "Count")
    cpu_peak, memory_peak = _metric(summary, "CPUUtilization", unit="Percent"), _metric(summary, "MemoryUtilization", unit="Percent")
    reasons = list(base) + _application_guards(summary,limits) + _required_constraints(limits, ("cpu_headroom_fraction", "memory_headroom_fraction", "burst_requirements_known", "autoscaling_reviewed"))
    if cpu is None or memory is None or replicas is None or replicas <= 0:
        reasons.append("ECS_TASK_RESOURCES_OR_RUNNING_REPLICAS_UNKNOWN")
    if cpu_peak is None or memory_peak is None or min_replicas is None or max_replicas is None:
        reasons.append("ECS_CPU_MEMORY_AND_SCALING_PEAK_EVIDENCE_REQUIRED")
    if "fargate_cohort" in c and (min_replicas != replicas or max_replicas != replicas):
        reasons.append("ECS_STEADY_NATIVE_TASK_COHORT_HISTORY_REQUIRED")
    if limits.get("burst_requirements_known") is not True or limits.get("autoscaling_reviewed") is not True:
        reasons.append("ECS_BURST_AND_AUTOSCALING_REQUIREMENTS_UNRESOLVED")
    if _native(c.get("pendingCount", 0)) > 0 or _native(c.get("desiredCount", 0)) != replicas:
        reasons.append("ECS_DEPLOYMENT_OR_CAPACITY_UNSTABLE")
    deployments = c.get("deployments", [])
    if len(deployments) > 1 or any(d.get("rolloutState") not in (None, "COMPLETED") for d in deployments):
        reasons.append("ECS_DEPLOYMENT_IN_PROGRESS")
    candidates = []
    shapes = _obj(data.get("capabilities", {})).get("candidates", [])
    if not shapes:
        reasons.append("ECS_COMPATIBLE_TASK_SHAPES_REQUIRED")
    head_cpu = _num(limits.get("cpu_headroom_fraction"), True)
    head_mem = _num(limits.get("memory_headroom_fraction"), True)
    if any(v is not None and v >= 1 for v in (head_cpu, head_mem)):
        raise EvidenceError("headroom must be less than one")
    for shape in shapes[:256]:
        _obj(shape)
        candidate_cpu, candidate_mem = _num(shape.get("cpu_units")), _num(shape.get("memory_mib"))
        if candidate_cpu <= 0 or candidate_mem <= 0:
            raise EvidenceError("positive ECS candidate capacity required")
        _ref(shape.get("source_ref"), data["binding"])
        if cpu is not None and memory is not None and (candidate_cpu > cpu or candidate_mem > memory):
            continue
        blocked = list(reasons)
        runtime=_obj(task.get("runtimePlatform",{}))
        if shape.get("architecture")!=runtime.get("cpuArchitecture") or shape.get("operating_system_family")!=runtime.get("operatingSystemFamily"):
            blocked.append("ECS_CANDIDATE_RUNTIME_OR_ARCHITECTURE_INCOMPATIBLE")
        if "containerDefinitions" in task:
            containers=task["containerDefinitions"]
            if not isinstance(containers,list) or not containers:
                blocked.append("ECS_NATIVE_CONTAINER_REQUIREMENTS_UNKNOWN")
            else:
                reserved_cpu=Decimal(0);reserved_memory=Decimal(0)
                for container in containers:
                    _obj(container)
                    reserved_cpu+=_native(container.get("cpu",0))
                    reserved_memory+=max(_native(container.get("memory",0)),_native(container.get("memoryReservation",0)))
                if reserved_cpu>candidate_cpu or reserved_memory>candidate_mem:
                    blocked.append("ECS_CONTAINER_REQUIREMENTS_EXCEED_CANDIDATE")
        # AWS documents Maximum as the most resource-intensive individual task;
        # Average is the fleet aggregate. Never substitute Average for this gate.
        cpu_limit=min(1-head_cpu,_num(limits.get("cpu_max_fraction"),True) or Decimal(1)) if head_cpu is not None else None
        memory_limit=min(1-head_mem,_num(limits.get("memory_max_fraction"),True) or Decimal(1)) if head_mem is not None else None
        if cpu_peak is not None and cpu is not None and cpu_limit is not None and cpu*cpu_peak/100 > candidate_cpu*cpu_limit:
            blocked.append("ECS_NATIVE_TASK_CPU_MAXIMUM_EXCEEDS_CANDIDATE")
        if memory_peak is not None and memory is not None and memory_limit is not None and memory*memory_peak/100 > candidate_mem*memory_limit:
            blocked.append("ECS_NATIVE_TASK_MEMORY_MAXIMUM_EXCEEDS_CANDIDATE")
        proposed = {"cpu_units": shape["cpu_units"], "memory_mib": shape["memory_mib"], "replica_count": str(replicas) if replicas is not None else None}
        replacement = {}
        for component, before, after in (("FARGATE_CPU", cpu, candidate_cpu), ("FARGATE_MEMORY", memory, candidate_mem)):
            rows = [r for r in fin["components"] if r["component"] == component]
            rate = _rate(fin, component)
            replacement[component] = sum((r["_quantity"]*rate*after/before for r in rows), Decimal(0)) if rows and before and rate is not None and all(r["_quantity"] is not None and r["_rate"] == rate for r in rows) else None
        launch = c.get("launchType")
        if launch != "FARGATE":
            blocked.append("ECS_EC2_HOST_AVOIDANCE_AND_SHARED_ALLOCATION_UNPROVEN")
        kind = "FARGATE_TASK_RIGHTSIZE" if launch == "FARGATE" else "ECS_TASK_CPU_MEMORY_RIGHTSIZE"
        candidates.append(_candidate(_text(shape.get("id")), kind, task, proposed, blocked,
                                     _econ(fin, replacement, ["UNCHANGED_SUCCESSFUL_WORK_AND_TASK_RUNTIME_REQUIRED", "AWS_ECS_MAXIMUM_IS_HIGHEST_OBSERVED_TASK_NOT_FLEET_AVERAGE"])))
    if not candidates:
        candidates.append(_candidate("ecs-task-evidence", "FARGATE_TASK_RIGHTSIZE" if c.get("launchType") == "FARGATE" else "ECS_TASK_CPU_MEMORY_RIGHTSIZE", task, None, reasons, _econ(fin)))
    idle_reasons = list(base)
    if activity is None:
        idle_reasons.append("ECS_INDEPENDENT_WORKLOAD_ACTIVITY_REQUIRED")
    elif activity > 0:
        idle_reasons.append("ECS_WORKLOAD_ACTIVITY_PRESENT")
    candidates.append(_candidate("ecs-idle", "ECS_SERVICE_IDLE_REVIEW", c, None, idle_reasons, _econ(fin), review=True))
    scaling_reasons = list(base)
    if not any(k in c for k in ("scalable_targets", "scaling_policies")):
        scaling_reasons.append("ECS_AUTOSCALING_CONFIGURATION_UNKNOWN")
    if max_replicas is None or min_replicas is None:
        scaling_reasons.append("ECS_REPLICA_HISTORY_UNKNOWN")
    candidates.append(_candidate("ecs-scaling", "ECS_SCALING_POLICY_REVIEW", c, None, scaling_reasons, _econ(fin), review=True))
    return candidates


def _dynamodb(data, summary, fin, base):
    c, limits = data["configuration"], _limits(data["policy"])
    throughput = _obj(c.get("ProvisionedThroughput", {}))
    current_read, current_write = _native(throughput.get("ReadCapacityUnits"), True), _native(throughput.get("WriteCapacityUnits"), True)
    reasons = list(base) + _required_constraints(limits, ("read_target_utilization_fraction", "write_target_utilization_fraction", "min_read_capacity_units", "min_write_capacity_units", "burst_requirements_known", "autoscaling_reviewed"))
    read_total, write_total = _metric(summary,"ConsumedReadCapacityUnits","Sum","sum","Count"), _metric(summary,"ConsumedWriteCapacityUnits","Sum","sum","Count")
    read_bound, write_bound = _metric(summary,"ConsumedReadCapacityUnits","Sum",unit="Count"), _metric(summary,"ConsumedWriteCapacityUnits","Sum",unit="Count")
    throttle_read, throttle_write = _metric(summary,"ReadThrottleEvents","Sum","sum","Count"), _metric(summary,"WriteThrottleEvents","Sum","sum","Count")
    if any(v is None for v in (read_total,write_total,read_bound,write_bound,throttle_read,throttle_write)):
        reasons.append("DYNAMODB_CAPACITY_AND_THROTTLING_EVIDENCE_INCOMPLETE")
    if any(v is not None and v > 0 for v in (throttle_read,throttle_write)):
        reasons.append("DYNAMODB_THROTTLING_BLOCKS_REDUCTION")
    if limits.get("burst_requirements_known") is not True or limits.get("autoscaling_reviewed") is not True:
        reasons.append("DYNAMODB_BURST_OR_AUTOSCALING_REQUIREMENTS_UNKNOWN")
    mode = _obj(c.get("BillingModeSummary", {})).get("BillingMode") or c.get("billing_mode")
    if mode not in ("PROVISIONED","PAY_PER_REQUEST"):
        reasons.append("DYNAMODB_BILLING_MODE_UNKNOWN")
    rt,wt = _num(limits.get("read_target_utilization_fraction"),True),_num(limits.get("write_target_utilization_fraction"),True)
    if any(v is not None and (v<=0 or v>1) for v in (rt,wt)):
        raise EvidenceError("DynamoDB utilization target outside zero to one")
    desired_read = max(Decimal(1),_num(limits.get("min_read_capacity_units"),True) or Decimal(1), (read_bound/rt).to_integral_value(rounding=ROUND_CEILING)) if read_bound is not None and rt else None
    desired_write = max(Decimal(1),_num(limits.get("min_write_capacity_units"),True) or Decimal(1), (write_bound/wt).to_integral_value(rounding=ROUND_CEILING)) if write_bound is not None and wt else None
    rightsizing_reasons = list(reasons)
    if mode!="PROVISIONED" or current_read is None or current_write is None:
        rightsizing_reasons.append("DYNAMODB_PROVISIONED_CURRENT_CAPACITY_REQUIRED")
    # The entire interval's units assigned to one second is an upper bound; it
    # deliberately does NOT use Sum/period as a fictitious observed peak.
    proposed={"read_capacity_units":_money(desired_read),"write_capacity_units":_money(desired_write),"peak_basis":"CONSERVATIVE_PERIOD_TOTAL_PER_SECOND_UPPER_BOUND","billing_mode":"PROVISIONED"}
    rr,wr = _rate(fin,"READ_PROVISIONED"),_rate(fin,"WRITE_PROVISIONED")
    replacement={"READ_PROVISIONED":desired_read*fin["hours"]*rr if desired_read is not None and rr is not None else None,"WRITE_PROVISIONED":desired_write*fin["hours"]*wr if desired_write is not None and wr is not None else None}
    candidates=[_candidate("dynamodb-capacity","DYNAMODB_PROVISIONED_CAPACITY_RIGHTSIZE",c,proposed,rightsizing_reasons,_econ(fin,replacement,["ALL_PERIOD_CONSUMPTION_CONSERVATIVELY_ASSIGNED_TO_ONE_SECOND","NO_SUBPERIOD_PEAK_FABRICATED"]))]
    mode_reasons=list(reasons)
    on_read,on_write=_rate(fin,"READ_REQUEST"),_rate(fin,"WRITE_REQUEST")
    mode_proposed={"billing_mode":"PAY_PER_REQUEST" if mode=="PROVISIONED" else "PROVISIONED","economic_break_even":None}
    if on_read is None or on_write is None or rr is None or wr is None:
        mode_reasons.append("DYNAMODB_BOTH_MODE_CUSTOMER_RATES_REQUIRED")
    if data.get("billing",{}).get("capacity_request_unit_equivalence_known") is not True:
        mode_reasons.append("DYNAMODB_CAPACITY_REQUEST_UNIT_MAPPING_UNPROVEN")
    if None not in (on_read,on_write,rr,wr,current_read,current_write):
        provisioned_cost=(current_read*rr+current_write*wr)*fin["hours"]
        measured_request_cost=read_total*on_read+write_total*on_write if read_total is not None and write_total is not None else None
        mode_proposed["economic_break_even"]={"provisioned_comparison_cost":_money(provisioned_cost),"request_comparison_cost":_money(measured_request_cost),"read_request_units_per_rcu_hour_break_even":_money(rr/on_read) if on_read else None,"write_request_units_per_wcu_hour_break_even":_money(wr/on_write) if on_write else None,"currency":fin["currency"]}
    mode_replacement={"READ_PROVISIONED":read_total*on_read if read_total is not None and on_read is not None else None,"WRITE_PROVISIONED":write_total*on_write if write_total is not None and on_write is not None else None}
    if mode!="PROVISIONED":mode_reasons.append("DYNAMODB_REVERSE_MODE_PROVISIONING_EVIDENCE_REQUIRED")
    candidates.append(_candidate("dynamodb-mode","DYNAMODB_BILLING_MODE_REVIEW",c,mode_proposed,mode_reasons,_econ(fin,mode_replacement)))
    idle_reasons=list(base)
    if read_total is None or write_total is None:idle_reasons.append("DYNAMODB_READ_WRITE_COVERAGE_REQUIRED")
    elif read_total>0 or write_total>0:idle_reasons.append("DYNAMODB_TRAFFIC_PRESENT")
    candidates.append(_candidate("dynamodb-idle","DYNAMODB_IDLE_TABLE_REVIEW",c,None,idle_reasons,_econ(fin),review=True))
    if data["binding"]["provider_resource_id"].find("/index/")>=0 or c.get("GlobalSecondaryIndexes") is not None:
        candidates.append(_candidate("dynamodb-gsi","DYNAMODB_GSI_UTILISATION_REVIEW",c,None,list(base)+([] if read_total is not None and write_total is not None else ["DYNAMODB_GSI_METRIC_SCOPE_UNKNOWN"]),_econ(fin),review=True))
    return candidates


def _cache(data,summary,fin,base):
    c,limits=data["configuration"],_limits(data["policy"])
    reasons=list(base)+_application_guards(summary,limits)+_required_constraints(limits,("cpu_headroom_fraction","memory_headroom_fraction","max_swap_bytes","max_evictions","max_replication_lag_seconds","min_replicas_per_shard","recovery_requirements_known"))
    cpu,mem=_metric(summary,"CPUUtilization",unit="Percent"),_metric(summary,"DatabaseMemoryUsagePercentage",unit="Percent")
    swap,evictions,lag=_metric(summary,"SwapUsage",unit="Bytes"),_metric(summary,"Evictions","Sum","sum","Count"),_metric(summary,"ReplicationLag",unit="Seconds")
    if cpu is None or mem is None or swap is None or evictions is None:reasons.append("ELASTICACHE_CPU_MEMORY_SWAP_EVICTION_EVIDENCE_REQUIRED")
    if str(c.get("Engine","")).lower() in ("redis","valkey") and _metric(summary,"EngineCPUUtilization",unit="Percent") is None:reasons.append("ELASTICACHE_ENGINE_CPU_EVIDENCE_REQUIRED")
    if limits.get("recovery_requirements_known") is not True:reasons.append("ELASTICACHE_RECOVERY_REQUIREMENTS_UNKNOWN")
    if swap is not None and limits.get("max_swap_bytes") is not None and swap>_num(limits["max_swap_bytes"]):reasons.append("ELASTICACHE_SWAP_GUARD")
    if evictions is not None and limits.get("max_evictions") is not None and evictions>_num(limits["max_evictions"]):reasons.append("ELASTICACHE_EVICTION_GUARD")
    if c.get("ReplicationGroupId") and (lag is None or limits.get("max_replication_lag_seconds") is None):reasons.append("ELASTICACHE_REPLICATION_LAG_UNKNOWN")
    elif lag is not None and limits.get("max_replication_lag_seconds") is not None and lag>_num(limits["max_replication_lag_seconds"]):reasons.append("ELASTICACHE_REPLICATION_LAG_GUARD")
    current_capacity=_obj(data.get("capabilities",{})).get("current",{})
    current_memory,current_cpu=_num(current_capacity.get("memory_bytes"),True),_num(current_capacity.get("vcpu"),True)
    if current_memory is None or current_cpu is None:reasons.append("ELASTICACHE_INDEPENDENT_PHYSICAL_CAPACITY_REQUIRED")
    candidates=[]
    for shape in data.get("capabilities",{}).get("candidates",[])[:256]:
        _obj(shape);_ref(shape.get("source_ref"),data["binding"])
        candidate_memory,candidate_cpu=_num(shape.get("memory_bytes")),_num(shape.get("vcpu"))
        blocked=list(reasons);head_cpu,head_mem=_num(limits.get("cpu_headroom_fraction"),True),_num(limits.get("memory_headroom_fraction"),True)
        if any(v is not None and v>=1 for v in (head_cpu,head_mem)):raise EvidenceError("invalid cache headroom")
        memory_limit=min(1-head_mem,_num(limits.get("memory_max_fraction"),True) or Decimal(1)) if head_mem is not None else None
        cpu_limit=min(1-head_cpu,_num(limits.get("cpu_max_fraction"),True) or Decimal(1)) if head_cpu is not None else None
        if current_memory is not None and mem is not None and memory_limit is not None and current_memory*mem/100>candidate_memory*memory_limit:blocked.append("ELASTICACHE_MEMORY_PRESSURE_REJECTS_CANDIDATE")
        if current_cpu is not None and cpu is not None and cpu_limit is not None and current_cpu*cpu/100>candidate_cpu*cpu_limit:blocked.append("ELASTICACHE_CPU_PEAK_REJECTS_CANDIDATE")
        engine=_metric(summary,"EngineCPUUtilization",unit="Percent")
        if engine is not None and cpu_limit is not None and engine>cpu_limit*100:blocked.append("ELASTICACHE_ENGINE_CPU_SATURATION_GUARD")
        if shape.get("engine")!=c.get("Engine") or shape.get("engine_version")!=c.get("EngineVersion") or shape.get("preserves_topology") is not True:blocked.append("ELASTICACHE_ENGINE_OR_TOPOLOGY_INCOMPATIBLE")
        identity=_text(shape.get("id"));rate=_rate(fin,"CACHE_NODE",identity);nodehours=sum((r["_quantity"] or Decimal(0) for r in fin["components"] if r["component"]=="CACHE_NODE"),Decimal(0))
        candidates.append(_candidate(identity,"ELASTICACHE_NODE_RIGHTSIZE",c,shape,blocked,_econ(fin,{"CACHE_NODE":nodehours*rate if rate is not None else None})))
    if not candidates:candidates.append(_candidate("cache-capacity","ELASTICACHE_NODE_RIGHTSIZE",c,None,reasons+["ELASTICACHE_COMPATIBLE_NATIVE_CAPABILITY_AND_CUSTOMER_RATE_REQUIRED"],_econ(fin)))
    hits,misses,connections=_metric(summary,"CacheHits","Sum","sum","Count"),_metric(summary,"CacheMisses","Sum","sum","Count"),_metric(summary,"CurrConnections",unit="Count")
    idle=list(base)
    if any(v is None for v in (hits,misses,connections)):idle.append("ELASTICACHE_ACCESS_AND_CONNECTION_COVERAGE_UNKNOWN")
    elif hits>0 or misses>0 or connections>0:idle.append("ELASTICACHE_ACTIVITY_PRESENT")
    candidates.append(_candidate("cache-idle","ELASTICACHE_IDLE_CLUSTER_REVIEW",c,None,idle,_econ(fin),review=True))
    replica=list(base)
    if limits.get("failover_required") is None or limits.get("min_replicas_per_shard") is None or limits.get("recovery_requirements_known") is not True:replica.append("ELASTICACHE_FAILOVER_AND_REPLICA_MINIMA_UNKNOWN")
    candidates.append(_candidate("cache-replicas","ELASTICACHE_REPLICA_COUNT_REVIEW",c,{"action":"HUMAN_TOPOLOGY_REVIEW_PRESERVE_FAILOVER"},replica,_econ(fin),review=True))
    return candidates


def _activity(data,summary):
    # Historical native queries never manufacture independent workload receipts.
    rows=data.get("observations",{}).get("activity",[])
    if not rows:return None
    if not isinstance(rows,list):raise EvidenceError("workload observations required")
    metrics=[]
    for row in rows:
        _obj(row)
        if row.get("metric") not in ("AcceptedWork","CompletedWork","RejectedWork","Backlog","InFlightWork"):raise EvidenceError("unsupported independent workload metric")
        metrics.append(row)
    shadow={**data,"observations":{**data["observations"],"metrics":metrics}}
    _,_,activity,_=_history(shadow,data["policy"])
    values=[_metric(activity,name,"Sum","sum","Count") for name in ("AcceptedWork","CompletedWork","RejectedWork")]
    backlog=[_metric(activity,name,"Maximum",unit="Count") for name in ("Backlog","InFlightWork")]
    return sum(values+backlog,Decimal(0)) if all(v is not None for v in values+backlog) else None


def _elb(data,summary,fin,base):
    c,limits=data["configuration"],_limits(data["policy"])
    subtype=c.get("subtype") or c.get("Type")
    traffic=_metric(summary,"NewFlowCount" if subtype in ("NLB","network") else "RequestCount","Sum","sum","Count")
    bytes_total=_metric(summary,"ProcessedBytes","Sum","sum","Bytes")
    active=_metric(summary,"ActiveFlowCount" if subtype in ("NLB","network") else "ActiveConnectionCount",unit="Count")
    candidates=[]
    idle=list(base)
    if traffic is None or bytes_total is None or subtype in ("NLB","network") and active is None:idle.append("LOAD_BALANCER_MISSING_TRAFFIC_IS_UNKNOWN_NOT_ZERO")
    elif traffic>0 or bytes_total>0 or active is not None and active>0:idle.append("LOAD_BALANCER_TRAFFIC_PRESENT")
    candidates.append(_candidate("load-balancer-idle","LOAD_BALANCER_IDLE_REVIEW",c,{"action":"REVIEW_ONLY_NO_DELETION","purpose":limits.get("purpose","UNKNOWN")},idle,_econ(fin),review=True))
    low=list(base)
    if traffic is None or bytes_total is None:low.append("LOAD_BALANCER_COMPLETE_ACTIVITY_WINDOW_REQUIRED")
    request_limit,byte_limit=_num(limits.get("low_requests_per_second"),True),_num(limits.get("low_bytes_per_second"),True)
    if request_limit is None or byte_limit is None:low.append("LOAD_BALANCER_CUSTOMER_LOW_USAGE_THRESHOLDS_REQUIRED")
    elif traffic is not None and bytes_total is not None and (traffic/(fin["hours"]*3600)>request_limit or bytes_total/(fin["hours"]*3600)>byte_limit):low.append("LOAD_BALANCER_ABOVE_REVIEW_THRESHOLD")
    candidates.append(_candidate("load-balancer-low","LOAD_BALANCER_LOW_UTILISATION_REVIEW",c,{"action":"HUMAN_PURPOSE_AND_RESILIENCE_REVIEW"},low,_econ(fin),review=True))
    targets=c.get("targets") or c.get("target_health") or c.get("target_groups")
    orphan=list(base)
    if targets is None:orphan.append("LOAD_BALANCER_TARGET_ENUMERATION_UNKNOWN")
    else:
        # Empty observed target populations are a review, not proof of no use.
        if isinstance(targets,(dict,list)) and targets:orphan.append("LOAD_BALANCER_TARGETS_REQUIRE_INDIVIDUAL_OWNERSHIP_REVIEW")
    candidates.append(_candidate("load-balancer-orphan","LOAD_BALANCER_ORPHAN_TARGET_REVIEW",c,{"action":"REVIEW_TARGET_REGISTRATION_AND_PURPOSE"},orphan,_econ(fin),review=True))
    return candidates


def evaluate_aws_service(data):
    _obj(data,{"schema_version","model_version","model_kind","binding","family","now","configuration","snapshot_ref","observations","capabilities","policy","billing","source_refs","config_hash","period"})
    if data.get("schema_version")!="1" or data.get("model_version") not in (None,MODEL_VERSION) or data.get("model_kind") not in (None,MODEL_KIND) or data.get("family") not in FAMILIES:raise EvidenceError("AWS service model version required")
    binding=_obj(data.get("binding"),BINDING)
    for key in BINDING-{"workload_id"}:_text(binding.get(key))
    if binding.get("workload_id") not in (None, ""):_text(binding["workload_id"])
    if binding["provider"]!="AWS" or not re.fullmatch("[0-9]{12}",binding["account_id"]) or not binding["provider_resource_id"].startswith("arn:aws:") or (":"+binding["region"]+":"+binding["account_id"]+":") not in binding["provider_resource_id"]:raise EvidenceError("AWS service target binding mismatch")
    _obj(data.get("configuration"));policy=_obj(data.get("policy",{}));_ref(data.get("snapshot_ref"),binding)
    refs=data.get("source_refs",[])
    if not isinstance(refs,list) or len(refs)>512:raise EvidenceError("bounded AWS service refs required")
    seen={}
    for ref in refs:
        _ref(ref,binding);key=(ref["kind"],ref["id"],ref["version"])
        if key in seen and seen[key]!=ref:raise EvidenceError("conflicting AWS service source revisions")
        seen[key]=ref
    with localcontext() as ctx:
        ctx.prec=64
        start,end,summary,reasons=_history(data,policy)
        if not policy.get("owner") or policy.get("configuration_authority") in (None,"UNKNOWN"):reasons.append("AWS_SERVICE_OWNERSHIP_AND_CONFIGURATION_AUTHORITY_REQUIRED")
        fin=_financial(data,start,end)
        candidates={"ECS":_ecs,"DYNAMODB":_dynamodb,"ELASTICACHE":_cache,"ELB":_elb}[data["family"]](data,summary,fin,reasons)
        recommended=[c for c in candidates if c["status"]=="RECOMMENDED"]
        numerical=[c for c in recommended if c["economics"]["estimated_window_saving"] is not None]
        winner=max(numerical,key=lambda c:Decimal(c["economics"]["estimated_window_saving"])) if numerical else recommended[0] if recommended else next((c for c in candidates if c["status"]=="NO_CHANGE"),candidates[0])
        all_reasons=sorted(set(reasons+[reason for c in candidates for reason in c["reason_codes"]]))
        analysed=sorted(r["id"] for r in fin["components"]) if numerical and not fin["reasons"] else []
        return {"schema_version":"1","model_version":MODEL_VERSION,"model_kind":MODEL_KIND,"family":data["family"],"binding":binding,"resource_id":binding["resource_id"],"config_hash":data.get("config_hash"),"status":winner["status"],"decision_code":winner["decision_code"],"recommendation_kind":winner["recommendation_kind"],"current_configuration":data["configuration"],"proposed_configuration":winner["proposed_configuration"],"evidence_window":{"start":start.isoformat().replace("+00:00","Z"),"end":end.isoformat().replace("+00:00","Z")},"metric_distributions":summary,"candidates":candidates,"reason_codes":all_reasons,"blockers":all_reasons,"economics":winner["economics"],"source_refs":refs,"economically_analysed_source_record_ids":analysed,"confidence":winner["confidence"],"risk_class":"R3","read_only":True,"pre_execution_ready":False,"execution_authorized":False,"verified_saving":None}
