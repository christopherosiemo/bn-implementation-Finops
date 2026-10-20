"""Pure, read-only EBS observed-demand and native customer cost screening.

The control plane authenticates native/catalog/CUR/policy receipts. This module
checks their exact arithmetic and scope; a receipt-shaped dictionary is not
provider authentication. Period-statistic percentiles are not raw I/O latency
percentiles, forecasts, execution permission, or verified savings.
"""
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import re

from .model import EvidenceError, decimal, instant

SCHEMA_VERSION = "1"
MODEL_VERSION = "storage-observed-demand-v1"
ROUTE = "/v8/storage-assessment"
MONTH_HOURS = Decimal(730)
YEAR_HOURS = Decimal(8760)
MIB = Decimal(1048576)
ECONOMIC_BASIS = "HELD_NATIVE_CUR_NET_COMPONENT_RATES_730H_MONTH_8760H_YEAR"
BINDING = ("tenant_id", "workload_id", "resource_id", "provider", "provider_resource_id", "account_id", "region")
POLICY = ("criticality", "high_seasonality", "iops_max_fraction", "throughput_max_fraction",
          "reserve_above_demand_fraction", "demand_growth_multiplier", "max_read_latency_seconds", "max_write_latency_seconds",
          "max_disk_queue_depth", "min_burst_balance_percent", "snapshot_retention_days", "quarantine_days",
          "backup_required", "allows_lower_durability", "requires_multi_attach", "filesystem_review_required", "source_ref")
SAFETY = ("owner", "configuration_authority", "configuration_ref", "attachment_compatible", "instance_iops_limit",
          "instance_throughput_mib_per_second_limit", "filesystem_reviewed", "backup_observed",
          "application_slo_clear", "dependency_complete", "io_latency_compatible", "io_durability_compatible",
          "modification_state", "source_refs")
CONFIG = ("capability_id", "volume_type", "size_gib", "iops", "throughput_mib_per_second", "state",
          "multi_attach_enabled", "encrypted", "kms_key_id", "created_at", "attachments", "source_ref",
          "snapshot_id", "source_volume_id", "started_at", "storage_tier", "throughput_basis",
          "native_provisioned_throughput_mib_per_second")
CAPABILITY = ("id", "volume_type", "min_size_gib", "max_size_gib", "min_iops", "max_iops",
              "min_throughput_mib_per_second", "max_throughput_mib_per_second", "max_iops_per_gib",
              "max_throughput_kib_per_iop", "baseline_iops", "baseline_throughput_mib_per_second",
              "multi_attach_supported", "durability_class", "latency_class", "source_ref")
# The mapper retains maxima of actual source-period rates/means, not invented
# one-second peaks. Native TotalRead/WriteTime divided by positive native Ops
# provides a period mean, never a raw-operation p95 latency.
METRICS = {
    "read_iops": ("Count/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES"),
    "write_iops": ("Count/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES"),
    "read_throughput": ("Bytes/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES"),
    "write_throughput": ("Bytes/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES"),
    "queue_length": ("Count", "Maximum"),
    "read_latency": ("Seconds", "MAXIMUM_OF_NATIVE_PERIOD_OPERATION_MEANS"),
    "write_latency": ("Seconds", "MAXIMUM_OF_NATIVE_PERIOD_OPERATION_MEANS"),
    "burst_balance": ("Percent", "Minimum"),
    "iops_exceeded": ("Count", "Maximum"),
    "throughput_exceeded": ("Count", "Maximum"),
    "throughput_percentage": ("Percent", "Maximum"),
    "consumed_iops": ("Count/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES"),
    "idle_time": ("Seconds", "Sum"),
    "filesystem_used_bytes": ("Bytes", "Maximum"),
}
BASE_METRICS = tuple(list(METRICS)[:7])
COMPONENT_UNITS = {"storage": "GiB-Mo", "iops": "IOPS-Mo", "throughput": "MiBps-Mo"}
CONTINUING = ("snapshots", "fast_snapshot_restore", "archive", "continuing")
TOP = ("schema_version", "model_version", "resource_kind", "binding", "as_of", "current_configuration",
       "capabilities", "candidate_configurations", "history", "observations", "policy", "safety",
       "current_pricing", "continuing_costs", "snapshots")
MIGRATION_STEPS = ["NEW_VOLUME", "DATA_MIGRATION", "FILESYSTEM_HANDLING", "VALIDATION", "CUTOVER", "ROLLBACK"]


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise EvidenceError("unsupported storage object fields")
    return value


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 1024 or any(ord(c) < 32 for c in value):
        raise EvidenceError("storage identity required")
    return value


def _number(value, nonnegative=True):
    result = decimal(value, "storage quantity")
    if nonnegative and result < 0:
        raise EvidenceError("negative storage quantity")
    return result


def _int(value, minimum=0, maximum=100000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise EvidenceError("storage integer outside bound")
    return value


def _money(value):
    with localcontext() as context:
        context.prec = 80
        result = value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN)
    if abs(result) >= Decimal("1e26"):
        raise EvidenceError("storage result exceeds DECIMAL(38,12)")
    return format(result, "f")


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _utc(value):
    if not isinstance(value, str) or not (value.endswith("Z") or value.endswith("+00:00")):
        raise EvidenceError("storage UTC timestamp required")
    return instant(value)


def _period(value):
    _object(value, ("start", "end"), ("start", "end"))
    start, end = _utc(value["start"]), _utc(value["end"])
    if end <= start:
        raise EvidenceError("storage interval must be positive")
    return start, end


def _ref(value, refs, reasons, label):
    if value is None:
        reasons.add("STORAGE_REFERENCE_UNAVAILABLE:" + label)
        return False
    _object(value, ("kind", "id", "version", "sha256"), ("kind", "id", "version", "sha256"))
    for field in ("kind", "id", "version"):
        _text(value[field])
    if not isinstance(value["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", value["sha256"]):
        raise EvidenceError("storage immutable receipt hash required")
    key = (value["kind"], value["id"], value["version"])
    if key in refs and refs[key] != value:
        raise EvidenceError("conflicting storage receipt version")
    refs[key] = value
    return True


def _refs(values, refs, reasons, label):
    if not isinstance(values, list) or not 1 <= len(values) <= 1000:
        reasons.add("STORAGE_REFERENCE_UNAVAILABLE:" + label)
        return
    for value in values:
        _ref(value, refs, reasons, label)


def _policy(value, refs, reasons):
    if value is None:
        reasons.add("STORAGE_POLICY_UNAVAILABLE")
        return {}, None
    _object(value, POLICY)
    _ref(value.get("source_ref"), refs, reasons, "POLICY")
    kind, seasonal = value.get("criticality"), value.get("high_seasonality")
    days = 90 if seasonal is True else 14 if kind == "NON_PRODUCTION" else 30
    if kind not in ("NON_PRODUCTION", "TIER_0", "TIER_1", "TIER_2", "TIER_3") or type(seasonal) is not bool:
        reasons.add("STORAGE_POLICY_CLASSIFICATION_UNAVAILABLE")
        days = None
    result = {}
    for name in POLICY:
        raw = value.get(name)
        if name in ("criticality", "high_seasonality", "source_ref"):
            continue
        if name in ("backup_required", "allows_lower_durability", "requires_multi_attach", "filesystem_review_required"):
            if raw is not None and type(raw) is not bool:
                raise EvidenceError("storage policy boolean differs")
            result[name] = raw
        elif name in ("snapshot_retention_days", "quarantine_days"):
            result[name] = _int(raw, 1, 36500) if raw is not None else None
        else:
            result[name] = _number(raw) if raw is not None else None
            number = result[name]
            if number is not None and name.endswith("max_fraction") and not 0 < number <= 1:
                raise EvidenceError("storage capacity fraction outside bound")
            if number is not None and name == "reserve_above_demand_fraction" and number > 10:
                raise EvidenceError("storage reserve outside bound")
            if number is not None and name == "demand_growth_multiplier" and not 1 <= number <= 100:
                raise EvidenceError("storage demand growth multiplier outside bound")
            if number is not None and name == "min_burst_balance_percent" and number > 100:
                raise EvidenceError("storage burst threshold outside bound")
    return result, days


def _history(data, refs, reasons, required_days):
    h = data.get("history")
    if h is None:
        reasons.add("STORAGE_PERFORMANCE_HISTORY_UNAVAILABLE")
        return None, [], {}, set()
    _object(h, ("start", "end", "metrics", "source_refs"), ("start", "end", "metrics", "source_refs"))
    start, end = _period({k: h[k] for k in ("start", "end")})
    if any((v.hour, v.minute, v.second, v.microsecond) != (0, 0, 0, 0) for v in (start, end)):
        raise EvidenceError("storage history requires complete UTC days")
    days, as_of = (end - start).days, _utc(data["as_of"])
    if not 1 <= days <= 90 or end > as_of:
        raise EvidenceError("storage historical interval outside bound")
    if as_of - end > timedelta(hours=48):
        reasons.add("STORAGE_HISTORY_STALE")
    if required_days is None or days < required_days:
        reasons.add("STORAGE_INSUFFICIENT_COMPLETE_UTC_DAYS")
    _refs(h["source_refs"], refs, reasons, "HISTORY")
    definitions = h["metrics"]
    if not isinstance(definitions, list) or len(definitions) > len(METRICS):
        raise EvidenceError("storage metric definition bound")
    specs = {}
    for spec in definitions:
        _object(spec, ("name", "unit", "statistic", "period_seconds", "sample_period_seconds", "expected_sample_count", "expected_native_sample_count"), ("name",))
        name = spec["name"]
        if name not in METRICS or name in specs:
            raise EvidenceError("unknown or duplicate storage metric")
        cadence = spec.get("sample_period_seconds")
        valid = (spec.get("unit"), spec.get("statistic")) == METRICS[name] and spec.get("period_seconds") == 3600
        valid = valid and type(cadence) is int and cadence in (60, 300, 3600)
        valid = valid and type(spec.get("expected_sample_count")) is int and spec["expected_sample_count"] == 3600 // cadence
        native = spec.get("expected_native_sample_count")
        valid = valid and type(native) is int and native == 60
        specs[name] = spec if valid else None
        if not valid:
            reasons.add("STORAGE_METRIC_DEFINITION_UNSUPPORTED:" + name)
    required = set(BASE_METRICS)
    if data["current_configuration"].get("volume_type") == "gp2":
        required.add("burst_balance")
    required |= set(specs) - {"filesystem_used_bytes", "idle_time"}
    for name in required - set(specs):
        reasons.add("STORAGE_METRIC_DEFINITION_UNAVAILABLE:" + name)
    observations = data.get("observations")
    if not isinstance(observations, list) or len(observations) > 90 * 24:
        raise EvidenceError("storage observation bound")
    values, known, counts, native_counts, idle = {}, {}, {}, {}, {}
    for name in specs:
        values[name], known[name], counts[name], native_counts[name], idle[name] = [], 0, 0, Decimal(0), 0
    seen = set()
    for row in observations:
        _object(row, ("start", "end", "metrics"), ("start", "end", "metrics"))
        a, b = _period({k: row[k] for k in ("start", "end")})
        if b - a != timedelta(hours=1) or a < start or b > end or (a - start).total_seconds() % 3600 or a in seen:
            raise EvidenceError("storage duplicate or off-grid hour")
        seen.add(a)
        points = _object(row["metrics"], METRICS)
        for name, spec in specs.items():
            point = points.get(name)
            if point is None or spec is None:
                if name in required:
                    reasons.add("STORAGE_METRIC_UNKNOWN:" + name)
                continue
            _object(point, ("value", "sample_count", "native_sample_count", "duplicate_sample_count", "operations"), ("value", "sample_count"))
            count = _int(point["sample_count"], 0, 3600)
            duplicate = point.get("duplicate_sample_count")
            native = point.get("native_sample_count")
            complete = count == spec["expected_sample_count"] and duplicate is not None and _int(duplicate) == 0
            complete = complete and native is not None and _number(native) >= spec["expected_native_sample_count"]
            if not complete:
                if name in required:
                    reasons.add("STORAGE_NATIVE_SAMPLE_COVERAGE_INCOMPLETE:" + name)
                continue
            if point["value"] is None:
                operation_name = "read_iops" if name == "read_latency" else "write_iops"
                operations = points.get(operation_name)
                known_zero_rate = isinstance(operations, dict) and operations.get("value") is not None and _number(operations["value"]) == 0
                if name in ("read_latency", "write_latency") and point.get("operations") is not None and _number(point["operations"]) == 0 and known_zero_rate:
                    idle[name] += 1
                else:
                    if name in required:
                        reasons.add("STORAGE_METRIC_UNKNOWN:" + name)
                    continue
            else:
                value = _number(point["value"])
                if name == "burst_balance" and value > 100:
                    raise EvidenceError("storage burst percentage exceeds one hundred")
                values[name].append(value)
            known[name] += 1
            counts[name] += count
            native_counts[name] += _number(native)
    hours = days * 24
    if len(seen) != hours:
        reasons.add("STORAGE_HOUR_COVERAGE_INCOMPLETE")
    distributions, extrema, all_idle = [], {}, set()
    for name in specs:
        series = sorted(values[name])
        complete = known[name] == hours
        if not complete and name in required:
            reasons.add("STORAGE_METRIC_HISTORY_INCOMPLETE:" + name)
        if idle[name] == hours:
            all_idle.add(name)
        extrema[name] = (min(series) if name == "burst_balance" else max(series)) if complete and series else None
        def percentile(n):
            return _money(series[(len(series) * n + 99) // 100 - 1]) if complete and series else None
        spec = specs[name]
        distributions.append({"metric": name, "unit": METRICS[name][0], "statistic": METRICS[name][1],
                              "status": "COMPLETE_ZERO_OPERATIONS" if name in all_idle else "COMPLETE" if complete else "INCOMPLETE",
                              "expected_hours": hours, "observed_hours": known[name],
                              "expected_sample_count": hours * spec["expected_sample_count"] if spec else None,
                              "expected_native_sample_count": hours * spec["expected_native_sample_count"] if spec else None,
                              "sample_count": counts[name], "native_sample_count": _money(native_counts[name]),
                              "minimum": _money(series[0]) if series else None, "maximum": _money(series[-1]) if series else None,
                              "p50_of_period_statistics": percentile(50), "p95_of_period_statistics": percentile(95),
                              "p99_of_period_statistics": percentile(99), "zero_operation_hours": idle[name]})
    return {"start": h["start"], "end": h["end"], "observed_utc_days": days, "required_utc_days": required_days,
            "expected_hours": hours, "observed_hours": len(seen), "coverage_basis": "ACTUAL_NATIVE_BINS_AND_SAMPLE_COUNTS_NO_INTERPOLATION"}, distributions, extrema, all_idle


def _capabilities(data, refs, reasons):
    value = data.get("capabilities")
    if value is None:
        reasons.add("STORAGE_PROVIDER_CAPABILITIES_UNAVAILABLE")
        return {}
    _object(value, ("source_ref", "entries"), ("entries",))
    _ref(value.get("source_ref"), refs, reasons, "CAPABILITIES")
    if not isinstance(value["entries"], list) or not 1 <= len(value["entries"]) <= 32:
        raise EvidenceError("storage capability bound")
    out = {}
    for entry in value["entries"]:
        _object(entry, CAPABILITY, ("id", "volume_type"))
        identifier = _text(entry["id"])
        if identifier in out:
            raise EvidenceError("duplicate storage capability")
        _text(entry["volume_type"])
        out[identifier] = entry
    return out


def _candidate_capability(candidate, capabilities, current, refs, reasons):
    entry = capabilities.get(candidate["capability_id"])
    if entry is None:
        reasons.add("STORAGE_CANDIDATE_CAPABILITY_UNAVAILABLE")
        return None
    _ref(entry.get("source_ref"), refs, reasons, "CANDIDATE_CAPABILITY")
    if entry["volume_type"] != candidate["volume_type"]:
        reasons.add("STORAGE_NATIVE_VOLUME_TYPE_MISMATCH")
    numbers = {}
    for field in CAPABILITY:
        if field in ("id", "volume_type", "multi_attach_supported", "durability_class", "latency_class", "source_ref"):
            continue
        raw = entry.get(field)
        numbers[field] = _number(raw) if raw is not None else None
        if raw is None:
            reasons.add("STORAGE_CAPABILITY_UNKNOWN:" + field)
    for dimension, lower, upper in (("size_gib", "min_size_gib", "max_size_gib"), ("iops", "min_iops", "max_iops"),
                                    ("throughput_mib_per_second", "min_throughput_mib_per_second", "max_throughput_mib_per_second")):
        value = _number(candidate[dimension])
        if numbers[lower] is not None and value < numbers[lower] or numbers[upper] is not None and value > numbers[upper]:
            reasons.add("STORAGE_PROVIDER_LIMIT_EXCEEDED:" + dimension)
    size, iops, throughput = (_number(candidate[k]) for k in ("size_gib", "iops", "throughput_mib_per_second"))
    if numbers["max_iops_per_gib"] is not None and iops > size * numbers["max_iops_per_gib"]:
        reasons.add("STORAGE_PROVIDER_IOPS_SIZE_RATIO_EXCEEDED")
    if numbers["max_throughput_kib_per_iop"] is not None and throughput * 1024 > iops * numbers["max_throughput_kib_per_iop"]:
        reasons.add("STORAGE_PROVIDER_THROUGHPUT_IOPS_RATIO_EXCEEDED")
    if type(entry.get("multi_attach_supported")) is not bool:
        reasons.add("STORAGE_MULTI_ATTACH_CAPABILITY_UNKNOWN")
    elif current.get("multi_attach_enabled") is True and entry["multi_attach_supported"] is not True:
        reasons.add("STORAGE_MULTI_ATTACH_INCOMPATIBLE")
    return entry


def _pricing(value, config, capability, data, refs, reasons):
    if value is None:
        reasons.add("STORAGE_NATIVE_CUSTOMER_PRICING_UNAVAILABLE")
        return None
    _object(value, ("basis", "volume_type", "region", "account_id", "currency", "period", "components"), ("components",))
    if value.get("basis") != "AWS_CUR_NET_USAGE" or any(value.get(k) != expected for k, expected in
          (("volume_type", config.get("volume_type")), ("region", data["binding"]["region"]), ("account_id", data["binding"]["account_id"]))):
        reasons.add("STORAGE_NATIVE_PRICE_DIMENSIONS_UNSUPPORTED")
        return None
    currency = value.get("currency")
    if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency) or value.get("period") is None:
        reasons.add("STORAGE_NATIVE_PRICE_CURRENCY_OR_PERIOD_UNKNOWN")
        return None
    start, end = _period(value["period"])
    if end > _utc(data["as_of"]):
        raise EvidenceError("future storage price")
    if _utc(data["as_of"]) - end > timedelta(hours=48):
        reasons.add("STORAGE_NATIVE_CUSTOMER_PRICE_STALE")
    rows = value["components"]
    if not isinstance(rows, list) or len(rows) != 3:
        reasons.add("STORAGE_NATIVE_COMPONENT_PRICE_INCOMPLETE")
        return None
    result = {}
    for row in rows:
        _object(row, ("component", "unit", "basis", "rate", "quantity", "amount", "source_ref"), ("component",))
        name = row["component"]
        if name not in COMPONENT_UNITS or name in result:
            raise EvidenceError("unknown or duplicate storage price component")
        if not _ref(row.get("source_ref"), refs, reasons, "NATIVE_CUR_" + name.upper()):
            continue
        if row.get("unit") != COMPONENT_UNITS[name] or any(row.get(k) is None for k in ("rate", "quantity", "amount")):
            reasons.add("STORAGE_NATIVE_COMPONENT_PRICE_UNKNOWN:" + name)
            continue
        dimension = "size_gib" if name == "storage" else "iops" if name == "iops" else "throughput_mib_per_second"
        if config.get(dimension) is None:
            reasons.add("STORAGE_NATIVE_COMPONENT_CONFIGURATION_UNKNOWN:" + name)
            continue
        rate, quantity, amount = _number(row["rate"], False), _number(row["quantity"]), _number(row["amount"], False)
        if _money(rate * quantity) != _money(amount):
            raise EvidenceError("storage native price arithmetic differs")
        if rate < 0 or amount < 0:
            reasons.add("STORAGE_CREDIT_IS_NOT_A_UNIT_RATE_WITNESS:" + name)
            continue
        if row.get("basis") == "INCLUDED_IN_NATIVE_STORAGE_RATE" and name != "storage":
            baseline = capability.get("baseline_iops" if name == "iops" else "baseline_throughput_mib_per_second") if capability else None
            demand = _number(config["iops" if name == "iops" else "throughput_mib_per_second"])
            supported = config["volume_type"] in ("gp2", "gp3") or config["volume_type"] in ("io1", "io2") and name == "throughput"
            documented = capability is not None and _ref(capability.get("source_ref"), refs, reasons, "INCLUDED_COMPONENT_CAPABILITY")
            if not supported or not documented or rate != 0 or quantity != 0 or amount != 0 or config["volume_type"] == "gp3" and (baseline is None or demand > _number(baseline)):
                reasons.add("STORAGE_PAID_COMPONENT_PRICE_UNAVAILABLE:" + name)
                continue
            monthly = Decimal(0)
        elif row.get("basis") == "AWS_CUR_NET_USAGE" and quantity > 0:
            if name == "storage":
                units = _number(config["size_gib"])
            else:
                field = "iops" if name == "iops" else "throughput_mib_per_second"
                baseline = capability.get("baseline_iops" if name == "iops" else "baseline_throughput_mib_per_second") if capability else None
                if baseline is None:
                    reasons.add("STORAGE_INCLUDED_BASELINE_UNKNOWN:" + name)
                    continue
                units = max(Decimal(0), _number(config[field]) - _number(baseline))
            monthly = units * rate
        else:
            reasons.add("STORAGE_NATIVE_PRICE_BASIS_UNSUPPORTED:" + name)
            continue
        result[name] = {"monthly": monthly, "actual_amount": amount, "ref": row["source_ref"], "basis": row["basis"], "unit": row["unit"]}
    if len(result) != 3:
        return None
    return {"currency": currency, "period": value["period"], "components": result}


def _continuing(data, refs, reasons):
    value = data.get("continuing_costs")
    if value is None:
        reasons.add("STORAGE_CONTINUING_COSTS_UNKNOWN")
        return None
    _object(value, ("currency", "period", "components"), ("components",))
    currency = value.get("currency")
    if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency) or value.get("period") is None:
        reasons.add("STORAGE_CONTINUING_COST_CURRENCY_OR_PERIOD_UNKNOWN")
        return None
    a, b = _period(value["period"])
    if b > _utc(data["as_of"]):
        raise EvidenceError("future continuing storage cost")
    if _utc(data["as_of"]) - b > timedelta(hours=48):
        reasons.add("STORAGE_CONTINUING_COST_STALE")
    rows = value["components"]
    if not isinstance(rows, list) or len(rows) > 32:
        raise EvidenceError("continuing storage component bound")
    result = {}
    hours = Decimal(str((b - a).total_seconds())) / 3600
    for row in rows:
        _object(row, ("component", "amount", "source_refs"), ("component",))
        name = row["component"]
        if name not in CONTINUING or name in result:
            raise EvidenceError("unknown or duplicate continuing storage component")
        before = len(reasons)
        _refs(row.get("source_refs"), refs, reasons, "CONTINUING_" + name.upper())
        if row.get("amount") is None or len(reasons) != before:
            reasons.add("STORAGE_CONTINUING_COMPONENT_UNKNOWN:" + name)
            continue
        amount = _number(row["amount"], False)
        result[name] = {"monthly": amount / hours * MONTH_HOURS, "actual_amount": amount, "refs": row["source_refs"]}
    if set(result) != set(CONTINUING):
        reasons.add("STORAGE_CONTINUING_COMPONENT_SCOPE_INCOMPLETE")
        return None
    return {"currency": currency, "period": value["period"], "components": result}


def _economics(data, candidate, current_capability, target_capability, refs, reasons):
    empty = {"current_hourly_cost": None, "current_monthly_cost": None, "candidate_hourly_cost": None,
             "candidate_monthly_cost": None, "estimated_monthly_saving": None, "estimated_annual_saving": None,
             "currency": None, "basis": ECONOMIC_BASIS, "status": "UNAVAILABLE", "component_costs": [], "verified_saving": None}
    current = _pricing(data.get("current_pricing"), data["current_configuration"], current_capability, data, refs, reasons) if data["resource_kind"] == "EBS_VOLUME" else None
    target = _pricing(candidate.get("pricing"), candidate, target_capability, data, refs, reasons) if candidate else None
    continuing = _continuing(data, refs, reasons)
    if continuing is None or data["resource_kind"] == "EBS_VOLUME" and current is None or candidate and target is None:
        return empty
    values = [v for v in (current, target, continuing) if v]
    if any(v["currency"] != continuing["currency"] or v["period"] != continuing["period"] for v in values):
        reasons.add("STORAGE_NATIVE_ECONOMIC_CURRENCY_OR_PERIOD_MISMATCH")
        return empty
    rows, current_total, target_total = [], Decimal(0), Decimal(0)
    if current:
        for name in COMPONENT_UNITS:
            a = current["components"][name]
            b = target["components"][name] if target else None
            current_total += a["monthly"]
            if b:
                target_total += b["monthly"]
            rows.append({"component": name, "unit": COMPONENT_UNITS[name], "basis": "NATIVE_CUSTOMER_EFFECTIVE_COMPONENT_RATE",
                         "current_monthly_cost": _money(a["monthly"]), "candidate_monthly_cost": _money(b["monthly"]) if b else None,
                         "actual_period_amount": _money(a["actual_amount"]), "currency": continuing["currency"],
                         "current_source_refs": [a["ref"]], "candidate_source_refs": [b["ref"]] if b else [], "continuing": False})
    for name, row in continuing["components"].items():
        current_total += row["monthly"]
        target_total += row["monthly"]
        rows.append({"component": name, "unit": "CURRENCY_PER_SELECTED_PERIOD", "basis": "NATIVE_ATTRIBUTABLE_CONTINUING_COST",
                     "current_monthly_cost": _money(row["monthly"]), "candidate_monthly_cost": _money(row["monthly"]) if candidate else None,
                     "actual_period_amount": _money(row["actual_amount"]), "currency": continuing["currency"],
                     "current_source_refs": row["refs"], "candidate_source_refs": row["refs"] if candidate else [], "continuing": True})
    saving = current_total - target_total if candidate else None
    return {"current_hourly_cost": _money(current_total / MONTH_HOURS), "current_monthly_cost": _money(current_total),
            "candidate_hourly_cost": _money(target_total / MONTH_HOURS) if candidate else None,
            "candidate_monthly_cost": _money(target_total) if candidate else None,
            "estimated_monthly_saving": _money(saving) if saving is not None else None,
            "estimated_annual_saving": _money(saving * YEAR_HOURS / MONTH_HOURS) if saving is not None else None,
            "currency": continuing["currency"], "basis": ECONOMIC_BASIS,
            "status": "CARRYING_COST_ONLY" if candidate is None else "CHEAPER" if saving > 0 else "NOT_CHEAPER" if saving < 0 else "NO_CHANGE",
            "component_costs": rows, "verified_saving": None}


def _snapshot_reviews(data, policy, refs):
    snapshots = data.get("snapshots")
    if snapshots is None:
        return [], ["STORAGE_SNAPSHOT_INVENTORY_UNKNOWN"]
    if not isinstance(snapshots, list) or len(snapshots) > 1000:
        raise EvidenceError("snapshot review bound")
    results, seen = [], set()
    for snapshot in snapshots:
        _object(snapshot, ("id", "volume_id", "started_at", "state", "storage_tier", "dependency_state", "ami_ids",
                           "restore_references", "policy_required", "source_ref", "monthly_cost", "currency", "pricing_source_ref"), ("id",))
        identifier = _text(snapshot["id"])
        if identifier in seen:
            raise EvidenceError("duplicate snapshot review")
        seen.add(identifier)
        reasons = set()
        _ref(snapshot.get("source_ref"), refs, reasons, "SNAPSHOT")
        age = None
        if snapshot.get("started_at") is not None:
            age_seconds = (_utc(data["as_of"]) - _utc(snapshot["started_at"])).total_seconds()
            if age_seconds < 0:
                raise EvidenceError("future snapshot")
            age = int(age_seconds // 86400)
        else:
            reasons.add("SNAPSHOT_AGE_UNKNOWN")
        dependency = snapshot.get("dependency_state")
        for field in ("ami_ids", "restore_references"):
            entries = snapshot.get(field)
            if entries is not None and (not isinstance(entries, list) or len(entries) > 1000 or any(not isinstance(v, str) or not v for v in entries)):
                raise EvidenceError("snapshot dependency shape differs")
        if snapshot.get("policy_required") is True:
            classification, next_action = "POLICY_REQUIRED", "RETAIN_POLICY_REQUIRED"
        elif dependency == "AMI_OR_RESTORE_DEPENDENT" or snapshot.get("ami_ids") or snapshot.get("restore_references"):
            classification, next_action = "AMI_OR_RESTORE_DEPENDENT", "RETAIN_AND_REVIEW_DEPENDENCIES"
        elif dependency != "KNOWN_UNREFERENCED" or snapshot.get("ami_ids") is None or snapshot.get("restore_references") is None or snapshot.get("policy_required") is not False:
            classification, next_action = "UNKNOWN_DEPENDENCY", "ESTABLISH_DEPENDENCY_AND_RETENTION_POLICY"
            reasons.add("SNAPSHOT_DEPENDENCIES_UNKNOWN")
        elif snapshot.get("state") != "completed":
            classification, next_action = "STATE_UNKNOWN_OR_NOT_COMPLETE", "REVIEW_SNAPSHOT_STATE"
            reasons.add("SNAPSHOT_STATE_UNKNOWN_OR_NOT_COMPLETE")
        elif policy.get("snapshot_retention_days") is None or age is None:
            classification, next_action = "RETENTION_POLICY_UNKNOWN", "REVIEW_RETENTION_POLICY"
            reasons.add("SNAPSHOT_RETENTION_POLICY_UNKNOWN")
        elif age >= policy["snapshot_retention_days"] and snapshot.get("state") == "completed":
            classification, next_action = "POTENTIALLY_REDUNDANT", "OWNER_RETENTION_REVIEW"
        else:
            classification, next_action = "WITHIN_RETENTION", "RETAIN_WITHIN_POLICY"
        monthly = snapshot.get("monthly_cost")
        if monthly is not None:
            if not _ref(snapshot.get("pricing_source_ref"), refs, reasons, "SNAPSHOT_CUR") or not isinstance(snapshot.get("currency"), str) or not re.fullmatch("[A-Z]{3}", snapshot["currency"]):
                monthly = None
            else:
                monthly = _money(_number(monthly, False))
        results.append({"snapshot_id": identifier, "source_volume_id": snapshot.get("volume_id"), "classification": classification,
                        "age_days": age, "monthly_carrying_cost": monthly, "currency": snapshot.get("currency") if monthly is not None else None,
                        "dependency_state": dependency, "ami_ids": snapshot.get("ami_ids"), "restore_references": snapshot.get("restore_references"),
                        "next_action": next_action, "blockers": sorted(reasons), "deletion_recommended": False,
                        "execution_authorized": False, "estimated_saving": None})
    return results, []


def _safety(data, policy, refs, reasons, target):
    safety = data.get("safety")
    if safety is None:
        reasons.add("STORAGE_SAFETY_EVIDENCE_UNAVAILABLE")
        return {}, "UNKNOWN", "REVIEW_CONFIGURATION_AUTHORITY"
    _object(safety, SAFETY)
    _refs(safety.get("source_refs"), refs, reasons, "SAFETY")
    _ref(safety.get("configuration_ref"), refs, reasons, "CONFIGURATION_AUTHORITY")
    if safety.get("owner") is not None:
        _text(safety["owner"])
    if not safety.get("owner") or not data["binding"].get("workload_id"):
        reasons.add("STORAGE_OWNER_OR_WORKLOAD_UNKNOWN")
    authority = safety.get("configuration_authority")
    if authority in ("TERRAFORM", "GITOPS", "CLOUDFORMATION", "OTHER_DECLARATIVE"):
        method = "DECLARATIVE_REMEDIATION_REVIEW"
    elif authority == "MANUAL":
        method = "MANUAL_STORAGE_CHANGE_REVIEW"
    else:
        method = "REVIEW_CONFIGURATION_AUTHORITY"
        reasons.add("STORAGE_CONFIGURATION_AUTHORITY_UNKNOWN")
    for name in ("attachment_compatible", "application_slo_clear", "dependency_complete"):
        if safety.get(name) is not True:
            reasons.add("STORAGE_SAFETY_UNKNOWN_OR_UNSATISFIED:" + name)
    for name in ("attachment_compatible", "filesystem_reviewed", "backup_observed", "application_slo_clear", "dependency_complete", "io_latency_compatible", "io_durability_compatible"):
        if safety.get(name) is not None and type(safety[name]) is not bool:
            raise EvidenceError("storage safety boolean differs")
    for requirement, observed in (("backup_required", "backup_observed"), ("filesystem_review_required", "filesystem_reviewed")):
        if policy.get(requirement) is None or policy[requirement] is True and safety.get(observed) is not True:
            reasons.add("STORAGE_POLICY_REQUIREMENT_UNSATISFIED:" + requirement)
    if policy.get("requires_multi_attach") is None:
        reasons.add("STORAGE_MULTI_ATTACH_POLICY_UNKNOWN")
    elif policy["requires_multi_attach"] and target.get("volume_type") == "gp3":
        reasons.add("STORAGE_MULTI_ATTACH_REQUIRED")
    if safety.get("modification_state") not in ("NONE", "COMPLETED"):
        reasons.add("STORAGE_MODIFICATION_ACTIVE_OR_UNKNOWN")
    if data["current_configuration"]["volume_type"] in ("io1", "io2") and target.get("volume_type") == "gp3":
        if safety.get("io_latency_compatible") is not True:
            reasons.add("STORAGE_IO_LATENCY_EQUIVALENCE_UNPROVEN")
        if safety.get("io_durability_compatible") is not True or policy.get("allows_lower_durability") is not True:
            reasons.add("STORAGE_IO_DURABILITY_EQUIVALENCE_UNPROVEN")
    return safety, authority, method


def evaluate_storage(data):
    with localcontext() as context:
        context.prec = 80
        return _evaluate(data)


def _evaluate(data):
    _object(data, TOP, TOP)
    if data["schema_version"] != SCHEMA_VERSION or data["model_version"] != MODEL_VERSION or data["resource_kind"] not in ("EBS_VOLUME", "EBS_SNAPSHOT"):
        raise EvidenceError("unsupported storage model")
    binding = _object(data["binding"], BINDING, BINDING)
    for field in BINDING:
        if field == "workload_id" and binding[field] is None:
            continue
        _text(binding[field])
    if binding["provider"] != "AWS":
        raise EvidenceError("unsupported storage provider")
    if not re.fullmatch(r"[0-9]{12}", binding["account_id"]) or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", binding["region"]):
        raise EvidenceError("storage native account or region differs")
    prefix = "vol" if data["resource_kind"] == "EBS_VOLUME" else "snap"
    native_id = binding["provider_resource_id"]
    if native_id.startswith("arn:"):
        match = re.fullmatch(r"arn:([a-z0-9-]+):ec2:([^:]+):([0-9]{12}):(volume|snapshot)/(.+)", native_id)
        if match is None or match[2] != binding["region"] or match[3] != binding["account_id"] or match[4] != ("volume" if prefix == "vol" else "snapshot"):
            raise EvidenceError("storage ARN scope differs")
        native_id = match[5]
    if not re.fullmatch(prefix + r"-(?:[a-f0-9]{8}|[a-f0-9]{17})", native_id):
        raise EvidenceError("storage native resource ID differs")
    _utc(data["as_of"])
    current = _object(data["current_configuration"], CONFIG, ("state", "source_ref"))
    refs, global_reasons = {}, set()
    _ref(current["source_ref"], refs, global_reasons, "CURRENT_CONFIGURATION")
    policy, days = _policy(data["policy"], refs, global_reasons)
    snapshot_reviews, snapshot_unknown = _snapshot_reviews(data, policy, refs)
    attached = current.get("attachments")
    if attached is not None and (not isinstance(attached, list) or len(attached) > 64):
        raise EvidenceError("storage attachment bound")
    if data["resource_kind"] == "EBS_SNAPSHOT" or attached == []:
        reasons = set(global_reasons)
        review_caps = _capabilities(data, refs, reasons) if data["resource_kind"] == "EBS_VOLUME" else {}
        economics = _economics(data, None, review_caps.get(current.get("capability_id")), None, refs, reasons)
        if data["resource_kind"] == "EBS_SNAPSHOT":
            kind, next_action = "STORAGE_SNAPSHOT_RETENTION_REVIEW", "REVIEW_SNAPSHOT_DEPENDENCIES_AND_RETENTION"
        else:
            kind, next_action = "STORAGE_UNATTACHED_REVIEW", "OWNER_RELEVANCE_REVIEW"
        safety = _object(data["safety"], SAFETY) if data["safety"] is not None else {}
        owner = safety.get("owner")
        if not owner:
            reasons.add("STORAGE_OWNER_UNKNOWN")
        if current["state"] not in ("available", "completed"):
            reasons.add("STORAGE_STATE_REQUIRES_REVIEW")
        if policy.get("quarantine_days") is None or policy.get("backup_required") is None:
            reasons.add("STORAGE_QUARANTINE_OR_BACKUP_POLICY_UNKNOWN")
        if kind == "STORAGE_UNATTACHED_REVIEW" and owner and policy.get("quarantine_days") is not None:
            next_action = "QUARANTINE_AND_BACKUP_POLICY_REVIEW"
        review = {"owner": owner, "age_days": None, "prior_attachment_context": "UNKNOWN_NOT_INFERRED_FROM_CURRENT_ABSENCE",
                  "backup_observed": safety.get("backup_observed"), "quarantine_days": policy.get("quarantine_days"),
                  "next_action": next_action, "deletion_recommended": False}
        if current.get("created_at") is not None:
            age = (_utc(data["as_of"]) - _utc(current["created_at"])).total_seconds()
            if age < 0:
                raise EvidenceError("future volume creation")
            review["age_days"] = int(age // 86400)
        selected = {"id": "read-only-review", "status": "OBSERVATION_ONLY", "recommendation_kind": kind,
                    "decision_code": "REVIEW_ONLY_NO_DELETION", "candidate_configuration": None, "checks": [],
                    "economics": economics, "blockers": sorted(reasons | set(snapshot_unknown)),
                    "target_validation_required": True, "execution_authorized": False, "verified_saving": None}
        return _output(data, selected, [selected], None, [], snapshot_reviews, refs, review,
                       safety.get("configuration_authority"), "OWNER_POLICY_AND_DEPENDENCY_REVIEW")
    for name in ("capability_id", "volume_type", "size_gib", "iops", "throughput_mib_per_second"):
        if current.get(name) is None:
            global_reasons.add("STORAGE_CURRENT_CONFIGURATION_UNKNOWN:" + name)
    if current.get("state") != "in-use" or attached is None:
        global_reasons.add("STORAGE_ATTACHMENT_STATE_UNAVAILABLE")
    if isinstance(attached, list):
        attachment_ids = set()
        for item in attached:
            _object(item, ("instance_id", "device", "state", "delete_on_termination", "root_device"), ("instance_id",))
            identifier = _text(item["instance_id"])
            if identifier in attachment_ids:
                raise EvidenceError("duplicate storage attachment instance")
            attachment_ids.add(identifier)
            if item.get("state") != "attached" or not isinstance(item.get("device"), str) or not item["device"]:
                global_reasons.add("STORAGE_NATIVE_ATTACHMENT_NOT_READY")
            if type(item.get("delete_on_termination")) is not bool or type(item.get("root_device")) is not bool:
                global_reasons.add("STORAGE_ROOT_OR_DELETE_ON_TERMINATION_UNKNOWN")
    if type(current.get("multi_attach_enabled")) is not bool or type(current.get("encrypted")) is not bool:
        global_reasons.add("STORAGE_NATIVE_FEATURE_STATE_UNKNOWN")
    if not isinstance(current.get("throughput_basis"), str) or not current["throughput_basis"]:
        global_reasons.add("STORAGE_CURRENT_THROUGHPUT_BASIS_UNKNOWN")
    if current.get("native_provisioned_throughput_mib_per_second") is None:
        if current.get("throughput_basis") == "NATIVE_PROVISIONED":
            global_reasons.add("STORAGE_NATIVE_PROVISIONED_THROUGHPUT_ABSENT")
    elif current.get("throughput_mib_per_second") is None or _number(current["native_provisioned_throughput_mib_per_second"]) != _number(current["throughput_mib_per_second"]):
        global_reasons.add("STORAGE_NATIVE_PROVISIONED_THROUGHPUT_MISMATCH")
    capabilities = _capabilities(data, refs, global_reasons)
    current_cap = capabilities.get(current.get("capability_id"))
    if current_cap is None:
        global_reasons.add("STORAGE_CURRENT_CAPABILITY_UNAVAILABLE")
    elif current_cap["volume_type"] != current.get("volume_type"):
        global_reasons.add("STORAGE_CURRENT_CAPABILITY_TYPE_MISMATCH")
    window, distributions, extrema, all_idle = _history(data, refs, global_reasons, days)
    candidates = data["candidate_configurations"]
    if not isinstance(candidates, list) or len(candidates) > 32:
        raise EvidenceError("storage candidate bound")
    if not candidates:
        global_reasons.add("STORAGE_CANDIDATES_UNAVAILABLE")
        economics = _economics(data, None, current_cap, None, refs, global_reasons)
        selected = {"id": "unavailable", "status": "BLOCKED", "recommendation_kind": "STORAGE_UNSUPPORTED_CONFIGURATION",
                    "decision_code": "EVIDENCE_OR_COMPATIBILITY_BLOCKED", "candidate_configuration": None, "checks": [],
                    "economics": economics, "blockers": sorted(global_reasons), "target_validation_required": True,
                    "execution_authorized": False, "verified_saving": None}
        safety = data.get("safety") or {}
        return _output(data, selected, [selected], window, distributions, snapshot_reviews, refs, None,
                       safety.get("configuration_authority"), "REVIEW_CONFIGURATION_AUTHORITY")
    results, identifiers, authority, method = [], set(), None, None
    for candidate in candidates:
        _object(candidate, ("id", "capability_id", "volume_type", "size_gib", "iops", "throughput_mib_per_second", "pricing"),
                ("id", "capability_id", "volume_type", "size_gib", "iops", "throughput_mib_per_second", "pricing"))
        identifier = _text(candidate["id"])
        if identifier in identifiers:
            raise EvidenceError("duplicate storage candidate")
        identifiers.add(identifier)
        for field in ("size_gib", "iops", "throughput_mib_per_second"):
            _number(candidate[field])
        reasons = set(global_reasons)
        checks = []
        safety, authority, method = _safety(data, policy, refs, reasons, candidate)
        target_cap = _candidate_capability(candidate, capabilities, current, refs, reasons)
        if current.get("size_gib") is not None and _number(candidate["size_gib"]) < _number(current["size_gib"]):
            used = extrema.get("filesystem_used_bytes")
            viable = used is not None and used * (1 + (policy.get("reserve_above_demand_fraction") or Decimal(0))) <= _number(candidate["size_gib"]) * (1024 ** 3)
            reasons.add("STORAGE_SIZE_REDUCTION_REQUIRES_NEW_VOLUME_MIGRATION")
            if not viable:
                reasons.add("STORAGE_FILESYSTEM_USED_CAPACITY_UNAVAILABLE_OR_TOO_LARGE")
            economics = _economics(data, None, current_cap, None, refs, reasons)
            results.append({"id": identifier, "status": "OBSERVATION_ONLY" if viable else "BLOCKED", "recommendation_kind": "MIGRATION_OPPORTUNITY",
                            "decision_code": "NEW_VOLUME_MIGRATION_REQUIRED", "candidate_configuration": {k: candidate[k] for k in candidate if k != "pricing"},
                            "checks": [], "economics": economics, "blockers": sorted(reasons), "migration_requirements": list(MIGRATION_STEPS),
                            "target_validation_required": True, "execution_authorized": False, "verified_saving": None})
            continue
        if current.get("size_gib") is not None and _number(candidate["size_gib"]) != _number(current["size_gib"]):
            reasons.add("STORAGE_SIZE_CHANGE_OUTSIDE_PERFORMANCE_SCREEN")
        before, after = current.get("volume_type"), candidate["volume_type"]
        if before == "gp2" and after == "gp3":
            kind = "STORAGE_GP2_TO_GP3"
        elif before == after == "gp3":
            kind = "STORAGE_GP3_IOPS_RIGHTSIZE" if current.get("iops") is not None and _number(candidate["iops"]) < _number(current["iops"]) else "STORAGE_GP3_THROUGHPUT_RIGHTSIZE"
            if any(current.get(field) is not None and _number(candidate[field]) > _number(current[field]) for field in ("iops", "throughput_mib_per_second")):
                reasons.add("STORAGE_GP3_PERFORMANCE_INCREASE_OUTSIDE_RIGHTSIZE_SCOPE")
        elif before in ("io1", "io2") and after == "gp3":
            kind = "STORAGE_IO_TO_GP3"
        else:
            kind = "STORAGE_UNSUPPORTED_CONFIGURATION"
            reasons.add("STORAGE_TRANSITION_OUTSIDE_SUPPORTED_SCREEN")
        def check(dimension, demand, available, fraction, unit, reserve=True):
            required, limit = None, None
            r = policy.get("reserve_above_demand_fraction") if reserve else Decimal(0)
            growth = policy.get("demand_growth_multiplier") if reserve else Decimal(1)
            if demand is None or available is None or fraction is None or r is None or growth is None:
                status = "BLOCKED"
                reasons.add("STORAGE_CAPACITY_OR_DEMAND_UNKNOWN:" + dimension)
            else:
                required, limit = demand * growth * (1 + r), available * fraction
                status = "PASS" if required <= limit else "FAIL"
                if status == "FAIL":
                    reasons.add("STORAGE_OBSERVED_CHECK_FAILED:" + dimension)
            checks.append({"dimension": dimension, "status": status, "unit": unit,
                           "observed_demand": _money(demand) if demand is not None else None,
                           "required_with_reserve": _money(required) if required is not None else None,
                           "available": _money(available) if available is not None else None,
                           "planning_limit": _money(limit) if limit is not None else None,
                           "basis": "OBSERVED_NATIVE_PERIOD_PEAK_WITH_EXPLICIT_HEADROOM" if reserve else "OBSERVED_CURRENT_SLO_NOT_TARGET_LATENCY_PREDICTION"})
        def total(a, b):
            return extrema[a] + extrema[b] if extrema.get(a) is not None and extrema.get(b) is not None else None
        iops, throughput = total("read_iops", "write_iops"), total("read_throughput", "write_throughput")
        instance_iops = safety.get("instance_iops_limit")
        instance_throughput = safety.get("instance_throughput_mib_per_second_limit")
        if instance_iops is None or instance_throughput is None:
            reasons.add("STORAGE_ATTACHED_INSTANCE_SUSTAINED_BUDGET_UNKNOWN")
        iops_limit = min(_number(candidate["iops"]), _number(instance_iops)) if instance_iops is not None else None
        throughput_limit = min(_number(candidate["throughput_mib_per_second"]), _number(instance_throughput)) * MIB if instance_throughput is not None else None
        check("iops", iops, iops_limit, policy.get("iops_max_fraction"), "Count/Second")
        check("throughput", throughput, throughput_limit, policy.get("throughput_max_fraction"), "Bytes/Second")
        for name, threshold in (("read_latency", "max_read_latency_seconds"), ("write_latency", "max_write_latency_seconds"), ("queue_length", "max_disk_queue_depth")):
            if name in all_idle:
                checks.append({"dimension": name, "status": "NOT_APPLICABLE_ZERO_OPERATIONS", "unit": METRICS[name][0], "observed_demand": None,
                               "required_with_reserve": None, "available": _money(policy[threshold]) if policy.get(threshold) is not None else None,
                               "planning_limit": None, "basis": "KNOWN_ZERO_NATIVE_OPERATIONS_LATENCY_UNDEFINED"})
            else:
                check(name, extrema.get(name), policy.get(threshold), Decimal(1), METRICS[name][0], False)
        if before == "gp2":
            balance, threshold = extrema.get("burst_balance"), policy.get("min_burst_balance_percent")
            if balance is None or threshold is None:
                reasons.add("STORAGE_BURST_BEHAVIOUR_UNKNOWN")
            elif balance < threshold:
                reasons.add("STORAGE_BURST_DEPLETION_CAN_HIDE_DEMAND")
        for name in ("iops_exceeded", "throughput_exceeded"):
            if extrema.get(name) is not None and extrema[name] > 0:
                reasons.add("STORAGE_NATIVE_LIMIT_EXCEEDED_CAN_HIDE_DEMAND:" + name)
        if extrema.get("throughput_percentage") is not None and extrema["throughput_percentage"] > 100:
            reasons.add("STORAGE_NATIVE_THROUGHPUT_LIMIT_CAN_HIDE_DEMAND")
        economics = _economics(data, candidate, current_cap, target_cap, refs, reasons)
        failed = any(item["status"] == "FAIL" for item in checks)
        unknown = any(item["status"] == "BLOCKED" for item in checks)
        unsafe = reasons - {"STORAGE_OBSERVED_CHECK_FAILED:" + item["dimension"] for item in checks if item["status"] == "FAIL"}
        same = before == after and all(current.get(k) is not None and _number(current[k]) == _number(candidate[k]) for k in ("size_gib", "iops", "throughput_mib_per_second"))
        if unsafe or unknown or economics["status"] == "UNAVAILABLE":
            status, code = "BLOCKED", "EVIDENCE_OR_COMPATIBILITY_BLOCKED"
        elif failed:
            status, code = "NO_CHANGE", "DO_NOT_PROCEED"
        elif same:
            status, code = "NO_CHANGE", "CURRENT_CONFIGURATION_RETAINED"
        elif economics["status"] != "CHEAPER":
            status, code = "NO_CHANGE", "DO_NOT_PROCEED"
            reasons.add("STORAGE_TARGET_NOT_CHEAPER")
        else:
            status, code = "RECOMMENDED", "CONSIDER_PERFORMANCE_CONFIGURATION_CHANGE"
        results.append({"id": identifier, "status": status, "recommendation_kind": kind, "decision_code": code,
                        "candidate_configuration": {k: candidate[k] for k in candidate if k != "pricing"}, "checks": checks,
                        "economics": economics, "blockers": sorted(reasons), "target_validation_required": True,
                        "execution_authorized": False, "verified_saving": None})
    eligible = [row for row in results if row["status"] == "RECOMMENDED"] or [row for row in results if row["status"] == "NO_CHANGE"]
    selected = min(eligible, key=lambda row: (Decimal(row["economics"]["candidate_monthly_cost"]), row["id"])) if eligible else results[0]
    return _output(data, selected, results, window, distributions, snapshot_reviews, refs, None, authority, method)


def _output(data, selected, results, window, distributions, snapshot_reviews, refs, review, authority, method):
    output = {"schema_version": SCHEMA_VERSION, "model_version": MODEL_VERSION, "resource_kind": data["resource_kind"],
              "binding": data["binding"], "current_configuration": data["current_configuration"],
              "candidate_configuration": selected["candidate_configuration"], "evidence_window": window,
              "metric_distributions": distributions, "economics": selected["economics"], "checks": selected["checks"], "blockers": selected["blockers"],
              "confidence": {"status": "MEDIUM" if selected["status"] in ("RECOMMENDED", "NO_CHANGE") else "UNAVAILABLE",
                             "meaning": "OBSERVED_DEMAND_SCREEN_NOT_STATISTICAL_CONFIDENCE",
                             "reasons": ["PERIOD_STATISTICS_ARE_NOT_RAW_IO_PERCENTILES", "TARGET_VALIDATION_REQUIRED", "HELD_CUR_RATES_ARE_NOT_FUTURE_PRICE_GUARANTEES"]},
              "proposal": {"risk_class": "R3", "executable": False, "execution_authorized": False}, "verified_saving": None,
              "configuration_authority": authority, "implementation_method": method, "unattached_review": review,
              "snapshot_reviews": snapshot_reviews, "source_refs": sorted(refs.values(), key=lambda ref: (ref["kind"], ref["id"], ref["version"])),
              "candidates": results, "recommendation_kind": selected["recommendation_kind"], "decision_code": selected["decision_code"], "status": selected["status"],
              "model_assumptions": ["Same size, encryption, KMS identity and current attachment scope; no direct GiB shrink",
                                    "Native source-period peaks plus explicit policy reserve and independent IOPS/throughput headroom",
                                    "Attached instance limits must be server-resolved remaining sustained budgets, including other volumes",
                                    "Continuing snapshot, FSR, archive and other attributable charges are retained",
                                    "Snapshot and unattached-volume reviews never authorize deletion", "No calibrated forecast, mutation or verified saving"]}
    if selected.get("migration_requirements"):
        output["migration_requirements"] = selected["migration_requirements"]
    output["assessment_hash"] = _hash(output)
    return output
