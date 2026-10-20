"""Read-only RDS/Aurora observed-demand screening, never execution authority.

The control plane resolves native catalog, parameters, configuration, metrics,
CUR and policy receipts. This pure engine validates their scoped arithmetic;
receipt-shaped input alone does not authenticate AWS provenance. Hourly extrema
and their empirical percentiles are not raw-sample percentiles or forecasts.
"""
from datetime import timedelta, timezone
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import re

from .model import EvidenceError, decimal, instant

MODEL_VERSION = "database-observed-capacity-v1"
SCHEMA_VERSION = "1"
ROUTE = "/v7/database-assessment"
MONTH_HOURS, YEAR_HOURS = Decimal(730), Decimal(8760)
PRICE_BASIS = "NATIVE_CUR_NET_USAGE_EXCLUDING_COMMITMENT_FEES"
ECONOMIC_BASIS = "HELD_NATIVE_NET_USAGE_AND_CONTINUING_COSTS_730H_MONTH_8760H_YEAR"
BINDING = ("tenant_id", "workload_id", "resource_id", "provider",
           "provider_resource_id", "account_id", "region")
CAPACITIES = ("vcpu", "memory_bytes", "max_connections", "iops",
              "throughput_bytes_per_second", "network_bytes_per_second", "storage_bytes")
# FreeableMemory is available RAM: retain its native minimum, not an invented
# working-set distribution. The memory check uses allocated minus freeable.
METRICS = {
    "cpu_utilization": ("Percent", "Maximum"),
    "freeable_memory": ("Bytes", "Minimum"),
    "connections": ("Count", "Maximum"),
    "read_iops": ("Count/Second", "Maximum"),
    "write_iops": ("Count/Second", "Maximum"),
    "read_throughput": ("Bytes/Second", "Maximum"),
    "write_throughput": ("Bytes/Second", "Maximum"),
    "network_receive": ("Bytes/Second", "Maximum"),
    "network_transmit": ("Bytes/Second", "Maximum"),
    "used_storage": ("Bytes", "Maximum"),
    "read_latency": ("Seconds", "Maximum"),
    "write_latency": ("Seconds", "Maximum"),
    "disk_queue_depth": ("Count", "Maximum"),
    "replica_lag": ("Seconds", "Maximum"),
}
POLICY_NUMBERS = ("cpu_max_fraction", "memory_max_fraction", "connections_max_fraction",
                  "iops_max_fraction", "throughput_max_fraction", "network_max_fraction",
                  "storage_max_fraction", "cpu_headroom_fraction", "memory_headroom_fraction",
                  "reserve_above_forecast_fraction", "max_read_latency_seconds",
                  "max_write_latency_seconds", "max_disk_queue_depth", "max_replica_lag_seconds")
TOP_FIELDS = ("schema_version", "model_version", "resource_kind", "binding", "as_of", "engine",
              "engine_version", "license_model", "storage_type", "current_catalog_id",
              "current_configuration", "catalog", "candidate_configurations", "history",
              "observations", "policy", "current_pricing", "continuing_costs")


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise EvidenceError("unsupported database object fields")
    return value


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 1024 or any(ord(c) < 32 for c in value):
        raise EvidenceError("database identity required")
    return value


def _int(value, minimum=0, maximum=100000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise EvidenceError("database integer outside bound")
    return value


def _number(value, nonnegative=True):
    number = decimal(value, "database quantity")
    if nonnegative and number < 0:
        raise EvidenceError("negative database quantity")
    return number


def _money(value):
    with localcontext() as ctx:
        ctx.prec = 80
        result = value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN)
    if abs(result) >= Decimal("1e26"):
        raise EvidenceError("database result exceeds DECIMAL(38,12)")
    return format(result, "f")


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _utc(value):
    # Do not silently turn a non-UTC billing/history calendar into a UTC day.
    if not isinstance(value, str) or not (value.endswith("Z") or value.endswith("+00:00")):
        raise EvidenceError("database UTC timestamp required")
    return instant(value)


def _period(value):
    _object(value, ("start", "end"), ("start", "end"))
    start, end = _utc(value["start"]), _utc(value["end"])
    if end <= start:
        raise EvidenceError("database interval must be positive")
    return start, end


def _strings(values, empty=False):
    if not isinstance(values, list) or len(values) > 16 or (not values and not empty):
        raise EvidenceError("database member set outside bound")
    for value in values:
        _text(value)
    if len(values) != len(set(values)):
        raise EvidenceError("ambiguous database member set")
    return sorted(values)


def _ref(value, refs, reasons, label):
    if value is None:
        reasons.add("UNKNOWN_" + label)
        return False
    _object(value, ("kind", "id", "version", "sha256"), ("kind", "id", "version", "sha256"))
    for key in ("kind", "id", "version"):
        _text(value[key])
    if not isinstance(value["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", value["sha256"]):
        raise EvidenceError("immutable database receipt hash required")
    key = (value["kind"], value["id"], value["version"])
    if key in refs and refs[key] != value:
        raise EvidenceError("conflicting database receipt version")
    refs[key] = value
    return True


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate database object member")
        result[key] = value
    return result


def _policy(value, refs, reasons):
    if value is None:
        reasons.add("DATABASE_POLICY_UNAVAILABLE")
        return None, None
    _object(value, (*POLICY_NUMBERS, "criticality", "high_seasonality", "min_instances",
                    "min_zones", "source_ref"))
    _ref(value.get("source_ref"), refs, reasons, "POLICY_REFERENCE")
    criticality = value.get("criticality")
    if criticality not in ("NON_PRODUCTION", "TIER_0", "TIER_1", "TIER_2", "TIER_3") or type(value.get("high_seasonality")) is not bool:
        reasons.add("DATABASE_POLICY_CLASSIFICATION_UNAVAILABLE")
        days = None
    else:
        days = 90 if value["high_seasonality"] else 14 if criticality == "NON_PRODUCTION" else 30
    parsed = {}
    for name in POLICY_NUMBERS:
        if value.get(name) is None:
            reasons.add("UNKNOWN_POLICY_" + name.upper())
            parsed[name] = None
        else:
            parsed[name] = _number(value[name])
            if name == "reserve_above_forecast_fraction":
                if parsed[name] > 10:
                    raise EvidenceError("database reserve exceeds policy bound")
            elif name in ("cpu_headroom_fraction", "memory_headroom_fraction"):
                if parsed[name] >= 1:
                    raise EvidenceError("database headroom must be below one")
            elif name.endswith("fraction") and not 0 < parsed[name] <= 1:
                raise EvidenceError("database utilization cap must be positive and at most one")
    for name in ("min_instances", "min_zones"):
        if value.get(name) is None:
            reasons.add("UNKNOWN_POLICY_" + name.upper())
            parsed[name] = None
        else:
            parsed[name] = _int(value[name], 1, 16)
    return parsed, days


def _catalog(data, refs, reasons):
    value = data.get("catalog")
    if value is None:
        reasons.add("NATIVE_DATABASE_CATALOG_UNAVAILABLE")
        return {}
    _object(value, ("source_ref", "entries"), ("entries",))
    _ref(value.get("source_ref"), refs, reasons, "NATIVE_CATALOG_REFERENCE")
    entries = value["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 101:
        raise EvidenceError("database catalog outside bound")
    result = {}
    for entry in entries:
        _object(entry, ("id", "class_id", "engine", "engine_version", "license_model", "storage_type",
                        "region", "architecture", "cpu_model", "multi_az_capable", "zones", "capacity",
                        "source_ref", "parameter_source_ref"), ("id", "class_id"))
        identifier = _text(entry["id"])
        if identifier in result:
            raise EvidenceError("ambiguous database catalog ID")
        _text(entry["class_id"])
        result[identifier] = entry
    return result


def _entry(entry, data, refs, reasons):
    if entry is None:
        reasons.add("NATIVE_CATALOG_ENTRY_UNAVAILABLE")
        return None
    _ref(entry.get("source_ref"), refs, reasons, "NATIVE_CATALOG_ENTRY_REFERENCE")
    _ref(entry.get("parameter_source_ref"), refs, reasons, "EFFECTIVE_PARAMETER_REFERENCE")
    for field in ("engine", "engine_version", "license_model", "storage_type", "region"):
        expected = data["binding"]["region"] if field == "region" else data[field]
        if entry.get(field) is None:
            reasons.add("UNKNOWN_CATALOG_" + field.upper())
        elif entry[field] != expected:
            reasons.add("CATALOG_" + field.upper() + "_MISMATCH")
    if not entry.get("architecture") or not entry.get("cpu_model"):
        reasons.add("CATALOG_PROCESSOR_UNAVAILABLE")
    elif not isinstance(entry["architecture"], str) or not isinstance(entry["cpu_model"], str):
        raise EvidenceError("database processor metadata differs")
    if type(entry.get("multi_az_capable")) is not bool:
        reasons.add("CATALOG_HA_CAPABILITY_UNAVAILABLE")
    if entry.get("zones") is None:
        reasons.add("CATALOG_ZONES_UNAVAILABLE")
    else:
        _strings(entry["zones"])
    capacity = entry.get("capacity")
    if capacity is None:
        reasons.add("CATALOG_CAPACITY_UNAVAILABLE")
        return {name: None for name in CAPACITIES}
    _object(capacity, CAPACITIES)
    result = {name: None if capacity.get(name) is None else _number(capacity[name]) for name in CAPACITIES}
    for name, value in result.items():
        if value == 0:
            reasons.add("NATIVE_DATABASE_CAPACITY_UNAVAILABLE:" + name)
            result[name] = None
    return result


def _history(data, members, replicas, network_supported, refs, reasons, required_days):
    history = data["history"]
    _object(history, ("start", "end", "metrics", "source_refs"), ("start", "end", "metrics", "source_refs"))
    start, end = _period({key: history[key] for key in ("start", "end")})
    if start.hour or start.minute or start.second or start.microsecond or end.hour or end.minute or end.second or end.microsecond:
        raise EvidenceError("database history requires complete UTC days")
    days = (end - start).days
    if not 1 <= days <= 90:
        raise EvidenceError("database history outside ninety-day bound")
    as_of = _utc(data["as_of"])
    if as_of < end:
        raise EvidenceError("future database observations")
    if as_of - end > timedelta(hours=48):
        reasons.add("DATABASE_HISTORY_STALE")
    if required_days is None or days < required_days:
        reasons.add("INSUFFICIENT_COMPLETE_UTC_DAYS")
    if not isinstance(history["source_refs"], list) or not 1 <= len(history["source_refs"]) <= 1000:
        raise EvidenceError("database metric receipt set outside bound")
    for ref in history["source_refs"]:
        _ref(ref, refs, reasons, "METRIC_REFERENCE")
    definitions = history["metrics"]
    if not isinstance(definitions, list) or len(definitions) > len(METRICS):
        raise EvidenceError("database metric definitions outside bound")
    specs = {}
    for item in definitions:
        _object(item, ("name", "unit", "statistic", "period_seconds", "sample_period_seconds", "expected_sample_count",
                       "expected_native_sample_count"), ("name",))
        name = item["name"]
        if name not in METRICS or name in specs:
            raise EvidenceError("unknown or duplicate database metric")
        valid = (item.get("unit"), item.get("statistic")) == METRICS[name] and item.get("period_seconds") == 3600
        sample_period = item.get("sample_period_seconds")
        if type(sample_period) is not int or sample_period not in (60, 300, 3600):
            valid = False
        if valid and (type(item.get("expected_sample_count")) is not int or item["expected_sample_count"] != 3600 // sample_period):
            valid = False
        # Accepted instance metrics are native one-minute series. One known
        # hourly CloudWatch bin is insufficient when it contains one sample.
        # Cluster five-minute Volume metrics are not part of this mapping.
        if type(item.get("expected_native_sample_count")) is not int or item["expected_native_sample_count"] != 60:
            valid = False
        specs[name] = item if valid else None
        if not valid:
            reasons.add("DATABASE_METRIC_DEFINITION_UNSUPPORTED:" + name)
    observations = data["observations"]
    if not isinstance(observations, list) or len(observations) > 16 * 90 * 24:
        raise EvidenceError("database observation bound")
    hours = days * 24
    series = {(member, name): [] for member in members for name in METRICS}
    counts = {(member, name): 0 for member in members for name in METRICS}
    native_counts = {(member, name): Decimal(0) for member in members for name in METRICS}
    seen = set()
    for row in observations:
        _object(row, ("member_id", "start", "end", "metrics"), ("member_id", "start", "end", "metrics"))
        member = row["member_id"]
        if member not in members:
            raise EvidenceError("foreign database observation member")
        a, b = _period({key: row[key] for key in ("start", "end")})
        if b - a != timedelta(hours=1) or a < start or b > end or (a - start).total_seconds() % 3600:
            raise EvidenceError("database observation hourly grid differs")
        key = (member, a)
        if key in seen:
            raise EvidenceError("duplicate database member-hour")
        seen.add(key)
        metrics = _object(row["metrics"], METRICS)
        for name in METRICS:
            applicable = not (name == "replica_lag" and member not in replicas or name.startswith("network_") and network_supported is False)
            if not applicable:
                continue
            spec, point = specs.get(name), metrics.get(name)
            if point is None:
                reasons.add("DATABASE_METRIC_UNKNOWN:" + name)
                continue
            _object(point, ("value", "sample_count", "native_sample_count", "duplicate_sample_count"), ("value", "sample_count"))
            count = _int(point["sample_count"], 0, 3600)
            if point.get("duplicate_sample_count") is None:
                reasons.add("DATABASE_DUPLICATE_SAMPLE_STATUS_UNKNOWN:" + name)
                continue
            if _int(point["duplicate_sample_count"], 0, 100000) != 0:
                reasons.add("DATABASE_NATIVE_SAMPLE_BINS_AMBIGUOUS:" + name)
                continue
            if spec is None or count != spec["expected_sample_count"]:
                reasons.add("DATABASE_METRIC_SAMPLE_COVERAGE_INCOMPLETE:" + name)
                continue
            if point.get("native_sample_count") is None or _number(point["native_sample_count"]) <= 0:
                reasons.add("DATABASE_NATIVE_SAMPLE_COUNT_UNKNOWN:" + name)
                continue
            if _number(point["native_sample_count"]) < spec["expected_native_sample_count"]:
                reasons.add("DATABASE_NATIVE_SAMPLE_COVERAGE_INCOMPLETE:" + name)
                continue
            if point["value"] is None:
                reasons.add("DATABASE_METRIC_UNKNOWN:" + name)
                continue
            value = _number(point["value"], nonnegative=name != "replica_lag")
            if name == "replica_lag" and value < 0:
                reasons.add("DATABASE_REPLICA_LAG_UNAVAILABLE_SENTINEL")
                continue
            if name == "cpu_utilization" and value > 100:
                raise EvidenceError("database CPU percentage exceeds one hundred")
            series[(member, name)].append(value)
            counts[(member, name)] += count
            native_counts[(member, name)] += _number(point["native_sample_count"])
    if len(seen) != len(members) * hours:
        reasons.add("DATABASE_MEMBER_HOUR_COVERAGE_INCOMPLETE")
    distributions, extrema = [], {}
    for (member, name), values in sorted(series.items()):
        applicable = not (name == "replica_lag" and member not in replicas or name.startswith("network_") and network_supported is False)
        values.sort()
        complete = len(values) == hours and applicable
        if applicable and not complete:
            reasons.add("DATABASE_METRIC_HISTORY_INCOMPLETE:" + name)
        extrema[(member, name)] = (min(values) if name == "freeable_memory" else max(values)) if complete else None
        def percentile(n):
            return _money(values[(len(values) * n + 99) // 100 - 1]) if complete else None
        distributions.append({"member_id": member, "metric": name, "unit": METRICS[name][0],
                              "statistic": "HOURLY_" + METRICS[name][1].upper() + "_OF_NATIVE_PERIOD_VALUES",
                              "status": "NOT_APPLICABLE" if not applicable else "COMPLETE" if complete else "INCOMPLETE",
                              "expected_hours": hours if applicable else 0, "observed_hours": len(values),
                              "expected_sample_count": hours * specs[name]["expected_sample_count"] if applicable and specs.get(name) else None,
                              "expected_native_sample_count": hours * specs[name]["expected_native_sample_count"] if applicable and specs.get(name) else None,
                              "sample_count": counts[(member, name)],
                              "native_sample_count": _money(native_counts[(member, name)]),
                              "minimum": _money(values[0]) if values else None, "maximum": _money(values[-1]) if values else None,
                              "p50_of_period_statistics": percentile(50), "p95_of_period_statistics": percentile(95),
                              "p99_of_period_statistics": percentile(99)})
    return {"start": history["start"], "end": history["end"], "observed_utc_days": days,
            "required_utc_days": required_days, "expected_member_hours": len(members) * hours,
            "observed_member_hours": len(seen), "coverage_basis": "COMPLETE_HOURLY_EXTREMA_AND_NATIVE_SAMPLE_COUNTS"}, distributions, extrema


def _price(value, entry, data, multi_az, refs, reasons):
    if value is None or entry is None:
        reasons.add("NATIVE_CONTRACTED_PRICE_UNAVAILABLE")
        return None
    _object(value, ("basis", "class_id", "engine", "license_model", "region", "multi_az", "currency",
                    "unit", "rate", "quantity", "amount", "period", "source_ref"))
    if not _ref(value.get("source_ref"), refs, reasons, "NATIVE_CUR_REFERENCE"):
        return None
    for field, expected in (("basis", PRICE_BASIS), ("class_id", entry["class_id"]), ("engine", data["engine"]),
                            ("license_model", data["license_model"]), ("region", data["binding"]["region"]),
                            ("multi_az", multi_az), ("unit", "Hrs")):
        if value.get(field) != expected or field == "multi_az" and type(value.get(field)) is not bool:
            reasons.add("NATIVE_PRICE_DIMENSIONS_UNSUPPORTED")
            return None
    if not isinstance(value.get("currency"), str) or not re.fullmatch("[A-Z]{3}", value["currency"]):
        reasons.add("NATIVE_PRICE_CURRENCY_UNKNOWN")
        return None
    if any(value.get(field) is None for field in ("rate", "quantity", "amount", "period")):
        reasons.add("NATIVE_CONTRACTED_PRICE_UNKNOWN")
        return None
    start, end = _period(value["period"])
    if end > _utc(data["as_of"]):
        raise EvidenceError("future native database price")
    if _utc(data["as_of"]) - end > timedelta(hours=48):
        reasons.add("NATIVE_CONTRACTED_PRICE_STALE")
    rate, quantity, amount = (_number(value[field]) for field in ("rate", "quantity", "amount"))
    if quantity <= 0 or _money(quantity * rate) != _money(amount):
        raise EvidenceError("native contracted database price arithmetic differs")
    return rate, value["currency"]


def _economics(data, candidate, current_entry, target_entry, refs, reasons):
    empty = {"current_hourly_cost": None, "current_monthly_cost": None, "candidate_hourly_cost": None,
             "candidate_monthly_cost": None, "estimated_monthly_saving": None, "estimated_annual_saving": None,
             "currency": None, "basis": ECONOMIC_BASIS, "status": "UNAVAILABLE", "verified_saving": None}
    current = data["current_configuration"]
    a = _price(data.get("current_pricing"), current_entry, data, current["multi_az"], refs, reasons)
    b = _price(candidate.get("pricing"), target_entry, data, candidate.get("multi_az"), refs, reasons)
    continuing = data.get("continuing_costs")
    if continuing is None:
        reasons.add("CONTINUING_DATABASE_COSTS_UNAVAILABLE")
        return empty
    _object(continuing, ("currency", "period", "storage", "backup", "io", "commitment_exposure"))
    currency = continuing.get("currency")
    if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency):
        reasons.add("CONTINUING_DATABASE_CURRENCY_UNKNOWN")
    if continuing.get("period") is None:
        reasons.add("CONTINUING_DATABASE_COST_PERIOD_UNKNOWN")
        return empty
    start, end = _period(continuing["period"])
    if end > _utc(data["as_of"]):
        raise EvidenceError("future continuing database costs")
    if _utc(data["as_of"]) - end > timedelta(hours=48):
        reasons.add("CONTINUING_DATABASE_COSTS_STALE")
    hours = Decimal(int((end - start).total_seconds())) / 3600
    if hours <= 0:
        raise EvidenceError("continuing database cost interval differs")
    amounts = []
    for name in ("storage", "backup", "io"):
        part = continuing.get(name)
        if part is None:
            reasons.add("UNKNOWN_CONTINUING_" + name.upper() + "_COST")
            continue
        _object(part, ("amount", "source_ref"))
        known_ref = _ref(part.get("source_ref"), refs, reasons, "CONTINUING_" + name.upper() + "_REFERENCE")
        if part.get("amount") is None or not known_ref:
            reasons.add("UNKNOWN_CONTINUING_" + name.upper() + "_COST")
        else:
            amounts.append(_number(part["amount"]))
    exposure = continuing.get("commitment_exposure")
    ac = bc = None
    if exposure is None:
        reasons.add("CONTINUING_COMMITMENT_EXPOSURE_UNKNOWN")
    else:
        _object(exposure, ("current_amount", "candidate_amounts", "source_ref"))
        known_ref = _ref(exposure.get("source_ref"), refs, reasons, "COMMITMENT_EXPOSURE_REFERENCE")
        targets = exposure.get("candidate_amounts")
        if not isinstance(targets, dict) or len(targets) > 100:
            raise EvidenceError("database commitment exposure candidates differ")
        if exposure.get("current_amount") is None or targets.get(candidate["id"]) is None or not known_ref:
            reasons.add("CONTINUING_COMMITMENT_EXPOSURE_UNKNOWN")
        else:
            ac, bc = _number(exposure["current_amount"]), _number(targets[candidate["id"]])
            if bc < ac:
                reasons.add("UNPROVEN_REDUCTION_OF_CONTINUING_COMMITMENT_COST")
    if a is None or b is None or len(amounts) != 3 or ac is None or bc is None:
        return empty
    if a[1] != b[1] or a[1] != currency:
        reasons.add("MIXED_DATABASE_CURRENCIES")
        return empty
    current_hourly = a[0] * len(current["member_ids"]) + (sum(amounts) + ac) / hours
    target_hourly = b[0] * candidate["member_count"] + (sum(amounts) + bc) / hours
    difference = current_hourly - target_hourly
    return {"current_hourly_cost": _money(current_hourly), "current_monthly_cost": _money(current_hourly * MONTH_HOURS),
            "candidate_hourly_cost": _money(target_hourly), "candidate_monthly_cost": _money(target_hourly * MONTH_HOURS),
            "estimated_monthly_saving": _money(difference * MONTH_HOURS), "estimated_annual_saving": _money(difference * YEAR_HOURS),
            "currency": currency, "basis": ECONOMIC_BASIS, "status": "CHEAPER" if difference > 0 else "NO_CHANGE" if difference == 0 else "NOT_CHEAPER",
            "continuing_costs_preserved": True, "verified_saving": None}


def evaluate_database(data):
    """Return all candidates, including explicit unknown, unsafe and uneconomic cases."""
    with localcontext() as ctx:
        ctx.prec = 80
        ctx.rounding = ROUND_HALF_EVEN
        return _evaluate(data)


def _evaluate(data):
    _object(data, TOP_FIELDS, ("schema_version", "model_version", "resource_kind", "binding", "as_of", "engine",
                              "engine_version", "license_model", "storage_type", "current_catalog_id", "current_configuration",
                              "candidate_configurations", "history", "observations"))
    if data["schema_version"] != SCHEMA_VERSION or data["model_version"] != MODEL_VERSION or data["resource_kind"] not in ("RDS_INSTANCE", "RDS_CLUSTER"):
        raise EvidenceError("unsupported database assessment version or kind")
    binding = _object(data["binding"], BINDING, BINDING)
    for value in binding.values():
        _text(value)
    if binding["provider"] != "AWS" or not re.fullmatch("[0-9]{12}", binding["account_id"]):
        raise EvidenceError("native AWS database binding required")
    for name in ("engine", "engine_version", "license_model", "storage_type", "current_catalog_id"):
        _text(data[name])
    configuration = _object(data["current_configuration"], ("class_id", "member_ids", "member_class_ids", "replica_member_ids", "zones", "multi_az", "network_metrics_supported", "ha_context", "source_ref"),
                            ("class_id", "member_ids", "replica_member_ids", "zones", "multi_az", "network_metrics_supported"))
    members, replicas, zones = _strings(configuration["member_ids"]), _strings(configuration["replica_member_ids"], True), _strings(configuration["zones"])
    if not set(replicas) <= set(members) or data["resource_kind"] == "RDS_INSTANCE" and len(members) != 1:
        raise EvidenceError("database topology members differ")
    if type(configuration["multi_az"]) is not bool or configuration["network_metrics_supported"] is not None and type(configuration["network_metrics_supported"]) is not bool:
        raise EvidenceError("explicit database native capabilities required")
    refs, global_reasons = {}, set()
    _ref(configuration.get("source_ref"), refs, global_reasons, "CONFIGURATION_REFERENCE")
    classes = configuration.get("member_class_ids")
    if classes is None:
        global_reasons.add("PER_MEMBER_NATIVE_DATABASE_CLASSES_UNKNOWN")
    elif not isinstance(classes, dict) or set(classes) != set(members):
        raise EvidenceError("native member class scope differs")
    elif any(value != configuration["class_id"] for value in classes.values()):
        global_reasons.add("MIXED_NATIVE_DATABASE_CLASSES_UNSUPPORTED")
    ha = configuration.get("ha_context")
    ha_members, ha_zones = [], []
    if ha is None:
        global_reasons.add("WHOLE_DATABASE_HA_CONTEXT_UNKNOWN")
    else:
        _object(ha, ("member_ids", "zones", "source_ref"), ("member_ids", "zones"))
        ha_members, ha_zones = _strings(ha["member_ids"]), _strings(ha["zones"])
        _ref(ha.get("source_ref"), refs, global_reasons, "HA_CONTEXT_REFERENCE")
        if not set(members) <= set(ha_members) or not set(zones) <= set(ha_zones):
            raise EvidenceError("selected database absent from whole HA context")
        if data["resource_kind"] == "RDS_CLUSTER" and (members != ha_members or zones != ha_zones):
            raise EvidenceError("database cluster observations must cover whole HA context")
    if configuration["network_metrics_supported"] is None:
        global_reasons.add("NETWORK_METRIC_SUPPORT_UNKNOWN")
    policy, required_days = _policy(data.get("policy"), refs, global_reasons)
    catalog = _catalog(data, refs, global_reasons)
    current_entry = catalog.get(data["current_catalog_id"])
    current_capacity = _entry(current_entry, data, refs, global_reasons)
    if current_entry is not None and current_entry["class_id"] != configuration["class_id"]:
        global_reasons.add("CURRENT_NATIVE_CLASS_MISMATCH")
    window, distributions, extrema = _history(data, members, replicas, configuration["network_metrics_supported"], refs, global_reasons, required_days)
    candidates = data["candidate_configurations"]
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 100:
        raise EvidenceError("database candidate bound")
    results, identifiers = [], set()
    for candidate in candidates:
        _object(candidate, ("id", "catalog_id", "member_count", "zones", "multi_az", "pricing"), ("id", "catalog_id", "member_count", "zones", "multi_az"))
        identifier = _text(candidate["id"])
        if identifier in identifiers:
            raise EvidenceError("ambiguous database candidate")
        identifiers.add(identifier)
        _int(candidate["member_count"], 1, 16)
        target_zones = _strings(candidate["zones"])
        if type(candidate["multi_az"]) is not bool:
            raise EvidenceError("candidate multi-AZ capability must be explicit")
        reasons, checks = set(global_reasons), []
        target_entry = catalog.get(candidate["catalog_id"])
        capacity = _entry(target_entry, data, refs, reasons)
        if target_entry and current_entry and (target_entry.get("architecture"), target_entry.get("cpu_model")) != (current_entry.get("architecture"), current_entry.get("cpu_model")):
            reasons.add("TARGET_PROCESSOR_PERFORMANCE_NOT_COMPARABLE")
        if candidate["member_count"] != len(members) or target_zones != zones:
            reasons.add("DATABASE_TOPOLOGY_CHANGE_UNSUPPORTED")
        if target_entry and (not set(target_zones) <= set(target_entry.get("zones") or []) or candidate["multi_az"] and target_entry.get("multi_az_capable") is not True):
            reasons.add("NATIVE_CANDIDATE_NOT_ORDERABLE_IN_TARGET_TOPOLOGY")
        if configuration["multi_az"] and not candidate["multi_az"]:
            reasons.add("EXISTING_MULTI_AZ_PROTECTION_MUST_BE_RETAINED")
        if policy and ((policy["min_instances"] is not None and len(ha_members) < policy["min_instances"]) or
                       (policy["min_zones"] is not None and len(ha_zones) < policy["min_zones"])):
            reasons.add("DATABASE_HA_MINIMUM_NOT_PRESERVED")

        def check(member, dimension, demand, available, fraction, unit, basis, reserve_capacity=True):
            if demand is None or available is None or fraction is None:
                status, limit, required = "BLOCKED", None, None
                reasons.add("UNKNOWN_DATABASE_CAPACITY_OR_DEMAND:" + dimension)
            else:
                reserve = policy["reserve_above_forecast_fraction"] if policy and reserve_capacity else Decimal(0) if not reserve_capacity else None
                if reserve is None:
                    status, limit, required = "BLOCKED", None, None
                    reasons.add("UNKNOWN_POLICY_RESERVE")
                else:
                    required, limit = demand * (1 + reserve), available * fraction
                    status = "PASS" if required <= limit else "FAIL"
            checks.append({"member_id": member, "dimension": dimension, "status": status, "unit": unit,
                           "observed_demand": _money(demand) if demand is not None else None,
                           "required_with_reserve": _money(required) if required is not None else None,
                           "available": _money(available) if available is not None else None,
                           "planning_limit": _money(limit) if limit is not None else None, "basis": basis})
        for member in members:
            values = {name: extrema[(member, name)] for name in METRICS}
            cp = current_capacity or {}
            tp = capacity or {}
            p = policy or {}
            cpu = values["cpu_utilization"] * cp["vcpu"] / 100 if values["cpu_utilization"] is not None and cp.get("vcpu") is not None else None
            free = values["freeable_memory"]
            memory = cp["memory_bytes"] - free if cp.get("memory_bytes") is not None and free is not None else None
            if memory is not None and memory < 0:
                raise EvidenceError("freeable memory exceeds native allocated memory")
            def fraction(name, headroom=None):
                if p.get(name) is None or headroom and p.get(headroom) is None:
                    return None
                return min(p[name], 1 - p[headroom]) if headroom else p[name]
            def sum_values(a, b):
                return values[a] + values[b] if values[a] is not None and values[b] is not None else None
            check(member, "cpu", cpu, tp.get("vcpu"), fraction("cpu_max_fraction", "cpu_headroom_fraction"), "vCPU", "OBSERVED_PEAK_SAME_PROCESSOR_RATIO_SCREEN")
            check(member, "memory", memory, tp.get("memory_bytes"), fraction("memory_max_fraction", "memory_headroom_fraction"), "Bytes", "ALLOCATED_MINUS_MINIMUM_FREEABLE_MEMORY_PROXY")
            check(member, "connections", values["connections"], tp.get("max_connections"), fraction("connections_max_fraction"), "Count", "NATIVE_EFFECTIVE_PARAMETER_LIMIT")
            check(member, "iops", sum_values("read_iops", "write_iops"), tp.get("iops"), fraction("iops_max_fraction"), "Count/Second", "SUM_OF_OBSERVED_READ_WRITE_MAXIMA")
            check(member, "throughput", sum_values("read_throughput", "write_throughput"), tp.get("throughput_bytes_per_second"), fraction("throughput_max_fraction"), "Bytes/Second", "SUM_OF_OBSERVED_READ_WRITE_MAXIMA")
            if configuration["network_metrics_supported"] is not False:
                check(member, "network", sum_values("network_receive", "network_transmit"), tp.get("network_bytes_per_second"), fraction("network_max_fraction"), "Bytes/Second", "SUM_OF_OBSERVED_RECEIVE_TRANSMIT_MAXIMA")
            check(member, "storage", values["used_storage"], tp.get("storage_bytes"), fraction("storage_max_fraction"), "Bytes", "EXISTING_STORAGE_CONFIGURATION_RETAINED")
            for metric, maximum in (("read_latency", "max_read_latency_seconds"), ("write_latency", "max_write_latency_seconds"), ("disk_queue_depth", "max_disk_queue_depth"), ("replica_lag", "max_replica_lag_seconds")):
                if metric == "replica_lag" and member not in replicas:
                    continue
                # These are observed SLO gates, not predictions of target latency.
                check(member, metric, values[metric], p.get(maximum), Decimal(1), METRICS[metric][0], "OBSERVED_NATIVE_PERIOD_STATISTIC_SLO_GATE", False)
        economics = _economics(data, candidate, current_entry, target_entry, refs, reasons)
        physical = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "BLOCKED" if any(c["status"] == "BLOCKED" for c in checks) else "PASS"
        same = target_entry is not None and target_entry["class_id"] == configuration["class_id"] and candidate["member_count"] == len(members) and target_zones == zones and candidate["multi_az"] == configuration["multi_az"]
        if reasons or physical == "BLOCKED" or economics["status"] == "UNAVAILABLE":
            kind, status = "BLOCKED", "BLOCKED"
        elif physical == "FAIL":
            kind, status = "DO_NOT_PROCEED", "ASSESSED"
        elif same:
            kind, status = "NO_CHANGE", "ASSESSED"
        elif economics["status"] == "CHEAPER":
            kind, status = "CONSIDER_CLASS_CHANGE", "ASSESSED"
        else:
            kind, status = "DO_NOT_PROCEED", "ASSESSED"
        target = {key: candidate[key] for key in ("id", "catalog_id", "member_count", "zones", "multi_az")}
        target["class_id"] = target_entry["class_id"] if target_entry else None
        if kind == "DO_NOT_PROCEED":
            reasons.update("DATABASE_OBSERVED_CHECK_FAILED:" + item["dimension"] for item in checks if item["status"] == "FAIL")
            if economics["status"] in ("NOT_CHEAPER", "NO_CHANGE"):
                reasons.add("DATABASE_TARGET_NOT_CHEAPER")
        public_status = "RECOMMENDED" if kind == "CONSIDER_CLASS_CHANGE" else "BLOCKED" if status == "BLOCKED" else "NO_CHANGE"
        results.append({"id": identifier, "status": public_status,
                        "recommendation_kind": "DATABASE_INSTANCE_RIGHTSIZE", "decision_code": kind,
                        "candidate_configuration": target, "physical_status": physical,
                        "checks": checks, "economics": economics, "blockers": sorted(reasons),
                        "target_validation_required": True, "execution_authorized": False, "verified_saving": None})
    positive = [row for row in results if row["decision_code"] == "CONSIDER_CLASS_CHANGE"]
    eligible = positive or [row for row in results if row["decision_code"] == "NO_CHANGE"] or [row for row in results if row["status"] != "BLOCKED"]
    selected = min(eligible, key=lambda row: (Decimal(row["economics"]["candidate_monthly_cost"]), row["id"])) if eligible else None
    selected = selected or results[0]
    output = {"schema_version": SCHEMA_VERSION, "model_version": MODEL_VERSION, "resource_kind": data["resource_kind"],
              "engine": data["engine"], "binding": binding, "current_configuration": configuration,
              "candidate_configuration": selected["candidate_configuration"], "evidence_window": window,
              "metric_distributions": distributions, "economics": selected["economics"],
              "blockers": sorted(set(global_reasons) | set(selected["blockers"])),
              "confidence": {"status": "UNAVAILABLE" if selected["status"] == "BLOCKED" else "MEDIUM",
                             "meaning": "OBSERVED_DEMAND_SCREEN_NOT_STATISTICAL_CONFIDENCE",
                             "reasons": ["TARGET_LOAD_AND_FAILOVER_VALIDATION_REQUIRED", "PERIOD_STATISTIC_PERCENTILES_ARE_NOT_RAW_SAMPLE_PERCENTILES", "HELD_CURRENT_RATES_ARE_NOT_FUTURE_PRICE_GUARANTEES"]},
              "proposal": {"risk_class": "R3", "executable": False, "execution_authorized": False},
              "verified_saving": None, "source_refs": sorted(refs.values(), key=lambda ref: (ref["kind"], ref["id"], ref["version"])),
              "candidates": results, "recommendation_kind": selected["recommendation_kind"],
              "decision_code": selected["decision_code"], "status": selected["status"],
              "unsupported_opportunities": ["IDLE_DELETION", "STORAGE_RECONFIGURATION", "SERVERLESS_CONVERSION", "REPLICA_COUNT_CHANGE"],
              "model_assumptions": ["Same observed workload, processor model, topology, storage and effective parameters", "Every member is checked; capacity is never borrowed from another member", "Independent CPU/memory headroom and conservative observed-peak reserve", "Continuing storage, backup, IO and commitment costs are not removed", "No forecast calibration, target SLO guarantee or verified saving"]}
    output["assessment_hash"] = _hash(output)
    return output
