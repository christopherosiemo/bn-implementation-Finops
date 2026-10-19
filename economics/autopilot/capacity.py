"""Evidence-driven capacity planning; this private calculation grants no authority.

All quantities are exact decimal strings in canonical physical units. Counts
project fleet cost only: one resource's observations never prove another replica
is safe. Source authenticity and source selection belong to the control plane;
this worker checks immutable references, scope and arithmetic consistency.

Observed sample/distribution quantiles, weekday/hour forecasts, conformal block
intervals and production future-risk calibration are different claims. In this
first model the last remains UNCALIBRATED, even when an observed breach rate is
zero. No source maximum, average or short backtest becomes a <1% future claim.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_CEILING, localcontext
import hashlib
import json
import math
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .model import EvidenceError, decimal, instant, money

PPM = Decimal(1_000_000)
UNITS = {"cpu": "vCPU", "memory": "bytes", "network": "bytes/second",
         "storage_iops": "operations/second", "storage_throughput": "bytes/second",
         "demand": "count/second"}
LEGACY_MODEL_VERSION = "capacity-weekday-block-v1"
MODEL_VERSION = "capacity-weekday-block-v2"
PROXY_ROLE = "REQUEST_THROUGHPUT_PROXY"
_PROXY_FIELDS = {"semantic_role": {"const": PROXY_ROLE}, "source_metric": {"const": "request_count"},
                 "source_unit": {"enum": ["count", "requests"]}}
DIMENSIONS = tuple(name for name in UNITS if name != "demand")
HORIZONS = {"7_day": 7, "30_day": 30, "90_day": 90, "annual": 365}
BINDING = ("tenant_id", "workload_id", "resource_id", "provider",
           "provider_resource_id", "account_id", "region")
CATALOG = ("id", "count", "capacity", "architecture", "cpu_model", "operating_system",
           "licensing", "region", "zones", "accelerator", "local_storage", "disk_types",
           "commitment_compatible", "source_ref")
POLICY = {"cpu_p95_max_ppm": 700000, "memory_p95_max_ppm": 750000,
          "cpu_free_ppm": 0, "memory_free_ppm": 0, "unused_capacity_ppm": 0,
          "reserve_above_forecast_ppm": 0, "cpu_p99_rollback_ppm": 850000,
          "memory_p99_rollback_ppm": 900000, "prediction_coverage_ppm": 950000,
          "max_future_breach_probability_ppm": 10000, "min_replicas": 1, "min_zones": 1}

# A strict machine-readable integration contract. Cross-field/time/provenance
# invariants are additionally enforced below; no validation boolean is accepted.
_DECIMAL = {"type": "string", "pattern": r"^[0-9]+(\.[0-9]{1,12})?$"}
_TIME = {"type": "string", "format": "date-time"}
_STRING = {"type": "string", "minLength": 1}


def _schema(properties, required=None):
    return {"type": "object", "additionalProperties": False,
            "required": list(properties) if required is None else required, "properties": properties}


_BINDING_SCHEMA = _schema({key: _STRING for key in BINDING})
_REF_SCHEMA = _schema({"id": _STRING, "version": _STRING, "receipt_id": _STRING,
                       "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                       "binding": _BINDING_SCHEMA})
_PRICE_SCHEMA = _schema({"amount": _DECIMAL, "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
                         "unit": {"const": "instance-hour"}, "basis": {"enum": ["NATIVE_CONTRACTED", "PUBLIC_LIST", "UNKNOWN"]},
                         "avoidable_compute": {"type": "boolean"}, "source_ref": _REF_SCHEMA})
_CATALOG_SCHEMA = _schema({**{key: _STRING for key in ("id", "architecture", "cpu_model", "operating_system", "licensing", "region", "accelerator")},
                          "count": {"type": "integer", "minimum": 1, "maximum": 500000},
                          "capacity": _schema({key: {"anyOf": [_DECIMAL, {"type": "null"}]} for key in DIMENSIONS}),
                          "zones": {"type": "array", "minItems": 1, "uniqueItems": True, "items": _STRING},
                          "disk_types": {"type": "array", "minItems": 1, "uniqueItems": True, "items": _STRING},
                          "local_storage": {"type": "boolean"}, "commitment_compatible": {"type": ["boolean", "null"]},
                          "source_ref": _REF_SCHEMA, "pricing": {"anyOf": [_PRICE_SCHEMA, {"type": "null"}]}}, list(CATALOG))
_POINT_SCHEMA = _schema({"start": _TIME, "end": _TIME, "value": {"anyOf": [_DECIMAL, {"type": "null"}]},
                         "sample_count": {"type": "integer", "minimum": 0},
                         "buckets": {"type": "array", "minItems": 1, "maxItems": 256,
                                     "items": _schema({"upper": {"anyOf": [_DECIMAL, {"type": "null"}]}, "count": {"type": "integer", "minimum": 0}})}}, ["start", "end"])
INPUT_SCHEMA = _schema({
    "schema_version": {"const": "4"}, "binding": _BINDING_SCHEMA, "as_of": _TIME,
    "history": _schema({"start": _TIME, "end": _TIME, "timezone": _STRING,
                        "environment": {"enum": ["NON_PRODUCTION", "PRODUCTION"]},
                        "high_seasonality": {"type": "boolean"}, "cadence_seconds": {"type": "integer", "minimum": 1, "maximum": 86400}}),
    "metrics": {"type": "array", "maxItems": 6, "items": _schema({"name": {"enum": list(UNITS)}, "unit": _STRING,
                 "statistic": {"enum": ["RAW_SAMPLE", "OBSERVED_INTERVAL_RATE", "DISTRIBUTION", "INTERVAL_MAXIMUM"]},
                 "denominator": _DECIMAL, "source_refs": {"type": "array", "minItems": 1, "items": _REF_SCHEMA},
                 "points": {"type": "array", "maxItems": 100000, "items": _POINT_SCHEMA}}, ["name", "unit", "statistic", "source_refs", "points"])},
    "current": _CATALOG_SCHEMA, "candidates": {"type": "array", "maxItems": 100, "items": _CATALOG_SCHEMA},
    "policy": _schema({key: {"type": "integer", "minimum": 0} for key in POLICY}, []),
    "events": {"type": "array", "maxItems": 100, "items": _schema({"id": _STRING, "start": _TIME, "end": _TIME,
                "multiplier": _DECIMAL, "source_ref": _REF_SCHEMA})},
    "forecast_horizons": {"type": "array", "minItems": 1, "uniqueItems": True, "items": {"enum": list(HORIZONS)}},
    "pricing_period_hours": _DECIMAL,
})
# Missing model_version is the original v1 contract, retained for replay only.
INPUT_SCHEMA["properties"]["model_version"] = {"enum": [LEGACY_MODEL_VERSION, MODEL_VERSION]}
INPUT_SCHEMA["properties"]["metrics"]["items"]["properties"].update(_PROXY_FIELDS)
_REASONS_SCHEMA = {"type": "array", "items": _STRING}
_NULL_DECIMAL = {"anyOf": [_DECIMAL, {"type": "null"}]}
_NULL_INTEGER = {"type": ["integer", "null"], "minimum": 0}
_QUANTILE_SCHEMA = _schema({"lower": _NULL_DECIMAL, "upper": _NULL_DECIMAL, "status": {"enum": ["OBSERVED", "UNAVAILABLE"]}})
_METRIC_SCHEMA = _schema({
    "name": {"enum": list(UNITS)}, "unit": _STRING, "statistic": INPUT_SCHEMA["properties"]["metrics"]["items"]["properties"]["statistic"],
    "cadence_seconds": {"type": "integer", "minimum": 1},
    **{key: {"type": "integer", "minimum": 0, "maximum": 1000000} for key in ("coverage_ppm", "time_coverage_ppm", "sampling_coverage_ppm")},
    **{key: {"type": "integer", "minimum": 0} for key in ("observed_intervals", "expected_intervals", "missing_intervals", "missing_range_count")},
    "unknown_seconds": _DECIMAL, "missing_ranges": {"type": "array", "items": _schema({"start": _TIME, "end": _TIME})},
    "observed_samples": {"type": "string", "pattern": "^[0-9]+$"},
    "quantile_method": {"enum": ["HISTOGRAM_BOUNDS", "OBSERVED_INTERVAL_RATE", "NEAREST_RANK_OBSERVED_SAMPLES", "UNAVAILABLE"]},
    "observed_quantiles": _schema({key: _QUANTILE_SCHEMA for key in ("p50", "p90", "p95", "p99", "p999")}),
    "observed_maximum": _NULL_DECIMAL, "denominator": {"anyOf": [_schema({"value": _DECIMAL, "unit": _STRING}), {"type": "null"}]},
    "reason_codes": _REASONS_SCHEMA, "source_refs": {"type": "array", "items": _REF_SCHEMA},
})
_METRIC_SCHEMA["properties"].update(_PROXY_FIELDS)
_FORECAST_METRIC_SCHEMA = _schema({
    "status": {"enum": ["CALIBRATED_BACKTEST", "UNCALIBRATED"]}, "reason_codes": _REASONS_SCHEMA,
    "point_peak": _NULL_DECIMAL, "point_p99": _NULL_DECIMAL, "declared_event_peak": _DECIMAL, "event_multiplier_peak": _DECIMAL,
    "prediction_interval": {"anyOf": [_schema({"lower": _DECIMAL, "upper": _DECIMAL, "nominal_coverage_ppm": {"type": "integer", "minimum": 500000, "maximum": 999999}}), {"type": "null"}]},
    "daily_points": {"type": "array", "items": _schema({"date": {"type": "string", "format": "date"}, "point_peak": _DECIMAL, "point_mean": _DECIMAL})},
    "backtest": _schema({"method": {"const": "EXPANDING_ORIGIN_WEEKDAY_HOUR_MEDIAN"}, "block_days": {"type": "integer", "minimum": 1},
                         "residual_day_count": {"type": "integer", "minimum": 0}, "nonoverlapping_block_count": {"type": "integer", "minimum": 0},
                         "absolute_block_residuals": {"type": "array", "items": _DECIMAL}, "uses_future_observations": {"const": False}}),
    "model_time_bucket_seconds": {"const": 3600},
})
_FORECAST_METRIC_SCHEMA["properties"].update({**_PROXY_FIELDS, "unit": _STRING})
_ECONOMICS_SCHEMA = _schema({
    "status": {"enum": ["UNAVAILABLE", "EVIDENCED", "NOT_CHEAPER"]}, "reason_codes": _REASONS_SCHEMA,
    "currency": {"type": ["string", "null"], "pattern": "^[A-Z]{3}$"}, "period_hours": _DECIMAL,
    "current_cost": _NULL_DECIMAL, "candidate_cost": _NULL_DECIMAL,
    "estimated_saving": {"anyOf": [{"type": "string", "pattern": r"^-?[0-9]+(\.[0-9]{1,12})?$"}, {"type": "null"}]},
    "verified_saving": {"type": "null"}, "price_source_refs": {"type": "array", "items": _REF_SCHEMA},
}, ["status", "reason_codes", "currency", "current_cost", "candidate_cost", "estimated_saving"])
_CHECK_SCHEMA = _schema({
    "dimension": {"enum": list(DIMENSIONS)}, "unit": _STRING, "candidate_capacity": _DECIMAL, "observed_p99": _DECIMAL,
    "forecast_requirement": _DECIMAL, "required_with_reserve": _DECIMAL,
    **{key: {"type": "integer", "minimum": 0} for key in ("reserve_above_forecast_ppm", "unused_capacity_ppm", "projected_p99_utilization_ppm")},
    **{key: _NULL_INTEGER for key in ("observed_p95_utilization_ppm", "p95_planning_limit_ppm", "p99_rollback_limit_ppm", "observed_capacity_breach_ppm")},
    "status": {"enum": ["PASS", "FAIL"]},
})
_FUTURE_RISK_SCHEMA = _schema({"status": {"const": "UNCALIBRATED"}, "future_breach_probability_upper_ppm": {"type": "null"},
                             "required_maximum_ppm": {"type": "integer", "minimum": 0}, "reason_code": {"const": "FUTURE_PROBABILITY_MODEL_NOT_CALIBRATED"}})
OUTPUT_SCHEMA = _schema({
    "schema_version": {"const": "4"}, "model_version": {"enum": [LEGACY_MODEL_VERSION, MODEL_VERSION]}, "binding": _BINDING_SCHEMA,
    "status": {"enum": ["VALIDATED", "BLOCKED", "INSUFFICIENT_OBSERVATION"]},
    "reason_codes": _REASONS_SCHEMA,
    "history": _schema({**INPUT_SCHEMA["properties"]["history"]["properties"],
                         **{key: {"type": "integer", "minimum": 0} for key in ("observed_calendar_days", "required_calendar_days", "production_minimum_days_does_not_replace_default", "stale_after_hours")}}),
    "metrics": {"type": "array", "items": _METRIC_SCHEMA},
    "forecasts": {"type": "array", "items": _schema({"horizon": {"enum": list(HORIZONS)}, "days": {"type": "integer", "minimum": 1},
                   "status": {"enum": ["CALIBRATED_BACKTEST", "UNCALIBRATED"]}, "metrics": _schema({key: _FORECAST_METRIC_SCHEMA for key in UNITS}, []),
                   "future_breach_probability_upper_ppm": {"type": "null"}})},
    "candidates": {"type": "array", "items": _schema({"id": _STRING, "count": {"type": "integer", "minimum": 1},
                    "capacity_suitable": {"type": "boolean"}, "status": {"enum": ["VALIDATED", "BLOCKED", "INSUFFICIENT_OBSERVATION"]},
                    "reason_codes": _REASONS_SCHEMA, "checks": {"type": "array", "items": _CHECK_SCHEMA},
                    "economics": _ECONOMICS_SCHEMA, "future_risk": _FUTURE_RISK_SCHEMA, "source_ref": _REF_SCHEMA})},
    "evidence_refs": {"type": "array", "items": _REF_SCHEMA},
    "model_assumptions": {"type": "array", "items": _STRING}, "assessment_hash": _STRING,
})


def _object(value, allowed, required, label):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise EvidenceError(f"invalid {label} fields")
    return value


def _integer(value, label, lower=0, upper=10**12):
    if type(value) is not int or not lower <= value <= upper:
        raise EvidenceError(f"invalid {label}")
    return value


def _number(value, label, positive=False):
    result = decimal(value, label)
    if result < 0 or positive and result <= 0:
        raise EvidenceError(f"invalid {label}")
    return result


def _strings(value, label):
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x for x in value) or len(set(value)) != len(value):
        raise EvidenceError(f"invalid {label}")
    return value


def _ref(value, binding):
    _object(value, ("id", "version", "receipt_id", "sha256", "binding"), ("id", "version", "receipt_id", "sha256", "binding"), "source reference")
    if any(not isinstance(value[key], str) or not value[key] for key in ("id", "version", "receipt_id")) or not re.fullmatch("[a-f0-9]{64}", str(value["sha256"])):
        raise EvidenceError("immutable source reference required")
    if value["binding"] != binding:
        raise EvidenceError("source reference binding mismatch")
    return value


def _catalog(value, binding, current=False):
    _object(value, (*CATALOG, "pricing"), CATALOG, "catalog")
    for key in ("id", "architecture", "cpu_model", "operating_system", "licensing", "region", "accelerator"):
        if not isinstance(value[key], str) or not value[key]:
            raise EvidenceError(f"explicit catalog {key} required")
    _integer(value["count"], "catalog count", 1, 500000)
    _strings(value["zones"], "catalog zones")
    _strings(value["disk_types"], "catalog disk types")
    if type(value["local_storage"]) is not bool or value["commitment_compatible"] is not None and type(value["commitment_compatible"]) is not bool:
        raise EvidenceError("explicit catalog capabilities required")
    _object(value["capacity"], DIMENSIONS, DIMENSIONS, "physical capacity")
    capacities = {key: None if val is None else _number(val, key, True) for key, val in value["capacity"].items()}
    if current and (any(val is None for val in capacities.values()) or value["region"] != binding["region"]):
        raise EvidenceError("current physical capacities and region required")
    _ref(value["source_ref"], binding)
    price = value.get("pricing")
    if price is not None:
        _object(price, _PRICE_SCHEMA["properties"], _PRICE_SCHEMA["required"], "price")
        _number(price["amount"], "native hourly price")
        if not re.fullmatch("[A-Z]{3}", str(price["currency"])) or price["unit"] != "instance-hour" or price["basis"] not in ("NATIVE_CONTRACTED", "PUBLIC_LIST", "UNKNOWN") or type(price["avoidable_compute"]) is not bool:
            raise EvidenceError("native price units/basis required")
        _ref(price["source_ref"], binding)
    return capacities


def _quantile(weighted, numerator, denominator=100):
    total = sum(count for _, count in weighted)
    if not total:
        return None
    rank = (total * numerator + denominator - 1) // denominator
    observed = 0
    for value, count in sorted(weighted, key=lambda item: (item[0] is None, item[0] or Decimal(0))):
        observed += count
        if observed >= rank:
            return value
    return None


def _median(values):
    return sorted(values)[(len(values)-1)//2] if values else None


def _event_factor(events, at):
    result = Decimal(1)
    for event in events:
        if event["start"] <= at < event["end"]:
            result *= event["multiplier"]
            if result > 1_000_000:
                raise EvidenceError("combined event multiplier exceeds supported range")
    return result


def _interval_event_factor(events, left, right):
    # Applying every overlapping event is conservative even for a short event
    # between hourly model timestamps; it cannot silently disappear.
    result = Decimal(1)
    for event in events:
        if event["start"] < right and event["end"] > left:
            result *= event["multiplier"]
            if result > 1_000_000: raise EvidenceError("combined event multiplier exceeds supported range")
    return result


def _stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def _metric(stream, binding, current_capacity, start, end, cadence, zone, events, model_version):
    _object(stream, ("name", "unit", "statistic", "denominator", "source_refs", "points", *_PROXY_FIELDS),
            ("name", "unit", "statistic", "source_refs", "points"), "metric")
    name, statistic = stream["name"], stream["statistic"]
    proxy = name == "demand" and model_version == MODEL_VERSION
    if proxy:
        if stream.get("semantic_role") != PROXY_ROLE or stream.get("source_metric") != "request_count" or stream.get("source_unit") not in ("count", "requests") or statistic != "OBSERVED_INTERVAL_RATE" or "denominator" in stream:
            raise EvidenceError("explicit request-throughput proxy metadata and interval rate required")
        expected_unit = stream["source_unit"] + "/second"
    else:
        if any(key in stream for key in _PROXY_FIELDS):
            raise EvidenceError("proxy metadata requires the v2 demand contract")
        expected_unit = "work_unit/second" if name == "demand" else UNITS.get(name)
    if name not in UNITS or stream["unit"] != expected_unit or statistic not in ("RAW_SAMPLE", "OBSERVED_INTERVAL_RATE", "DISTRIBUTION", "INTERVAL_MAXIMUM"):
        raise EvidenceError("canonical metric units/statistic required")
    if statistic == "OBSERVED_INTERVAL_RATE" and name in ("cpu", "memory"):
        raise EvidenceError("capacity gauges cannot be interval averages")
    if name in DIMENSIONS and _number(stream.get("denominator"), "physical denominator", True) != current_capacity[name]:
        raise EvidenceError("metric physical denominator mismatch")
    if not isinstance(stream["source_refs"], list) or not stream["source_refs"]:
        raise EvidenceError("metric source references required")
    refs = [_ref(ref, binding) for ref in stream["source_refs"]]
    if len({ref["receipt_id"] for ref in refs}) != len(refs):
        raise EvidenceError("duplicate metric source reference")
    points = stream["points"]
    if not isinstance(points, list) or len(points) > 100000:
        raise EvidenceError("metric point limit")
    previous = start
    covered = Decimal(0)
    gaps, lower, upper, series = [], [], [], []
    maximum, unbounded, populated_intervals = None, False, 0
    seen = set()
    for point in sorted(points, key=lambda p: instant(p.get("start")) if isinstance(p, dict) else instant(None)):
        _object(point, ("start", "end", "value", "buckets", "sample_count"), ("start", "end"), "metric point")
        left, right = instant(point["start"]), instant(point["end"])
        if left < start or right > end or left < previous or right <= left or (right-left).total_seconds() > 2 * cadence or (left, right) in seen:
            raise EvidenceError("overlapping/out-of-scope metric intervals")
        seen.add((left, right))
        if left > previous:
            gaps.append((previous, left))
        previous = right
        scalar, populated = None, False
        if statistic == "DISTRIBUTION":
            if "value" in point or "sample_count" not in point or "buckets" not in point:
                raise EvidenceError("raw distribution required")
            n = _integer(point["sample_count"], "sample count")
            buckets = point["buckets"]
            if not isinstance(buckets, list) or not 1 <= len(buckets) <= 256:
                raise EvidenceError("distribution bucket limit")
            total, last = 0, Decimal(0)
            occupied = []
            for index, bucket in enumerate(buckets):
                _object(bucket, ("upper", "count"), ("upper", "count"), "distribution bucket")
                bound = None if bucket["upper"] is None else _number(bucket["upper"], "bucket upper")
                if bound is None and index != len(buckets)-1 or bound is not None and (index == len(buckets)-1 or index and bound <= last):
                    raise EvidenceError("increasing finite buckets and final infinity required")
                count = _integer(bucket["count"], "bucket count")
                total += count
                lower.append((last, count)); upper.append((bound, count))
                if count:
                    occupied.append(bound)
                if bound is not None:
                    last = bound
            if total != n:
                raise EvidenceError("distribution sample count mismatch")
            populated = n > 0
            if occupied and occupied[-1] is not None:
                scalar = occupied[-1]  # Conservative observed interval envelope, never a mean.
            elif occupied:
                gaps.append((left, right))
                unbounded = True
        else:
            if "value" not in point or "buckets" in point or "sample_count" in point:
                raise EvidenceError("explicit observed value required")
            if point["value"] is not None:
                scalar = _number(point["value"], "observed metric")
                populated = True
                if statistic != "INTERVAL_MAXIMUM":
                    lower.append((scalar, 1)); upper.append((scalar, 1))
        if populated:
            covered += Decimal(str((right-left).total_seconds()))
            populated_intervals += 1
        else:
            gaps.append((left, right))
        if scalar is not None:
            maximum = scalar if maximum is None else max(maximum, scalar)
            local = left.astimezone(zone)
            series.append((local.date(), (local.weekday(), local.hour), scalar / _event_factor(events, left)))
    if previous < end:
        gaps.append((previous, end))
    seconds = Decimal(str((end-start).total_seconds()))
    expected_intervals = math.ceil(seconds / cadence)
    time_coverage = int(covered * PPM / seconds)
    sampling_coverage = min(1000000, populated_intervals*1000000//expected_intervals)
    coverage = min(time_coverage, sampling_coverage)
    quantiles = {}
    samples = sum(n for _, n in upper)
    for label, numerator, denominator in (("p50", 50, 100), ("p90", 90, 100), ("p95", 95, 100), ("p99", 99, 100), ("p999", 999, 1000)):
        sufficient = samples >= (1000 if label == "p999" else 1)
        lo = _quantile(lower, numerator, denominator) if sufficient else None
        hi = _quantile(upper, numerator, denominator) if sufficient else None
        quantiles[label] = {"lower": None if lo is None else money(lo), "upper": None if hi is None else money(hi),
                            "status": "OBSERVED" if hi is not None else "UNAVAILABLE"}
    reasons = []
    if coverage != 1000000: reasons.append("METRIC_COVERAGE_INCOMPLETE")
    if statistic == "INTERVAL_MAXIMUM": reasons.append("MAXIMUM_IS_NOT_QUANTILE_EVIDENCE")
    if quantiles["p99"]["upper"] is None: reasons.append("METRIC_P99_UNAVAILABLE")
    if unbounded: reasons.append("METRIC_ENVELOPE_UNBOUNDED")
    summary = {"name": name, "unit": stream["unit"], "statistic": statistic, "cadence_seconds": cadence,
               "coverage_ppm": coverage, "time_coverage_ppm": time_coverage, "sampling_coverage_ppm": sampling_coverage,
               "observed_intervals": populated_intervals,
               "expected_intervals": expected_intervals, "missing_intervals": max(math.ceil((seconds-covered) / cadence), expected_intervals-populated_intervals),
               "unknown_seconds": money(seconds-covered), "missing_range_count": len(gaps),
               "missing_ranges": [{"start": _stamp(a), "end": _stamp(b)} for a, b in gaps[:20]],
               "observed_samples": str(samples), "quantile_method": "HISTOGRAM_BOUNDS" if statistic == "DISTRIBUTION" else "OBSERVED_INTERVAL_RATE" if statistic == "OBSERVED_INTERVAL_RATE" else "NEAREST_RANK_OBSERVED_SAMPLES" if statistic == "RAW_SAMPLE" else "UNAVAILABLE",
               "observed_quantiles": quantiles, "observed_maximum": None if maximum is None else money(maximum),
               "denominator": None if name == "demand" else {"value": money(current_capacity[name]), "unit": UNITS[name]},
               "reason_codes": reasons, "source_refs": refs}
    if proxy:
        summary.update({key: stream[key] for key in _PROXY_FIELDS})
    return summary, series, upper


def _forecast(series, history_end, zone, events, horizon, coverage_ppm):
    """Expanding-origin hourly weekday medians; residual blocks preserve days."""
    by_day = defaultdict(list)
    for day, key, value in series:
        by_day[day].append((key, value))
    slots, residual_days = defaultdict(list), []
    for day in sorted(by_day):
        if len(slots) >= 168:
            medians = {key: _median(values) for key, values in slots.items()}
            residuals = [abs(value-medians[key]) for key, value in by_day[day] if key in medians]
            if residuals:
                residual_days.append((day, max(residuals)))
        for key, value in by_day[day]:
            slots[key].append(value)
    medians = {key: _median(values) for key, values in slots.items()}
    days = HORIZONS[horizon]
    blocks = [max(value for _, value in residual_days[index:index+days])
              for index in range(0, len(residual_days)-days+1, days)]
    rank = (len(blocks)+1) * coverage_ppm
    order = (rank + 999999) // 1000000
    radius = sorted(blocks)[order-1] if blocks and order <= len(blocks) else None
    reasons = []
    if len(medians) != 168: reasons.append("WEEKDAY_TIME_HISTORY_INCOMPLETE")
    if radius is None: reasons.append("HORIZON_BACKTEST_INSUFFICIENT")
    left = history_end.astimezone(zone)
    right = datetime.combine(left.date()+timedelta(days=days), datetime.min.time(), zone).astimezone(timezone.utc)
    at = history_end
    predicted, daily = [], defaultdict(list)
    event_peak, maximum_factor = Decimal(0), Decimal(1)
    while at < right:
        local = at.astimezone(zone)
        value = medians.get((local.weekday(), local.hour))
        if value is None:
            reasons.append("FUTURE_TIME_SLOT_UNOBSERVED")
        else:
            factor = _interval_event_factor(events, at, min(at+timedelta(hours=1), right))
            maximum_factor = max(maximum_factor, factor)
            point = value * factor
            predicted.append(point); daily[local.date()].append(point)
            if factor > 1: event_peak = max(event_peak, point)
        at += timedelta(hours=1)
    complete = not reasons
    peak = max(predicted) if predicted else None
    point99 = _quantile([(value, 1) for value in predicted], 99)
    if radius is not None: radius *= maximum_factor
    interval = None if radius is None or not complete else {"lower": money(max(Decimal(0), peak-radius)), "upper": money(peak+radius), "nominal_coverage_ppm": coverage_ppm}
    return {"status": "CALIBRATED_BACKTEST" if complete else "UNCALIBRATED", "reason_codes": sorted(set(reasons)),
            "point_peak": None if peak is None else money(peak), "point_p99": None if point99 is None else money(point99),
            "declared_event_peak": money(event_peak), "event_multiplier_peak": money(maximum_factor), "prediction_interval": interval,
            "daily_points": [{"date": str(day), "point_peak": money(max(values)), "point_mean": money(sum(values)/len(values))} for day, values in sorted(daily.items())],
            "backtest": {"method": "EXPANDING_ORIGIN_WEEKDAY_HOUR_MEDIAN", "block_days": days,
                         "residual_day_count": len(residual_days), "nonoverlapping_block_count": len(blocks),
                         "absolute_block_residuals": [money(value) for value in blocks],
                         "uses_future_observations": False}, "model_time_bucket_seconds": 3600}


def _price(current, candidate, hours):
    prices = [current.get("pricing"), candidate.get("pricing")]
    if any(price is None or price["basis"] != "NATIVE_CONTRACTED" or not price["avoidable_compute"] for price in prices):
        return {"status": "UNAVAILABLE", "reason_codes": ["NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED"], "currency": None, "current_cost": None, "candidate_cost": None, "estimated_saving": None}
    old, new = prices
    if old["currency"] != new["currency"]:
        return {"status": "UNAVAILABLE", "reason_codes": ["CURRENCY_MISMATCH_NO_FX"], "currency": None, "current_cost": None, "candidate_cost": None, "estimated_saving": None}
    before = decimal(old["amount"]) * current["count"] * hours
    after = decimal(new["amount"]) * candidate["count"] * hours
    saving = before-after
    for value in (before, after, saving):
        decimal(money(value), "projected price result")
    return {"status": "EVIDENCED" if saving > 0 else "NOT_CHEAPER", "reason_codes": [] if saving > 0 else ["NO_POSITIVE_MARGINAL_SAVING"],
            "currency": old["currency"], "period_hours": money(hours), "current_cost": money(before), "candidate_cost": money(after),
            "estimated_saving": money(saving), "verified_saving": None, "price_source_refs": [price["source_ref"] for price in prices]}


def evaluate_capacity(data):
    """Return a deterministic assessment, never an approval or verified saving."""
    with localcontext() as context:
        context.prec = 80
        return _evaluate(data)


def _evaluate(data):
    _object(data, INPUT_SCHEMA["properties"], INPUT_SCHEMA["required"], "capacity request")
    if data["schema_version"] != "4": raise EvidenceError("capacity schema version 4 required")
    model_version = data.get("model_version", LEGACY_MODEL_VERSION)
    if model_version not in (LEGACY_MODEL_VERSION, MODEL_VERSION): raise EvidenceError("unsupported capacity model version")
    binding = _object(data["binding"], BINDING, BINDING, "resource binding")
    if any(not isinstance(binding[key], str) or not binding[key] for key in BINDING): raise EvidenceError("resource identity required")
    now = instant(data["as_of"])
    history = _object(data["history"], INPUT_SCHEMA["properties"]["history"]["properties"], INPUT_SCHEMA["properties"]["history"]["required"], "history")
    try: zone = ZoneInfo(history["timezone"])
    except (ZoneInfoNotFoundError, TypeError) as exc: raise EvidenceError("explicit IANA timezone required") from exc
    if history["environment"] not in ("PRODUCTION", "NON_PRODUCTION") or type(history["high_seasonality"]) is not bool: raise EvidenceError("history environment/seasonality required")
    start, end = instant(history["start"]), instant(history["end"])
    first, last = start.astimezone(zone), end.astimezone(zone)
    if end <= start or end > now or any(t.hour or t.minute or t.second or t.microsecond for t in (first, last)): raise EvidenceError("complete local calendar days required")
    observed_days = (last.date()-first.date()).days
    if observed_days > 3660: raise EvidenceError("history limit")
    required_days = 90 if history["high_seasonality"] else 30 if history["environment"] == "PRODUCTION" else 14
    cadence = _integer(history["cadence_seconds"], "cadence", 1, 86400)
    policy = dict(POLICY)
    _object(data["policy"], POLICY, (), "capacity policy")
    for key, value in data["policy"].items():
        upper = 500000 if key == "min_replicas" else 100 if key == "min_zones" else 10000000 if key == "reserve_above_forecast_ppm" else 999999 if key in ("cpu_free_ppm", "memory_free_ppm", "unused_capacity_ppm") else 1000000
        policy[key] = _integer(value, key, 1 if key in ("min_replicas", "min_zones") else 0, upper)
    if not 500000 <= policy["prediction_coverage_ppm"] < 1000000: raise EvidenceError("prediction coverage must be 50% to below100%")
    current_capacity = _catalog(data["current"], binding, True)
    if not isinstance(data["candidates"], list) or len(data["candidates"]) > 100: raise EvidenceError("candidate limit")
    if len({candidate.get("id") for candidate in data["candidates"] if isinstance(candidate, dict)}) != len(data["candidates"]): raise EvidenceError("duplicate candidate")
    candidate_capacities = [_catalog(candidate, binding) for candidate in data["candidates"]]
    events = []
    if not isinstance(data["events"], list) or len(data["events"]) > 100: raise EvidenceError("event limit")
    for event in data["events"]:
        _object(event, ("id", "start", "end", "multiplier", "source_ref"), ("id", "start", "end", "multiplier", "source_ref"), "demand event")
        a, b = instant(event["start"]), instant(event["end"])
        factor = _number(event["multiplier"], "event multiplier", True)
        if not isinstance(event["id"], str) or not event["id"] or b <= a or not Decimal(1) <= factor <= 1000: raise EvidenceError("conservative demand event required")
        _ref(event["source_ref"], binding)
        events.append({**event, "start": a, "end": b, "multiplier": factor})
    if len({event["id"] for event in events}) != len(events): raise EvidenceError("duplicate demand event")
    horizons = _strings(data["forecast_horizons"], "forecast horizons")
    if any(horizon not in HORIZONS for horizon in horizons): raise EvidenceError("unknown forecast horizon")
    hours = _number(data["pricing_period_hours"], "pricing period hours", True)
    if hours > 8784: raise EvidenceError("pricing period exceeds one leap year")
    if not isinstance(data["metrics"], list) or len(data["metrics"]) > 6: raise EvidenceError("metric limit")
    summaries, series, weighted, reasons = {}, {}, {}, []
    for stream in data["metrics"]:
        result, points, weights = _metric(stream, binding, current_capacity, start, end, cadence, zone, events, model_version)
        name = result["name"]
        if name in summaries: raise EvidenceError("duplicate capacity metric")
        summaries[name], series[name], weighted[name] = result, points, weights
        reasons.extend(f"{name.upper()}_{reason}" for reason in result["reason_codes"])
    for name in UNITS:
        if name not in summaries: reasons.append(f"{name.upper()}_METRIC_REQUIRED")
    if observed_days < required_days: reasons.append("INSUFFICIENT_OBSERVATION")
    if now-end > timedelta(hours=48): reasons.append("HISTORY_STALE")
    forecasts = []
    for horizon in horizons:
        metrics = {name: _forecast(points, end, zone, events, horizon, policy["prediction_coverage_ppm"]) for name, points in series.items()}
        if model_version == MODEL_VERSION and "demand" in metrics:
            metrics["demand"].update({key: summaries["demand"][key] for key in (*_PROXY_FIELDS, "unit")})
        if reasons:
            for result in metrics.values():
                result["status"], result["prediction_interval"] = "UNCALIBRATED", None
                result["reason_codes"] = sorted(set(result["reason_codes"] + ["HISTORY_OR_METRIC_EVIDENCE_INCOMPLETE"]))
        forecasts.append({"horizon": horizon, "days": HORIZONS[horizon], "status": "CALIBRATED_BACKTEST" if metrics and all(metric["status"] == "CALIBRATED_BACKTEST" for metric in metrics.values()) and not reasons else "UNCALIBRATED",
                          "metrics": metrics, "future_breach_probability_upper_ppm": None})
    candidates = []
    for candidate, capacities in zip(data["candidates"], candidate_capacities):
        blockers = list(reasons)
        for key in ("architecture", "cpu_model", "operating_system", "licensing", "region", "accelerator"):
            if candidate[key] != data["current"][key]: blockers.append(f"INCOMPATIBLE_{key.upper()}")
        if not set(data["current"]["zones"]) <= set(candidate["zones"]): blockers.append("INCOMPATIBLE_ZONES")
        if not set(data["current"]["disk_types"]) <= set(candidate["disk_types"]): blockers.append("INCOMPATIBLE_DISK_TYPES")
        if candidate["local_storage"] or data["current"]["local_storage"]: blockers.append("LOCAL_STORAGE_MIGRATION_REQUIRED")
        if candidate["commitment_compatible"] is not True: blockers.append("COMMITMENT_COMPATIBILITY_UNKNOWN_OR_FALSE")
        if candidate["count"] != data["current"]["count"]: blockers.append("COUNT_CHANGE_REQUIRES_SEPARATE_ACTION")
        if candidate["count"] < policy["min_replicas"]: blockers.append("MINIMUM_REPLICAS_VIOLATED")
        if len(candidate["zones"]) < policy["min_zones"]: blockers.append("MINIMUM_ZONES_VIOLATED")
        checks = []
        for name in DIMENSIONS:
            summary = summaries.get(name)
            capacity = capacities[name]
            if capacity is None or summary is None:
                blockers.append(f"{name.upper()}_CAPACITY_OR_EVIDENCE_REQUIRED")
                continue
            p95, p99 = (summary["observed_quantiles"][q]["upper"] for q in ("p95", "p99"))
            if p99 is None:
                continue
            observed = decimal(p99)
            projected = [decimal(metric[name]["point_p99"]) for metric in [forecast["metrics"] for forecast in forecasts] if name in metric and metric[name]["point_p99"] is not None]
            event_peaks = [decimal(forecast["metrics"][name]["declared_event_peak"]) for forecast in forecasts if name in forecast["metrics"]]
            interval_peaks = [decimal(forecast["metrics"][name]["prediction_interval"]["upper"]) for forecast in forecasts if name in forecast["metrics"] and forecast["metrics"][name]["prediction_interval"] is not None]
            future_factor = max([Decimal(1), *[_event_factor(events, max(now, event["start"])) for event in events if event["end"] > now]])
            forecast99 = max([observed * future_factor, *projected, *event_peaks, *interval_peaks])
            reserve = forecast99 * (1 + Decimal(policy["reserve_above_forecast_ppm"])/PPM)
            unused = forecast99 / (1-Decimal(policy["unused_capacity_ppm"])/PPM)
            required = max(reserve, unused)
            ok = capacity >= required
            if not ok: blockers.append(f"{name.upper()}_FORECAST_RESERVE_INSUFFICIENT")
            utilization95 = None if p95 is None else decimal(p95)/capacity
            plan_limit = None
            if name in ("cpu", "memory"):
                plan_limit = min(policy[f"{name}_p95_max_ppm"], 1000000-policy[f"{name}_free_ppm"])
                if utilization95 is None or utilization95 * PPM > plan_limit: blockers.append(f"{name.upper()}_P95_PLANNING_LIMIT")
            projected99 = observed/capacity*PPM
            rollback_ok = name not in ("cpu", "memory") or projected99 <= policy[f"{name}_p99_rollback_ppm"]
            if not rollback_ok: blockers.append(f"{name.upper()}_P99_ROLLBACK_LIMIT")
            observed_breaches = sum(count for value, count in weighted.get(name, []) if value is None or value > capacity)
            population = sum(count for _, count in weighted.get(name, []))
            planning_ok = ok and rollback_ok and (plan_limit is None or utilization95 is not None and utilization95*PPM <= plan_limit)
            checks.append({"dimension": name, "unit": UNITS[name], "candidate_capacity": money(capacity), "observed_p99": p99,
                           "forecast_requirement": money(forecast99), "required_with_reserve": money(required),
                           "reserve_above_forecast_ppm": policy["reserve_above_forecast_ppm"], "unused_capacity_ppm": policy["unused_capacity_ppm"],
                           "observed_p95_utilization_ppm": None if utilization95 is None else int((utilization95*PPM).to_integral_value(rounding=ROUND_CEILING)),
                           "p95_planning_limit_ppm": plan_limit,
                           "p99_rollback_limit_ppm": policy.get(f"{name}_p99_rollback_ppm"),
                           "projected_p99_utilization_ppm": int(projected99.to_integral_value(rounding=ROUND_CEILING)),
                           "observed_capacity_breach_ppm": None if not population else (observed_breaches*1000000+population-1)//population,
                           "status": "PASS" if planning_ok else "FAIL"})
        economics = _price(data["current"], candidate, hours)
        capacity_blockers = sorted(set(blockers))
        if history["environment"] == "PRODUCTION": blockers.append("FUTURE_BREACH_PROBABILITY_UNCALIBRATED")
        blockers.extend(economics["reason_codes"])
        candidates.append({"id": candidate["id"], "count": candidate["count"], "capacity_suitable": not capacity_blockers,
                           "status": "INSUFFICIENT_OBSERVATION" if any("INSUFFICIENT_OBSERVATION" == reason or "METRIC_REQUIRED" in reason or "COVERAGE_INCOMPLETE" in reason for reason in blockers) else "BLOCKED" if blockers else "VALIDATED",
                           "reason_codes": sorted(set(blockers)), "checks": checks, "economics": economics,
                           "future_risk": {"status": "UNCALIBRATED", "future_breach_probability_upper_ppm": None,
                                           "required_maximum_ppm": policy["max_future_breach_probability_ppm"], "reason_code": "FUTURE_PROBABILITY_MODEL_NOT_CALIBRATED"},
                           "source_ref": candidate["source_ref"]})
    refs = {json.dumps(ref, sort_keys=True): ref for stream in summaries.values() for ref in stream["source_refs"]}
    for item in [data["current"], *data["candidates"]]:
        for ref in [item["source_ref"], *([item["pricing"]["source_ref"]] if item.get("pricing") else [])]: refs[json.dumps(ref, sort_keys=True)] = ref
    for event in data["events"]: refs[json.dumps(event["source_ref"], sort_keys=True)] = event["source_ref"]
    result = {"schema_version": "4", "model_version": model_version, "binding": dict(binding),
              "status": "INSUFFICIENT_OBSERVATION" if reasons else "VALIDATED" if any(candidate["status"] == "VALIDATED" for candidate in candidates) else "BLOCKED",
              "reason_codes": sorted(set(reasons)),
              "history": {**history, "observed_calendar_days": observed_days, "required_calendar_days": required_days,
                          "production_minimum_days_does_not_replace_default": 7, "stale_after_hours": 48},
              "metrics": list(summaries.values()), "forecasts": forecasts, "candidates": candidates,
              "evidence_refs": [refs[key] for key in sorted(refs)],
              "model_assumptions": ["Per-resource capacity; equal replica counts; count only projects cost.",
                  "Observed quantiles describe measured samples or bucket bounds, not unseen bursts.",
                  "Weekday/hour medians assume repeating patterns; explicit demand events multiply capacity requirements.",
                  "Prediction intervals use nonoverlapping horizon-length daily-maximum residual blocks and require finite conformal rank.",
                  "Backtest calibration is conditional on exchangeability; annual/seasonal extrapolation may remain uncalibrated.",
                  "No calibrated future <1% capacity-breach claim, execution authority or verified savings is produced."]}
    if model_version == MODEL_VERSION:
        result["model_assumptions"].append("REQUEST_THROUGHPUT_PROXY preserves native request counter units; requests do not prove completed business work or work preservation.")
    result["assessment_hash"] = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result
