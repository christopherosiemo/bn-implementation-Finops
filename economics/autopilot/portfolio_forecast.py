"""Bounded stable-floor forecasts from authenticated post-optimization history.

Go resolves sources/ownership and issues the resulting immutable receipts.
Rolling full-term windows overlap: reported coverage is empirical held-out path
coverage under the stated model, never an IID confidence or breach probability.
Insufficient history returns unavailable rather than a shorter-horizon proxy.
"""
from collections import defaultdict
from datetime import timedelta
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path

from .portfolio import STAGES, analysis_hash, decimal, need, stamp
from .portfolio_decision import dimensions, keys, money, period, reference, _stages

MODEL_VERSION = "commitment-stable-floor-v1"
METHOD = "ROLLING_ORIGIN_TERM_BLOCK_V1"
TRAIN_HOURS = 90*24
STRIDE_HOURS = 7*24
CALIBRATION_ORIGINS = VALIDATION_ORIGINS = 12
MAX_HISTORY = 100000
# Bind the numerical dependency closure. Changes to shared decimal, scope or
# stage semantics must not retain the old forecast model identity.
MODEL_SOURCE_SHA256 = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                       for name in ("portfolio.py", "portfolio_decision.py", "portfolio_forecast.py")}
MODEL_SHA256 = hashlib.sha256(json.dumps({"algorithm": "SHA256_CLOSURE_V1", "files": MODEL_SOURCE_SHA256},
                                       sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _iso(value):
    return value.isoformat().replace("+00:00", "Z")


def _quantile(values, numerator, denominator=10):
    ordered = sorted(values)
    return ordered[(len(ordered)-1)*numerator//denominator]


def _model(series, offset):
    slots = defaultdict(list)
    for i in range(offset-TRAIN_HOURS, offset):
        slots[i % 168].append(series[i])
    need(len(slots) == 168, "weekly training slots incomplete")
    return {slot: (_quantile(values, 1), _quantile(values, 5), _quantile(values, 9))
            for slot, values in slots.items()}


def produce(data):
    keys(data, ("schema_version", "request_id", "scope", "observed_at", "optimization_order", "input_refs", "history"))
    need(data["schema_version"] == "2" and isinstance(data["request_id"], str) and 0 < len(data["request_id"]) <= 128,
         "forecast request binding required")
    scope = data["scope"]
    need(analysis_hash({**scope, "sha256": ""}) == scope["sha256"], "forecast scope hash differs")
    projection = period(scope["projection_period"])
    observed = stamp(data["observed_at"])
    need(observed <= projection[0], "forecast observed after projection start")
    need(isinstance(data["input_refs"], list) and 0 < len(data["input_refs"]) <= 2048, "bounded forecast proof set required")
    refs = {reference(r) for r in data["input_refs"]}
    need(len(refs) == len(data["input_refs"]) and reference(scope["ownership_ref"]) in refs, "forecast proof closure differs")
    # The producer establishes the fifth stage. Requiring its output here
    # would create circular authority or force a fabricated no-change record.
    last, stage_error = _stages(data, scope, refs, observed, STAGES[:-1])
    result = {"schema_version": "2", "id": "", "request_id": data["request_id"], "scope_sha256": scope["sha256"],
              "recalculated_at": data["observed_at"], "status": "UNAVAILABLE", "hours": [], "calibration": None,
              "reason_codes": [], "input_refs": data["input_refs"]}
    def unavailable(reason):
        result["reason_codes"] = [reason]
        result["id"] = analysis_hash(result)
        return result
    if stage_error or last is None:
        return unavailable(stage_error or "POST_OPTIMIZATION_ORDER_INCOMPLETE")
    term = projection[1]-projection[0]
    if term != timedelta(hours=8760):
        return unavailable("TERM_HORIZON_UNSUPPORTED")
    if (projection[0].minute or projection[0].second or projection[0].microsecond
            or not timedelta(0) <= projection[0]-observed < timedelta(hours=1)):
        return unavailable("PROJECTED_NATIVE_HOUR_START_UNSUPPORTED")
    need(isinstance(data["history"], list) and len(data["history"]) <= MAX_HISTORY, "bounded native historical population required")
    if not data["history"]:
        return unavailable("POST_OPTIMIZATION_HISTORY_UNAVAILABLE")
    groups, native_dimensions = defaultdict(dict), {}
    for row in data["history"]:
        keys(row, ("period", "dimensions", "usage_amount", "configuration_sha256", "native_ref"))
        span = period(row["period"])
        need(span[1]-span[0] == timedelta(hours=1) and span[1] <= observed
             and span[0].minute == span[0].second == span[0].microsecond == 0,
             "native history must retain complete actual UTC hours")
        need(reference(row["native_ref"]) in refs, "native forecast source absent")
        if row["configuration_sha256"] != scope["configuration_sha256"]:
            return unavailable("PRE_OPTIMIZATION_CONFIGURATION_HISTORY_REJECTED")
        key = dimensions(row["dimensions"], scope)
        need(span[0] not in groups[key], "duplicate native forecast interval")
        groups[key][span[0]] = decimal(row["usage_amount"])
        native_dimensions[key] = row["dimensions"]
    first = min(min(series) for series in groups.values())
    final = max(max(series)+timedelta(hours=1) for series in groups.values())
    if not timedelta(0) <= observed-final <= timedelta(hours=48):
        return unavailable("LATEST_NATIVE_FORECAST_HISTORY_GAP")
    gap_hours = int((projection[0]-final).total_seconds()//3600)
    count = int((final-first).total_seconds()//3600)
    expected_stamps = [first+timedelta(hours=i) for i in range(count)]
    expected_set = set(expected_stamps)
    if any(set(series) != expected_set for series in groups.values()):
        return unavailable("NATIVE_FORECAST_INTERVALS_MISSING")
    horizon = 8760
    required = TRAIN_HOURS+2*horizon+2*gap_hours+STRIDE_HOURS*(CALIBRATION_ORIGINS+VALIDATION_ORIGINS-2)
    if count < required:
        return unavailable("FULL_TERM_CALIBRATION_HISTORY_INADEQUATE")
    # Fixed chronological split: calibration outcomes precede held-out origins.
    # Every origin is tested against an entire actual term, never extrapolated
    # counts or scaled short-horizon errors. Overlap remains explicitly labelled.
    last_origin = count-horizon
    validation_origins = [last_origin-STRIDE_HOURS*i for i in reversed(range(VALIDATION_ORIGINS))]
    last_calibration = validation_origins[0]-horizon-gap_hours
    calibration_origins = [last_calibration-STRIDE_HOURS*i for i in reversed(range(CALIBRATION_ORIGINS))]
    origins = calibration_origins+validation_origins
    series_by_key = {key: [rows[t] for t in expected_stamps] for key, rows in groups.items()}
    with localcontext() as context:
        context.prec = 80
        models = {key: [_model(series, origin-gap_hours) for origin in origins] for key, series in series_by_key.items()}
        radii = {}
        for key, series in series_by_key.items():
            errors = []
            for origin, fitted in zip(origins[:CALIBRATION_ORIGINS], models[key][:CALIBRATION_ORIGINS]):
                error = Decimal(0)
                for i in range(origin, origin+horizon):
                    lower, _, upper = fitted[i % 168]
                    error = max(error, lower-series[i], series[i]-upper)
                errors.append(error)
            # Finite sample rank for 90% nominal coverage, without fitting to
            # validation outcomes. With12 calibration blocks this is the maximum.
            rank = ((len(errors)+1)*9+9)//10-1
            radii[key] = sorted(errors)[min(rank, len(errors)-1)]
        passed = 0
        for n, origin in enumerate(origins[CALIBRATION_ORIGINS:], CALIBRATION_ORIGINS):
            fits = {key: models[key][n] for key in series_by_key}
            covered = True
            for key, series in series_by_key.items():
                radius = radii[key]
                for i in range(origin, origin+horizon):
                    lower, _, upper = fits[key][i % 168]
                    if not max(Decimal(0), lower-radius) <= series[i] <= upper+radius:
                        covered = False
                        break
                if not covered:
                    break
            passed += int(covered)
        observed_coverage = Decimal(passed)/VALIDATION_ORIGINS
        if observed_coverage < Decimal("0.9"):
            return unavailable("FULL_TERM_HELDOUT_COVERAGE_UNCALIBRATED")
        final_models = {key: _model(series, count) for key, series in series_by_key.items()}
        for n in range(horizon):
            span = {"start": _iso(projection[0]+timedelta(hours=n)), "end": _iso(projection[0]+timedelta(hours=n+1))}
            for key in sorted(groups, key=repr):
                lower, expected, upper = final_models[key][(count+gap_hours+n) % 168]
                radius = radii[key]
                result["hours"].append({"period": span, "dimensions": native_dimensions[key], "lower_usage": money(max(Decimal(0), lower-radius)),
                                        "expected_usage": money(expected), "upper_usage": money(upper+radius)})
        result["calibration"] = {"target": "TERM_UTILIZATION_AND_NET_COST", "horizon_hours": horizon,
                                 "backtest_origin_count": VALIDATION_ORIGINS, "method": METHOD, "model_version": MODEL_VERSION,
                                 "model_sha256": MODEL_SHA256,
                                 "training_period": {"start": _iso(first), "end": _iso(first+timedelta(hours=origins[CALIBRATION_ORIGINS]-gap_hours))},
                                 "holdout_period": {"start": _iso(first+timedelta(hours=origins[CALIBRATION_ORIGINS])), "end": _iso(final)},
                                 "sample_count": VALIDATION_ORIGINS, "nominal_coverage": "0.9", "observed_coverage": money(observed_coverage),
                                 "scope_sha256": scope["sha256"]}
        result["status"] = "CALIBRATED"
        result["reason_codes"] = ["DEPENDENT_ROLLING_ORIGIN_EMPIRICAL_PATH_COVERAGE", "HELD_CURRENT_NATIVE_NET_RATE_ASSUMPTION",
                                  "STATIONARITY_AND_UNCHANGED_CONFIGURATION_ASSUMPTIONS", "NO_GUARANTEED_FUTURE_PRICE_OR_DEMAND"]
        result["id"] = analysis_hash(result)
        return result
