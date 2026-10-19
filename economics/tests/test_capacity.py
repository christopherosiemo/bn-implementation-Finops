"""Historical capacity, units, forecasting and native economics acceptance."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

from autopilot.capacity import evaluate_capacity, INPUT_SCHEMA, OUTPUT_SCHEMA, UNITS, MODEL_VERSION, LEGACY_MODEL_VERSION, PROXY_ROLE
from autopilot.model import EvidenceError
from autopilot.server import Handler


BINDING = {"tenant_id": "tenant-a", "workload_id": "api", "resource_id": "resource-a", "provider": "AWS",
           "provider_resource_id": "i-0123456789abcdef0", "account_id": "111122223333", "region": "eu-west-1"}
VALUES = {"cpu": "1.2", "memory": "4000000000", "network": "20", "storage_iops": "20", "storage_throughput": "20", "demand": "5"}
CAPACITY = {"cpu": "4", "memory": "16000000000", "network": "100", "storage_iops": "100", "storage_throughput": "100"}


def stamp(value): return value.isoformat().replace("+00:00", "Z")


def ref(name):
    return {"id": name, "version": "1", "receipt_id": "receipt-"+name, "sha256": hashlib.sha256(name.encode()).hexdigest(), "binding": copy.deepcopy(BINDING)}


def catalog(name, rate, capacities=None):
    return {"id": name, "count": 10, "capacity": capacities or copy.deepcopy(CAPACITY), "architecture": "x86_64", "cpu_model": "m6i-reference",
            "operating_system": "linux", "licensing": "BYOL_NONE", "region": "eu-west-1", "zones": ["eu-west-1a", "eu-west-1b"],
            "accelerator": "NONE", "local_storage": False, "disk_types": ["gp3"], "commitment_compatible": True,
            "source_ref": ref("catalog-"+name), "pricing": {"amount": rate, "currency": "GBP", "unit": "instance-hour", "basis": "NATIVE_CONTRACTED", "avoidable_compute": True, "source_ref": ref("price-"+name)}}


def evidence(days=14, zone="UTC", end=None, cadence=3600):
    tz = ZoneInfo(zone)
    end = end or datetime(2026, 9, 15, tzinfo=tz)
    start = datetime.combine(end.astimezone(tz).date()-timedelta(days=days), datetime.min.time(), tz).astimezone(timezone.utc)
    end = end.astimezone(timezone.utc)
    metrics = []
    for name, unit in UNITS.items():
        points, at = [], start
        while at < end:
            right = min(at+timedelta(seconds=cadence), end)
            points.append({"start": stamp(at), "end": stamp(right), "value": VALUES[name]})
            at = right
        stream = {"name": name, "unit": unit, "statistic": "RAW_SAMPLE" if name in ("cpu", "memory") else "OBSERVED_INTERVAL_RATE", "source_refs": [ref("metric-"+name)], "points": points}
        if name == "demand": stream.update(semantic_role=PROXY_ROLE, source_metric="request_count", source_unit="count")
        if name != "demand": stream["denominator"] = CAPACITY[name]
        metrics.append(stream)
    candidate = {"cpu": "2", "memory": "8000000000", "network": "50", "storage_iops": "50", "storage_throughput": "50"}
    return {"schema_version": "4", "model_version": MODEL_VERSION, "binding": copy.deepcopy(BINDING), "as_of": stamp(end+timedelta(hours=1)),
            "history": {"start": stamp(start), "end": stamp(end), "timezone": zone, "environment": "NON_PRODUCTION", "high_seasonality": False, "cadence_seconds": cadence},
            "metrics": metrics, "current": catalog("current", "2"), "candidates": [catalog("candidate", "1", candidate)],
            "policy": {"reserve_above_forecast_ppm": 300000}, "events": [], "forecast_horizons": ["7_day"], "pricing_period_hours": "800"}


def metric(data, name): return next(item for item in data["metrics"] if item["name"] == name)
def candidate(result): return result["candidates"][0]
def check(result, name): return next(item for item in candidate(result)["checks"] if item["dimension"] == name)


def replay_evidence():
    """Mixed populations, missing evidence and DST with every forecast horizon."""
    data = evidence(30, zone="Europe/London", end=datetime(2026, 11, 2, tzinfo=ZoneInfo("Europe/London")))
    data["forecast_horizons"] = ["7_day", "30_day", "90_day", "annual"]
    cpu = metric(data, "cpu")
    cpu["statistic"] = "DISTRIBUTION"
    for index, point in enumerate(cpu["points"]):
        point.pop("value")
        point.update(sample_count=10, buckets=[{"upper": "0", "count": 0},
                     {"upper": "1.2", "count": index % 10}, {"upper": "3.8", "count": 10-index % 10},
                     {"upper": None, "count": 0}])
    for index, point in enumerate(metric(data, "memory")["points"]):
        if index % 103 == 0: point["value"] = None
    for index, point in enumerate(metric(data, "demand")["points"]):
        point["value"] = str(index % 7)
    data["events"] = [{"id": "launch", "start": "2026-11-02T10:05:00Z", "end": "2026-11-02T10:10:00Z",
                       "multiplier": "4", "source_ref": ref("replay-launch")}]
    return data


class CapacityTests(unittest.TestCase):
    def test_distribution_and_forecast_optimization_preserves_issued_model_hashes(self):
        # These hashes are from the original v1/v2 evaluator before the
        # request-local distribution and forecast-history reuse changes.
        for version, expected in ((LEGACY_MODEL_VERSION, "6069d45c71883b20ed302858bceda08fa8c5bf97ac3f478b36f738a0a1b93f19"),
                                  (MODEL_VERSION, "6904e3ce6efbe6c28b72d82bf24c8e4c13e9c73351c1e936b3312df7b414d228")):
            with self.subTest(model_version=version):
                data = replay_evidence()
                data["model_version"] = version
                if version == LEGACY_MODEL_VERSION:
                    demand = metric(data, "demand")
                    for key in ("semantic_role", "source_metric", "source_unit"): demand.pop(key)
                    demand["unit"] = "work_unit/second"
                original = copy.deepcopy(data)
                result = evaluate_capacity(data)
                self.assertEqual(result["assessment_hash"], expected)
                self.assertEqual(data, original)
                self.assertGreater(metric(result, "memory")["missing_intervals"], 0)
                self.assertIsNone(candidate(result)["economics"]["verified_saving"])

    def test_request_throughput_proxy_preserves_native_units_without_work_authority(self):
        for source_unit in ("count", "requests"):
            data = evidence()
            demand = metric(data, "demand")
            demand.update(source_unit=source_unit, unit=source_unit+"/second")
            original = copy.deepcopy(data)
            result = evaluate_capacity(data)
            self.assertEqual(data, original)
            self.assertEqual(result["model_version"], MODEL_VERSION)
            for summary in (metric(result, "demand"), result["forecasts"][0]["metrics"]["demand"]):
                self.assertEqual(summary["semantic_role"], PROXY_ROLE)
                self.assertEqual(summary["source_metric"], "request_count")
                self.assertEqual(summary["source_unit"], source_unit)
                self.assertEqual(summary["unit"], source_unit+"/second")
            self.assertEqual(metric(result, "demand")["observed_quantiles"]["p99"]["upper"], "5.000000000000")
            self.assertTrue(any("do not prove completed business work" in line for line in result["model_assumptions"]))
            self.assertIsNone(candidate(result)["economics"]["verified_saving"])

    def test_proxy_contract_rejects_generic_work_units_and_semantic_promotion(self):
        mutations = [lambda d: d.pop("semantic_role"), lambda d: d.update(semantic_role="COMPLETED_WORK"),
                     lambda d: d.update(source_metric="completed_orders"), lambda d: d.update(source_unit="work_unit"),
                     lambda d: d.update(unit="work_unit/second"), lambda d: d.update(unit="requests/second"),
                     lambda d: d.update(statistic="RAW_SAMPLE"), lambda d: d.update(denominator="1"),
                     lambda d: d.update(completed_work_proven=True)]
        for mutate in mutations:
            data = evidence(); mutate(metric(data, "demand"))
            with self.assertRaises(EvidenceError): evaluate_capacity(data)
        data = evidence(); data["model_version"] = "future-model"
        with self.assertRaises(EvidenceError): evaluate_capacity(data)

    def test_legacy_v1_contract_is_not_upgraded_or_relabelled(self):
        data = evidence(); data.pop("model_version")
        demand = metric(data, "demand")
        for key in ("semantic_role", "source_metric", "source_unit"): demand.pop(key)
        demand["unit"] = "work_unit/second"
        result = evaluate_capacity(data)
        self.assertEqual(result["model_version"], LEGACY_MODEL_VERSION)
        # Computed independently by the original v1 implementation before this
        # change: retaining the old contract also retains its immutable hash.
        self.assertEqual(result["assessment_hash"], "263eb9558d8187e158ada23bc1477cfccd98130e75517de8e9b4fd45e6d68f74")
        self.assertEqual(metric(result, "demand")["unit"], "work_unit/second")
        self.assertNotIn("semantic_role", metric(result, "demand"))
        self.assertNotIn("semantic_role", result["forecasts"][0]["metrics"]["demand"])
        explicit = copy.deepcopy(data); explicit["model_version"] = LEGACY_MODEL_VERSION
        self.assertEqual(evaluate_capacity(explicit), result)
        promoted = copy.deepcopy(data); metric(promoted, "demand")["semantic_role"] = PROXY_ROLE
        with self.assertRaises(EvidenceError): evaluate_capacity(promoted)
        self.assertIn(LEGACY_MODEL_VERSION, OUTPUT_SCHEMA["properties"]["model_version"]["enum"])
        self.assertIn(MODEL_VERSION, OUTPUT_SCHEMA["properties"]["model_version"]["enum"])
        self.assertEqual(INPUT_SCHEMA["properties"]["metrics"]["items"]["properties"]["semantic_role"], {"const": PROXY_ROLE})

    def test_evidenced_nonproduction_candidate_and_counted_contracted_cost(self):
        result = evaluate_capacity(evidence())
        self.assertEqual(result["status"], "VALIDATED")
        self.assertTrue(candidate(result)["capacity_suitable"])
        self.assertEqual(candidate(result)["economics"]["estimated_saving"], "8000.000000000000")
        self.assertEqual(candidate(result)["economics"]["current_cost"], "16000.000000000000")
        self.assertIsNone(candidate(result)["economics"]["verified_saving"])
        self.assertIsNone(candidate(result)["future_risk"]["future_breach_probability_upper_ppm"])
        self.assertEqual(check(result, "cpu")["observed_p95_utilization_ppm"], 600000)

    def test_physical_denominators_and_per_resource_scope_are_mandatory(self):
        for value in (None, "40", "0", 4):
            data = evidence(); metric(data, "cpu")["denominator"] = value
            with self.subTest(value=value), self.assertRaises(EvidenceError): evaluate_capacity(data)
        data = evidence(); data["candidates"][0]["count"] = 5
        result = evaluate_capacity(data)
        self.assertIn("COUNT_CHANGE_REQUIRES_SEPARATE_ACTION", candidate(result)["reason_codes"])
        self.assertFalse(candidate(result)["capacity_suitable"])

    def test_memory_pressure_rejects_downsize_despite_low_cpu(self):
        data = evidence()
        for point in metric(data, "cpu")["points"]: point["value"] = "0.6"
        for point in metric(data, "memory")["points"]: point["value"] = "15200000000"
        result = evaluate_capacity(data)
        self.assertFalse(candidate(result)["capacity_suitable"])
        self.assertIn("MEMORY_P95_PLANNING_LIMIT", candidate(result)["reason_codes"])
        self.assertIn("MEMORY_FORECAST_RESERVE_INSUFFICIENT", candidate(result)["reason_codes"])

    def test_unsafe_halving_is_not_justified_by_cpu40_memory50(self):
        data = evidence()
        for point in metric(data, "cpu")["points"]: point["value"] = "1.6"
        for point in metric(data, "memory")["points"]: point["value"] = "8000000000"
        result = evaluate_capacity(data)
        self.assertIn("CPU_P95_PLANNING_LIMIT", candidate(result)["reason_codes"])
        self.assertIn("MEMORY_FORECAST_RESERVE_INSUFFICIENT", candidate(result)["reason_codes"])

    def test_safe_candidate_with_explicit30percent_reserve(self):
        data = evidence()
        for point in metric(data, "cpu")["points"]: point["value"] = "1.6"
        for point in metric(data, "memory")["points"]: point["value"] = "8000000000"
        data["candidates"][0]["capacity"].update(cpu="3", memory="12000000000")
        result = evaluate_capacity(data)
        self.assertEqual(candidate(result)["status"], "VALIDATED")
        self.assertEqual(check(result, "memory")["required_with_reserve"], "10400000000.000000000000")

    def test_spare_fraction_is_distinct_from_additive_reserve(self):
        data = evidence(); data["policy"] = {"reserve_above_forecast_ppm": 300000}
        additive = check(evaluate_capacity(data), "cpu")["required_with_reserve"]
        data["policy"] = {"unused_capacity_ppm": 300000}
        unused = check(evaluate_capacity(data), "cpu")["required_with_reserve"]
        self.assertEqual(additive, "1.560000000000")
        self.assertEqual(unused, "1.714285714286")
        self.assertGreater(Decimal(unused), Decimal(additive))

    def test_planning_p95_thresholds_are_not_runtime_p99_rollback_thresholds(self):
        result = evaluate_capacity(evidence())
        self.assertEqual(check(result, "cpu")["p95_planning_limit_ppm"], 700000)
        self.assertEqual(check(result, "cpu")["p99_rollback_limit_ppm"], 850000)
        self.assertEqual(check(result, "memory")["p95_planning_limit_ppm"], 750000)
        self.assertEqual(check(result, "memory")["p99_rollback_limit_ppm"], 900000)
        self.assertNotIn("rollback_required", candidate(result))

    def test_low_p95_cannot_hide_candidate_already_above_p99rollback_limit(self):
        data = evidence(); data["policy"] = {"reserve_above_forecast_ppm": 0}
        points = metric(data, "cpu")["points"]
        for point in points[-7:]: point["value"] = "1.9"
        result = evaluate_capacity(data)
        self.assertEqual(check(result, "cpu")["observed_p95_utilization_ppm"], 600000)
        self.assertEqual(check(result, "cpu")["projected_p99_utilization_ppm"], 950000)
        self.assertIn("CPU_P99_ROLLBACK_LIMIT", candidate(result)["reason_codes"])
        self.assertEqual(check(result, "cpu")["status"], "FAIL")
        for point in points[-7:]: point["value"] = "1.7"
        result = evaluate_capacity(data)
        self.assertEqual(check(result, "cpu")["projected_p99_utilization_ppm"], 850000)
        self.assertNotIn("CPU_P99_ROLLBACK_LIMIT", candidate(result)["reason_codes"])

    def test_long_intervals_cannot_hide_missing_cadence_observations(self):
        data = evidence(); stream = metric(data, "cpu")
        points = stream["points"]
        stream["points"] = [{**points[index], "end": points[index+1]["end"]} for index in range(0, len(points), 2)]
        result = evaluate_capacity(data)
        self.assertEqual(metric(result, "cpu")["time_coverage_ppm"], 1000000)
        self.assertEqual(metric(result, "cpu")["sampling_coverage_ppm"], 500000)
        self.assertEqual(metric(result, "cpu")["coverage_ppm"], 500000)
        self.assertFalse(candidate(result)["capacity_suitable"])

    def test_observed_quantiles_use_raw_distribution_not_average(self):
        data = evidence(); points = metric(data, "cpu")["points"]
        for index, point in enumerate(points): point["value"] = "3.8" if index % 10 == 0 else "0.1"
        result = evaluate_capacity(data)
        observed = metric(result, "cpu")["observed_quantiles"]
        self.assertEqual(observed["p50"]["upper"], "0.100000000000")
        self.assertEqual(observed["p95"]["upper"], "3.800000000000")
        self.assertIn("CPU_P95_PLANNING_LIMIT", candidate(result)["reason_codes"])

    def test_hourly_maximum_does_not_become_p95(self):
        data = evidence(); metric(data, "cpu")["statistic"] = "INTERVAL_MAXIMUM"
        result = evaluate_capacity(data)
        self.assertIsNone(metric(result, "cpu")["observed_quantiles"]["p95"]["upper"])
        self.assertEqual(metric(result, "cpu")["observed_maximum"], "1.200000000000")
        self.assertIn("CPU_MAXIMUM_IS_NOT_QUANTILE_EVIDENCE", result["reason_codes"])
        self.assertFalse(candidate(result)["capacity_suitable"])

    def test_histogram_population_merged_by_bucket_counts_not_average_percentiles(self):
        data = evidence(); stream = metric(data, "cpu"); stream["statistic"] = "DISTRIBUTION"
        for index, point in enumerate(stream["points"]):
            point.pop("value"); point["sample_count"] = 1000 if index == 0 else 1
            point["buckets"] = [{"upper": "1", "count": point["sample_count"] if index == 0 else 0}, {"upper": "3", "count": 0 if index == 0 else 1}, {"upper": None, "count": 0}]
        result = evaluate_capacity(data)
        self.assertEqual(metric(result, "cpu")["quantile_method"], "HISTOGRAM_BOUNDS")
        self.assertEqual(metric(result, "cpu")["observed_quantiles"]["p50"]["upper"], "1.000000000000")
        self.assertEqual(metric(result, "cpu")["observed_quantiles"]["p95"]["upper"], "3.000000000000")

    def test_unbounded_histogram_cannot_supply_capacity_envelope(self):
        data = evidence(); stream = metric(data, "cpu"); stream["statistic"] = "DISTRIBUTION"
        for point in stream["points"]:
            point.pop("value"); point.update(sample_count=1000, buckets=[{"upper": "1", "count": 999}, {"upper": None, "count": 1}])
        result = evaluate_capacity(data)
        self.assertIn("CPU_METRIC_ENVELOPE_UNBOUNDED", result["reason_codes"])
        self.assertFalse(candidate(result)["capacity_suitable"])

    def test_p999_requires_sufficient_observed_volume(self):
        result = evaluate_capacity(evidence())
        self.assertIsNone(metric(result, "cpu")["observed_quantiles"]["p999"]["upper"])
        result = evaluate_capacity(evidence(cadence=900))
        self.assertEqual(metric(result, "cpu")["observed_quantiles"]["p999"]["upper"], "1.200000000000")

    def test_missing_memory_points_are_visible_and_not_zero(self):
        for missing in ("point", "null", "stream"):
            data = evidence()
            if missing == "point": metric(data, "memory")["points"].pop(0)
            elif missing == "null": metric(data, "memory")["points"][0]["value"] = None
            else: data["metrics"] = [item for item in data["metrics"] if item["name"] != "memory"]
            result = evaluate_capacity(data)
            self.assertEqual(candidate(result)["status"], "INSUFFICIENT_OBSERVATION")
            self.assertFalse(candidate(result)["capacity_suitable"])
            if missing != "stream":
                self.assertEqual(metric(result, "memory")["missing_intervals"], 1)
                self.assertNotEqual(metric(result, "memory")["coverage_ppm"], 1000000)

    def test_calendar_windows_respect_iana_dst23and25hour_days(self):
        for end, seconds in ((datetime(2026, 4, 2, tzinfo=ZoneInfo("Europe/London")), (14*24-1)*3600),
                             (datetime(2026, 11, 2, tzinfo=ZoneInfo("Europe/London")), (14*24+1)*3600)):
            data = evidence(zone="Europe/London", end=end)
            result = evaluate_capacity(data)
            self.assertEqual(result["history"]["observed_calendar_days"], 14)
            self.assertEqual(metric(result, "cpu")["expected_intervals"], seconds//3600)
            self.assertEqual(metric(result, "cpu")["coverage_ppm"], 1000000)

    def test14nonproduction30production90seasonal_history_requirements(self):
        for environment, seasonal, days, expected in (("NON_PRODUCTION", False, 13, 14), ("PRODUCTION", False, 29, 30), ("NON_PRODUCTION", True, 89, 90)):
            data = evidence(days); data["history"].update(environment=environment, high_seasonality=seasonal)
            result = evaluate_capacity(data)
            self.assertEqual(result["history"]["required_calendar_days"], expected)
            self.assertIn("INSUFFICIENT_OBSERVATION", result["reason_codes"])

    def test_future_and_stale_history_and_partial_calendar_days_rejected_or_blocked(self):
        data = evidence(); data["as_of"] = data["history"]["start"]
        with self.assertRaises(EvidenceError): evaluate_capacity(data)
        data = evidence(); data["history"]["start"] = "2026-09-01T01:00:00Z"
        with self.assertRaises(EvidenceError): evaluate_capacity(data)
        data = evidence(); data["as_of"] = "2026-09-17T00:00:01Z"
        self.assertIn("HISTORY_STALE", evaluate_capacity(data)["reason_codes"])

    def test_sources_units_denominators_and_exact_decimals_fail_closed(self):
        mutations = [lambda d: metric(d, "cpu").update(unit="percent"),
                     lambda d: metric(d, "memory")["source_refs"][0]["binding"].update(tenant_id="tenant-b"),
                     lambda d: metric(d, "cpu")["source_refs"][0].update(sha256="bad"),
                     lambda d: metric(d, "cpu")["points"][0].update(value=1.2),
                     lambda d: metric(d, "cpu")["points"].append(copy.deepcopy(metric(d, "cpu")["points"][0])),
                     lambda d: d.update(execution_ready=True)]
        for mutate in mutations:
            data = evidence(); mutate(data)
            with self.assertRaises(EvidenceError): evaluate_capacity(data)

    def test_compatibility_checks_all_hardware_and_governing_constraints(self):
        for field, value, reason in (("architecture", "arm64", "INCOMPATIBLE_ARCHITECTURE"), ("cpu_model", "unknown", "INCOMPATIBLE_CPU_MODEL"),
                ("licensing", "unknown", "INCOMPATIBLE_LICENSING"), ("operating_system", "windows", "INCOMPATIBLE_OPERATING_SYSTEM"),
                ("region", "us-east-1", "INCOMPATIBLE_REGION"), ("accelerator", "GPU", "INCOMPATIBLE_ACCELERATOR"),
                ("zones", ["eu-west-1a"], "INCOMPATIBLE_ZONES"), ("disk_types", ["gp2"], "INCOMPATIBLE_DISK_TYPES"),
                ("local_storage", True, "LOCAL_STORAGE_MIGRATION_REQUIRED"), ("commitment_compatible", None, "COMMITMENT_COMPATIBILITY_UNKNOWN_OR_FALSE")):
            data = evidence(); data["candidates"][0][field] = value
            self.assertIn(reason, candidate(evaluate_capacity(data))["reason_codes"])
        data = evidence(); data["candidates"][0]["capacity"]["network"] = None
        self.assertIn("NETWORK_CAPACITY_OR_EVIDENCE_REQUIRED", candidate(evaluate_capacity(data))["reason_codes"])

    def test_short_history_forecasts_are_explainable_but_uncalibrated(self):
        data = evidence(); data["forecast_horizons"] = ["7_day", "30_day", "90_day", "annual"]
        result = evaluate_capacity(data)
        self.assertEqual([item["days"] for item in result["forecasts"]], [7, 30, 90, 365])
        for forecast in result["forecasts"]:
            self.assertEqual(forecast["status"], "UNCALIBRATED")
            self.assertIsNone(forecast["future_breach_probability_upper_ppm"])
            self.assertIsNone(forecast["metrics"]["cpu"]["prediction_interval"])
            self.assertEqual(forecast["metrics"]["cpu"]["point_peak"], "1.200000000000")
        self.assertEqual(candidate(result)["status"], "VALIDATED")

    def test_long_history_block_calibration_does_not_claim1percent_future_risk(self):
        data = evidence(150)
        result = evaluate_capacity(data)
        forecast = result["forecasts"][0]["metrics"]["cpu"]
        self.assertEqual(forecast["status"], "CALIBRATED_BACKTEST")
        self.assertGreaterEqual(forecast["backtest"]["nonoverlapping_block_count"], 19)
        self.assertEqual(forecast["prediction_interval"]["nominal_coverage_ppm"], 950000)
        self.assertEqual(forecast["prediction_interval"]["upper"], "1.200000000000")
        data["history"]["environment"] = "PRODUCTION"
        result = evaluate_capacity(data)
        self.assertIn("FUTURE_BREACH_PROBABILITY_UNCALIBRATED", candidate(result)["reason_codes"])
        self.assertEqual(candidate(result)["future_risk"]["status"], "UNCALIBRATED")

    def test_weekday_time_model_and_rolling_origin_use_only_past_observations(self):
        data = evidence(30)
        for point in metric(data, "demand")["points"]:
            at = datetime.fromisoformat(point["start"].replace("Z", "+00:00"))
            point["value"] = "20" if at.weekday() == 0 and at.hour == 12 else "1"
        result = evaluate_capacity(data)
        forecast = result["forecasts"][0]["metrics"]["demand"]
        self.assertEqual(forecast["point_peak"], "20.000000000000")
        old_blocks = forecast["backtest"]["absolute_block_residuals"]
        metric(data, "demand")["points"][-1]["value"] = "999"
        newer = evaluate_capacity(data)["forecasts"][0]["metrics"]["demand"]["backtest"]["absolute_block_residuals"]
        self.assertEqual(old_blocks[:-1], newer[:-1])
        self.assertFalse(forecast["backtest"]["uses_future_observations"])

    def test_declared4xseasonal_event_preserves_capacity_even_between_model_hours(self):
        data = evidence(90); data["history"]["high_seasonality"] = True
        data["events"] = [{"id": "launch", "start": "2026-09-15T10:05:00Z", "end": "2026-09-15T10:10:00Z", "multiplier": "4", "source_ref": ref("event-launch")}]
        result = evaluate_capacity(data)
        self.assertGreaterEqual(Decimal(check(result, "cpu")["forecast_requirement"]), Decimal("4.8"))
        self.assertIn("CPU_FORECAST_RESERVE_INSUFFICIENT", candidate(result)["reason_codes"])
        self.assertEqual(result["forecasts"][0]["metrics"]["cpu"]["event_multiplier_peak"], "4.000000000000")
        self.assertEqual(result["forecasts"][0]["metrics"]["demand"]["point_peak"], "20.000000000000")

    def test_declared_event_beyond_requested_forecast_horizon_still_blocks_unsafe_permanent_downsize(self):
        data = evidence(); data["events"] = [{"id": "annual-peak", "start": "2026-12-01T00:00:00Z", "end": "2026-12-02T00:00:00Z", "multiplier": "4", "source_ref": ref("event-december")}]
        self.assertIn("CPU_FORECAST_RESERVE_INSUFFICIENT", candidate(evaluate_capacity(data))["reason_codes"])

    def test_native_pricing_only_currency_separation_and_negative_results(self):
        for mutate, reason in ((lambda d: d["candidates"][0]["pricing"].update(basis="PUBLIC_LIST"), "NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED"),
                (lambda d: d["current"]["pricing"].update(avoidable_compute=False), "NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED"),
                (lambda d: d["candidates"][0]["pricing"].update(currency="USD"), "CURRENCY_MISMATCH_NO_FX")):
            data = evidence(); mutate(data)
            result = candidate(evaluate_capacity(data))
            self.assertIsNone(result["economics"]["estimated_saving"])
            self.assertIn(reason, result["reason_codes"])
        data = evidence(); data["candidates"][0]["pricing"]["amount"] = "3"
        result = candidate(evaluate_capacity(data))
        self.assertEqual(result["economics"]["estimated_saving"], "-8000.000000000000")
        self.assertEqual(result["economics"]["status"], "NOT_CHEAPER")

    def test_pure_deterministic_assessment_and_strict_schema_exports(self):
        data = evidence(); original = copy.deepcopy(data)
        first, second = evaluate_capacity(data), evaluate_capacity(data)
        self.assertEqual(data, original)
        self.assertEqual(first, second)
        self.assertEqual(len(first["assessment_hash"]), 64)
        self.assertFalse(INPUT_SCHEMA["additionalProperties"])
        self.assertFalse(OUTPUT_SCHEMA["additionalProperties"])
        self.assertNotIn("execution_ready", first)


class CapacityHTTPTests(unittest.TestCase):
    def test_private_route_token_and_strict_body(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/v4/capacity"
            with patch.dict(os.environ, {"ECONOMICS_TOKEN": "capacity-private-test-token"}):
                raw = json.dumps(evidence()).encode()
                with self.assertRaises(HTTPError) as denied:
                    urlopen(Request(url, data=raw, headers={"Content-Type": "application/json"}), timeout=10)
                self.assertEqual(denied.exception.code, 401)
                response = urlopen(Request(url, data=raw, headers={"Content-Type": "application/json", "Authorization": "Bearer capacity-private-test-token"}), timeout=10)
                self.assertEqual(json.load(response)["status"], "VALIDATED")
                invalid = evidence(); invalid["execution_ready"] = True
                with self.assertRaises(HTTPError) as rejected:
                    urlopen(Request(url, data=json.dumps(invalid).encode(), headers={"Authorization": "Bearer capacity-private-test-token"}), timeout=10)
                self.assertEqual(rejected.exception.code, 422)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__": unittest.main()
