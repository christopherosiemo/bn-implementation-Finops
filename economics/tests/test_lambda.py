"""Explicit synthetic components; connected native acceptance is separate."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from http.server import ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from autopilot.lambda_model import evaluate_lambda, MODEL_KIND
from autopilot.model import EvidenceError
from autopilot.server import Handler


def ref(name):
    return {"kind": "SYNTHETIC_LAMBDA_COMPONENT", "id": name, "version": "1", "sha256": hashlib.sha256(name.encode()).hexdigest()}


def fixture(days=14):
    end = datetime(2026, 10, 20, tzinfo=timezone.utc)
    start = end - timedelta(days=days)
    stamp = lambda d: d.isoformat().replace("+00:00", "Z")
    binding = {"tenant_id": "synthetic-tenant", "account_id": "111122223333", "region": "eu-west-1", "resource_id": "lambda-synthetic", "provider": "AWS", "provider_resource_id": "arn:aws:lambda:eu-west-1:111122223333:function:synthetic", "workload_id": "synthetic-workload"}
    config = {"base_function_arn": binding["provider_resource_id"], "qualified_arn": binding["provider_resource_id"] + ":prod", "version": "42", "qualifier": "prod", "model": "EVENT_DEFAULT", "memory_size_mb": 2048, "architecture": "x86_64", "runtime": "python3.13", "package_type": "Zip", "code_sha256": "code-digest", "timeout_seconds": 30, "ephemeral_storage_mb": 512, "reserved_concurrency": 100, "provisioned_concurrency": 0}
    policy = {"owner": "customer-team", "configuration_authority": "TERRAFORM", "criticality": "NON_PRODUCTION", "seasonal": False, "latency_sensitive": True, "latency_slo_ms": "2000", "max_duration_ms": "10000", "max_error_rate": "0", "max_throttle_rate": "0", "memory_headroom_fraction": "0.2", "concurrency_headroom_fraction": "0.2", "minimum_provisioned_concurrency": "0", "bursts_known": True, "architecture_compatibility": {k: "COMPATIBLE" for k in ("runtime", "package", "native_dependencies", "layers", "extensions", "container_image", "customer_declaration")}}
    metrics = []
    for i in range(days):
        for name, stat, value, unit in (("Invocations", "Sum", "100", "Count"), ("Errors", "Sum", "0", "Count"), ("Throttles", "Sum", "0", "Count"), ("ConcurrentExecutions", "Maximum", "10", "Count"), ("Duration", "Maximum", "1500", "Milliseconds"), ("ProvisionedConcurrentExecutions", "Maximum", "2", "Count"), ("ProvisionedConcurrencyInvocations", "Sum", "100", "Count"), ("ProvisionedConcurrencySpilloverInvocations", "Sum", "0", "Count"), ("ProvisionedConcurrencyUtilization", "Maximum", "0.2", "None")):
            metrics.append({"metric": name, "statistic": stat, "value": value, "unit": unit, "source_time": stamp(start + timedelta(days=i)), "period_seconds": 86400, "sample_count": "100", "qualified_arn": config["qualified_arn"], "version": "42"})
    reports = {"rows": [{"request_id_hash": "bounded-equivalent-cohort", "count": str(days * 100), "event_time": stamp(start + timedelta(hours=1)), "duration_ms": "900", "billed_duration_ms": "1000", "memory_size_mb": "2048", "max_memory_used_mb": "800", "init_duration_ms": "100", "version": "42"}], "coverage": {"status": "COMPLETE_OBSERVED", "start": stamp(start), "end": stamp(end)}}
    def point(identity, memory, billed):
        return {"id": identity, "version": "1", "sha256": ref(identity)["sha256"], "binding": copy.deepcopy(binding), "received_at": stamp(end), "measurement_start": stamp(start + timedelta(hours=1)), "measurement_end": stamp(start + timedelta(hours=2)), "provenance": "REGISTERED_MACHINE_BENCHMARK", "qualifier": "prod", "executed_version": "42", "code_sha256": "code-digest", "comparison_fingerprint": "same-runtime-layers-dependency-input-profile", "workload_definition_id": "completed-images", "workload_definition_version": "1", "workload_mix_hash": "same-mix", "load_profile_hash": "same-profile", "memory_size_mb": memory, "architecture": "x86_64", "invocations": "100", "successful_work": "100", "errors": "0", "throttles": "0", "total_duration_ms": str(Decimal(billed) * 100 - 100), "total_billed_duration_ms": str(Decimal(billed) * 100), "p95_duration_ms": billed, "p99_duration_ms": str(Decimal(billed) + 100), "max_memory_used_mb": "800", "peak_concurrent_executions": "10", "p95_application_latency_ms": "1500", "cold_start_p95_ms": "100", "source_ref": ref(identity)}
    def charge(category, quantity, rate, unit):
        amount = str(Decimal(quantity) * Decimal(rate))
        return {"id": category, "component": category, "amount": amount, "effective_amount": amount, "quantity": quantity, "rate": rate, "currency": "GBP", "unit": unit, "architecture": "x86_64", "basis": "AWS_CUR_NATIVE_NET", "marginal_pricing_known": True, "source_ref": ref(category), "rate_bracket": {"begin": "0", "end": None, "aggregate_quantity": quantity, "resolved": True}}
    return {"schema_version": "1", "model_version": "lambda-v1", "binding": binding, "resource_id": binding["resource_id"], "config_hash": "a" * 64, "as_of": stamp(end + timedelta(hours=1)), "configuration": config, "policy": policy,
            "observation": {"start": stamp(start), "end": stamp(end), "metrics": metrics, "reports": reports}, "performance": {"receipts": [point("current", 2048, "1000"), point("lower", 1536, "1200"), point("higher", 3072, "500")]},
            "billing": {"currency": "GBP", "start": stamp(start), "end": stamp(end), "complete": True, "scope_complete": True, "marginal_pricing_known": True, "commitment_scope_known": True, "free_tier_resolved": True, "components": [charge("REQUEST", str(days * 100), "0.0000002", "Request"), charge("ON_DEMAND_COMPUTE", str(days * 200), "0.00002", "GB-s")]}, "rates": [], "provider_recommendations": [], "source_refs": [ref("native-snapshot")]}


def candidate(data, identity):
    return next(c for c in evaluate_lambda(data)["candidates"] if c["id"] == identity)


class LambdaEconomicsTests(unittest.TestCase):
    def test_lower_memory_and_faster_higher_memory_compare_actual_billed_curve(self):
        d = fixture()
        saved = copy.deepcopy(d)
        result = evaluate_lambda(d)
        self.assertEqual(result["model_kind"], MODEL_KIND)
        lower, higher = (next(c for c in result["candidates"] if c["id"] == "memory-" + n) for n in ("lower", "higher"))
        self.assertEqual(lower["decision"], "REDUCE_MEMORY")
        self.assertEqual(higher["decision"], "INCREASE_MEMORY_FOR_LOWER_COST")
        self.assertEqual(Decimal(lower["economics"]["estimated_window_saving"]), Decimal("0.0056"))
        self.assertEqual(Decimal(higher["economics"]["estimated_window_saving"]), Decimal("0.014"))
        self.assertEqual(next(f for f in result["decision_families"] if f["family"] == "MEMORY")["decision"], "INCREASE_MEMORY_FOR_LOWER_COST")
        self.assertEqual(result["observations"]["report_summary"]["total_billed_duration_ms"], "1400000.000000000000")
        self.assertEqual(result["observations"]["report_summary"]["total_duration_ms"], "1260000.000000000000")
        self.assertEqual(result["economically_analysed_source_record_ids"], ["ON_DEMAND_COMPUTE", "REQUEST"])
        self.assertEqual(d, saved)
        self.assertEqual(evaluate_lambda(d), result)
        for item in [result] + result["candidates"]:
            self.assertTrue(item["read_only"])
            self.assertFalse(item["pre_execution_ready"])
            self.assertFalse(item["execution_authorized"])
            self.assertIsNone(item["verified_saving"])

    def test_slower_downsize_more_expensive_preserves_negative_result(self):
        d = fixture()
        p = d["performance"]["receipts"][1]
        p["total_billed_duration_ms"] = "200000"
        c = candidate(d, "memory-lower")
        self.assertEqual(c["decision"], "KEEP_CURRENT_MEMORY")
        self.assertLess(Decimal(c["economics"]["estimated_window_saving"]), 0)

    def test_memory_pressure_errors_throttles_slo_and_concurrency_refuse(self):
        for change in ("memory", "errors", "throttles", "latency", "concurrency"):
            with self.subTest(change=change):
                d = fixture()
                p = d["performance"]["receipts"][1]
                if change == "memory": p["max_memory_used_mb"] = "1500"
                if change == "errors": p["errors"] = "1"
                if change == "throttles": p["throttles"] = "1"
                if change == "latency": p["p95_application_latency_ms"] = "2500"
                if change == "concurrency": p["peak_concurrent_executions"] = "90"
                c = candidate(d, "memory-lower")
                self.assertEqual(c["status"], "BLOCKED")
                self.assertIsNone(c["economics"]["estimated_window_saving"])

    def test_missing_memory_or_one_point_cannot_manufacture_response_curve(self):
        d = fixture()
        d["observation"]["reports"]["rows"] = []
        self.assertEqual(candidate(d, "memory-lower")["status"], "BLOCKED")
        d = fixture()
        d["performance"]["receipts"] = d["performance"]["receipts"][:1]
        self.assertEqual(candidate(d, "memory-current")["decision"], "KEEP_CURRENT_MEMORY")
        self.assertFalse(any(c["decision"] == "REDUCE_MEMORY" for c in evaluate_lambda(d)["candidates"]))
        d["performance"]["receipts"] = []
        self.assertIn("LAMBDA_COMPARABLE_PERFORMANCE_CURVE_REQUIRED", candidate(d, "memory-insufficient")["reason_codes"])

    def test_missing_bins_unknown_zero_and_policy_history(self):
        d = fixture()
        d["observation"]["metrics"] = d["observation"]["metrics"][1:]
        self.assertIn("LAMBDA_INVOCATIONS_EVIDENCE_INCOMPLETE", evaluate_lambda(d)["reason_codes"])
        d = fixture(13)
        self.assertIn("INSUFFICIENT_OBSERVATION", evaluate_lambda(d)["reason_codes"])
        d = fixture()
        d["policy"]["criticality"] = "PRODUCTION"
        self.assertIn("INSUFFICIENT_OBSERVATION", evaluate_lambda(d)["reason_codes"])
        d = fixture(30)
        d["policy"]["seasonal"] = True
        self.assertIn("INSUFFICIENT_OBSERVATION", evaluate_lambda(d)["reason_codes"])

    def test_performance_receipt_identity_workload_epoch_and_code_bindings(self):
        for field in ("comparison_fingerprint", "workload_mix_hash", "load_profile_hash", "code_sha256", "qualifier"):
            d = fixture()
            d["performance"]["receipts"][1][field] = "different"
            self.assertFalse(any(c["id"] == "memory-lower" for c in evaluate_lambda(d)["candidates"]))
        d = fixture()
        d["performance"]["receipts"][1]["binding"]["tenant_id"] = "another-tenant"
        with self.assertRaises(EvidenceError): evaluate_lambda(d)
        d = fixture()
        d["observation"]["metrics"][0]["version"] = "43"
        with self.assertRaises(EvidenceError): evaluate_lambda(d)

    def test_prices_free_tier_commitment_and_currency_fail_closed(self):
        for field in ("complete", "scope_complete", "marginal_pricing_known", "commitment_scope_known", "free_tier_resolved"):
            d = fixture()
            d["billing"][field] = False
            c = candidate(d, "memory-lower")
            self.assertEqual(c["status"], "BLOCKED")
            self.assertIsNone(c["economics"]["estimated_window_saving"])
        for value in (0.00002, "0.00003", None):
            d = fixture()
            d["billing"]["components"][1]["rate"] = value
            if isinstance(value, float):
                with self.assertRaises(EvidenceError): evaluate_lambda(d)
            else:
                self.assertIsNone(candidate(d, "memory-lower")["economics"]["estimated_window_saving"])
        d = fixture()
        d["billing"]["components"][1]["currency"] = "USD"
        with self.assertRaises(EvidenceError): evaluate_lambda(d)

    def test_pc_peak_reserve_spillover_latency_and_reserved_no_savings(self):
        d = fixture()
        d["configuration"]["provisioned_concurrency"] = 10
        d["billing"]["components"].append({"id": "pc-native", "component": "PROVISIONED_CAPACITY", "amount": "96.768", "effective_amount": "96.768", "quantity": "24192000", "rate": "0.000004", "currency": "GBP", "unit": "GB-s", "architecture": "x86_64", "basis": "AWS_CUR_NATIVE_NET", "marginal_pricing_known": True, "source_ref": ref("pc"), "rate_bracket": {"begin": "0", "end": None, "aggregate_quantity": "24192000", "resolved": True}})
        c = candidate(d, "provisioned-concurrency")
        self.assertEqual(c["decision"], "REDUCE_PROVISIONED_CONCURRENCY")
        self.assertEqual(c["provisioned_concurrency"], 3)
        self.assertEqual(Decimal(c["economics"]["estimated_window_saving"]), Decimal("67.7376"))
        self.assertIsNone(candidate(d, "reserved-concurrency-review")["economics"]["estimated_window_saving"])
        for row in d["observation"]["metrics"]:
            if row["metric"] == "ProvisionedConcurrencySpilloverInvocations": row["value"] = "1"
        self.assertIn("LAMBDA_SPILLOVER_PREVENTS_REDUCTION", candidate(d, "provisioned-concurrency")["reason_codes"])
        self.assertIsNone(candidate(d, "provisioned-concurrency")["economics"]["estimated_window_saving"])
        d["policy"]["minimum_provisioned_concurrency"] = "10"
        for row in d["observation"]["metrics"]:
            if row["metric"] == "ProvisionedConcurrencySpilloverInvocations": row["value"] = "0"
        self.assertEqual(candidate(d, "provisioned-concurrency")["decision"], "KEEP_CURRENT")

    def test_arm_review_compatibility_and_provider_comparison(self):
        d = fixture()
        c = candidate(d, "arm64-review")
        self.assertEqual(c["decision"], "ARM64_BENCHMARK_RECOMMENDED")
        self.assertIsNone(c["economics"]["estimated_window_saving"])
        d["policy"]["architecture_compatibility"]["native_dependencies"] = "INCOMPATIBLE"
        self.assertIn("LAMBDA_ARM64_DEPENDENCY_INCOMPATIBLE", candidate(d, "arm64-review")["reason_codes"])
        d["provider_recommendations"] = [{"memorySizeRecommendationOptions": [{"memorySize": 1024, "estimatedMonthlySavings": "9999"}]}]
        result = evaluate_lambda(d)
        self.assertEqual(result["difference"], "DIFFERS")
        self.assertNotEqual(result["economics"]["current_effective_cost"], "9999")
        self.assertEqual(result["implementation_method"], "DECLARATIVE_REMEDIATION_REVIEW")

    def test_high_memory_arm_low_volume_unsupported_and_missing_provider_remain(self):
        for model, size, architecture in (("EVENT_DEFAULT", 4096, "arm64"), ("EVENT_MANAGED_INSTANCES", 32768, "x86_64")):
            d = fixture()
            d["configuration"].update(model=model, memory_size_mb=size, architecture=architecture)
            d["observation"]["reports"]["rows"] = []
            result = evaluate_lambda(d)
            self.assertEqual(result["configuration"]["memory_size_mb"], size)
            self.assertEqual(result["configuration"]["architecture"], architecture)
            self.assertEqual(result["difference"], "NO_PROVIDER_ADVICE")
        d = fixture()
        for row in d["observation"]["metrics"]:
            if row["metric"] == "Invocations": row["value"] = "0"
        d["observation"]["reports"]["rows"] = []
        self.assertEqual(evaluate_lambda(d)["observations"]["metrics_summary"]["Invocations:Sum"]["total"], "0.000000000000")
        self.assertIn("LAMBDA_NO_WORKLOAD_FOR_PERFORMANCE_COMPARISON", candidate(d, "memory-lower")["reason_codes"])

    def test_credits_continuing_cost_and_init_are_not_invented_savings(self):
        d = fixture()
        for name, amount in (("CREDIT", "-1"), ("CONTINUING", "4")):
            d["billing"]["components"].append({"id": name, "component": name, "amount": amount, "effective_amount": amount, "quantity": None, "rate": None, "currency": "GBP", "unit": "Unknown", "source_ref": ref(name)})
        c = candidate(d, "memory-lower")
        self.assertEqual(Decimal(c["economics"]["estimated_window_saving"]), Decimal("0.0056"))
        r = evaluate_lambda(d)["observations"]["report_summary"]
        self.assertEqual(r["init_duration_ms"], "140000.000000000000")
        self.assertIn("HIGH_WATER", r["memory_semantics"])

    def test_private_route_auth_duplicate_json_and_float_money(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict("os.environ", {"ECONOMICS_TOKEN": "lambda-test-token", "DATA_MODE": "live"}):
                url = "http://127.0.0.1:%d/v11/lambda-assessment" % server.server_port
                body = json.dumps(fixture()).encode()
                with self.assertRaises(HTTPError) as error: urlopen(Request(url, body, method="POST"), timeout=5)
                self.assertEqual(error.exception.code, 401)
                request = Request(url, body, {"Authorization": "Bearer lambda-test-token", "Content-Type": "application/json"}, method="POST")
                self.assertEqual(json.load(urlopen(request, timeout=5))["model_kind"], MODEL_KIND)
                duplicate = b'{"schema_version":"1",' + body[1:]
                with self.assertRaises(HTTPError) as error: urlopen(Request(url, duplicate, request.headers, method="POST"), timeout=5)
                self.assertEqual(error.exception.code, 422)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
