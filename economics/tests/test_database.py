"""Pure typed database evidence and private-route tests; no AWS/DB acceptance."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from http.server import ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from autopilot.database import evaluate_database, METRICS, MODEL_VERSION, PRICE_BASIS
from autopilot.model import EvidenceError
from autopilot.server import Handler


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def ref(name):
    return {"kind": "TEST_COMPONENT_EVIDENCE", "id": name, "version": "1",
            "sha256": hashlib.sha256(name.encode()).hexdigest()}


def evidence(days=14, cluster=False):
    end = datetime(2026, 10, 20, tzinfo=timezone.utc)
    start = end - timedelta(days=days)
    members = ["db-writer", "db-reader"] if cluster else ["db-writer"]
    zones = ["eu-west-1a", "eu-west-1b"] if cluster else ["eu-west-1a"]
    engine = "aurora-postgresql" if cluster else "postgres"
    def entry(identifier, class_id, vcpu, memory):
        return {"id": identifier, "class_id": class_id, "engine": engine, "engine_version": "16.4",
                "license_model": "postgresql-license", "storage_type": "aurora" if cluster else "gp3",
                "region": "eu-west-1", "architecture": "x86_64", "cpu_model": "IceLake",
                "multi_az_capable": True, "zones": zones,
                "capacity": {"vcpu": vcpu, "memory_bytes": memory, "max_connections": "200",
                             "iops": "1000", "throughput_bytes_per_second": "100000000",
                             "network_bytes_per_second": "1000000000", "storage_bytes": "100000000000"},
                "source_ref": ref("native-catalog-" + identifier), "parameter_source_ref": ref("native-parameters-" + identifier)}
    current = entry("current", "db.r6i.2xlarge", "8", "34359738368")
    target = entry("target", "db.r6i.xlarge", "4", "17179869184")
    def price(class_id, rate, amount):
        return {"basis": PRICE_BASIS, "class_id": class_id, "engine": engine,
                "license_model": "postgresql-license", "region": "eu-west-1", "multi_az": cluster,
                "currency": "USD", "unit": "Hrs", "rate": rate, "quantity": "24", "amount": amount,
                "period": {"start": stamp(end - timedelta(days=1)), "end": stamp(end)},
                "source_ref": ref("cur-" + class_id)}
    policy = {"criticality": "NON_PRODUCTION", "high_seasonality": False,
              "min_instances": len(members), "min_zones": len(zones), "source_ref": ref("policy"),
              "cpu_max_fraction": "0.7", "memory_max_fraction": "0.8", "connections_max_fraction": "0.8",
              "iops_max_fraction": "0.8", "throughput_max_fraction": "0.8", "network_max_fraction": "0.8",
              "storage_max_fraction": "0.8", "cpu_headroom_fraction": "0.2", "memory_headroom_fraction": "0.2",
              "reserve_above_forecast_fraction": "0.1", "max_read_latency_seconds": "0.01",
              "max_write_latency_seconds": "0.02", "max_disk_queue_depth": "2", "max_replica_lag_seconds": "2"}
    values = {"cpu_utilization": "10", "freeable_memory": "25769803776", "connections": "20",
              "read_iops": "100", "write_iops": "50", "read_throughput": "1000000", "write_throughput": "500000",
              "network_receive": "1000000", "network_transmit": "1000000", "used_storage": "1000000000",
              "read_latency": "0.002", "write_latency": "0.003", "disk_queue_depth": "0.2", "replica_lag": "0.01"}
    observations = []
    for i in range(days * 24):
        a = start + timedelta(hours=i)
        for member in members:
            observations.append({"member_id": member, "start": stamp(a), "end": stamp(a + timedelta(hours=1)),
                                 "metrics": {name: {"value": value, "sample_count": 12, "native_sample_count": "120",
                                                    "duplicate_sample_count": 0} for name, value in values.items()
                                             if name != "replica_lag" or member == "db-reader"}})
    period = {"start": stamp(end - timedelta(days=1)), "end": stamp(end)}
    return {"schema_version": "1", "model_version": MODEL_VERSION, "resource_kind": "RDS_CLUSTER" if cluster else "RDS_INSTANCE",
            "binding": {"tenant_id": "tenant-a", "workload_id": "database", "resource_id": "database-a", "provider": "AWS",
                        "provider_resource_id": "arn:aws:rds:eu-west-1:111122223333:" + ("cluster:db" if cluster else "db:db"),
                        "account_id": "111122223333", "region": "eu-west-1"},
            "as_of": stamp(end + timedelta(hours=1)), "engine": engine, "engine_version": "16.4",
            "license_model": "postgresql-license", "storage_type": "aurora" if cluster else "gp3", "current_catalog_id": "current",
            "current_configuration": {"class_id": current["class_id"], "member_ids": members,
                                      "member_class_ids": {member: current["class_id"] for member in members},
                                      "replica_member_ids": ["db-reader"] if cluster else [], "zones": zones,
                                      "multi_az": cluster, "network_metrics_supported": True, "source_ref": ref("native-configuration"),
                                      "ha_context": {"member_ids": members, "zones": zones, "source_ref": ref("native-whole-ha")}},
            "catalog": {"source_ref": ref("native-orderable-options"), "entries": [current, target]},
            "candidate_configurations": [{"id": "smaller", "catalog_id": "target", "member_count": len(members), "zones": zones,
                                          "multi_az": cluster, "pricing": price(target["class_id"], "0.25", "6")}],
            "current_pricing": price(current["class_id"], "0.5", "12"),
            "continuing_costs": {"currency": "USD", "period": period,
                                 "storage": {"amount": "24", "source_ref": ref("storage")},
                                 "backup": {"amount": "2.4", "source_ref": ref("backup")},
                                 "io": {"amount": "1.2", "source_ref": ref("io")},
                                 "commitment_exposure": {"current_amount": "0", "candidate_amounts": {"smaller": "0"}, "source_ref": ref("commitment-fees")}},
            "history": {"start": stamp(start), "end": stamp(end), "source_refs": [ref("native-cloudwatch")],
                        "metrics": [{"name": name, "unit": unit, "statistic": statistic, "period_seconds": 3600,
                                     "sample_period_seconds": 300, "expected_sample_count": 12,
                                     "expected_native_sample_count": 60}
                                    for name, (unit, statistic) in METRICS.items()]}, "observations": observations, "policy": policy}


class DatabaseAssessmentTests(unittest.TestCase):
    def test_complete_14_30_90_policy_windows_and_deterministic_no_authority(self):
        for days, criticality, seasonal in ((14, "NON_PRODUCTION", False), (30, "TIER_0", False), (90, "TIER_3", True)):
            with self.subTest(days=days):
                value = evidence(days)
                value["policy"].update(criticality=criticality, high_seasonality=seasonal)
                before = copy.deepcopy(value)
                result = evaluate_database(value)
                self.assertEqual(result["status"], "RECOMMENDED")
                self.assertEqual(result["decision_code"], "CONSIDER_CLASS_CHANGE")
                self.assertEqual(result["recommendation_kind"], "DATABASE_INSTANCE_RIGHTSIZE")
                self.assertEqual(result["evidence_window"]["required_utc_days"], days)
                self.assertEqual(result["evidence_window"]["observed_member_hours"], days * 24)
                self.assertEqual(result["economics"]["current_hourly_cost"], "1.650000000000")
                self.assertEqual(result["economics"]["candidate_hourly_cost"], "1.400000000000")
                self.assertEqual(result["economics"]["estimated_monthly_saving"], "182.500000000000")
                self.assertEqual(result["economics"]["estimated_annual_saving"], "2190.000000000000")
                self.assertEqual(result["proposal"], {"risk_class": "R3", "executable": False, "execution_authorized": False})
                self.assertIsNone(result["verified_saving"])
                self.assertEqual(result["confidence"]["status"], "MEDIUM")
                self.assertEqual(evaluate_database(value), result)
                self.assertEqual(value, before)

    def test_criticality_does_not_invent_ninety_day_requirement(self):
        value = evidence(30)
        value["policy"]["criticality"] = "TIER_0"
        self.assertEqual(evaluate_database(value)["evidence_window"]["required_utc_days"], 30)
        value["policy"]["high_seasonality"] = True
        self.assertIn("INSUFFICIENT_COMPLETE_UTC_DAYS", evaluate_database(value)["blockers"])
        del value["policy"]
        self.assertEqual(evaluate_database(value)["status"], "BLOCKED")

    def test_low_cpu_does_not_override_high_memory_or_any_other_signal(self):
        cases = {"freeable_memory": "0", "connections": "190", "read_iops": "900",
                 "read_throughput": "90000000", "network_receive": "900000000",
                 "used_storage": "90000000000", "read_latency": "0.02", "write_latency": "0.03", "disk_queue_depth": "3"}
        for metric, value in cases.items():
            with self.subTest(metric=metric):
                data = evidence()
                data["observations"][0]["metrics"]["cpu_utilization"]["value"] = "0"
                data["observations"][0]["metrics"][metric]["value"] = value
                result = evaluate_database(data)
                self.assertEqual(result["candidates"][0]["physical_status"], "FAIL")
                self.assertEqual(result["decision_code"], "DO_NOT_PROCEED")
                self.assertFalse(result["proposal"]["executable"])

    def test_missing_native_values_bins_and_duplicate_bins_block_without_zero(self):
        mutations = [lambda x: x["observations"].pop(),
                     lambda x: x["observations"][0]["metrics"]["connections"].update(value=None),
                     lambda x: x["observations"][0]["metrics"]["connections"].update(sample_count=11),
                     lambda x: x["observations"][0]["metrics"]["connections"].update(duplicate_sample_count=1),
                     lambda x: x["observations"][0]["metrics"]["connections"].update(native_sample_count=None),
                     lambda x: x["history"]["metrics"][0].update(expected_sample_count=1),
                     lambda x: x["current_configuration"].update(network_metrics_supported=None)]
        for change in mutations:
            data = evidence()
            change(data)
            result = evaluate_database(data)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(result["blockers"])
        data = evidence()
        data["observations"].append(copy.deepcopy(data["observations"][0]))
        with self.assertRaises(EvidenceError):
            evaluate_database(data)

    def test_native_sample_sum_is_not_the_distinct_bin_count(self):
        result = evaluate_database(evidence())
        metric = next(m for m in result["metric_distributions"] if m["metric"] == "cpu_utilization")
        self.assertEqual(metric["sample_count"], 336 * 12)
        self.assertEqual(metric["native_sample_count"], "40320.000000000000")
        self.assertEqual(metric["p95_of_period_statistics"], "10.000000000000")
        self.assertNotIn("p95", metric)
        self.assertEqual(metric["statistic"], "HOURLY_MAXIMUM_OF_NATIVE_PERIOD_VALUES")

    def test_sparse_native_rollup_and_missing_native_cadence_block(self):
        data = evidence()
        for definition in data["history"]["metrics"]:
            definition.update(sample_period_seconds=3600, expected_sample_count=1)
        for row in data["observations"]:
            for point in row["metrics"].values():
                point.update(sample_count=1, native_sample_count="60")
        self.assertEqual(evaluate_database(data)["status"], "RECOMMENDED")
        data["observations"][0]["metrics"]["cpu_utilization"]["native_sample_count"] = "1"
        self.assertIn("DATABASE_NATIVE_SAMPLE_COVERAGE_INCOMPLETE:cpu_utilization", evaluate_database(data)["blockers"])
        del data["history"]["metrics"][0]["expected_native_sample_count"]
        self.assertIn("DATABASE_METRIC_DEFINITION_UNSUPPORTED:cpu_utilization", evaluate_database(data)["blockers"])

    def test_normative_policy_caps_and_reserve_have_independent_bounds(self):
        data = evidence()
        data["policy"].update(cpu_max_fraction="1", memory_max_fraction="1", reserve_above_forecast_fraction="1.5")
        self.assertNotEqual(evaluate_database(data)["status"], "BLOCKED")
        for key, value in (("cpu_max_fraction", "1.000001"), ("cpu_headroom_fraction", "1"),
                           ("reserve_above_forecast_fraction", "10.000001")):
            bad = evidence()
            bad["policy"][key] = value
            with self.assertRaises(EvidenceError):
                evaluate_database(bad)

    def test_independent_headroom_and_capacity_reserve_do_not_change_observed_slo(self):
        data = evidence()
        data["policy"]["cpu_headroom_fraction"] = "0.9"
        self.assertEqual(evaluate_database(data)["decision_code"], "DO_NOT_PROCEED")
        data = evidence()
        data["policy"]["reserve_above_forecast_fraction"] = "0.5"
        data["observations"][0]["metrics"]["read_latency"]["value"] = "0.0099"
        result = evaluate_database(data)
        check = next(c for c in result["candidates"][0]["checks"] if c["dimension"] == "read_latency")
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["required_with_reserve"], "0.009900000000")

    def test_aurora_every_member_lag_ha_and_mixed_classes(self):
        data = evidence(cluster=True)
        self.assertEqual(evaluate_database(data)["status"], "RECOMMENDED")
        for value in ("3", "-1", None):
            changed = copy.deepcopy(data)
            reader = next(row for row in changed["observations"] if row["member_id"] == "db-reader")
            reader["metrics"]["replica_lag"]["value"] = value
            result = evaluate_database(changed)
            self.assertIn(result["decision_code"], ("BLOCKED", "DO_NOT_PROCEED"))
        data["policy"]["min_instances"] = 3
        self.assertIn("DATABASE_HA_MINIMUM_NOT_PRESERVED", evaluate_database(data)["blockers"])
        data = evidence(cluster=True)
        data["current_configuration"]["member_class_ids"]["db-reader"] = "db.other"
        self.assertIn("MIXED_NATIVE_DATABASE_CLASSES_UNSUPPORTED", evaluate_database(data)["blockers"])
        data = evidence(cluster=True)
        data["candidate_configurations"][0]["multi_az"] = False
        self.assertIn("EXISTING_MULTI_AZ_PROTECTION_MUST_BE_RETAINED", evaluate_database(data)["blockers"])

    def test_instance_whole_ha_context_is_preserved_without_borrowing_capacity(self):
        data = evidence()
        data["current_configuration"]["ha_context"].update(member_ids=["db-writer", "external-reader"], zones=["eu-west-1a", "eu-west-1b"])
        data["policy"].update(min_instances=2, min_zones=2)
        self.assertEqual(evaluate_database(data)["status"], "RECOMMENDED")
        data["current_configuration"]["ha_context"] = None
        self.assertEqual(evaluate_database(data)["status"], "BLOCKED")

    def test_only_issued_native_catalog_and_parameters_are_candidates(self):
        for mutate in (lambda x: x["candidate_configurations"][0].update(catalog_id="invented"),
                       lambda x: x["catalog"]["entries"][1].update(parameter_source_ref=None),
                       lambda x: x["catalog"]["entries"][1].update(cpu_model="different"),
                       lambda x: x["catalog"]["entries"][1]["capacity"].update(max_connections=None),
                       lambda x: x["catalog"]["entries"][1].update(engine="mysql")):
            data = evidence()
            mutate(data)
            self.assertEqual(evaluate_database(data)["status"], "BLOCKED")

    def test_unknown_public_price_currency_and_continuing_costs_cannot_suggest_saving(self):
        for mutate in (lambda x: x["candidate_configurations"][0].update(pricing=None),
                       lambda x: x["candidate_configurations"][0]["pricing"].update(basis="PUBLIC_LIST"),
                       lambda x: x["candidate_configurations"][0]["pricing"].update(currency="EUR"),
                       lambda x: x["continuing_costs"].update(backup=None),
                       lambda x: x["continuing_costs"]["storage"].update(amount=None),
                       lambda x: x["continuing_costs"]["commitment_exposure"].update(current_amount=None)):
            data = evidence()
            mutate(data)
            result = evaluate_database(data)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertIsNone(result["economics"]["estimated_monthly_saving"])
        data = evidence()
        data["candidate_configurations"][0]["pricing"]["amount"] = "5.99"
        with self.assertRaises(EvidenceError):
            evaluate_database(data)

    def test_continuing_commitment_cost_can_make_cheaper_compute_uneconomic(self):
        data = evidence()
        data["continuing_costs"]["commitment_exposure"]["candidate_amounts"]["smaller"] = "24"
        result = evaluate_database(data)
        self.assertEqual(result["decision_code"], "DO_NOT_PROCEED")
        self.assertEqual(result["economics"]["estimated_monthly_saving"], "-547.500000000000")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertTrue(result["economics"]["continuing_costs_preserved"])

    def test_explicit_zero_and_no_change_are_retained(self):
        data = evidence()
        data["candidate_configurations"][0].update(catalog_id="current", pricing=copy.deepcopy(data["current_pricing"]))
        result = evaluate_database(data)
        self.assertEqual(result["decision_code"], "NO_CHANGE")
        self.assertEqual(result["economics"]["estimated_monthly_saving"], "0.000000000000")
        for key in ("storage", "backup", "io"):
            data["continuing_costs"][key]["amount"] = "0"
        for price in (data["current_pricing"], data["candidate_configurations"][0]["pricing"]):
            price.update(rate="0", amount="0")
        self.assertEqual(evaluate_database(data)["economics"]["candidate_hourly_cost"], "0.000000000000")

    def test_decimal_rounding_rejects_float_and_preserves_half_even(self):
        data = evidence()
        data["current_pricing"].update(rate="0.100000000001", quantity="2", amount="0.200000000002")
        data["candidate_configurations"][0]["pricing"].update(rate="0.100000000000", quantity="2", amount="0.2")
        self.assertEqual(evaluate_database(data)["economics"]["estimated_monthly_saving"], "0.000000000730")
        data["current_pricing"]["rate"] = 0.1
        with self.assertRaises(EvidenceError):
            evaluate_database(data)
        from autopilot.database import _money
        self.assertEqual(_money(Decimal("1.0000000000005")), "1.000000000000")
        self.assertEqual(_money(Decimal("1.0000000000015")), "1.000000000002")


class DatabaseRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v7/database-assessment"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_private_route_auth_and_versioned_result(self):
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "private-database-test-token"}):
            with self.assertRaises(HTTPError) as caught:
                urlopen(Request(self.url, data=b"{}"))
            self.assertEqual(caught.exception.code, 401)
            request = Request(self.url, data=json.dumps(evidence()).encode(), headers={"Authorization": "Bearer private-database-test-token"})
            with urlopen(request) as response:
                result = json.load(response)
            self.assertEqual(result["model_version"], MODEL_VERSION)
            self.assertFalse(result["proposal"]["execution_authorized"])

    def test_duplicate_wire_keys_and_bad_version_are_refused(self):
        for raw in (b'{"schema_version":"1","schema_version":"1"}', b'{"schema_version":"wrong"}'):
            with patch.dict("os.environ", {"ECONOMICS_TOKEN": "private-database-test-token"}):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(self.url, data=raw, headers={"Authorization": "Bearer private-database-test-token"}))
                self.assertEqual(caught.exception.code, 422)


if __name__ == "__main__":
    unittest.main()
