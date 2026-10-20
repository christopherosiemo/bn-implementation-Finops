"""Typed component evidence only; no AWS, customer, or execution acceptance."""
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

from autopilot.model import EvidenceError
from autopilot.storage import evaluate_storage, MODEL_VERSION, METRICS, BASE_METRICS, MIGRATION_STEPS
from autopilot.server import Handler


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def ref(name):
    return {"kind": "TEST_COMPONENT_EVIDENCE", "id": name, "version": "1", "sha256": hashlib.sha256(name.encode()).hexdigest()}


def evidence(days=14, volume_type="gp2", candidate_iops="3000", candidate_throughput="125"):
    """One complete, visibly synthetic private-wire example for the Go mapper."""
    end = datetime(2026, 10, 20, tzinfo=timezone.utc)
    start = end - timedelta(days=days)
    period = {"start": stamp(end - timedelta(days=1)), "end": stamp(end)}
    def capability(identifier, kind):
        return {"id": identifier, "volume_type": kind, "min_size_gib": "1", "max_size_gib": "65536",
                "min_iops": "3000" if kind == "gp3" else "100", "max_iops": "80000",
                "min_throughput_mib_per_second": "125" if kind == "gp3" else "1", "max_throughput_mib_per_second": "2000",
                "max_iops_per_gib": "500", "max_throughput_kib_per_iop": "256",
                "baseline_iops": "3000" if kind in ("gp2", "gp3") else "0",
                "baseline_throughput_mib_per_second": "125" if kind == "gp3" else "250",
                "multi_attach_supported": kind in ("io1", "io2"), "durability_class": "TEST_STANDARD" if kind != "io2" else "TEST_HIGHER",
                "latency_class": "TEST_SINGLE_DIGIT_MS", "source_ref": ref("capability-" + kind)}
    current_iops = "9000" if volume_type == "gp3" else "3000"
    current_throughput = "500" if volume_type == "gp3" else "250"
    def pricing(kind, storage_rate, iops, throughput):
        components = [{"component": "storage", "unit": "GiB-Mo", "basis": "AWS_CUR_NET_USAGE",
                       "rate": storage_rate, "quantity": "1000", "amount": str(Decimal(storage_rate) * 1000), "source_ref": ref("cur-storage-" + kind)}]
        for name, value, base, rate, unit in (("iops", iops, "3000" if kind in ("gp2", "gp3") else "0", "0.005", "IOPS-Mo"),
                                               ("throughput", throughput, "125", "0.04", "MiBps-Mo")):
            included = kind == "gp2" or kind in ("io1", "io2") and name == "throughput" or kind == "gp3" and Decimal(value) <= Decimal(base)
            components.append({"component": name, "unit": unit, "basis": "INCLUDED_IN_NATIVE_STORAGE_RATE" if included else "AWS_CUR_NET_USAGE",
                               "rate": "0" if included else rate, "quantity": "0" if included else "100",
                               "amount": "0" if included else str(Decimal(rate) * 100), "source_ref": ref("cur-" + name + "-" + kind)})
        return {"basis": "AWS_CUR_NET_USAGE", "volume_type": kind, "region": "eu-west-1", "account_id": "111122223333",
                "currency": "USD", "period": copy.deepcopy(period), "components": components}
    policy = {"criticality": "NON_PRODUCTION", "high_seasonality": False, "iops_max_fraction": "0.8", "throughput_max_fraction": "0.8",
              "reserve_above_demand_fraction": "0.1", "demand_growth_multiplier": "1", "max_read_latency_seconds": "0.01",
              "max_write_latency_seconds": "0.02", "max_disk_queue_depth": "2", "min_burst_balance_percent": "20",
              "snapshot_retention_days": 30, "quarantine_days": 14, "backup_required": True, "allows_lower_durability": False,
              "requires_multi_attach": False, "filesystem_review_required": True, "source_ref": ref("workload-policy")}
    selected = list(BASE_METRICS) + (["burst_balance"] if volume_type == "gp2" else [])
    cadence = 60 if days <= 14 else 300 if days <= 63 else 3600
    values = {"read_iops": "50", "write_iops": "25", "read_throughput": "1048576", "write_throughput": "524288",
              "queue_length": "0.2", "read_latency": "0.002", "write_latency": "0.003", "burst_balance": "90"}
    observations = []
    for hour in range(days * 24):
        a = start + timedelta(hours=hour)
        observations.append({"start": stamp(a), "end": stamp(a + timedelta(hours=1)), "metrics": {
            name: {"value": values[name], "sample_count": 3600 // cadence, "native_sample_count": "60", "duplicate_sample_count": 0}
            for name in selected}})
    return {"schema_version": "1", "model_version": MODEL_VERSION, "resource_kind": "EBS_VOLUME",
            "binding": {"tenant_id": "synthetic-tenant", "workload_id": "synthetic-workload", "resource_id": "synthetic-resource",
                        "provider": "AWS", "provider_resource_id": "vol-0123456789abcdef0", "account_id": "111122223333", "region": "eu-west-1"},
            "as_of": stamp(end + timedelta(hours=1)),
            "current_configuration": {"capability_id": "current", "volume_type": volume_type, "size_gib": "1000", "iops": current_iops,
                                      "throughput_mib_per_second": current_throughput, "throughput_basis": "SYNTHETIC_DOCUMENTED_TYPE_SIZE_BOUND" if volume_type != "gp3" else "NATIVE_PROVISIONED",
                                      "native_provisioned_throughput_mib_per_second": current_throughput if volume_type == "gp3" else None,
                                      "state": "in-use", "multi_attach_enabled": False, "encrypted": True, "kms_key_id": "synthetic-key",
                                      "created_at": stamp(start - timedelta(days=1)),
                                      "attachments": [{"instance_id": "i-0123456789abcdef0", "device": "/dev/sdf", "state": "attached", "delete_on_termination": False, "root_device": False}],
                                      "source_ref": ref("native-volume")},
            "capabilities": {"source_ref": ref("versioned-capability-asset"), "entries": [capability("current", volume_type), capability("gp3", "gp3")]},
            "candidate_configurations": [{"id": "candidate", "capability_id": "gp3", "volume_type": "gp3", "size_gib": "1000",
                                          "iops": candidate_iops, "throughput_mib_per_second": candidate_throughput,
                                          "pricing": pricing("gp3", "0.08", candidate_iops, candidate_throughput)}],
            "history": {"start": stamp(start), "end": stamp(end), "source_refs": [ref("native-metrics")], "metrics": [
                {"name": name, "unit": METRICS[name][0], "statistic": METRICS[name][1], "period_seconds": 3600,
                 "sample_period_seconds": cadence, "expected_sample_count": 3600 // cadence, "expected_native_sample_count": 60} for name in selected]},
            "observations": observations, "policy": policy,
            "safety": {"owner": "synthetic-owner", "configuration_authority": "TERRAFORM", "configuration_ref": ref("configuration"),
                       "attachment_compatible": True, "instance_iops_limit": "40000", "instance_throughput_mib_per_second_limit": "1250",
                       "filesystem_reviewed": True, "backup_observed": True, "application_slo_clear": True, "dependency_complete": True,
                       "io_latency_compatible": None, "io_durability_compatible": None, "modification_state": "NONE", "source_refs": [ref("safety")]},
            "current_pricing": pricing(volume_type, "0.10" if volume_type == "gp2" else "0.08", current_iops, current_throughput),
            "continuing_costs": {"currency": "USD", "period": period, "components": [
                {"component": name, "amount": "1" if name == "snapshots" else "0", "source_refs": [ref("complete-native-cost-scope-" + name)]}
                for name in ("snapshots", "fast_snapshot_restore", "archive", "continuing")]}, "snapshots": []}


class StorageTests(unittest.TestCase):
    def test_gp2_to_gp3_customer_economics_and_nonexecution(self):
        value = evidence()
        before = copy.deepcopy(value)
        result = evaluate_storage(value)
        self.assertEqual(result["status"], "RECOMMENDED")
        self.assertEqual(result["recommendation_kind"], "STORAGE_GP2_TO_GP3")
        self.assertEqual(result["economics"]["estimated_monthly_saving"], "20.000000000000")
        self.assertEqual(result["economics"]["estimated_annual_saving"], "240.000000000000")
        self.assertEqual(len(result["economics"]["component_costs"]), 7)
        self.assertEqual(result["proposal"], {"risk_class": "R3", "executable": False, "execution_authorized": False})
        self.assertIsNone(result["verified_saving"])
        self.assertEqual(result["implementation_method"], "DECLARATIVE_REMEDIATION_REVIEW")
        self.assertEqual(value, before)
        self.assertEqual(result, evaluate_storage(value))

    def test_gp3_iops_and_throughput_reduction(self):
        for dimension in ("iops", "throughput"):
            with self.subTest(dimension=dimension):
                data = evidence(volume_type="gp3", candidate_iops="3000" if dimension == "iops" else "9000",
                                candidate_throughput="500" if dimension == "iops" else "125")
                result = evaluate_storage(data)
                self.assertEqual(result["status"], "RECOMMENDED")
                self.assertEqual(result["recommendation_kind"], "STORAGE_GP3_" + ("IOPS" if dimension == "iops" else "THROUGHPUT") + "_RIGHTSIZE")
                self.assertEqual(result["candidate_configuration"]["size_gib"], "1000")
        data = evidence(volume_type="gp3", candidate_iops="10000", candidate_throughput="125")
        self.assertIn("STORAGE_GP3_PERFORMANCE_INCREASE_OUTSIDE_RIGHTSIZE_SCOPE", evaluate_storage(data)["blockers"])

    def test_peak_reserve_growth_and_instance_budget_reject(self):
        mutations = [lambda d: d["observations"][200]["metrics"]["read_iops"].update(value="3000"),
                     lambda d: d["policy"].update(demand_growth_multiplier="100"),
                     lambda d: d["safety"].update(instance_iops_limit="50")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                data = evidence()
                mutation(data)
                result = evaluate_storage(data)
                self.assertEqual(result["status"], "NO_CHANGE")
                self.assertEqual(result["decision_code"], "DO_NOT_PROCEED")
                self.assertIn("STORAGE_OBSERVED_CHECK_FAILED:iops", result["blockers"])

    def test_burst_depletion_and_exceeded_signal_blocks_hidden_demand(self):
        data = evidence()
        data["observations"][42]["metrics"]["burst_balance"]["value"] = "0"
        self.assertIn("STORAGE_BURST_DEPLETION_CAN_HIDE_DEMAND", evaluate_storage(data)["blockers"])
        data = evidence()
        data["history"]["metrics"].append({"name": "iops_exceeded", "unit": "Count", "statistic": "Maximum", "period_seconds": 3600,
                                              "sample_period_seconds": 60, "expected_sample_count": 60, "expected_native_sample_count": 60})
        for row in data["observations"]:
            row["metrics"]["iops_exceeded"] = {"value": "1", "sample_count": 60, "native_sample_count": "60", "duplicate_sample_count": 0}
        self.assertEqual(evaluate_storage(data)["status"], "BLOCKED")

    def test_missing_partial_duplicate_native_samples_are_unknown(self):
        changes = [lambda d: d["observations"][10]["metrics"].pop("read_iops"),
                   lambda d: d["observations"][10]["metrics"]["read_iops"].update(value=None),
                   lambda d: d["observations"][10]["metrics"]["read_iops"].update(sample_count=59),
                   lambda d: d["observations"][10]["metrics"]["read_iops"].update(native_sample_count="1"),
                   lambda d: d["observations"][10]["metrics"]["read_iops"].update(duplicate_sample_count=1),
                   lambda d: d["history"]["metrics"][0].update(expected_native_sample_count=1)]
        for change in changes:
            with self.subTest(change=change):
                data = evidence()
                change(data)
                result = evaluate_storage(data)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIsNone(next(x for x in result["checks"] if x["dimension"] == "iops")["observed_demand"])

    def test_zero_operations_latency_is_explicitly_undefined(self):
        data = evidence()
        for row in data["observations"]:
            for name in ("read_latency", "write_latency"):
                row["metrics"][name].update(value=None, operations="0")
            for name in ("read_iops", "write_iops", "read_throughput", "write_throughput"):
                row["metrics"][name]["value"] = "0"
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "RECOMMENDED")
        for row in result["metric_distributions"]:
            if row["metric"] in ("read_latency", "write_latency"):
                self.assertEqual(row["status"], "COMPLETE_ZERO_OPERATIONS")
                self.assertIsNone(row["minimum"])
                self.assertEqual(row["zero_operation_hours"], 336)
        data["observations"][1]["metrics"]["read_latency"]["operations"] = "1"
        self.assertEqual(evaluate_storage(data)["status"], "BLOCKED")
        data["observations"][1]["metrics"]["read_latency"]["operations"] = "0"
        data["observations"][1]["metrics"]["read_iops"]["value"] = "1"
        self.assertEqual(evaluate_storage(data)["status"], "BLOCKED")

    def test_required_windows_and_rollup_native_counts(self):
        for days, criticality, seasonal in ((14, "NON_PRODUCTION", False), (30, "TIER_0", False), (90, "TIER_3", True)):
            with self.subTest(days=days):
                data = evidence(days)
                data["policy"].update(criticality=criticality, high_seasonality=seasonal)
                result = evaluate_storage(data)
                self.assertEqual(result["status"], "RECOMMENDED")
                self.assertEqual(result["evidence_window"]["required_utc_days"], days)
        data = evidence()
        data["policy"].update(criticality="TIER_0")
        self.assertIn("STORAGE_INSUFFICIENT_COMPLETE_UTC_DAYS", evaluate_storage(data)["blockers"])
        data["policy"].update(criticality="NON_PRODUCTION", high_seasonality=True)
        self.assertEqual(evaluate_storage(data)["status"], "BLOCKED")

    def test_io_types_need_independent_equivalence_and_multiattach(self):
        for kind in ("io1", "io2"):
            with self.subTest(kind=kind):
                data = evidence(volume_type=kind)
                result = evaluate_storage(data)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("STORAGE_IO_LATENCY_EQUIVALENCE_UNPROVEN", result["blockers"])
                data["current_configuration"]["multi_attach_enabled"] = True
                self.assertIn("STORAGE_MULTI_ATTACH_INCOMPATIBLE", evaluate_storage(data)["blockers"])

    def test_modification_policy_iac_and_feature_unknowns(self):
        for field, value in (("modification_state", "OPTIMIZING"), ("application_slo_clear", None), ("attachment_compatible", False),
                             ("configuration_authority", None), ("backup_observed", None), ("instance_iops_limit", None)):
            with self.subTest(field=field):
                data = evidence()
                data["safety"][field] = value
                self.assertEqual(evaluate_storage(data)["status"], "BLOCKED")
        data = evidence()
        data["safety"]["configuration_authority"] = "MANUAL"
        self.assertEqual(evaluate_storage(data)["implementation_method"], "MANUAL_STORAGE_CHANGE_REVIEW")

    def test_unattached_review_needs_no_performance_and_never_deletes(self):
        data = evidence()
        data["current_configuration"].update(attachments=[], state="available")
        data.update(history=None, observations=[], candidate_configurations=[])
        data["safety"]["owner"] = None
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "OBSERVATION_ONLY")
        self.assertEqual(result["recommendation_kind"], "STORAGE_UNATTACHED_REVIEW")
        self.assertIsNone(result["evidence_window"])
        self.assertFalse(result["unattached_review"]["deletion_recommended"])
        self.assertIsNone(result["economics"]["candidate_monthly_cost"])
        self.assertIsNone(result["economics"]["estimated_monthly_saving"])
        self.assertIn("STORAGE_OWNER_UNKNOWN", result["blockers"])

    def test_snapshot_dependencies_and_actual_billed_cost_review_only(self):
        data = evidence()
        snap = {"id": "snap-0123456789abcdef0", "volume_id": "vol-0123456789abcdef0", "started_at": "2026-01-01T00:00:00Z", "state": "completed",
                "storage_tier": "standard", "dependency_state": "UNKNOWN", "ami_ids": None, "restore_references": None,
                "policy_required": None, "source_ref": ref("snapshot"), "monthly_cost": "-1.25", "currency": "EUR", "pricing_source_ref": ref("snapshot-cur")}
        data["snapshots"] = [snap]
        row = evaluate_storage(data)["snapshot_reviews"][0]
        self.assertEqual(row["classification"], "UNKNOWN_DEPENDENCY")
        self.assertFalse(row["deletion_recommended"])
        self.assertEqual(row["monthly_carrying_cost"], "-1.250000000000")
        snap.update(dependency_state="KNOWN_UNREFERENCED", ami_ids=[], restore_references=[], policy_required=False)
        self.assertEqual(evaluate_storage(data)["snapshot_reviews"][0]["classification"], "POTENTIALLY_REDUNDANT")
        snap.update(state=None)
        self.assertEqual(evaluate_storage(data)["snapshot_reviews"][0]["classification"], "STATE_UNKNOWN_OR_NOT_COMPLETE")
        snap.update(state="completed")
        snap.update(ami_ids=["ami-synthetic"])
        self.assertEqual(evaluate_storage(data)["snapshot_reviews"][0]["classification"], "AMI_OR_RESTORE_DEPENDENT")
        snap.update(policy_required=True)
        self.assertEqual(evaluate_storage(data)["snapshot_reviews"][0]["classification"], "POLICY_REQUIRED")
        data["resource_kind"] = "EBS_SNAPSHOT"
        data["binding"]["provider_resource_id"] = snap["id"]
        data["current_configuration"] = {"snapshot_id": snap["id"], "state": "completed", "source_ref": ref("snapshot")}
        data.update(current_pricing=None, history=None, observations=[], candidate_configurations=[], capabilities=None)
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "OBSERVATION_ONLY")
        self.assertEqual(result["economics"]["status"], "CARRYING_COST_ONLY")
        self.assertIsNone(result["economics"]["estimated_monthly_saving"])

    def test_shrink_is_only_migration_with_all_steps_and_no_saving(self):
        data = evidence()
        data["candidate_configurations"][0]["size_gib"] = "500"
        result = evaluate_storage(data)
        self.assertEqual(result["recommendation_kind"], "MIGRATION_OPPORTUNITY")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["migration_requirements"], MIGRATION_STEPS)
        self.assertIsNone(result["economics"]["estimated_monthly_saving"])

    def test_cost_unknown_list_price_currency_and_negative_continuing(self):
        data = evidence()
        data["current_pricing"] = None
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIsNone(result["economics"]["current_monthly_cost"])
        data = evidence()
        data["candidate_configurations"][0]["pricing"]["basis"] = "PUBLIC_LIST_PRICE"
        self.assertIn("STORAGE_NATIVE_PRICE_DIMENSIONS_UNSUPPORTED", evaluate_storage(data)["blockers"])
        data = evidence()
        data["candidate_configurations"][0]["pricing"]["currency"] = "EUR"
        self.assertEqual(evaluate_storage(data)["status"], "BLOCKED")
        data = evidence()
        data["continuing_costs"]["components"][-1]["amount"] = "-2"
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "RECOMMENDED")
        self.assertEqual(result["economics"]["component_costs"][-1]["actual_period_amount"], "-2.000000000000")
        self.assertEqual(result["economics"]["estimated_monthly_saving"], "20.000000000000")

    def test_paid_gp3_components_cannot_use_inclusive_zero(self):
        data = evidence(candidate_iops="6000")
        price = data["candidate_configurations"][0]["pricing"]["components"][1]
        price.update(basis="INCLUDED_IN_NATIVE_STORAGE_RATE", rate="0", quantity="0", amount="0")
        self.assertIn("STORAGE_PAID_COMPONENT_PRICE_UNAVAILABLE:iops", evaluate_storage(data)["blockers"])

    def test_no_cheaper_retains_negative_estimate(self):
        data = evidence()
        row = data["candidate_configurations"][0]["pricing"]["components"][0]
        row.update(rate="0.2", amount="200")
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "NO_CHANGE")
        self.assertEqual(result["economics"]["estimated_monthly_saving"], "-100.000000000000")
        self.assertEqual(result["decision_code"], "DO_NOT_PROCEED")

    def test_duplicate_hours_refs_and_nonfinite_fail_closed(self):
        data = evidence()
        data["observations"][1] = copy.deepcopy(data["observations"][0])
        with self.assertRaises(EvidenceError):
            evaluate_storage(data)

    def test_native_binding_and_empty_candidates(self):
        data = evidence()
        data["candidate_configurations"] = []
        result = evaluate_storage(data)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("STORAGE_CANDIDATES_UNAVAILABLE", result["blockers"])
        for field, value in (("account_id", "12"), ("region", "bad"), ("provider_resource_id", "vol-foreign"),
                             ("provider_resource_id", "arn:aws:ec2:us-east-1:111122223333:volume/vol-0123456789abcdef0")):
            with self.subTest(field=field):
                data = evidence()
                data["binding"][field] = value
                with self.assertRaises(EvidenceError):
                    evaluate_storage(data)
        data = evidence()
        data["current_pricing"]["components"][0]["amount"] = "99"
        with self.assertRaises(EvidenceError):
            evaluate_storage(data)
        data = evidence()
        data["history"]["source_refs"].append({**ref("native-metrics"), "sha256": "f" * 64})
        with self.assertRaises(EvidenceError):
            evaluate_storage(data)
        data = evidence()
        data["candidate_configurations"][0]["iops"] = "NaN"
        with self.assertRaises(EvidenceError):
            evaluate_storage(data)


class StorageHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v8/storage-assessment"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_private_auth_actual_dispatch_and_duplicate_rejection(self):
        raw = json.dumps(evidence()).encode()
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "storage-component-token", "FIXTURE_MODE": "false"}):
            with self.assertRaises(HTTPError) as denied:
                urlopen(Request(self.url, raw, {"Content-Type": "application/json"}))
            self.assertEqual(denied.exception.code, 401)
            with urlopen(Request(self.url, raw, {"Content-Type": "application/json", "Authorization": "Bearer storage-component-token"})) as response:
                result = json.load(response)
            self.assertEqual(result["model_version"], MODEL_VERSION)
            self.assertEqual(result["status"], "RECOMMENDED")
            duplicate = raw[:-1] + b',"schema_version":"1"}'
            with self.assertRaises(HTTPError) as rejected:
                urlopen(Request(self.url, duplicate, {"Content-Type": "application/json", "Authorization": "Bearer storage-component-token"}))
            self.assertEqual(rejected.exception.code, 422)


if __name__ == "__main__":
    unittest.main()
