"""Synthetic typed economics COMPONENT checks, never live AWS acceptance."""
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
from autopilot.object_storage import evaluate_object_storage, MODEL_VERSION, CLASSES, TIERS, KINDS
from autopilot.server import Handler


def ref(name):
    return {"kind": "SYNTHETIC_COMPONENT_EVIDENCE", "id": name, "version": "1", "sha256": hashlib.sha256(name.encode()).hexdigest()}


def evidence(days=90):
    end = datetime(2026, 10, 20, tzinfo=timezone.utc)
    def stamp(value):
        return value.isoformat().replace("+00:00", "Z")
    parts = []
    storage = {"STANDARD": "0.023", "STANDARD_IA": "0.0125", "ONEZONE_IA": "0.01", "GLACIER_INSTANT_RETRIEVAL": "0.004",
               "GLACIER_FLEXIBLE_RETRIEVAL": "0.0036", "DEEP_ARCHIVE": "0.00099",
               "IT_FREQUENT": "0.023", "IT_INFREQUENT": "0.0125", "IT_ARCHIVE_INSTANT": "0.004",
               "IT_ARCHIVE": "0.0036", "IT_DEEP_ARCHIVE": "0.00099"}
    for cls, rate in storage.items():
        parts.append({"class": cls, "component": "storage", "unit": "GiB-Mo", "rate": rate, "source_ref": ref("native-price-" + cls)})
    for cls in CLASSES:
        for component, unit, rate in (("request", "Request", "0.0000004"), ("retrieval", "GiB", "0.01"),
                                      ("transition", "Request", "0.00001"), ("monitoring", "Object-Mo", "0.0000025"),
                                      ("restore_request", "Request", "0.00005"), ("restore_storage", "GiB-Mo", "0.023")):
            parts.append({"class": cls, "component": component, "unit": unit, "rate": rate, "source_ref": ref("native-" + cls + "-" + component)})
    return {"schema_version": "1", "model_version": MODEL_VERSION,
            "binding": {"tenant_id": "synthetic-tenant", "resource_id": "synthetic-bucket", "account_id": "111122223333", "region": "eu-west-1",
                        "provider": "AWS", "provider_resource_id": "arn:aws:s3:::synthetic-component-bucket", "workload_id": "synthetic-workload"},
            "as_of": stamp(end + timedelta(hours=1)),
            "configuration": {"owner": "synthetic-owner", "configuration_authority": "TERRAFORM", "versioning": "ENABLED", "lifecycle_state": "KNOWN",
                              "replication_state": "NONE", "object_lock_state": "DISABLED", "source_ref": ref("configuration")},
            "policy": {"criticality": "NON_PRODUCTION", "high_seasonality": False, "remaining_lifetime_days": "365", "rto_seconds": "86400",
                       "retention_known": True, "compliance_clear": True, "recovery_known": True, "allow_onezone": False, "source_ref": ref("policy")},
            "cohorts": [{"id": "synthetic-current-standard", "label": "logs/", "source_class": "STANDARD", "access_tier": None, "state": "CURRENT",
                         "object_count": "1000", "total_bytes": "1073741824000", "size_bands": [{"count": "1000", "total_bytes": "1073741824000", "min_bytes": "1073741824", "max_bytes": "1073741824"}],
                         "age_days_min": "180", "age_days_max": "365", "minimum_duration_remaining_days": "0", "inventory_complete": True,
                         "population_hash": hashlib.sha256(b"synthetic-actual-object-identities").hexdigest(), "source_ref": ref("inventory"),
                         "access": {"state": "ACCESS_PATTERN_OBSERVED", "start": stamp(end - timedelta(days=days)), "end": stamp(end), "complete": True,
                                    "requests": "0", "retrieved_bytes": "0", "eligible_cold_bytes_fraction": "1",
                                    "it_tier_fractions": {"FREQUENT": "0", "INFREQUENT": "0", "ARCHIVE_INSTANT": "1", "ARCHIVE": "0", "DEEP_ARCHIVE": "0"}, "source_ref": ref("access")},
                         "lifecycle": {"state": "NONE", "already_targets": [], "conflicts": False, "archive_access_enabled": False,
                                       "deep_archive_access_enabled": False, "small_object_transition_allowed": False},
                         "retention": {"known": True, "legal_hold": False, "retained": False, "replication_pending": False, "dependencies_known": True},
                         "pricing": {"basis": "AWS_CUR_NET_USAGE", "currency": "GBP", "components": parts, "continuing_monthly_cost": "2", "source_ref": ref("cur")}}],
            "source_refs": [ref("complete-synthetic-native-population")]}


def candidate(result, target):
    return next(value for value in result["candidates"] if value["candidate_storage_class"] == target)


class ObjectStorageTests(unittest.TestCase):
    def test_standard_ia_native_positive_exact_decimal_and_no_mutation(self):
        data = evidence()
        original = copy.deepcopy(data)
        result = evaluate_object_storage(data)
        value = candidate(result, "STANDARD_IA")
        self.assertEqual(value["status"], "RECOMMENDED")
        self.assertEqual(value["economics"]["current_monthly_cost"], "25.000000000000")
        self.assertEqual(value["economics"]["candidate_monthly_cost"], "14.500000000000")
        self.assertEqual(value["economics"]["transition_cost"], "0.010000000000")
        self.assertEqual(value["economics"]["net_horizon_saving"], "125.990000000000")
        self.assertEqual(result["implementation_method"], "DECLARATIVE_REMEDIATION_REVIEW")
        self.assertEqual(result["class_semantics_version"], "aws-s3-general-purpose-2026-10-20")
        self.assertEqual(len(result["class_semantics_sha256"]), 64)
        self.assertEqual(result["declared_policy"]["remaining_lifetime_days"], "365")
        self.assertNotIn("source_ref", result["declared_policy"])
        self.assertEqual(result["proposal"], {"risk_class": "R3", "executable": False, "execution_authorized": False})
        self.assertFalse(result["pre_execution_ready"])
        self.assertIsNone(result["verified_saving"])
        self.assertIsNone(result["economics"]["estimated_monthly_saving"])
        self.assertEqual(data, original)
        self.assertEqual(result, evaluate_object_storage(data))

    def test_frequent_or_recent_access_cannot_become_ia_saving(self):
        for fraction in (None, "0.9", "0"):
            data = evidence()
            data["cohorts"][0]["access"]["eligible_cold_bytes_fraction"] = fraction
            value = candidate(evaluate_object_storage(data), "STANDARD_IA")
            self.assertEqual(value["status"], "BLOCKED")
            self.assertIsNone(value["economics"]["estimated_monthly_saving"])
        data = evidence()
        data["cohorts"][0]["age_days_min"] = "29"
        self.assertIn("S3_LIFECYCLE_IA_OBJECT_AGE_BELOW_30_DAYS", candidate(evaluate_object_storage(data), "STANDARD_IA")["blockers"])

    def test_minimum_duration_reverses_storage_price_saving(self):
        data = evidence()
        data["policy"]["remaining_lifetime_days"] = "1"
        value = candidate(evaluate_object_storage(data), "STANDARD_IA")
        self.assertEqual(value["status"], "NO_CHANGE")
        self.assertGreater(Decimal(value["economics"]["candidate_minimum_duration_penalty"]), 0)
        self.assertLess(Decimal(value["economics"]["net_horizon_saving"]), 0)
        self.assertIsNone(value["economics"]["estimated_annual_saving"])

    def test_retrieval_reverses_nominal_saving(self):
        data = evidence()
        data["cohorts"][0]["access"]["retrieved_bytes"] = "1073741824000000"
        data["cohorts"][0]["access"]["requests"] = "1000000"
        value = candidate(evaluate_object_storage(data), "STANDARD_IA")
        self.assertEqual(value["status"], "NO_CHANGE")
        self.assertLess(Decimal(value["economics"]["net_horizon_saving"]), 0)

    def test_small_object_minimum_reverses_nominal_gb_price(self):
        data = evidence()
        c = data["cohorts"][0]
        c.update(object_count="1000000", total_bytes="1000000", size_bands=[{"count": "1000000", "total_bytes": "1000000", "min_bytes": "1", "max_bytes": "1"}])
        c["lifecycle"]["small_object_transition_allowed"] = True
        result = evaluate_object_storage(data)
        value = candidate(result, "STANDARD_IA")
        self.assertEqual(value["status"], "NO_CHANGE")
        self.assertLess(Decimal(value["economics"]["net_horizon_saving"]), 0)
        self.assertTrue(any(value["recommendation_kind"] == KINDS[6] for value in result["candidates"]))

    def test_default_small_object_filter_and_ambiguous_size_band_block(self):
        data = evidence()
        c = data["cohorts"][0]
        c.update(object_count="2", total_bytes="262144", size_bands=[{"count": "2", "total_bytes": "262144", "min_bytes": "1", "max_bytes": "262143"}])
        result = evaluate_object_storage(data)
        self.assertIn("S3_SIZE_BAND_CROSSES_BILLABLE_MINIMUM", candidate(result, "STANDARD_IA")["blockers"])

    def test_it_positive_includes_monitoring_and_new_tier_clock(self):
        value = candidate(evaluate_object_storage(evidence()), "INTELLIGENT_TIERING")
        self.assertEqual(value["status"], "RECOMMENDED")
        part = next(p for p in value["economics"]["component_costs"] if p["component"] == "monitoring")
        self.assertEqual(part["candidate_monthly_cost"], "0.002500000000")
        self.assertGreater(Decimal(value["economics"]["tier_initialization_cost"]), 0)
        data = evidence()
        data["policy"]["remaining_lifetime_days"] = "15"
        value = candidate(evaluate_object_storage(data), "INTELLIGENT_TIERING")
        self.assertEqual(value["status"], "NO_CHANGE")

    def test_it_monitoring_can_reverse_saving(self):
        data = evidence()
        for part in data["cohorts"][0]["pricing"]["components"]:
            if part["class"] == "INTELLIGENT_TIERING" and part["component"] == "monitoring":
                part["rate"] = "100"
        self.assertEqual(candidate(evaluate_object_storage(data), "INTELLIGENT_TIERING")["status"], "NO_CHANGE")

    def test_it_small_objects_have_no_monitoring_and_never_auto_tier(self):
        data = evidence()
        c = data["cohorts"][0]
        c.update(object_count="1000", total_bytes="1000", size_bands=[{"count": "1000", "total_bytes": "1000", "min_bytes": "1", "max_bytes": "1"}])
        c["lifecycle"]["small_object_transition_allowed"] = True
        value = candidate(evaluate_object_storage(data), "INTELLIGENT_TIERING")
        monitoring = next(p for p in value["economics"]["component_costs"] if p["component"] == "monitoring")
        self.assertEqual(monitoring["candidate_monthly_cost"], "0.000000000000")
        self.assertEqual(value["status"], "NO_CHANGE")

    def test_it_cannot_create_ninety_days_tier_history(self):
        value = candidate(evaluate_object_storage(evidence(days=14)), "INTELLIGENT_TIERING")
        self.assertEqual(value["status"], "BLOCKED")
        self.assertIn("S3_TIER_RESIDENCE_HISTORY_INSUFFICIENT", value["blockers"])

    def test_archive_positive_with_metadata_and_rto_blocks(self):
        result = evaluate_object_storage(evidence())
        for cls in ("GLACIER_INSTANT_RETRIEVAL", "GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE"):
            self.assertEqual(candidate(result, cls)["status"], "RECOMMENDED")
        self.assertEqual(candidate(result, "DEEP_ARCHIVE")["recovery_requirement"]["restore_latency_seconds"], "43200.000000000000")
        self.assertEqual(candidate(result, "DEEP_ARCHIVE")["recovery_requirement"]["rto_seconds"], "86400")
        data = evidence()
        data["policy"]["rto_seconds"] = "60"
        result = evaluate_object_storage(data)
        self.assertEqual(candidate(result, "GLACIER_INSTANT_RETRIEVAL")["status"], "RECOMMENDED")
        for cls in ("GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE"):
            self.assertIn("S3_RTO_BLOCKS_ARCHIVE_CLASS", candidate(result, cls)["blockers"])
            self.assertIsNone(candidate(result, cls)["economics"]["estimated_monthly_saving"])

    def test_source_minimum_duration_remaining_penalty_is_preserved(self):
        data = evidence()
        c = data["cohorts"][0]
        c["source_class"] = "STANDARD_IA"
        c["minimum_duration_remaining_days"] = "30"
        result = evaluate_object_storage(data)
        value = candidate(result, "DEEP_ARCHIVE")
        self.assertGreater(Decimal(value["economics"]["current_minimum_duration_penalty"]), 0)
        c["minimum_duration_remaining_days"] = None
        self.assertIn("S3_CURRENT_MINIMUM_DURATION_REMAINING_UNKNOWN", candidate(evaluate_object_storage(data), "DEEP_ARCHIVE")["blockers"])

    def test_unchanged_baseline_also_pays_its_native_minimum_obligation(self):
        data = evidence()
        c = data["cohorts"][0]
        c["source_class"] = "STANDARD_IA"
        c["minimum_duration_remaining_days"] = "30"
        data["policy"]["remaining_lifetime_days"] = "1"
        value = candidate(evaluate_object_storage(data), "DEEP_ARCHIVE")
        self.assertEqual(value["economics"]["baseline_minimum_duration_penalty"], "11.917808219178")
        self.assertEqual(value["economics"]["current_horizon_cost"], "12.394520547945")
        self.assertEqual(value["economics"]["current_minimum_duration_penalty"], "12.328767123288")
        self.assertEqual(value["status"], "NO_CHANGE")
        self.assertLess(Decimal(value["economics"]["net_horizon_saving"]), 0)

    def test_unknown_access_age_and_missing_observations_never_manufacture_zero(self):
        for mutation in (lambda c: c["access"].update(state="AGE_OBSERVED"),
                         lambda c: c["access"].update(state="ACCESS_UNKNOWN"),
                         lambda c: c["access"].update(requests=None),
                         lambda c: c["access"].update(retrieved_bytes=None),
                         lambda c: c["access"].update(complete=False)):
            data = evidence()
            mutation(data["cohorts"][0])
            value = candidate(evaluate_object_storage(data), "STANDARD_IA")
            self.assertEqual(value["status"], "BLOCKED")
            self.assertIsNone(value["economics"]["estimated_monthly_saving"])

    def test_missing_native_price_public_reference_and_continuing_costs(self):
        for mutate in (lambda p: p.update(basis="UNAVAILABLE"), lambda p: p.update(basis="REFERENCE_ONLY"),
                       lambda p: p.update(continuing_monthly_cost=None),
                       lambda p: p.update(components=[v for v in p["components"] if v["class"] != "STANDARD_IA"])):
            data = evidence()
            mutate(data["cohorts"][0]["pricing"])
            value = candidate(evaluate_object_storage(data), "STANDARD_IA")
            self.assertEqual(value["status"], "BLOCKED")
            self.assertIsNone(value["economics"]["estimated_monthly_saving"])
        data = evidence()
        data["cohorts"][0]["pricing"]["basis"] = "REFERENCE_ONLY"
        self.assertIsNotNone(candidate(evaluate_object_storage(data), "STANDARD_IA")["economics"]["reference_scenario"])

    def test_signed_native_credit_continues_without_becoming_saving(self):
        data = evidence()
        before = candidate(evaluate_object_storage(data), "STANDARD_IA")
        data["cohorts"][0]["pricing"]["continuing_monthly_cost"] = "-100"
        after = candidate(evaluate_object_storage(data), "STANDARD_IA")
        self.assertEqual(after["status"], "RECOMMENDED")
        self.assertEqual(after["economics"]["net_horizon_saving"], before["economics"]["net_horizon_saving"])
        self.assertLess(Decimal(after["economics"]["current_monthly_cost"]), 0)

    def test_current_lifecycle_suppresses_duplicate(self):
        data = evidence()
        data["cohorts"][0]["lifecycle"]["already_targets"] = ["STANDARD_IA"]
        value = candidate(evaluate_object_storage(data), "STANDARD_IA")
        self.assertEqual(value["status"], "NO_CHANGE")
        self.assertEqual(value["reason_code"], "S3_ALREADY_IMPLEMENTED")
        self.assertIsNone(value["economics"]["estimated_monthly_saving"])
        self.assertIsNone(value["economics"]["net_horizon_saving"])
        alternate = candidate(evaluate_object_storage(data), "DEEP_ARCHIVE")
        self.assertEqual(alternate["status"], "BLOCKED")
        self.assertIn("S3_EXISTING_LIFECYCLE_COUNTERFACTUAL_REQUIRED", alternate["blockers"])

    def test_retention_and_replication_do_not_become_deletion_waste(self):
        data = evidence()
        c = data["cohorts"][0]
        c["state"] = "NONCURRENT"
        c["retention"].update(legal_hold=True, retained=True)
        data["configuration"]["replication_state"] = "KNOWN"
        result = evaluate_object_storage(data)
        value = result["candidates"][0]
        self.assertEqual(value["recommendation_kind"], KINDS[4])
        self.assertEqual(value["status"], "OBSERVATION_ONLY")
        self.assertIn("S3_DELETION_PROHIBITED_BY_RETENTION", value["blockers"])
        self.assertIsNone(value["economics"]["estimated_monthly_saving"])
        self.assertNotIn("duplicate", json.dumps(result).lower())

    def test_multipart_review_burden_only_and_existing_lifecycle(self):
        data = evidence()
        c = data["cohorts"][0]
        c["state"] = "MULTIPART"
        value = evaluate_object_storage(data)["candidates"][0]
        self.assertEqual(value["recommendation_kind"], KINDS[5])
        self.assertEqual(value["economics"]["status"], "BURDEN_ONLY")
        self.assertIsNotNone(value["economics"]["current_monthly_cost"])
        self.assertIsNone(value["economics"]["estimated_monthly_saving"])
        c["lifecycle"]["already_targets"] = ["MULTIPART_POLICY_REVIEW"]
        self.assertEqual(evaluate_object_storage(data)["candidates"][0]["status"], "NO_CHANGE")

    def test_existing_it_policy_is_reviewed_without_micromanagement(self):
        data = evidence()
        data["cohorts"][0]["source_class"] = "INTELLIGENT_TIERING"
        value = evaluate_object_storage(data)["candidates"][0]
        self.assertEqual(value["recommendation_kind"], KINDS[3])
        self.assertEqual(value["status"], "OBSERVATION_ONLY")
        self.assertEqual(value["economics"]["status"], "BURDEN_ONLY")
        self.assertIsNotNone(value["economics"]["current_monthly_cost"])
        self.assertEqual(value["policy_observations"]["monitored_object_count"], "1000.000000000000")

    def test_it_archive_exact_population_metadata_and_mixed_unknown_counts(self):
        data = evidence(days=180)
        c = data["cohorts"][0]
        c["source_class"] = "INTELLIGENT_TIERING"
        c["access_tier"] = "DEEP_ARCHIVE"
        c["access"]["it_tier_fractions"] = {tier: "1" if tier == "DEEP_ARCHIVE" else "0" for tier in TIERS}
        result = evaluate_object_storage(data)
        self.assertEqual(result["candidates"][0]["economics"]["status"], "BURDEN_ONLY")
        c["access"]["it_tier_fractions"].update(DEEP_ARCHIVE="0.5", ARCHIVE="0.5")
        result = evaluate_object_storage(data)
        self.assertIn("S3_IT_ARCHIVE_OBJECT_COUNT_UNAVAILABLE", result["candidates"][0]["blockers"])
        self.assertIsNone(result["candidates"][0]["economics"]["current_monthly_cost"])

    def test_onezone_requires_explicit_permission(self):
        data = evidence()
        self.assertFalse(any(v["candidate_storage_class"] == "ONEZONE_IA" for v in evaluate_object_storage(data)["candidates"]))
        data["policy"]["allow_onezone"] = True
        self.assertEqual(candidate(evaluate_object_storage(data), "ONEZONE_IA")["status"], "RECOMMENDED")

    def test_population_invalid_integer_count_mixed_band_and_duplicate_ids_reject(self):
        changes = [lambda d: d["cohorts"][0].update(object_count="1000.5"),
                   lambda d: d["cohorts"][0].update(total_bytes="1"),
                   lambda d: d["cohorts"][0]["size_bands"][0].update(max_bytes="0"),
                   lambda d: d["cohorts"].append(copy.deepcopy(d["cohorts"][0])),
                   lambda d: d["binding"].update(account_id="wrong"),
                   lambda d: d["cohorts"][0]["pricing"]["components"].append(copy.deepcopy(d["cohorts"][0]["pricing"]["components"][0]))]
        for change in changes:
            data = evidence()
            change(data)
            with self.assertRaises(EvidenceError):
                evaluate_object_storage(data)

    def test_missing_history_seasonality_and_unknown_authority_block(self):
        data = evidence(days=14)
        data["policy"]["high_seasonality"] = True
        self.assertIn("S3_ACCESS_HISTORY_INSUFFICIENT", candidate(evaluate_object_storage(data), "STANDARD_IA")["blockers"])
        for key, value in (("configuration_authority", "UNKNOWN"), ("replication_state", "UNKNOWN"), ("object_lock_state", "UNKNOWN"), ("owner", None)):
            data = evidence()
            data["configuration"][key] = value
            self.assertEqual(candidate(evaluate_object_storage(data), "STANDARD_IA")["status"], "BLOCKED")

    def test_currencies_and_alternatives_are_never_summed(self):
        data = evidence()
        other = copy.deepcopy(data["cohorts"][0])
        other["id"] = "synthetic-other"
        other["population_hash"] = "b" * 64
        other["pricing"]["currency"] = "EUR"
        data["cohorts"].append(other)
        result = evaluate_object_storage(data)
        self.assertEqual([x["currency"] for x in result["economics"]["groups"]], ["EUR", "GBP"])
        self.assertIsNone(result["economics"]["estimated_monthly_saving"])
        self.assertTrue(all(value["verified_saving"] is None for value in result["candidates"]))

    def test_conflicting_receipt_and_float_rate_are_rejected(self):
        data = evidence()
        r = copy.deepcopy(data["source_refs"][0])
        r["sha256"] = "a" * 64
        data["source_refs"].append(r)
        with self.assertRaises(EvidenceError):
            evaluate_object_storage(data)
        data = evidence()
        data["cohorts"][0]["pricing"]["components"][0]["rate"] = 0.023
        with self.assertRaises(EvidenceError):
            evaluate_object_storage(data)

    def test_authenticated_private_http_route(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "synthetic-private-economics-token", "FIXTURE_MODE": "false"}):
            thread.start()
            url = "http://127.0.0.1:%d/v9/object-storage-assessment" % server.server_address[1]
            raw = json.dumps(evidence()).encode()
            try:
                with self.assertRaises(HTTPError) as failure:
                    urlopen(Request(url, data=raw, headers={"Content-Type": "application/json"}), timeout=5)
                self.assertEqual(failure.exception.code, 401)
                request = Request(url, data=raw, headers={"Authorization": "Bearer synthetic-private-economics-token", "Content-Type": "application/json"})
                with urlopen(request, timeout=5) as response:
                    self.assertEqual(json.load(response)["model_kind"], "OBJECT_STORAGE_ASSESSMENT_V1")
                bad = raw.replace(b'"schema_version": "1"', b'"schema_version": "1", "schema_version": "1"', 1)
                with self.assertRaises(HTTPError) as failure:
                    urlopen(Request(url, data=bad, headers={"Authorization": "Bearer synthetic-private-economics-token"}), timeout=5)
                self.assertEqual(failure.exception.code, 422)
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()


if __name__ == "__main__":
    unittest.main()
