"""Typed synthetic model components; these do not claim native AWS acceptance."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from autopilot.model import EvidenceError
from autopilot.network import evaluate_network, MODEL_VERSION, MODEL_KIND
from autopilot.server import Handler


def ref(name):
    return {"kind": "SYNTHETIC_NETWORK_COMPONENT", "id": name, "version": "1", "sha256": hashlib.sha256(name.encode()).hexdigest()}


def evidence(family="A", days=30):
    end = datetime(2026, 10, 20, tzinfo=timezone.utc)
    stamp = lambda v: v.isoformat().replace("+00:00", "Z")
    return {"schema_version": "1", "model_version": MODEL_VERSION,
            "binding": {"tenant_id": "synthetic-tenant", "account_id": "111122223333", "region": "eu-west-1", "resource_id": "synthetic-nat", "provider": "AWS", "provider_resource_id": "nat-0123456789abcdef0", "workload_id": "synthetic-workload"},
            "as_of": stamp(end + timedelta(hours=1)),
            "topology": {"revision": "1", "hash": "a" * 64, "mode": "ZONAL", "vpc_id": "vpc-component", "source_az": "eu-west-1a", "nat_az": "eu-west-1a", "route_table_ids": ["rtb-component"], "route_current": True, "route_certain": True, "source_ref": ref("topology")},
            "policy": {"owner": "network-team", "configuration_authority": "TERRAFORM", "criticality": "NON_PRODUCTION", "seasonal": False, "security_reviewed": True, "network_policy_known": True, "dependencies_known": True, "recovery_known": True, "resilience_known": True, "allow_topology_change": True, "required_azs": 2, "ha_required": True, "on_premises_required": False, "cross_vpc_required": False, "dns_change_approved": True, "public_access_required": False, "traffic_purpose": "APPLICATION", "endpoint_policy_reviewed": True, "source_ref": ref("policy")},
            "observation": {"start": stamp(end - timedelta(days=days)), "end": stamp(end), "telemetry_complete": True, "flow_complete": True, "processed_bytes": "2147483648000", "byte_basis": "BYTES_IN_FROM_SOURCE_PLUS_BYTES_IN_FROM_DESTINATION", "maximum_active_connections": "20", "source_ref": ref("observation")},
            "billing": {"currency": "GBP", "basis": "AWS_CUR_NET_USAGE", "complete": True, "scope_complete": True, "marginal_pricing_known": True, "start": stamp(end - timedelta(days=days)), "end": stamp(end), "source_ref": ref("billing"), "components": [
                {"id": "nat-hours", "category": "NAT_HOURLY", "amount": "32.4", "quantity": str(days * 24), "unit": "Hour", "source_ref": ref("hours")},
                {"id": "nat-bytes", "category": "NAT_PROCESSING", "amount": "90", "quantity": "2000", "unit": "GB", "bytes_per_unit": "1073741824", "source_ref": ref("bytes")}]},
            "rates": [], "cohorts": [{"id": "s3-exclusive", "family": family, "bytes": "1073741824000", "traffic_complete": True, "attribution_complete": True, "destination_service": "s3", "destination_region": "eu-west-1", "traffic_source": "FLOW_LOGS", "current_path": ["subnet:component", "route-table:rtb-component", "nat:nat-component", "service:s3"], "target_path": ["subnet:component", "route-table:rtb-component", "gateway-endpoint:s3"],
                "billing_allocations": [{"component_id": "nat-hours", "fraction": "0.5"}, {"component_id": "nat-bytes", "fraction": "0.5"}],
                "technical": {"endpoint_available": True, "endpoint_scope_compatible": True, "current_endpoint": False, "dns_compatible": True, "on_premises_compatible": True, "cross_vpc_compatible": True, "security_compatible": True, "resilience_preserved": True, "rto_compatible": True, "topology_footprint_known": True, "target_az_count": 2, "nat_hourly_avoidable": False, "idle_threshold_bytes": "0", "public_ipv4_kind": None, "association_state": None, "purpose": "APPLICATION"}, "candidate_costs": [], "source_ref": ref("cohort")}]}


def interface(data, hourly="0.01", processing="0.01"):
    cohort = data["cohorts"][0]
    cohort["family"] = "B"
    cohort["destination_service"] = "secretsmanager"
    cohort["target_path"] = ["subnet:component", "interface-endpoint:secretsmanager"]
    for component, rate, unit in (("ENDPOINT_HOURLY", hourly, "Hour"), ("ENDPOINT_PROCESSING", processing, "GB")):
        data["rates"].append({"id": component, "component": component, "rate": rate, "unit": unit, "bytes_per_unit": "1073741824", "currency": "GBP", "payer_account_id": "111122223333", "usage_account_id": "111122223333", "region": "eu-west-1", "service": "secretsmanager", "pricing_bracket": "native-contracted-bracket", "pricing_bracket_resolved": True, "marginal_pricing_known": True, "source_ref": ref(component)})
        cohort["candidate_costs"].append({"component": component, "rate_id": component})
    return data


def first(data):
    return evaluate_network(data)["candidates"][0]


class NetworkEconomicsTests(unittest.TestCase):
    def test_s3_gateway_positive_native_net_and_no_hourly_removal(self):
        data = evidence()
        before = copy.deepcopy(data)
        result = evaluate_network(data)
        item = result["candidates"][0]
        self.assertEqual(item["status"], "RECOMMENDED")
        self.assertEqual(item["economics"]["current_window_cost"], "61.200000000000")
        self.assertEqual(item["economics"]["candidate_window_cost"], "16.200000000000")
        self.assertEqual(item["economics"]["estimated_window_saving"], "45.000000000000")
        self.assertEqual(item["economics"]["estimated_monthly_saving"], "45.625000000000")
        self.assertIsNone(item["economics"]["estimated_annual_saving"])
        self.assertEqual(item["implementation_method"], "DECLARATIVE_REMEDIATION_REVIEW")
        self.assertEqual(result["model_kind"], MODEL_KIND)
        self.assertEqual(result["proposal"], {"risk_class": "R3", "executable": False, "execution_authorized": False})
        for item in (result, item):
            self.assertTrue(item["read_only"])
            self.assertFalse(item["pre_execution_ready"])
            self.assertFalse(item["execution_authorized"])
            self.assertIsNone(item["verified_saving"])
        self.assertEqual(data, before)
        self.assertEqual(result, evaluate_network(data))

    def test_dynamodb_and_existing_endpoint_no_duplicate(self):
        data = evidence()
        data["cohorts"][0]["destination_service"] = "dynamodb"
        self.assertEqual(first(data)["status"], "RECOMMENDED")
        data["cohorts"][0]["technical"]["current_endpoint"] = True
        item = first(data)
        self.assertEqual(item["decision"], "ALREADY_IMPLEMENTED")
        self.assertEqual(item["status"], "NO_CHANGE")
        self.assertIsNone(item["economics"]["estimated_window_saving"])

    def test_interface_positive_and_negative_multiaz_economics(self):
        item = first(interface(evidence()))
        self.assertEqual(item["status"], "RECOMMENDED")
        self.assertEqual(item["economics"]["candidate_window_cost"], "40.600000000000")
        self.assertEqual(item["economics"]["estimated_window_saving"], "20.600000000000")
        item = first(interface(evidence(), hourly="0.05"))
        self.assertEqual(item["decision"], "DO_NOT_CREATE_ENDPOINT")
        self.assertEqual(item["economics"]["estimated_window_saving"], "-37.000000000000")
        self.assertEqual(item["security_impact"]["classification"], "REVIEW_REQUIRED")
        self.assertIn("DNS_BEHAVIOUR_CHANGES", item["security_impact"]["effects"])

    def test_interface_unknown_rate_or_ha_footprint_is_not_a_zero_price(self):
        data = evidence("B")
        self.assertIn("NETWORK_ENDPOINT_NATIVE_CUSTOMER_RATES_MISSING", first(data)["blockers"])
        data = interface(evidence())
        data["cohorts"][0]["technical"]["target_az_count"] = 1
        item = first(data)
        self.assertEqual(item["status"], "BLOCKED")
        self.assertIn("NETWORK_ENDPOINT_HA_FOOTPRINT_INSUFFICIENT", item["blockers"])
        self.assertIsNone(item["economics"]["estimated_window_saving"])

    def test_candidate_quantities_cannot_omit_azs_or_processed_bytes(self):
        for index, quantity in ((0, "720"), (1, "0")):
            data = interface(evidence())
            data["cohorts"][0]["candidate_costs"][index]["quantity"] = quantity
            with self.assertRaises(EvidenceError):
                evaluate_network(data)

    def test_no_high_confidence_on_partial_nat_attribution(self):
        item = first(evidence())
        self.assertEqual(item["confidence"]["status"], "LIMITED")
        self.assertIn("NETWORK_POPULATION_ATTRIBUTION_PARTIAL", item["confidence"]["reasons"])
        data = evidence()
        data["cohorts"][0]["bytes"] = data["observation"]["processed_bytes"]
        for part in data["cohorts"][0]["billing_allocations"]:
            part["fraction"] = "1"
        self.assertEqual(first(data)["confidence"]["status"], "HIGH")

    def test_missing_flow_logs_cannot_authorize_destination_saving(self):
        data = evidence()
        data["observation"]["flow_complete"] = False
        data["cohorts"][0]["traffic_source"] = "UNKNOWN"
        item = first(data)
        self.assertIn("NETWORK_FLOW_ATTRIBUTION_INCOMPLETE", item["blockers"])
        self.assertIsNone(item["economics"]["estimated_monthly_saving"])
        self.assertEqual(item["economics"]["observed_allocated_cost"], "61.200000000000")

    def test_security_ownership_iac_rto_and_resilience_refusals(self):
        for parent, field in (("policy", "owner"), ("policy", "configuration_authority"), ("policy", "security_reviewed"), ("policy", "network_policy_known"), ("policy", "endpoint_policy_reviewed")):
            data = evidence()
            data[parent][field] = None
            self.assertEqual(first(data)["status"], "BLOCKED")

    def test_gateway_is_not_transitive_and_interface_dns_requires_review(self):
        for field in ("on_premises_required", "cross_vpc_required"):
            data = evidence()
            data["policy"][field] = True
            self.assertIn("NETWORK_GATEWAY_LOCAL_VPC_ACCESS_SCOPE_REQUIRED", first(data)["blockers"])
        data = interface(evidence())
        data["policy"]["dns_change_approved"] = False
        self.assertIn("NETWORK_ENDPOINT_DNS_CHANGE_APPROVAL_REQUIRED", first(data)["blockers"])
        for field in ("rto_compatible", "resilience_preserved", "security_compatible", "on_premises_compatible", "cross_vpc_compatible", "dns_compatible"):
            data = evidence()
            data["cohorts"][0]["technical"][field] = False
            self.assertEqual(first(data)["status"], "BLOCKED")

    def test_wrong_region_service_or_changed_topology_fails_closed(self):
        for field, value in (("destination_region", "us-east-1"), ("destination_service", "ec2")):
            data = evidence()
            data["cohorts"][0][field] = value
            self.assertIn("NETWORK_GATEWAY_SERVICE_OR_REGION_UNSUPPORTED", first(data)["blockers"])
        data = evidence()
        data["topology"]["route_current"] = False
        self.assertIn("NETWORK_TOPOLOGY_STALE", first(data)["blockers"])
        self.assertIsNone(first(data)["economics"]["estimated_monthly_saving"])

    def test_native_rate_scope_currency_and_technical_mismatch_rejected(self):
        for field, value in (("usage_account_id", "999900001111"), ("currency", "USD"), ("region", "us-east-1"), ("service", "ec2")):
            data = interface(evidence())
            data["rates"][0][field] = value
            with self.assertRaises(EvidenceError):
                evaluate_network(data)

    def test_public_price_or_missing_native_billing_never_substituted(self):
        for field, value in (("basis", "PUBLIC_LIST_REFERENCE"), ("complete", False), ("scope_complete", False), ("marginal_pricing_known", None)):
            data = evidence()
            data["billing"][field] = value
            item = first(data)
            self.assertEqual(item["status"], "BLOCKED")
            self.assertIsNone(item["economics"]["estimated_window_saving"])
        data = evidence()
        data["billing"]["components"] = []
        data["cohorts"][0]["billing_allocations"] = []
        result = evaluate_network(data)
        self.assertIsNone(result["denominators"]["native_processed_bytes"])
        self.assertIsNone(result["candidates"][0]["economics"]["observed_allocated_cost"])

    def test_counter_pair_and_exact_native_quantity_do_not_double_count(self):
        data = evidence()
        data["observation"]["byte_basis"] = "SUM_ALL_FOUR_BYTE_COUNTERS"
        self.assertIn("NETWORK_PROCESSED_BYTE_DENOMINATOR_UNKNOWN", first(data)["blockers"])
        data = evidence()
        data["billing"]["components"][1]["quantity"] = "4000"
        self.assertIn("NETWORK_BILLED_TELEMETRY_BYTE_QUANTITY_MISMATCH", first(data)["blockers"])

    def test_complete_zero_is_distinct_from_missing_traffic(self):
        data = evidence("D")
        data["observation"]["processed_bytes"] = "0"
        data["observation"]["maximum_active_connections"] = "0"
        data["billing"]["components"][1]["quantity"] = "0"
        data["billing"]["components"][1]["amount"] = "0"
        data["cohorts"][0]["bytes"] = "0"
        data["cohorts"][0]["billing_allocations"][1]["fraction"] = "0"
        item = first(data)
        self.assertEqual(item["classification"], "APPARENTLY_IDLE")
        self.assertEqual(item["decision"], "REVIEW_IDLE_NAT_DEPENDENCIES")
        self.assertIsNone(item["economics"]["estimated_window_saving"])
        data["observation"]["telemetry_complete"] = False
        data["observation"]["processed_bytes"] = None
        self.assertEqual(first(data)["classification"], "UNKNOWN")
        data["observation"]["telemetry_complete"] = True
        data["observation"]["processed_bytes"] = "0"
        data["topology"]["mode"] = "REGIONAL"
        data["topology"]["nat_az"] = None
        self.assertEqual(first(data)["classification"], "UNKNOWN")
        self.assertIn("NETWORK_REGIONAL_NAT_HISTORICAL_AZ_FOOTPRINT_UNKNOWN", first(data)["blockers"])

    def test_unassociated_and_associated_ipv4_are_never_automatically_unused(self):
        data = evidence("E")
        data["topology"]["vpc_id"] = None
        tech = data["cohorts"][0]["technical"]
        tech["public_ipv4_kind"] = "ELASTIC_IP"
        tech["association_state"] = "UNASSOCIATED"
        self.assertEqual(first(data)["decision"], "REVIEW_UNASSOCIATED_EIP")
        tech["association_state"] = "ASSOCIATED"
        item = first(data)
        self.assertEqual(item["decision"], "REVIEW_PUBLIC_IPV4_ACCESS_ARCHITECTURE")
        self.assertIsNone(item["economics"]["estimated_window_saving"])
        tech["public_ipv4_kind"] = "BYOIP"
        self.assertEqual(first(data)["status"], "NO_CHANGE")

    def test_cross_az_region_egress_and_regional_nat_are_architectural_reviews(self):
        for family in ("C", "F", "G", "H"):
            data = evidence(family)
            data["topology"]["source_az"] = "eu-west-1b"
            item = first(data)
            self.assertEqual(item["status"], "OBSERVATION_ONLY")
            self.assertIsNone(item["economics"]["estimated_window_saving"])
            self.assertTrue(item["security_impact"]["effects"])
        data = evidence("G")
        data["cohorts"][0]["technical"]["purpose"] = "DR"
        self.assertIn("NETWORK_CROSS_REGION_PURPOSE_MUST_BE_PRESERVED", first(data)["blockers"])
        data = evidence("F")
        data["cohorts"][0]["technical"]["purpose"] = "HA"
        self.assertIn("NETWORK_CROSS_AZ_RESILIENCE_MUST_BE_PRESERVED", first(data)["blockers"])
        data = evidence("C")
        data["topology"]["mode"] = "REGIONAL"
        data["topology"]["nat_az"] = None
        data["cohorts"][0]["technical"]["topology_footprint_known"] = None
        data["policy"]["allow_topology_change"] = False
        item = first(data)
        self.assertIn("NETWORK_REGIONAL_NAT_AZ_FOOTPRINT_UNKNOWN", item["blockers"])
        self.assertIn("NETWORK_TOPOLOGY_CHANGE_POLICY_BLOCKED", item["blockers"])

    def test_history_14_30_90_days_and_stale_observation(self):
        data = evidence(days=13)
        self.assertIn("NETWORK_INSUFFICIENT_HISTORY", first(data)["blockers"])
        data = evidence(days=14)
        self.assertEqual(first(data)["status"], "RECOMMENDED")
        data["policy"]["criticality"] = "PRODUCTION"
        self.assertIn("NETWORK_INSUFFICIENT_HISTORY", first(data)["blockers"])
        data = evidence(days=89)
        data["policy"]["seasonal"] = True
        self.assertIn("NETWORK_INSUFFICIENT_HISTORY", first(data)["blockers"])
        data = evidence(days=90)
        data["policy"]["seasonal"] = True
        self.assertEqual(first(data)["status"], "RECOMMENDED")
        data["as_of"] = "2026-10-23T00:00:00Z"
        self.assertIn("NETWORK_OBSERVATION_STALE", first(data)["blockers"])

    def test_credits_negative_results_and_billing_correction_preserved(self):
        data = evidence()
        data["billing"]["components"][1]["amount"] = "-90"
        item = first(data)
        self.assertEqual(item["decision"], "NO_ECONOMIC_BENEFIT")
        self.assertEqual(item["economics"]["estimated_window_saving"], "-45.000000000000")
        old = evaluate_network(evidence())["assessment_hash"]
        self.assertNotEqual(old, evaluate_network(data)["assessment_hash"])
        data = evidence()
        data["billing"]["components"].append({"id": "continuing", "category": "CONTINUING", "amount": "100", "quantity": None, "unit": "Unknown", "source_ref": ref("continuing")})
        data["cohorts"][0]["billing_allocations"].append({"component_id": "continuing", "fraction": "1"})
        self.assertEqual(first(data)["economics"]["estimated_window_saving"], "45.000000000000")

    def test_exclusive_cohorts_and_native_records_cannot_double_count(self):
        for mutation in ("missing_record", "fraction", "overlap"):
            data = evidence()
            if mutation == "missing_record":
                data["cohorts"][0]["billing_allocations"][0]["component_id"] = "absent"
            elif mutation == "fraction":
                data["cohorts"][0]["billing_allocations"][1]["fraction"] = "0.6"
            else:
                other = copy.deepcopy(data["cohorts"][0])
                other["id"] = "overlap"
                data["cohorts"].extend([other, dict(other, id="overlap2")])
            with self.assertRaises(EvidenceError):
                evaluate_network(data)

    def test_nonterminating_native_byte_ratios_conserve_exact_allocations(self):
        data = evidence()
        data["observation"]["processed_bytes"] = "3"
        data["billing"]["components"][1].update({"quantity": "3", "unit": "Byte", "amount": "1"})
        for key in ("bytes_per_unit",):
            data["billing"]["components"][1].pop(key, None)
        original = data["cohorts"][0]
        data["cohorts"] = []
        for index in range(3):
            row = copy.deepcopy(original)
            row["id"] = "third-" + str(index)
            row["bytes"] = "1"
            row["source_ref"] = ref(row["id"])
            row["billing_allocations"] = [{"component_id": "nat-hours", "numerator": "1", "denominator": "3"},
                                          {"component_id": "nat-bytes", "numerator": "1", "denominator": "3"}]
            data["cohorts"].append(row)
        result = evaluate_network(data)
        self.assertEqual(result["denominators"]["attributed_cohort_bytes"], "3.000000000000")
        self.assertEqual(len(result["candidates"]), 3)
        self.assertTrue(all(c["economics"]["estimated_window_saving"] == "0.333333333333" for c in result["candidates"]))
        self.assertIsNone(result["economics"]["estimated_monthly_saving"])
        for mutation in ("zero", "overlap", "ambiguous", "wrong-byte-ratio"):
            bad = copy.deepcopy(data)
            allocation = bad["cohorts"][0]["billing_allocations"][1]
            if mutation == "zero":
                allocation["denominator"] = "0"
            elif mutation == "ambiguous":
                allocation["fraction"] = "0.333333333333"
            elif mutation == "wrong-byte-ratio":
                allocation["numerator"] = "2"
            else:
                fourth = copy.deepcopy(bad["cohorts"][0])
                fourth["id"] = "fourth"
                bad["cohorts"].append(fourth)
            with self.assertRaises(EvidenceError):
                evaluate_network(bad)

    def test_scoped_receipt_confusion_decimal_floats_and_unknown_fields_rejected(self):
        for key, value in (("tenant_id", "other"), ("account_id", "999900001111"), ("region", "us-east-1")):
            data = evidence()
            data["topology"]["source_ref"]["binding"] = {key: value}
            with self.assertRaises(EvidenceError):
                evaluate_network(data)
        for field, value in (("bytes", 1000), ("arbitrary_saving", "100")):
            data = evidence()
            data["cohorts"][0][field] = value
            with self.assertRaises(EvidenceError):
                evaluate_network(data)


class NetworkWorkerRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v10/network-assessment"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_private_versioned_route_requires_worker_identity(self):
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "component-worker-token"}):
            request = Request(self.url, data=b"{}", headers={"Content-Type": "application/json"})
            with self.assertRaises(HTTPError) as caught:
                urlopen(request)
            self.assertEqual(caught.exception.code, 401)
            request = Request(self.url, data=json.dumps(evidence()).encode(), headers={"Authorization": "Bearer component-worker-token", "Content-Type": "application/json"})
            with urlopen(request) as response:
                result = json.load(response)
            self.assertEqual(result["model_kind"], MODEL_KIND)
            self.assertFalse(result["pre_execution_ready"])

    def test_duplicate_or_unknown_contract_is_not_legacy_fallback(self):
        for raw in (b'{"schema_version":"1","schema_version":"1"}', b'{"schema_version":"2","model_version":"network-v1"}'):
            request = Request(self.url, data=raw, headers={"Authorization": "Bearer component-worker-token", "Content-Type": "application/json"})
            with patch.dict("os.environ", {"ECONOMICS_TOKEN": "component-worker-token"}):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request)
                self.assertEqual(caught.exception.code, 422)


if __name__ == "__main__":
    unittest.main()
