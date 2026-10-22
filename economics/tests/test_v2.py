import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest

from autopilot.model import EvidenceError
from autopilot.normalize import normalize
from autopilot.v2 import evaluate_v2


BINDING = {"tenant_id": "tenant-a", "resource_id": "resource-a", "provider_resource_id": "i-0123456789abcdef0", "account_id": "111111111111", "region": "eu-west-1", "currency": "GBP"}


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def snapshot(start, source, stopped=None, quarters=False):
    step = timedelta(minutes=15 if quarters else 60)
    count = 14 * 24 * (4 if quarters else 1)
    raw, samples = [], []
    for index in range(count):
        left, right = start + step * index, start + step * (index + 1)
        off = stopped and left >= stopped[0] and right <= stopped[1]
        cost = "0" if off else "0.12" if quarters else "0.48"
        raw.append({"identity_line_item_id": f"{source}-{index}", "line_item_line_item_type": "Usage", "line_item_usage_account_id": BINDING["account_id"], "line_item_resource_id": BINDING["provider_resource_id"], "line_item_currency_code": "GBP", "line_item_unblended_cost": cost, "ContractedCost": cost,
                    "product_servicecode": "AmazonEC2", "product_region_code": "eu-west-1", "product_product_family": "Compute Instance", "pricing_term": "OnDemand", "line_item_operation": "RunInstances", "line_item_usage_start_date": stamp(left), "line_item_usage_end_date": stamp(right)})
        samples.append({**BINDING, "start": stamp(left), "end": stamp(right), "units": ("2.5" if quarters else "10") if 8 <= left.hour < 18 else "0", "source_record_id": f"activity-{source}-{index}"})
    canonical = normalize({"source_id": source, "source_version": "v1", "records": raw})
    return {"start": stamp(start), "end": stamp(start + timedelta(days=14)), "source_id": source, "source_version": "v1", "billing_records": canonical["records"], "workload_samples": samples}


def evidence(phase="MEASUREMENT"):
    base = datetime(2026, 9, 1, tzinfo=timezone.utc)
    start = datetime(2026, 9, 16, tzinfo=timezone.utc)
    stopped = start + timedelta(hours=20), start + timedelta(days=1, hours=6, minutes=45)
    baseline = snapshot(base, "baseline")
    baseline["schedule"] = {"timezone": "UTC", "stop_time": "20:00", "ready_time": "07:00", "days": list(range(1, 8))}
    data = {"schema_version": "2", "phase": phase, "binding": copy.deepcopy(BINDING), "baseline_id": "baseline-immutable-1", "measurement_id": "measurement-reserved-1", "activation_at": "2026-09-15T20:00:00Z", "as_of": "2026-10-01T00:00:00Z", "baseline": baseline}
    if phase == "MEASUREMENT":
        measurement = snapshot(start, "measurement", stopped, quarters=True)
        measurement["owned_intervals"] = [{"execution_id": "exec-owned", "stopped_at": stamp(stopped[0]), "running_at": stamp(stopped[1])}]
        measurement["invoice"] = {"invoice_id": "invoice-1", "issued_at": "2026-10-01T00:00:00Z", "final": True, "total": "156.12", "reconciled_billed_total": "156.12"}
        data["measurement"] = measurement
    return data


def remap(data, name):
    part = data[name]
    part["billing_records"] = normalize({"source_id": part["source_id"], "source_version": part["source_version"], "records": [row["x_ProviderFields"] for row in part["billing_records"]]})["records"]


class SourceBoundEconomicsTests(unittest.TestCase):
    def test_baseline_ready_before_post_change_period_exists(self):
        data = evidence("BASELINE")
        data["as_of"] = data["activation_at"]
        result = evaluate_v2(data)
        self.assertTrue(result["pre_execution_ready"])
        self.assertEqual(result["baseline_days"], 14)
        self.assertEqual(result["status"], "MEASURING")
        self.assertIsNone(result["verified_saving"])
        self.assertIsNone(result["actual_cost"])
        self.assertIsNone(result["observed_saving"])

    def test_actual_observations_override_fake_complete_flags(self):
        for missing in ("billing_records", "workload_samples"):
            data = evidence("BASELINE")
            data["baseline"][missing].pop(10)
            data.update(baseline_complete=True, baseline_days=999, workload_evidence_complete=True)
            self.assertFalse(evaluate_v2(data)["pre_execution_ready"])
        data = evidence("BASELINE")
        data["baseline"]["start"] = "2026-09-02T00:00:00Z"
        for name in ("billing_records", "workload_samples"):
            data["baseline"][name] = data["baseline"][name][24:]
        self.assertFalse(evaluate_v2(data)["pre_execution_ready"])

    def test_complete_bound_owned_period_verifies_exact_money(self):
        result = evaluate_v2(evidence())
        self.assertTrue(result["pre_execution_ready"])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["verified_saving"], "5.160000000000")
        self.assertNotEqual(result["verified_saving"], result["annualised_estimate"])
        self.assertEqual(result["baseline_id"], "baseline-immutable-1")

    def test_binding_source_and_canonical_amount_tampering_rejected(self):
        cases = [("SubAccountId", "222222222222"), ("ResourceId", "i-other"), ("RegionId", "us-east-1"), ("BillingCurrency", "USD"), ("x_SourceVersion", "v2"), ("x_TenantId", "tenant-b"), ("EffectiveCost", "999.000000000000"), ("BilledCost", "999.000000000000"), ("x_SourceRecordId", "missing")]
        for key, value in cases:
            with self.subTest(key=key):
                data = evidence("BASELINE")
                data["baseline"]["billing_records"][0][key] = value
                with self.assertRaises(EvidenceError): evaluate_v2(data)
        for key in ("tenant_id", "account_id", "region", "resource_id", "provider_resource_id"):
            data = evidence("BASELINE")
            data["baseline"]["workload_samples"][0][key] = "wrong"
            with self.assertRaises(EvidenceError): evaluate_v2(data)

    def test_source_records_cannot_be_omitted_or_substituted(self):
        data = evidence("BASELINE")
        del data["baseline"]["billing_records"][0]["x_ProviderFields"]
        with self.assertRaises(EvidenceError): evaluate_v2(data)
        data = evidence("BASELINE")
        data["baseline"]["billing_records"][0]["x_ProviderFields"]["line_item_resource_id"] = "i-other"
        with self.assertRaises(EvidenceError): evaluate_v2(data)

    def test_zero_activity_is_valid_and_missing_is_unknown(self):
        data = evidence("BASELINE")
        self.assertTrue(evaluate_v2(data)["pre_execution_ready"])
        data["baseline"]["workload_samples"][20]["units"] = None
        result = evaluate_v2(data)
        self.assertFalse(result["pre_execution_ready"])
        self.assertEqual(result["reason_code"], "WORKLOAD_EVIDENCE_MISSING")

    def test_known_commitment_and_idle_evidence_required(self):
        for mutate in (lambda row: row.update(pricing_term="Reserved"), lambda row: row.pop("ContractedCost"), lambda row: row.update(savings_plan_savings_plan_a_r_n="arn:aws:savingsplans:covered")):
            data = evidence("BASELINE")
            mutate(data["baseline"]["billing_records"][0]["x_ProviderFields"])
            remap(data, "baseline")
            self.assertFalse(evaluate_v2(data)["pre_execution_ready"])
        data = evidence("BASELINE")
        data["baseline"]["workload_samples"][20]["units"] = "1"
        self.assertEqual(evaluate_v2(data)["reason_code"], "BASELINE_WORKLOAD_ACTIVE")

    def test_missing_or_incomplete_post_period_does_not_revoke_readiness(self):
        for mode in ("future", "missing-work", "provisional"):
            data = evidence()
            if mode == "future": data["as_of"] = "2026-09-20T00:00:00Z"
            elif mode == "missing-work": data["measurement"]["workload_samples"][0]["units"] = None
            else: data["measurement"]["invoice"]["final"] = False
            result = evaluate_v2(data)
            self.assertTrue(result["pre_execution_ready"])
            self.assertEqual(result["status"], "MEASURING")
            self.assertIsNone(result["verified_saving"])

    def test_invalid_baseline_never_overridden_by_later_invoice(self):
        data = evidence()
        data["baseline"]["workload_samples"][0]["units"] = None
        result = evaluate_v2(data)
        self.assertFalse(result["pre_execution_ready"])
        self.assertIsNone(result["verified_saving"])
        self.assertEqual(result["reason_code"], "WORKLOAD_EVIDENCE_MISSING")

    def test_historical_period_future_baseline_and_noncalendar_period_rejected(self):
        for mutation in (lambda data: data.update(activation_at="2026-10-01T00:00:00Z"), lambda data: data.update(activation_at="2026-09-10T00:00:00Z"), lambda data: data["measurement"].update(start="2026-09-16T01:00:00Z")):
            data = evidence(); mutation(data)
            with self.assertRaises(EvidenceError): evaluate_v2(data)

    def test_stale_baseline_does_not_authorize_new_activation(self):
        data = evidence("BASELINE")
        data["activation_at"] = "2026-09-16T20:00:00Z"
        with self.assertRaises(EvidenceError): evaluate_v2(data)

    def test_unowned_manual_shutdown_and_overlaps_cannot_claim(self):
        data = evidence(); data["measurement"]["owned_intervals"] = []
        self.assertEqual(evaluate_v2(data)["reason_code"], "OWNED_EXECUTION_REQUIRED")
        data = evidence(); duplicate = copy.deepcopy(data["measurement"]["owned_intervals"][0]); duplicate["execution_id"] = "other"
        data["measurement"]["owned_intervals"].append(duplicate)
        with self.assertRaises(EvidenceError): evaluate_v2(data)
        data = evidence(); data["measurement"]["owned_intervals"][0]["running_at"] = "2026-09-17T01:00:00Z"
        self.assertEqual(evaluate_v2(data)["reason_code"], "UNOWNED_RUNTIME_CHANGE")

    def test_workload_loss_during_day_is_not_preservation(self):
        data = evidence()
        before = evaluate_v2(data)
        data["measurement"]["workload_samples"][32]["units"] = "0"
        after = evaluate_v2(data)
        self.assertEqual(after["status"], "CONFOUNDED")
        self.assertIsNone(after["actual_cost"])
        self.assertEqual(after["claim_key"], before["claim_key"])

    def test_startup_costs_reduce_savings_and_negative_results_survive(self):
        data = evidence()
        # The final 15 minutes before availability are running, and an unusually
        # expensive startup makes the overall result negative.
        index = (24 + 6) * 4 + 3
        data["measurement"]["billing_records"][index]["x_ProviderFields"]["line_item_unblended_cost"] = "10"
        remap(data, "measurement")
        data["measurement"]["invoice"].update(total="166", reconciled_billed_total="166")
        result = evaluate_v2(data)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["verified_saving"], "-4.720000000000")

    def test_continuing_storage_does_not_inflate_savings(self):
        data = evidence()
        row = copy.deepcopy(data["measurement"]["billing_records"][0]["x_ProviderFields"])
        row.update(identity_line_item_id="retained-ebs", product_product_family="Storage", line_item_operation="EBS:VolumeUsage", line_item_usage_type="EUW1-EBS:VolumeUsage.gp3", line_item_unblended_cost="20", ContractedCost="20")
        data["measurement"]["billing_records"].append({"x_ProviderFields": row})
        remap(data, "measurement")
        data["measurement"]["invoice"].update(total="176.12", reconciled_billed_total="176.12")
        self.assertEqual(evaluate_v2(data)["verified_saving"], "5.160000000000")
        data["measurement"]["incremental_billing_record_ids"] = ["retained-ebs"]
        with self.assertRaises(EvidenceError): evaluate_v2(data)

    def test_reconciliation_boundary_is_independent_of_other_gates(self):
        data = evidence()
        data["measurement"]["invoice"].update(total="200", reconciled_billed_total="199")
        self.assertEqual(evaluate_v2(data)["status"], "VERIFIED")
        data["measurement"]["invoice"]["reconciled_billed_total"] = "198.999999999999"
        self.assertEqual(evaluate_v2(data)["reason_code"], "RECONCILIATION_BELOW_THRESHOLD")

    def test_append_only_correction_has_new_fingerprint_same_claim(self):
        data = evidence(); before = evaluate_v2(data)
        data["measurement"]["source_version"] = "v2"
        row = data["measurement"]["billing_records"][-1]["x_ProviderFields"]
        row["line_item_unblended_cost"] = "0.13"
        remap(data, "measurement")
        data["measurement"]["invoice"].update(total="156.13", reconciled_billed_total="156.13")
        after = evaluate_v2(data)
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])
        self.assertEqual(before["claim_key"], after["claim_key"])

    def test_new_measurement_reservation_cannot_create_another_claim(self):
        data = evidence(); before = evaluate_v2(data)
        data["measurement_id"] = "different-reservation-same-period"
        after = evaluate_v2(data)
        self.assertEqual(before["claim_key"], after["claim_key"])
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])


if __name__ == "__main__": unittest.main()
