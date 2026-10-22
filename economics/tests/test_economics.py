import copy
from datetime import datetime, timedelta, timezone
import unittest
from autopilot.model import EvidenceError, decimal, evaluate
from autopilot.normalize import normalize


def evidence():
    start = datetime(2026, 9, 1, 20, tzinfo=timezone.utc)
    return {
        "resource_id": "i-fixture-dev", "currency": "GBP", "baseline_days": 14,
        "verification_days": 14, "baseline_complete": True,
        "workload_evidence_complete": True, "work_preserved": True, "confounded": False,
        "commitment_known": True, "uncovered_on_demand": True, "invoice_final": True,
        "reconciliation_ratio": "1.0000", "source_version": "cur-version-1",
        "intervals": [{"source_record_id": f"slot-{day}",
                       "start": (start + timedelta(days=day)).isoformat(),
                       "end": (start + timedelta(days=day, hours=10, minutes=45)).isoformat(),
                       "baseline_compute_cost": "5.160000000000", "actual_compute_cost": "0.008000000000",
                       "incremental_cost": "0", "baseline_units": "0", "actual_units": "0"}
                      for day in range(14)],
    }


class EconomicsTests(unittest.TestCase):
    def test_exact_verified_period(self):
        result = evaluate(evidence())
        self.assertEqual(result["legacy_status"], "VERIFIED")
        self.assertEqual(result["observed_saving"], "72.128000000000")
        self.assertFalse(result["pre_execution_ready"])
        self.assertIsNone(result["verified_saving"])
        self.assertEqual(result["reason_code"], "LEGACY_EVIDENCE_VERSION")

    def test_no_binary_floats_or_excess_scale(self):
        for value in [0.1, "NaN", "Infinity", "0.0000000000001", "1e2", "1" * 27]:
            with self.assertRaises(EvidenceError):
                decimal(value)

    def test_negative_result_is_preserved(self):
        data = evidence()
        for row in data["intervals"]:
            row["actual_compute_cost"] = "6"
        self.assertEqual(evaluate(data)["observed_saving"], "-11.760000000000")

    def test_commitment_missing_and_covered_block_claim(self):
        for name, expected in [("commitment_known", "COMMITMENT_UNKNOWN"), ("uncovered_on_demand", "COMMITMENT_PORTFOLIO_MODEL_REQUIRED")]:
            data = evidence(); data[name] = False
            result = evaluate(data)
            self.assertEqual(result["legacy_reason_code"], expected)
            self.assertIsNone(result["verified_saving"])

    def test_provisional_and_reconciliation_gate(self):
        for key, value in [("invoice_final", False), ("reconciliation_ratio", "0.994999999999"), ("verification_days", 13), ("baseline_days", 13)]:
            data = evidence(); data[key] = value
            result = evaluate(data)
            self.assertEqual(result["legacy_status"], "MEASURING")
            self.assertIsNone(result["verified_saving"])
        data = evidence(); data["reconciliation_ratio"] = "0.995"
        self.assertEqual(evaluate(data)["legacy_status"], "VERIFIED")

    def test_zero_units_valid_missing_distinct_from_zero(self):
        data = evidence(); self.assertEqual(evaluate(data)["legacy_status"], "VERIFIED")
        data["intervals"][0]["actual_units"] = None
        self.assertEqual(evaluate(data)["legacy_reason_code"], "WORKLOAD_EVIDENCE_MISSING")

    def test_changed_workload_needs_model_not_division_by_runtime(self):
        data = evidence(); data["intervals"][0]["actual_units"] = "2"
        self.assertEqual(evaluate(data)["legacy_status"], "CONFOUNDED")
        data = evidence(); data["confounded"] = True
        self.assertEqual(evaluate(data)["legacy_reason_code"], "CONCURRENT_CHANGE")

    def test_duplicates_overlap_and_mixed_currency_rejected(self):
        data = evidence(); data["intervals"].append(copy.deepcopy(data["intervals"][0]))
        with self.assertRaises(EvidenceError): evaluate(data)
        data["intervals"][-1]["source_record_id"] = "different-source-same-slot"
        with self.assertRaises(EvidenceError): evaluate(data)
        data = evidence(); data["intervals"][0]["currency"] = "USD"
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_fake_14_day_declaration_rejected(self):
        data = evidence(); data["intervals"] = data["intervals"][:1]
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_correction_changes_fingerprint_and_result(self):
        data = evidence(); before = evaluate(data)
        data["source_version"] = "cur-version-2"
        data["intervals"][0]["actual_compute_cost"] = "2"
        after = evaluate(data)
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])
        self.assertEqual(before["claim_key"], after["claim_key"])
        self.assertNotEqual(before["observed_saving"], after["observed_saving"])


class BillingTests(unittest.TestCase):
    def invoice(self, usage):
        return {"source_id": "s3://fixture/cur.csv", "source_version": "v1", "records": [
            {"identity_line_item_id": str(i), "line_item_line_item_type": kind, "line_item_unblended_cost": amount, "line_item_currency_code": "GBP"}
            for i, (kind, amount) in enumerate([("Usage", usage), ("Fee", "150000"), ("Credit", "-80000"), ("Tax", "50000"), ("Usage", "20000")])]}

    def test_signed_invoice_erratum_and_million_fixture(self):
        self.assertEqual(normalize(self.invoice("700000"))["totals"]["GBP"], "840000.000000000000")
        data = self.invoice("860000"); data["invoice_totals"] = {"GBP": "1000000"}
        result = normalize(data)
        self.assertEqual(result["totals"]["GBP"], "1000000.000000000000")
        self.assertEqual(result["reconciliation"]["GBP"]["status"], "RECONCILED")

    def test_credits_not_silently_flipped_and_raw_fields_kept(self):
        data = self.invoice("700000"); result = normalize(data)
        self.assertEqual(result["records"][2]["BilledCost"], "-80000.000000000000")
        self.assertEqual(result["records"][2]["x_ProviderFields"], data["records"][2])
        self.assertIsNone(result["records"][0]["ContractedCost"])
        self.assertNotIn("ProviderName", result["records"][0])
        self.assertEqual(result["records"][0]["ServiceProviderName"], "Amazon Web Services")
        self.assertIn("MISSING_InvoiceIssuerName", result["mapping_gaps"])

    def test_commitment_fees_not_double_counted_as_compute(self):
        data = self.invoice("700000"); data["records"][0]["line_item_line_item_type"] = "SavingsPlanCoveredUsage"
        result = normalize(data)
        self.assertIsNone(result["records"][0]["EffectiveCost"])
        self.assertIn("COMMITMENT_EFFECTIVE_COST_MISSING", result["mapping_gaps"])

    def test_duplicate_source_and_missing_currency_rejected(self):
        data = self.invoice("1"); data["records"].append(data["records"][0])
        with self.assertRaises(EvidenceError): normalize(data)
        data = self.invoice("1"); del data["records"][0]["line_item_currency_code"]
        with self.assertRaises(EvidenceError): normalize(data)


if __name__ == "__main__": unittest.main()
