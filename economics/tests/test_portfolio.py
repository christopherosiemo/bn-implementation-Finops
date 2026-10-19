"""Analytical fixtures only; these do not constitute provider-issued evidence."""
import copy
import unittest
from autopilot.portfolio import evaluate, EvidenceError

def fixture():
    inv = {"kind": "AWS_COMMITMENT", "id": "inventory", "sha256": "a" * 64}
    cur = {"kind": "AWS_CUR2", "id": "billing", "sha256": "b" * 64}
    period = {"start": "2026-09-01T00:00:00Z", "end": "2026-09-01T02:00:00Z"}
    position = {"id": "plan", "account_id": "111122223333", "class": "COMPUTE_SAVINGS_PLAN", "state": "active", "region": None, "instance_family": None, "currency": "USD", "start": "2026-01-01T00:00:00Z", "end": "2027-01-01T00:00:00Z", "term_seconds": "31536000", "hourly_commitment": "2", "upfront_amount": "0", "recurring_amount": "2", "recurring_amount_unit": "PROVIDER_FIELD_UNIT_UNVERIFIED", "payment_option": "No Upfront", "reserved_instance_terms": None, "native_ref": inv, "reason_codes": []}
    lines = []
    for hour in range(2):
        lines.append({"id": "fee-"+str(hour), "commitment_id": "plan", "account_id": "111122223333", "currency": "USD", "kind": "SavingsPlanRecurringFee", "period": {"start": f"2026-09-01T0{hour}:00:00Z", "end": f"2026-09-01T0{hour+1}:00:00Z"}, "billed_cost": "2", "allocated_cost": None, "allocated_cost_basis": None, "total_commitment": "2", "used_commitment": "1.5", "native_ref": cur})
    return {"schema_version": "1", "request_id": "request-a", "tenant_id": "tenant-a", "payer_account_id": "111122223333", "usage_account_ids": ["111122223333"], "selection": {"source_id": "source", "commitment_receipt_id": "inventory", "billing_receipt_ids": ["billing"], "period": period}, "input_refs": [inv, cur], "inventory_status": "COMPLETE_POINT_IN_TIME", "positions": [position], "billing": lines, "billing_status": "COMPLETE_OBSERVED_WINDOW", "optimization_order": [], "observed_at": "2026-09-02T00:00:00Z"}

class PortfolioTests(unittest.TestCase):
    def test_native_charge_kind_cannot_borrow_another_commitment_pricing_basis(self):
        data = fixture()
        usage = copy.deepcopy(data["billing"][0])
        usage.update(id="covered", kind="SavingsPlanCoveredUsage", allocated_cost="0", allocated_cost_basis="NET_RI_EFFECTIVE", total_commitment=None, used_commitment=None)
        data["billing"].append(usage)
        with self.assertRaises(EvidenceError): evaluate(data)
        usage["allocated_cost_basis"] = "NET_SP_EFFECTIVE"
        self.assertEqual(evaluate(data)["positions"][0]["observed_allocated_cost"], "0")
        usage.update(kind="DiscountedUsage", allocated_cost_basis="NET_RI_EFFECTIVE")
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_partition_exposure_expiry_and_concentration_are_observed_not_forecast(self):
        data = fixture()
        second = copy.deepcopy(data["positions"][0])
        second.update(id="second", hourly_commitment="6", end="2026-09-20T00:00:00Z", term_seconds="22636800")
        data["positions"].append(second)
        for line in copy.deepcopy(data["billing"]):
            line.update(id=line["id"]+"-second", commitment_id="second", total_commitment="6", used_commitment="3")
            data["billing"].append(line)
        out = evaluate(data)
        partition = out["partitions"][0]
        self.assertEqual((partition["observed_committed_cost"], partition["observed_used_commitment"], partition["observed_unused_commitment"], partition["utilization"]), ("16", "9", "7", "0.5625"))
        self.assertEqual(partition["hourly_commitment_rate"], "8")
        self.assertEqual(partition["position_shares"], [{"position_id": "plan", "share": "0.25"}, {"position_id": "second", "share": "0.75"}])
        self.assertEqual(partition["expiring_position_ids"], ["second"])
        self.assertEqual(out["positions"][1]["expiry"], {"status": "ACTIVE", "remaining_seconds": "1555200", "within_days": 30, "expires_within_window": True})
        self.assertIsNone(out["expected_savings"])
        data["inventory_status"] = "PARTIAL"
        partial = evaluate(data)["partitions"][0]
        self.assertIsNone(partial["hourly_commitment_rate"])
        self.assertTrue(all(row["share"] is None for row in partial["position_shares"]))

    def test_consolidated_usage_requires_issued_member_scope_and_fee_ownership(self):
        data = fixture()
        usage = copy.deepcopy(data["billing"][0])
        usage.update(id="member-usage", kind="SavingsPlanCoveredUsage", account_id="444455556666", allocated_cost="1.5", allocated_cost_basis="NET_SP_EFFECTIVE", total_commitment=None, used_commitment=None, billed_cost="3")
        data["billing"].append(usage)
        with self.assertRaises(EvidenceError): evaluate(data)
        data["usage_account_ids"].append("444455556666")
        self.assertEqual(evaluate(data)["positions"][0]["observed_allocated_cost"], "1.5")
        data["billing"][0]["account_id"] = "444455556666"
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_unsupported_precision_and_wrong_term_cannot_become_exposure(self):
        data = fixture()
        data["billing"][0]["billed_cost"] = "0.0000000000001"
        with self.assertRaises(EvidenceError): evaluate(data)
        data = fixture()
        data["positions"][0]["term_seconds"] = "3600"
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_expiry_preserves_actual_nanosecond_clock_without_float_rounding(self):
        data = fixture()
        data["observed_at"] = "2026-09-02T00:00:00.123456789Z"
        self.assertEqual(evaluate(data)["positions"][0]["expiry"]["remaining_seconds"], "10454399.876543211")

    def test_retired_native_position_does_not_hide_authentic_historical_charges(self):
        data = fixture()
        row = copy.deepcopy(data["billing"][0])
        row.update(id="retired-credit", commitment_id="retired", kind="Credit", billed_cost="-0.25")
        data["billing"].append(row)
        out = evaluate(data)
        self.assertEqual(out["positions"][0]["observed_unused_commitment"], "1")
        self.assertEqual(out["unmatched_billing"], [{"commitment_id": "retired", "account_id": "111122223333", "currency": "USD", "line_ids": ["retired-credit"], "observed_billed_cost": "-0.25", "reason_codes": ["COMMITMENT_NOT_IN_SELECTED_NATIVE_POINT"]}])
        self.assertIsNone(out["expected_savings"])

    def test_exact_observed_allocation_never_authorizes_recommendation(self):
        out = evaluate(fixture())
        pos = out["positions"][0]
        self.assertEqual((pos["observed_committed_cost"], pos["observed_used_commitment"], pos["observed_unused_commitment"], pos["utilization"]), ("4", "3", "1", "0.75"))
        self.assertEqual(pos["downside_if_zero_usage_observed_window"], "4")
        for name in ("coverage", "break_even_utilization", "remaining_value", "cash_requirement", "confidence_interval", "expected_utilization"):
            self.assertIsNone(pos[name])
        self.assertEqual(len(out["optimization_order"]), 5)
        self.assertTrue(all(s["status"] == "BLOCKED" for s in out["optimization_order"]))
        for name in ("purchase_authorized", "execution_authorized", "recommendation_authorized"):
            self.assertFalse(out[name])
        self.assertIsNone(out["expected_savings"])

    def test_current_point_without_interval_rows_is_unknown_not_zero(self):
        data = fixture(); data["billing"] = []
        pos = evaluate(data)["positions"][0]
        self.assertIsNone(pos["utilization"])
        self.assertIsNone(pos["observed_billed_cost"])
        self.assertEqual(pos["status"], "UNKNOWN")

    def test_zero_denominator_does_not_imply_full_utilization(self):
        data = fixture()
        for row in data["billing"]:
            row["total_commitment"] = row["used_commitment"] = "0"
        pos = evaluate(data)["positions"][0]
        self.assertEqual(pos["observed_unused_commitment"], "0")
        self.assertIsNone(pos["utilization"])
        self.assertIn("ZERO_COMMITMENT_UTILIZATION_UNDEFINED", pos["reason_codes"])

    def test_missing_hour_and_partial_scope_cannot_produce_ratio(self):
        for mutation in (lambda d:d["billing"].pop(0), lambda d:d.update(billing_status="PARTIAL")):
            data = fixture(); mutation(data)
            self.assertIsNone(evaluate(data)["positions"][0]["utilization"])

    def test_negative_signed_credits_are_not_commitment_units(self):
        data = fixture(); data["billing"][0]["billed_cost"] = "-0.25"
        pos = evaluate(data)["positions"][0]
        self.assertEqual(pos["observed_billed_cost"], "1.75")
        self.assertEqual(pos["utilization"], "0.75")
        data["billing"][0]["used_commitment"] = "-0.25"
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_class_and_currency_partitions_do_not_cross_net(self):
        data = fixture(); second = copy.deepcopy(data["positions"][0]); second.update(id="plan-eur", currency="EUR", **{"class": "EC2_INSTANCE_SAVINGS_PLAN", "region": "eu-west-1", "instance_family": "m6i"}); data["positions"].append(second)
        for row in copy.deepcopy(data["billing"]):
            row.update(id=row["id"]+"-eur", commitment_id="plan-eur", currency="EUR");data["billing"].append(row)
        out = evaluate(data)
        self.assertEqual(len(out["partitions"]), 2)
        self.assertEqual({p["currency"] for p in out["partitions"]}, {"USD", "EUR"})
        data["billing"][0]["currency"] = "EUR"
        with self.assertRaises(EvidenceError): evaluate(data)

    def test_legacy_ri_stays_unclassified_unknown(self):
        data = fixture(); data["positions"][0].update(**{"class": "EC2_RI_UNCLASSIFIED", "currency": None, "hourly_commitment": None, "upfront_amount": None, "recurring_amount": None}); data["billing"] = []
        pos = evaluate(data)["positions"][0]
        self.assertIsNone(pos["utilization"])
        self.assertIsNone(pos["position"]["currency"])

    def test_overlap_duplicate_wrong_reference_and_overuse_refused(self):
        changes = [lambda d:d["billing"].append(copy.deepcopy(d["billing"][0])), lambda d:d["billing"][0].update(used_commitment="2.1"), lambda d:d["billing"][0].update(native_ref={**d["billing"][0]["native_ref"], "sha256":"c"*64}), lambda d:d["positions"][0].update(**{"class":"SAVINGS_PLAN_FUNGIBLE"})]
        for change in changes:
            data = fixture();change(data)
            with self.assertRaises(EvidenceError): evaluate(data)

    def test_unrelated_stage_proof_cannot_unlock_and_request_id_changes_fact_id(self):
        data = fixture(); a = evaluate(data);data["request_id"] = "request-b";self.assertNotEqual(a["id"], evaluate(data)["id"])
        data["optimization_order"] = [{"stage":"SCHEDULE","status":"COMPLETE","decision_ref":{"id":"unrelated"}}]
        with self.assertRaises(EvidenceError): evaluate(data)

if __name__ == "__main__":
    unittest.main()
