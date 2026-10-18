"""Source-native sparse exports: no generated billing rows for stopped hours."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from functools import lru_cache
import unittest

from autopilot.model import EvidenceError
from autopilot.native import native_cost, normalize_v3
from autopilot.v3 import evaluate_v3, _incremental, _scope_retained, _native_scope_risk, _invoices

BINDING = {"tenant_id": "tenant-a", "resource_id": "resource-a", "provider_resource_id": "i-0123456789abcdef0", "account_id": "111111111111", "region": "eu-west-1", "currency": "GBP", "payer_account_id": "111111111111", "invoice_entity": "AWS EMEA"}
MONTH = datetime(2026, 9, 1, tzinfo=timezone.utc)
POST = datetime(2026, 9, 16, tzinfo=timezone.utc)
STOP, RUNNING = POST + timedelta(hours=20), POST + timedelta(days=1, hours=6, minutes=45)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def source_proof(source, rows, final=False):
    return {"receipt_id": "receipt-" + source, "revision_id": "revision-" + source, "manifest_hash": "a" * 64, "source_id": source, "source_version": "v1", "payer_account_id": BINDING["payer_account_id"], "usage_account_id": BINDING["account_id"], "region": BINDING["region"], "currency": "GBP", "invoice_entity": "AWS EMEA", "period_start": stamp(MONTH), "period_end": "2026-10-01T00:00:00Z", "state": "FINAL" if final else "COMPLETE", "object_count": 1, "verified_object_count": 1, "row_count": rows, "verified_row_count": rows}


def commitment():
    return {"receipt_id": "commitment-receipt", "payer_account_id": BINDING["payer_account_id"], "usage_account_ids": [BINDING["account_id"]], "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": True, "reserved_instance_count": 0, "savings_plan_count": 0}


def activity(start, source):
    result = []
    for index in range(14 * 24 * 4):
        left = start + timedelta(minutes=15 * index)
        units = "2.5" if 8 <= left.hour < 18 else "0"
        result.append({"binding": copy.deepcopy(BINDING), "start": stamp(left), "end": stamp(left + timedelta(minutes=15)), "units": units, "accepted": units, "completed": units, "rejected": "0", "backlog": "0", "inflight": "0", "heartbeat": True, "metric_definition": {"id": "accepted-work", "version": "1", "unit": "jobs"}, "incident": "CLEAR", "deployment": "CLEAR", "job": "CLEAR", "source_id": "independent-machine", "receipt_id": f"activity-{source}-{index}", "received_at": stamp(left + timedelta(minutes=15)), "body_sha256": "b" * 64, "source_provenance": "INDEPENDENT_ACTIVITY"})
    return result


@lru_cache(maxsize=1)
def _fixture():
    raw = []
    for index in range(30 * 24 * 4):
        left, right = MONTH + timedelta(minutes=15 * index), MONTH + timedelta(minutes=15 * (index + 1))
        if STOP <= left < RUNNING:
            continue
        raw.append({"identity_line_item_id": f"native-{index}", "bill_invoice_id": "invoice-september", "bill_payer_account_id": BINDING["payer_account_id"], "bill_invoicing_entity": "AWS EMEA", "bill_billing_period_start_date": stamp(MONTH), "bill_billing_period_end_date": "2026-10-01T00:00:00Z", "line_item_line_item_type": "Usage", "line_item_usage_account_id": BINDING["account_id"], "line_item_resource_id": BINDING["provider_resource_id"], "line_item_currency_code": "GBP", "line_item_unblended_cost": "0.12", "product_servicecode": "AmazonEC2", "product_region_code": "eu-west-1", "product_product_family": "Compute Instance", "pricing_term": "OnDemand", "line_item_operation": "RunInstances", "line_item_usage_start_date": stamp(left), "line_item_usage_end_date": stamp(right)})
    full = normalize_v3({"source_id": "final-export", "source_version": "v1", "records": raw})["records"]
    base_rows = [row for row in raw if row["line_item_usage_end_date"] <= "2026-09-15T00:00:00Z"]
    base = {"start": stamp(MONTH), "end": "2026-09-15T00:00:00Z", "source_id": "baseline-export", "source_version": "v1", "billing_records": normalize_v3({"source_id": "baseline-export", "source_version": "v1", "records": base_rows})["records"], "workload_samples": activity(MONTH, "baseline"), "source_proof": source_proof("baseline-export", len(base_rows)), "commitment_scope": commitment(), "schedule": {"timezone": "UTC", "stop_time": "20:00", "ready_time": "07:00", "days": list(range(1, 8))}}
    base["invoice_scope_records"] = copy.deepcopy(base["billing_records"])
    target = [row for row in full if "2026-09-16T00:00:00Z" <= row["ChargePeriodStart"] and row["ChargePeriodEnd"] <= "2026-09-30T00:00:00Z"]
    observations = [{"start": row["ChargePeriodStart"], "end": row["ChargePeriodEnd"], "state": "OBSERVED", "source_record_ids": [row["x_SourceRecordId"]]} for row in target]
    observations.append({"start": stamp(STOP), "end": stamp(RUNNING), "state": "ABSENT_FINAL_EXPORT", "source_receipt_id": "receipt-final-export"})
    post = {"start": stamp(POST), "end": "2026-09-30T00:00:00Z", "source_id": "final-export", "source_version": "v1", "source_proof": source_proof("final-export", len(raw), True), "billing_records": target, "billing_observations": observations, "workload_samples": activity(POST, "post"), "owned_intervals": [{"execution_id": "owned-execution", "stopped_at": stamp(STOP), "running_at": stamp(RUNNING)}], "commitment_scope": commitment(), "invoice_scope_records": full, "invoices": [{"receipt_id": "native-invoice-receipt", "native": {"AccountId": BINDING["payer_account_id"], "InvoiceId": "invoice-september", "InvoiceType": "INVOICE", "TaxAuthorityStatus": "ISSUED", "IssuedDate": "2026-10-01T00:00:00Z", "BillingPeriod": {"Year": 2026, "Month": 9}, "Entity": {"InvoicingEntity": "AWS EMEA"}, "BaseCurrencyAmount": {"CurrencyCode": "GBP", "TotalAmount": "340.44"}}}]}
    return {"schema_version": "3", "phase": "MEASUREMENT", "binding": BINDING, "proof_set_id": "proof-set-1", "baseline_id": "baseline-1", "measurement_id": "measurement-1", "activation_at": "2026-09-15T20:00:00Z", "as_of": "2026-10-02T00:00:00Z", "baseline": base, "measurement": post}


def evidence(phase="MEASUREMENT"):
    data = copy.deepcopy(_fixture())
    data["phase"] = phase
    if phase == "BASELINE":
        data.pop("measurement")
        data["as_of"] = data["activation_at"]
    return data


def remap(data, name):
    part = data[name]
    part["billing_records"] = normalize_v3({"source_id": part["source_id"], "source_version": part["source_version"], "records": [row["x_ProviderFields"] for row in part["billing_records"]]})["records"]


class NativeV3Tests(unittest.TestCase):
    def test_native_pricing_prefers_net_including_zero(self):
        self.assertEqual(native_cost({"line_item_net_unblended_cost": "0", "line_item_unblended_cost": "100", "ContractedCost": "999"}), ("NET_UNBLENDED", Decimal("0")))
        self.assertEqual(native_cost({"ContractedCost": "999"}), ("UNKNOWN", None))
        result = normalize_v3({"source_id": "s", "source_version": "v", "records": [copy.deepcopy(_fixture()["baseline"]["billing_records"][0]["x_ProviderFields"])]})
        self.assertIsNone(result["records"][0]["ContractedCost"])
        self.assertNotIn("CONTRACTED_COST_NOT_PROVIDED", result["mapping_gaps"])

    def test_complete_actual_baseline_does_not_require_contracted_cost(self):
        result = evaluate_v3(evidence("BASELINE"))
        self.assertTrue(result["pre_execution_ready"])
        self.assertEqual(result["pricing_basis"], ["UNBLENDED"])
        self.assertIsNone(result["actual_cost"])

    def test_sparse_final_export_owned_absence_verifies_without_fake_zero_rows(self):
        data = evidence()
        self.assertEqual(len(data["measurement"]["billing_records"]), 14 * 24 * 4 - 43)
        result = evaluate_v3(data)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["verified_saving"], "5.160000000000")
        self.assertEqual(result["billing_observations"]["measurement"]["ABSENT_FINAL_EXPORT"], "38700")
        self.assertNotEqual(result["verified_saving"], result["annualised_estimate"])

    def test_missing_baseline_rows_cannot_be_filled_by_absence_or_flags(self):
        data = evidence("BASELINE")
        data["baseline"]["billing_records"].pop(0)
        data.update(baseline_complete=True, baseline_days=14)
        self.assertFalse(evaluate_v3(data)["pre_execution_ready"])
        data["baseline"]["billing_observations"] = [{"start": stamp(MONTH), "end": stamp(MONTH + timedelta(days=14)), "state": "ABSENT_FINAL_EXPORT", "source_receipt_id": "receipt-baseline-export"}]
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_exact_fourteen_complete_days_and_activation_age_required(self):
        for end in ("2026-09-14T00:00:00Z", "2026-09-16T00:00:00Z", "2026-09-15T01:00:00Z"):
            data = evidence("BASELINE"); data["baseline"]["end"] = end
            with self.assertRaises(EvidenceError): evaluate_v3(data)
        data = evidence("BASELINE"); data["activation_at"] = data["as_of"] = "2026-09-17T00:00:00Z"
        self.assertTrue(evaluate_v3(data)["pre_execution_ready"])
        data["activation_at"] = data["as_of"] = "2026-09-17T00:00:01Z"
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_unknown_actual_never_becomes_zero_savings(self):
        data = evidence(); data["measurement"]["billing_observations"][-1]["state"] = "UNKNOWN"
        result = evaluate_v3(data)
        self.assertEqual(result["reason_code"], "BILLING_OBSERVATION_UNKNOWN")
        self.assertIsNone(result["actual_cost"])
        self.assertIsNone(result["observed_saving"])
        self.assertIsNone(result["verified_saving"])

    def test_absence_requires_final_full_export_and_owned_stop(self):
        for mutation in (lambda p: p.update(currency="USD"), lambda p: p.pop("receipt_id")):
            data = evidence(); mutation(data["measurement"]["source_proof"])
            with self.assertRaises(EvidenceError): evaluate_v3(data)
        for mutation in (lambda p: p.update(state="COMPLETE"), lambda p: p.update(verified_object_count=0), lambda p: p.update(verified_row_count=0)):
            data = evidence(); mutation(data["measurement"]["source_proof"])
            result = evaluate_v3(data)
            self.assertEqual(result["status"], "MEASURING")
            self.assertIsNone(result["verified_saving"])
        data = evidence(); data["measurement"]["owned_intervals"] = []
        with self.assertRaises(EvidenceError): evaluate_v3(data)
        data = evidence(); data["measurement"]["billing_observations"][-1]["amount"] = "0"
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_canonical_native_amount_and_revision_are_bound(self):
        for key, value in (("x_NativeComputeCost", "999"), ("x_PricingBasis", "NET_UNBLENDED"), ("x_SourceVersion", "other"), ("BilledCost", "999"), ("InvoiceIssuerName", "other")):
            data = evidence("BASELINE"); data["baseline"]["billing_records"][0][key] = value
            with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_caller_contracted_amount_never_changes_native_model(self):
        data = evidence("BASELINE")
        data["baseline"]["billing_records"][0]["x_ProviderFields"]["ContractedCost"] = "999999"
        remap(data, "baseline")
        self.assertTrue(evaluate_v3(data)["pre_execution_ready"])
        data["baseline"]["billing_records"][0]["x_ProviderFields"].pop("line_item_unblended_cost")
        # Even a caller's fallback BilledCost cannot provide a native pricing basis.
        data["baseline"]["billing_records"][0]["x_ProviderFields"]["BilledCost"] = "0.12"
        remap(data, "baseline")
        self.assertFalse(evaluate_v3(data)["pre_execution_ready"])

    def test_native_invoice_cancellation_and_reconciliation(self):
        data = evidence(); data["measurement"]["invoices"][0]["native"]["TaxAuthorityStatus"] = "CANCELLED"
        self.assertEqual(evaluate_v3(data)["reason_code"], "INVOICE_CANCELLED")
        data = evidence(); data["measurement"]["invoices"][0]["native"]["BaseCurrencyAmount"]["TotalAmount"] = "1000"
        self.assertEqual(evaluate_v3(data)["reason_code"], "RECONCILIATION_BELOW_THRESHOLD")

    def test_invoice_scope_cannot_be_replaced_by_request_totals_or_other_identity(self):
        for mutation in (lambda n: n.update(AccountId="222222222222"), lambda n: n.update(IssuedDate="2026-09-30T00:00:00Z"), lambda n: n.update(IssuedDate="2026-10-03T00:00:00Z"), lambda n: n["Entity"].update(InvoicingEntity="other"), lambda n: n["BaseCurrencyAmount"].update(CurrencyCode="USD")):
            data = evidence(); mutation(data["measurement"]["invoices"][0]["native"])
            with self.assertRaises(EvidenceError): evaluate_v3(data)
        data = evidence(); data["measurement"]["invoices"] = []; data["measurement"]["invoice"] = {"final": True, "total": "340.44", "reconciled_billed_total": "340.44"}
        self.assertEqual(evaluate_v3(data)["status"], "MEASURING")
        data = evidence(); data["measurement"]["invoice_scope_records"] = data["measurement"]["billing_records"]
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_target_source_must_belong_to_reconciled_invoice(self):
        data = evidence(); data["measurement"]["billing_records"][0]["x_ProviderFields"]["bill_invoice_id"] = "unrelated-invoice"
        # Break shared fixture references deliberately: the complete invoice stays original.
        data["measurement"]["invoice_scope_records"] = copy.deepcopy(_fixture()["measurement"]["invoice_scope_records"])
        remap(data, "measurement")
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_commitment_inventory_cannot_be_partial_or_resource_only(self):
        for key in ("receipt_id", "reserved_instance_count", "savings_plan_count", "usage_account_ids"):
            data = evidence("BASELINE"); data["baseline"]["commitment_scope"].pop(key)
            with self.assertRaises(EvidenceError): evaluate_v3(data)
        data = evidence("BASELINE"); data["baseline"]["commitment_scope"]["scope"] = "RESOURCE"
        with self.assertRaises(EvidenceError): evaluate_v3(data)
        data = evidence("BASELINE"); data["baseline"]["commitment_scope"]["savings_plan_count"] = 1
        self.assertFalse(evaluate_v3(data)["pre_execution_ready"])

    def test_activity_receipt_heartbeat_metric_and_accepted_demand_required(self):
        for mutation in (lambda s: s.update(heartbeat=False), lambda s: s.pop("body_sha256"), lambda s: s.update(source_provenance="CUSTOMER_IMPORT"), lambda s: s.update(units="999"), lambda s: s["binding"].update(account_id="222222222222"), lambda s: s["metric_definition"].update(version="2")):
            data = evidence("BASELINE"); mutation(data["baseline"]["workload_samples"][0])
            with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_loss_of_completed_work_or_growing_queues_confounds(self):
        for key, value in (("completed", "0"), ("rejected", "1"), ("backlog", "1"), ("inflight", "1")):
            data = evidence(); data["measurement"]["workload_samples"][40][key] = value
            result = evaluate_v3(data)
            self.assertEqual(result["status"], "CONFOUNDED")
            self.assertIsNone(result["verified_saving"])

    def test_multiple_month_receipts_are_scoped_not_silently_replaced(self):
        data = evidence("BASELINE"); proof = data["baseline"].pop("source_proof")
        data["baseline"]["source_proofs"] = [proof, copy.deepcopy(proof)]
        with self.assertRaises(EvidenceError): evaluate_v3(data)
        data["baseline"]["source_proofs"] = [proof]
        self.assertTrue(evaluate_v3(data)["pre_execution_ready"])

    def test_invalidating_corrections_keep_claim_key_and_remove_verified_saving(self):
        previous = evaluate_v3(evidence())
        for mutation in (
            lambda p: p["source_proof"].update(state="COMPLETE"),
            lambda p: p["source_proof"].update(verified_row_count=0),
            lambda p: p["invoices"][0]["native"].update(TaxAuthorityStatus="CANCELLED"),
            lambda p: p["invoices"][0]["native"].update(InvoiceId="replacement-pending"),
            lambda p: p["invoices"][0]["native"].update(InvoiceType="CREDIT_MEMO"),
            lambda p: p["workload_samples"][40].update(completed="0"),
        ):
            data = evidence(); mutation(data["measurement"])
            result = evaluate_v3(data)
            self.assertEqual(result["claim_key"], previous["claim_key"])
            self.assertNotEqual(result["fingerprint"], previous["fingerprint"])
            self.assertNotEqual(result["status"], "VERIFIED")
            self.assertIsNone(result["verified_saving"])

    def test_retained_storage_rate_increases_cannot_be_ignored(self):
        def retained(cost, execution=None):
            raw = {"product_product_family": "Storage", "line_item_usage_type": "EU-EBS:VolumeUsage.gp3", "line_item_operation": "CreateVolume"}
            if execution: raw["finops_incremental_execution_id"] = execution
            return {"compute": False, "cost": Decimal(cost), "basis": "UNBLENDED", "row": {"ServiceName": "AmazonEC2", "x_ProviderFields": raw}}
        args = MONTH, MONTH + timedelta(days=14), POST, POST + timedelta(days=14), {"owned"}
        self.assertEqual(_incremental([retained("14")], [retained("14")], *args), Decimal("0"))
        self.assertEqual(_incremental([retained("14")], [retained("7")], *args), Decimal("0"))
        self.assertIsNone(_incremental([retained("14")], [retained("15")], *args))
        self.assertIsNone(_incremental([], [retained("14")], *args))
        self.assertEqual(_incremental([retained("14")], [retained("15", "owned")], *args), Decimal("1"))

    def test_unallocated_volume_with_different_resource_id_is_in_scope(self):
        def add_volume(data, post_cost="30", new_volume=False):
            for name, source, start, end, cost in (("baseline", "baseline-export", stamp(MONTH), "2026-09-15T00:00:00Z", "14"), ("measurement", "final-export", stamp(MONTH), "2026-10-01T00:00:00Z", post_cost)):
                raw = copy.deepcopy(data[name]["billing_records"][0]["x_ProviderFields"])
                raw.update(identity_line_item_id="volume-line", line_item_resource_id="vol-other" if name == "measurement" and new_volume else "vol-0123456789abcdef0", product_product_family="Storage", line_item_usage_type="EU-EBS:VolumeUsage.gp3", line_item_operation="CreateVolume", line_item_unblended_cost=cost, line_item_usage_start_date=start, line_item_usage_end_date=end)
                data[name]["invoice_scope_records"].extend(normalize_v3({"source_id": source, "source_version": "v1", "records": [raw]})["records"])
                data[name]["source_proof"]["row_count"] += 1
                data[name]["source_proof"]["verified_row_count"] += 1
            data["measurement"]["invoices"][0]["native"]["BaseCurrencyAmount"]["TotalAmount"] = str(Decimal("340.44") + Decimal(post_cost))
        data = evidence(); add_volume(data)
        self.assertEqual(evaluate_v3(data)["verified_saving"], "5.160000000000")
        previous = evaluate_v3(data)
        for cost, new in (("60", False), ("30", True)):
            data = evidence(); add_volume(data, cost, new)
            result = evaluate_v3(data)
            self.assertEqual(result["reason_code"], "ALLOCATION_SCOPE_REQUIRED")
            self.assertEqual(result["claim_key"], previous["claim_key"])
            self.assertIsNone(result["verified_saving"])

    def test_full_source_can_have_other_currency_outside_invoice_scope(self):
        data = evidence()
        for name in ("baseline", "measurement"):
            part = data[name]
            raw = copy.deepcopy(part["billing_records"][0]["x_ProviderFields"])
            raw.update(identity_line_item_id="other-currency-line", line_item_resource_id="other-resource", line_item_currency_code="USD", product_servicecode="AmazonS3", product_product_family="Storage")
            part["source_scope_records"] = copy.deepcopy(part["invoice_scope_records"])
            part["source_scope_records"].extend(normalize_v3({"source_id": part["source_id"], "source_version": part["source_version"], "records": [raw]})["records"])
            part["source_proof"]["row_count"] += 1
            part["source_proof"]["verified_row_count"] += 1
        self.assertEqual(evaluate_v3(data)["status"], "VERIFIED")
        data["measurement"]["invoice_scope_records"].pop(0)
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_actual_startup_cost_can_produce_negative_verified_saving(self):
        data = evidence()
        post = data["measurement"]
        row = next(row for row in post["billing_records"] if row["ChargePeriodStart"] == stamp(RUNNING))
        row["x_ProviderFields"]["line_item_unblended_cost"] = "6"
        remap(data, "measurement")
        post["invoice_scope_records"] = normalize_v3({"source_id": post["source_id"], "source_version": post["source_version"], "records": [row["x_ProviderFields"] for row in post["invoice_scope_records"]]})["records"]
        post["invoices"][0]["native"]["BaseCurrencyAmount"]["TotalAmount"] = "346.32"
        result = evaluate_v3(data)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["verified_saving"], "-0.720000000000")

    def test_large_native_retained_proration_keeps_decimal_precision(self):
        raw = copy.deepcopy(_fixture()["baseline"]["billing_records"][0]["x_ProviderFields"])
        raw.update(identity_line_item_id="large-volume", line_item_resource_id="vol-large", product_product_family="Storage", line_item_usage_type="EU-EBS:VolumeUsage.gp3", line_item_operation="CreateVolume", line_item_unblended_cost="10000000000000000000000000.123456789012", line_item_usage_start_date=stamp(MONTH), line_item_usage_end_date="2026-10-01T00:00:00Z")
        part = {"source_id": "s", "source_version": "v1", "source_proof": source_proof("s", 1), "source_scope_records": normalize_v3({"source_id": "s", "source_version": "v1", "records": [raw]})["records"]}
        rows = _scope_retained(part, BINDING, MONTH, MONTH + timedelta(days=14), [])
        with localcontext() as context:
            context.prec = 60
            expected = Decimal(raw["line_item_unblended_cost"]) * Decimal(14) / Decimal(30)
        self.assertEqual(rows[0]["cost"], expected)

    def test_repeated_native_ids_in_disjoint_revisions_resolve_by_coverage(self):
        data = evidence("BASELINE")
        part = data["baseline"]
        records, proofs = [], []
        for index, source in enumerate(("revision-a", "revision-b")):
            raw = [copy.deepcopy(row["x_ProviderFields"]) for row in part["billing_records"][index * 672:(index + 1) * 672]]
            raw[0]["identity_line_item_id"] = "repeated-native-id"
            records.extend(normalize_v3({"source_id": source, "source_version": "v1", "records": raw})["records"])
            proof = source_proof(source, 672)
            proof.update(period_start=stamp(MONTH + timedelta(days=7 * index)), period_end=stamp(MONTH + timedelta(days=7 * (index + 1))))
            proofs.append(proof)
        part["billing_records"], part["invoice_scope_records"], part["source_proofs"] = records, copy.deepcopy(records), proofs
        part.pop("source_proof")
        self.assertTrue(evaluate_v3(data)["pre_execution_ready"])
        part["billing_observations"] = [{"start": row["ChargePeriodStart"], "end": row["ChargePeriodEnd"], "state": "OBSERVED", "source_record_ids": [row["x_SourceRecordId"]]} for row in records]
        part["billing_observations"][1]["source_record_ids"] = ["repeated-native-id"]
        with self.assertRaises(EvidenceError): evaluate_v3(data)

    def test_retired_inventory_does_not_erase_historical_payer_commitments(self):
        for phase, name, kind in (("BASELINE", "baseline", "SavingsPlanRecurringFee"), ("MEASUREMENT", "measurement", "RIFee")):
            data = evidence(phase); part = data[name]
            raw = copy.deepcopy(part["billing_records"][0]["x_ProviderFields"])
            raw.update(identity_line_item_id="historical-portfolio", line_item_resource_id="other-resource", line_item_usage_account_id="222222222222", product_region_code="us-west-2", line_item_currency_code="USD", bill_invoicing_entity="AWS Inc", line_item_line_item_type=kind, line_item_unblended_cost="10", line_item_usage_start_date=part["start"], line_item_usage_end_date=part["end"])
            part["source_scope_records"] = copy.deepcopy(part["invoice_scope_records"])
            part["source_scope_records"].extend(normalize_v3({"source_id": part["source_id"], "source_version": part["source_version"], "records": [raw]})["records"])
            part["source_proof"]["row_count"] += 1; part["source_proof"]["verified_row_count"] += 1
            self.assertEqual(part["commitment_scope"]["reserved_instance_count"], 0)
            self.assertEqual(part["commitment_scope"]["savings_plan_count"], 0)
            result = evaluate_v3(data)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["reason_code"], "HISTORICAL_COMMITMENT_EXPOSURE")
            self.assertIsNone(result["verified_saving"])

    def test_global_native_credit_reconciles_but_cannot_inflate_avoidable_savings(self):
        data = evidence(); part = data["measurement"]
        raw = copy.deepcopy(part["billing_records"][0]["x_ProviderFields"])
        raw.update(identity_line_item_id="global-credit", line_item_resource_id="", line_item_usage_account_id="222222222222", product_region_code="us-west-2", product_servicecode="AWSBilling", line_item_line_item_type="Credit", line_item_unblended_cost="-10", line_item_usage_start_date=part["start"], line_item_usage_end_date=part["end"])
        part["invoice_scope_records"].extend(normalize_v3({"source_id": part["source_id"], "source_version": part["source_version"], "records": [raw]})["records"])
        part["source_proof"]["row_count"] += 1; part["source_proof"]["verified_row_count"] += 1
        part["invoices"][0]["native"]["BaseCurrencyAmount"]["TotalAmount"] = "330.44"
        finalized, _ = _invoices(part, BINDING, POST, POST + timedelta(days=14), datetime(2026,10,2,tzinfo=timezone.utc))
        self.assertTrue(finalized)
        result = evaluate_v3(data)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reason_code"], "UNALLOCATED_FINANCIAL_ADJUSTMENT")
        self.assertIsNone(result["verified_saving"])

    def test_native_portfolio_guards_cover_aliases_and_require_disjoint_evidence(self):
        raw = copy.deepcopy(_fixture()["baseline"]["billing_records"][0]["x_ProviderFields"])
        for kind in ("DiscountedUsage", "RIFee", "SavingsPlanCoveredUsage", "SavingsPlanNegation", "SavingsPlanRecurringFee", "SavingsPlanUpfrontFee"):
            current = {**raw, "line_item_line_item_type": kind}
            rows = normalize_v3({"source_id":"s", "source_version":"v", "records":[current]})["records"]
            self.assertEqual(_native_scope_risk({"source_scope_records":rows},BINDING,MONTH,MONTH+timedelta(days=14)), "HISTORICAL_COMMITMENT_EXPOSURE")
        for kind in ("Credit", "Refund", "Discount", "BundledDiscount"):
            current = {**raw, "line_item_line_item_type":kind}
            rows = normalize_v3({"source_id":"s", "source_version":"v", "records":[current]})["records"]
            self.assertEqual(_native_scope_risk({"source_scope_records":rows},BINDING,MONTH,MONTH+timedelta(days=14)), "UNALLOCATED_FINANCIAL_ADJUSTMENT")
            self.assertIsNone(_native_scope_risk({"source_scope_records":rows},BINDING,POST,POST+timedelta(days=14)))
        current = {**raw, "reservation/ReservationARN":"arn:aws:ec2:us-west-2:222222222222:reserved-instances/example"}
        rows = normalize_v3({"source_id":"s", "source_version":"v", "records":[current]})["records"]
        self.assertEqual(_native_scope_risk({"source_scope_records":rows},BINDING,MONTH,MONTH+timedelta(days=14)), "HISTORICAL_COMMITMENT_EXPOSURE")


if __name__ == "__main__": unittest.main()
