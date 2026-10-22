"""Unit doubles for private resolver output, never issued acceptance evidence."""
import copy
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
import unittest

from autopilot.portfolio import EvidenceError, STAGES, analysis_hash
from autopilot.portfolio_decision import evaluate, money, OFFER_VALIDITY_BASIS


def ref(kind, identity):
    return {"kind": kind, "id": "unit-"+identity, "sha256": analysis_hash(identity)}


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def fixture():
    from autopilot.portfolio_forecast import MODEL_SHA256
    start = datetime(2026, 10, 19, tzinfo=timezone.utc)
    history = {"start": iso(start-timedelta(days=1)), "end": iso(start)}
    projection = {"start": iso(start), "end": iso(start+timedelta(hours=8760))}
    cur, inv = ref("AWS_CUR2", "billing"), ref("AWS_COMMITMENT", "inventory")
    owner, offer_ref = ref("HISTORICAL_OWNERSHIP", "owner"), ref("AWS_SAVINGS_PLAN_OFFER", "offer")
    rate_ref = ref("AWS_SAVINGS_PLAN_OFFER_RATE", "offer-rate")
    forecast_ref, calibration_ref = ref("POST_OPTIMIZATION_FORECAST", "forecast"), ref("FORECAST_CALIBRATION", "calibration")
    refs = [cur, inv, owner, offer_ref, rate_ref, forecast_ref, calibration_ref]
    scope = {"tenant_id": "unit-tenant", "workload_id": "unit-workload", "payer_account_id": "111122223333",
             "usage_account_ids": ["111122223333"], "resource_ids": ["i-0123456789abcdef0"],
             "class": "COMPUTE_SAVINGS_PLAN", "currency": "USD", "configuration_sha256": "a"*64,
             "ownership_ref": owner, "history_period": history, "projection_period": projection, "sha256": ""}
    scope["sha256"] = analysis_hash(scope)
    dims = {"account_id": "111122223333", "service_code": "AmazonEC2", "product_type": "EC2",
            "usage_type": "EU-BoxUsage:m6i.large", "operation": "RunInstances", "region": "eu-west-1",
            "instance_type": "m6i.large", "instance_family": "m6i", "product_description": "Linux/UNIX",
            "tenancy": "Shared", "unit": "Hrs", "currency": "USD"}
    usage = []
    for n in range(24):
        a = start-timedelta(hours=24-n)
        usage.append({"id": "unit-line-"+str(n), "period": {"start": iso(a), "end": iso(a+timedelta(hours=1))},
                      "dimensions": dims, "kind": "Usage", "commitment_id": None, "usage_amount": "10",
                      "billed_cost": "2", "billed_cost_basis": "NATIVE_NET_UNBLENDED_COST", "net_usage_cost": "2",
                      "on_demand_equivalent_cost": "2.5", "on_demand_basis": "NATIVE_UNBLENDED_ON_DEMAND_EQUIVALENT",
                      "allocated_cost": None, "allocated_cost_basis": None, "contract_rate": None, "native_ref": cur})
    portfolio = {"id": "", "request_id": "unit-portfolio", "selection": {"period": history},
                 "input_refs": [cur, inv], "inventory_status": "COMPLETE_POINT_IN_TIME", "positions": [], "partitions": []}
    portfolio["id"] = analysis_hash(portfolio)
    refs.append({"kind": "COMMITMENT_PORTFOLIO_ANALYSIS", "id": portfolio["request_id"], "sha256": analysis_hash(portfolio)})
    stages = []
    for index, stage in enumerate(STAGES):
        decision_ref, outcome_ref = ref("OPTIMIZATION_DECISION", "stage-"+str(index)), ref("OPTIMIZATION_OUTCOME", "outcome-"+str(index))
        refs += [decision_ref, outcome_ref]
        stages.append({"stage": stage, "disposition": "EVIDENCED_NO_CHANGE", "decision_ref": decision_ref,
                       "outcome_ref": outcome_ref, "scope_sha256": scope["sha256"], "completed_at": iso(start), "reason_codes": []})
    calibration = {"target": "TERM_UTILIZATION_AND_NET_COST", "horizon_hours": 8760, "backtest_origin_count": 12,
                   "method": "ROLLING_ORIGIN_TERM_BLOCK_V1", "model_version": "commitment-stable-floor-v1", "model_sha256": MODEL_SHA256,
                   "training_period": {"start": "2024-01-01T00:00:00Z", "end": "2024-10-19T00:00:00Z"},
                   "holdout_period": {"start": "2024-10-19T00:00:00Z", "end": iso(start)},
                   "sample_count": 12, "nominal_coverage": "0.9", "observed_coverage": "1", "scope_sha256": scope["sha256"],
                   "native_ref": calibration_ref}
    hours = [{"period": {"start": iso(start+timedelta(hours=n)), "end": iso(start+timedelta(hours=n+1))},
              "dimensions": dims, "expected_usage": "10", "lower_usage": "8", "upper_usage": "12"} for n in range(8760)]
    return {"schema_version": "2", "request_id": "unit-decision",
            "selection": {"portfolio_analysis_request_id": "unit-portfolio", "offer_receipt_id": "unit-offer",
                          "post_optimization_assessment_id": "unit-optimization", "forecast_id": "unit-forecast"},
            "scope": scope, "portfolio": portfolio, "usage_status": "COMPLETE_OBSERVED_ELIGIBLE_WINDOW", "usage": usage,
            "contract_rates": [], "contract_rate_status": "COMPLETE_NATIVE_PLAN_RATE_SETS", "contract_rate_plan_ids": [], "contract_rate_refs": [],
            "offer": {"id": "unit-offer", "native_offering_id": "unit-native-offering", "class": "COMPUTE_SAVINGS_PLAN", "currency": "USD", "payment_option": "No Upfront",
                      "duration_seconds": "31536000", "effective_period": {"start": iso(start), "end": iso(start+timedelta(minutes=5))},
                      "validity_basis": OFFER_VALIDITY_BASIS,
                      "rates": [{"dimensions": dims, "rate": "0.12", "native_ref": rate_ref}], "native_ref": offer_ref},
            "payg_basis": [{"dimensions": dims, "observed_period": usage[-1]["period"], "rate": "0.2",
                            "basis": "CURRENT_NATIVE_NET_USAGE_COST_PER_UNIT", "source_line_ids": [usage[-1]["id"]], "native_refs": [cur]}],
            "optimization_order": stages, "forecast": {"id": "unit-forecast", "scope_sha256": scope["sha256"], "recalculated_at": iso(start),
                                                        "hours": hours, "calibration": calibration, "native_ref": forecast_ref},
            "input_refs": refs, "observed_at": iso(start), "reason_codes": []}


class DecisionTests(unittest.TestCase):
    @staticmethod
    def refresh_portfolio(data):
        data["portfolio"]["id"] = analysis_hash({**data["portfolio"], "id": ""})
        for reference in data["input_refs"]:
            if reference["kind"] == "COMMITMENT_PORTFOLIO_ANALYSIS":
                reference["sha256"] = analysis_hash(data["portfolio"])

    def test_explainable_positive_advice_never_grants_purchase_or_savings_authority(self):
        result = evaluate(fixture())
        self.assertEqual(result["status"], "RECOMMEND_PURCHASE_PENDING_FINANCE")
        self.assertEqual(result["proposed_hourly_commitment"]["value"], "0.96")
        self.assertEqual(result["proposed_term_obligation"]["value"], "8409.6")
        self.assertEqual(result["expected_savings"]["value"], "5606.4")
        self.assertEqual(result["break_even_utilization"]["value"], "0.6")
        self.assertEqual(result["cash_requirement"]["value"], "0")
        self.assertEqual(result["remaining_contractual_obligation"]["value"], "0")
        self.assertEqual(result["paid_unamortized_value"]["value"], "0")
        self.assertEqual(result["price_change_stress"]["break_even_payg_rate_drop_fraction"], "0.4")
        self.assertIsNone(result["verified_saving"])
        self.assertFalse(result["purchase_authorized"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["id"], analysis_hash({**result, "id": ""}))

    def test_expensive_native_offer_and_zero_net_price_preserve_negative_results(self):
        for payg_rate in ("0.2", "0"):
            with self.subTest(payg_rate=payg_rate):
                data = fixture()
                data["offer"]["rates"][0]["rate"] = "0.3"
                data["payg_basis"][0]["rate"] = payg_rate
                data["usage"][-1]["net_usage_cost"] = "2" if payg_rate == "0.2" else "0"
                out = evaluate(data)
                self.assertEqual(out["status"], "DO_NOT_PURCHASE")
                self.assertLess(Decimal(out["expected_savings"]["value"]), 0)

    def test_quote_read_freshness_is_not_a_promised_future_price_window(self):
        data = fixture()
        for span in [data["scope"]["projection_period"]] + [row["period"] for row in data["forecast"]["hours"]]:
            for key in ("start", "end"):
                span[key] = iso(datetime.fromisoformat(span[key].replace("Z", "+00:00"))+timedelta(hours=1))
        data["scope"]["sha256"] = analysis_hash({**data["scope"], "sha256": ""})
        for stage in data["optimization_order"]:
            stage["scope_sha256"] = data["scope"]["sha256"]
        data["forecast"]["scope_sha256"] = data["scope"]["sha256"]
        data["forecast"]["calibration"]["scope_sha256"] = data["scope"]["sha256"]
        out = evaluate(data)
        self.assertEqual(out["status"], "RECOMMEND_PURCHASE_PENDING_FINANCE")
        self.assertEqual(out["forward_price_assumption"], "HELD_CURRENT_NATIVE_NET_RATE")
        data["observed_at"] = iso(datetime.fromisoformat(data["observed_at"].replace("Z", "+00:00"))+timedelta(minutes=6))
        self.assertEqual(evaluate(data)["status"], "BLOCKED")
        data = fixture()
        data["offer"]["validity_basis"] = "NATIVE_PROVIDER_GUARANTEED_PRICE"
        self.assertEqual(evaluate(data)["status"], "BLOCKED")

    def test_missing_coverage_pre_rightsize_baseline_and_missing_stages_block(self):
        mutations = [lambda d: d.update(usage_status="PARTIAL"),
                     lambda d: d["portfolio"].update(inventory_status="PARTIAL"),
                     lambda d: d["optimization_order"][2].update(disposition="BLOCKED"),
                     lambda d: d["optimization_order"].pop(1),
                     lambda d: d["forecast"].update(recalculated_at="2026-10-18T23:59:59Z"),
                     lambda d: d["forecast"].update(calibration=None)]
        for change in mutations:
            data = fixture(); change(data)
            self.refresh_portfolio(data)
            self.assertEqual(evaluate(data)["status"], "BLOCKED")

    def test_scope_ref_and_net_amount_mismatches_are_refused(self):
        mutations = [lambda d: d["scope"].update(currency="EUR"),
                     lambda d: d["usage"][0]["dimensions"].update(account_id="444455556666"),
                     lambda d: d["usage"][-1].update(net_usage_cost="3"),
                     lambda d: d["payg_basis"][0].update(source_line_ids=["missing"]),
                     lambda d: d["input_refs"].remove(d["offer"]["rates"][0]["native_ref"]),
                     lambda d: d["forecast"]["hours"].pop(4)]
        for change in mutations:
            data = fixture(); change(data)
            with self.assertRaises(EvidenceError): evaluate(data)

    def test_no_older_or_gross_price_substitution_and_no_mixed_coverage_basis(self):
        for change in (lambda d: d["usage"][-1].update(net_usage_cost=None),
                       lambda d: d["payg_basis"][0].update(observed_period=d["usage"][-2]["period"]),
                       lambda d: d["usage"][-1].update(billed_cost_basis="NATIVE_UNBLENDED_COST")):
            data = fixture(); change(data)
            with self.assertRaises(EvidenceError): evaluate(data)
        data = fixture()
        data["usage"][0]["on_demand_basis"] = "NATIVE_NET_ON_DEMAND_EQUIVALENT"
        out = evaluate(data)
        self.assertIsNone(out["observed_coverage"]["value"])

    def test_deteriorating_demand_and_stranded_existing_commitment_prevent_overbuy(self):
        data = fixture()
        for hour in data["forecast"]["hours"]:
            hour.update(lower_usage="0", expected_usage="0", upper_usage="0")
        out = evaluate(data)
        self.assertEqual(out["status"], "DO_NOT_PURCHASE")
        self.assertEqual(out["proposed_hourly_commitment"]["value"], "0")
        data = fixture()
        p = {"id": "existing", "class": "COMPUTE_SAVINGS_PLAN", "state": "active", "start": "2026-01-01T00:00:00Z",
             "end": "2028-01-01T00:00:00Z", "currency": "USD", "hourly_commitment": "2", "payment_option": "No Upfront", "upfront_amount": "0"}
        data["portfolio"]["positions"] = [{"position": p}]
        data["portfolio"]["partitions"] = [{"currency": "USD", "observed_unused_commitment": "24"}]
        self.refresh_portfolio(data)
        rate_ref = ref("AWS_SAVINGS_PLAN_RATES", "existing-rates")
        data["contract_rates"] = [{"plan_id": "existing", "dimensions": data["usage"][0]["dimensions"], "rate": "0.1", "native_ref": rate_ref}]
        data["contract_rate_plan_ids"] = ["existing"]; data["contract_rate_refs"] = [rate_ref]; data["input_refs"].append(rate_ref)
        out = evaluate(data)
        self.assertEqual(out["status"], "DO_NOT_PURCHASE")
        self.assertEqual(out["observed_unused_exposure"]["value"], "24")
        self.assertEqual(out["paid_unamortized_value"]["value"], "0")
        self.assertGreater(Decimal(out["remaining_contractual_obligation"]["value"]), 0)

    def test_unsupported_amortization_or_term_calibration_remains_unavailable(self):
        data = fixture()
        data["forecast"]["calibration"]["target"] = "HOUR_POINT_COVERAGE"
        self.assertEqual(evaluate(data)["status"], "BLOCKED")
        data = fixture()
        data["forecast"]["calibration"]["sample_count"] = True
        self.assertEqual(evaluate(data)["status"], "BLOCKED")

    def test_decimal_policy_rounds_only_final_values_and_refuses_storage_overflow(self):
        with localcontext() as context:
            context.prec = 80
            self.assertEqual(money(Decimal("1.0000000000005")), "1")
            self.assertEqual(money(Decimal("1.0000000000015")), "1.000000000002")
            with self.assertRaises(EvidenceError): money(Decimal("1e26"))


if __name__ == "__main__":
    unittest.main()
