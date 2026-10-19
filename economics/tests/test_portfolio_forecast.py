"""Synthetic historical unit data; no provider or operational acceptance claim."""
import copy
from datetime import timedelta
import unittest

from autopilot.portfolio import EvidenceError, analysis_hash, stamp
from autopilot.portfolio_forecast import (produce, TRAIN_HOURS, STRIDE_HOURS,
                                         CALIBRATION_ORIGINS, VALIDATION_ORIGINS, MODEL_SHA256)
from test_portfolio_decision import fixture, iso, ref


def historical(value="10", extra_hours=0):
    decision = fixture()
    end = stamp(decision["observed_at"])
    count = TRAIN_HOURS+2*8760+STRIDE_HOURS*(CALIBRATION_ORIGINS+VALIDATION_ORIGINS-2)+extra_hours
    native_ref = ref("AWS_CUR2", "synthetic-historical")
    dims = decision["usage"][0]["dimensions"]
    history = []
    for index in range(count):
        start = end-timedelta(hours=count-index)
        history.append({"period": {"start": iso(start), "end": iso(start+timedelta(hours=1))},
                        "dimensions": dims, "usage_amount": value,
                        "configuration_sha256": decision["scope"]["configuration_sha256"], "native_ref": native_ref})
    return {"schema_version": "2", "request_id": "unit-forecast-production", "scope": decision["scope"],
            "observed_at": decision["observed_at"], "optimization_order": decision["optimization_order"][:-1],
            "input_refs": decision["input_refs"]+[native_ref], "history": history}


class ForecastTests(unittest.TestCase):
    def test_actual_full_term_backtests_produce_bounded_explainable_forecast(self):
        data = historical()
        out = produce(data)
        self.assertEqual(out["status"], "CALIBRATED")
        self.assertEqual(len(out["hours"]), 8760)
        self.assertEqual(out["calibration"]["horizon_hours"], 8760)
        self.assertEqual(out["calibration"]["observed_coverage"], "1")
        self.assertEqual(out["calibration"]["model_sha256"], MODEL_SHA256)
        self.assertTrue(all(h["lower_usage"] == h["expected_usage"] == h["upper_usage"] == "10" for h in out["hours"]))
        self.assertIn("DEPENDENT_ROLLING_ORIGIN_EMPIRICAL_PATH_COVERAGE", out["reason_codes"])
        self.assertEqual(out["id"], analysis_hash({**out, "id": ""}))

    def test_zero_history_is_known_zero_and_missing_interval_stays_unknown(self):
        data = historical("0")
        out = produce(data)
        self.assertEqual(out["status"], "CALIBRATED")
        self.assertTrue(all(h["upper_usage"] == "0" for h in out["hours"]))
        data["history"].pop(100)
        out = produce(data)
        self.assertEqual(out["status"], "UNAVAILABLE")
        self.assertIn("NATIVE_FORECAST_INTERVALS_MISSING", out["reason_codes"])

    def test_short_history_does_not_claim_full_year_calibration(self):
        data = historical()
        data["history"] = data["history"][-90*24:]
        out = produce(data)
        self.assertEqual(out["status"], "UNAVAILABLE")
        self.assertIn("FULL_TERM_CALIBRATION_HISTORY_INADEQUATE", out["reason_codes"])
        self.assertIsNone(out["calibration"])

    def test_native_billing_lag_is_backtested_and_capped_at_48hours(self):
        data = historical(extra_hours=98)
        observed = stamp(data["observed_at"])+timedelta(hours=48)
        data["observed_at"] = iso(observed)
        data["scope"]["projection_period"] = {"start": iso(observed), "end": iso(observed+timedelta(hours=8760))}
        data["scope"]["sha256"] = analysis_hash({**data["scope"], "sha256": ""})
        for stage in data["optimization_order"]:
            stage["scope_sha256"] = data["scope"]["sha256"]
        out = produce(data)
        self.assertEqual(out["status"], "CALIBRATED")
        self.assertEqual(out["hours"][0]["period"]["start"], iso(observed))
        data["observed_at"] = iso(observed+timedelta(seconds=1))
        data["scope"]["projection_period"] = {"start": iso(observed+timedelta(hours=1)), "end": iso(observed+timedelta(hours=8761))}
        data["scope"]["sha256"] = analysis_hash({**data["scope"], "sha256": ""})
        for stage in data["optimization_order"]:
            stage["scope_sha256"] = data["scope"]["sha256"]
        self.assertIn("LATEST_NATIVE_FORECAST_HISTORY_GAP", produce(data)["reason_codes"])

    def test_pre_rightsize_history_and_cross_scope_sources_cannot_be_forecast(self):
        data = historical()
        data["history"][0]["configuration_sha256"] = "c"*64
        self.assertIn("PRE_OPTIMIZATION_CONFIGURATION_HISTORY_REJECTED", produce(data)["reason_codes"])
        data = historical()
        data["input_refs"].pop()
        with self.assertRaises(EvidenceError): produce(data)
        data = historical()
        data["history"][0]["dimensions"] = {**data["history"][0]["dimensions"], "account_id": "444455556666"}
        with self.assertRaises(EvidenceError): produce(data)

    def test_duplicate_intervals_and_caller_bounds_are_rejected(self):
        data = historical(); data["history"].append(data["history"][0])
        with self.assertRaises(EvidenceError): produce(data)
        data = historical(); data["calibration"] = {"complete": True}
        with self.assertRaises(EvidenceError): produce(data)

    def test_future_demand_spike_is_heldout_and_can_fail_calibration(self):
        data = historical()
        # Neither training nor calibration sees this fourfold change. The
        # validation path genuinely contains it; no error fitting to validation.
        for item in data["history"][-8760:]:
            item["usage_amount"] = "40"
        out = produce(data)
        self.assertEqual(out["status"], "UNAVAILABLE")
        self.assertIn("FULL_TERM_HELDOUT_COVERAGE_UNCALIBRATED", out["reason_codes"])


if __name__ == "__main__":
    unittest.main()
