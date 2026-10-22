"""Real loopback HTTP contract, synthetic model input, no source trust credit."""
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from autopilot.portfolio_server import Handler
from test_portfolio import fixture as observed_fixture
from test_portfolio_decision import fixture, ref
from test_portfolio_forecast import historical


class ModelHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.model_token = b"unit-dedicated-portfolio-model-token"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def call(self, route, data, token="unit-dedicated-portfolio-model-token"):
        raw = json.dumps(data, separators=(",", ":")).encode() if not isinstance(data, bytes) else data
        request = Request(self.url+route, data=raw, headers={"Content-Type": "application/json", "Authorization": "Bearer "+token})
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    def test_additive_routes_use_same_dedicated_token_and_preserve_v5(self):
        old = self.call("/v5/commitment-portfolio", observed_fixture())
        self.assertEqual(old["schema_version"], "1")
        self.assertEqual(old["recommendation_status"], "BLOCKED")
        for route in ("/v5/commitment-portfolio", "/v6/commitment-forecast", "/v6/commitment-decision"):
            with self.assertRaises(HTTPError) as caught:
                self.call(route, {}, "unit-console-token")
            self.assertEqual(caught.exception.code, 401)
            with self.assertRaises(HTTPError) as caught:
                self.call(route, b'{"schema_version":"2","schema_version":"1"}')
            self.assertEqual(caught.exception.code, 422)

    def test_numerical_production_then_decision_uses_actual_returned_bounds(self):
        # Emulate only the private Go receipt envelope here. Issuance/currentness
        # and Finance authority require independent persisted integration tests.
        produced = self.call("/v6/commitment-forecast", historical())
        self.assertEqual(produced["status"], "CALIBRATED")
        decision = fixture()
        calibration = {**produced["calibration"], "native_ref": ref("FORECAST_CALIBRATION", "produced-calibration")}
        decision["forecast"].update(hours=produced["hours"], calibration=calibration)
        decision["input_refs"].append(calibration["native_ref"])
        out = self.call("/v6/commitment-decision", decision)
        self.assertEqual(out["status"], "RECOMMEND_PURCHASE_PENDING_FINANCE")
        self.assertEqual(out["proposed_hourly_commitment"]["value"], "1.2")
        self.assertEqual(out["expected_savings"]["value"], "7008")
        self.assertFalse(out["purchase_authorized"])
        self.assertFalse(out["execution_authorized"])
        self.assertIsNone(out["verified_saving"])


if __name__ == "__main__":
    unittest.main()
