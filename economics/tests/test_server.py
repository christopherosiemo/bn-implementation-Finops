import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from autopilot.server import Handler
from test_v2 import evidence
from test_v3 import evidence as evidence_v3


class WorkerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v2/evaluate"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_versioned_route_requires_worker_identity(self):
        # Early authentication rejection can close the socket while a client is
        # still uploading a large body. Keep the unauthenticated probe bounded.
        unauthorized = Request(self.url, data=b'{}', headers={"Content-Type": "application/json"})
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "local-test-only"}):
            with self.assertRaises(HTTPError) as caught: urlopen(unauthorized)
            self.assertEqual(caught.exception.code, 401)
            request = Request(self.url, data=json.dumps(evidence("BASELINE")).encode(), headers={"Authorization": "Bearer local-test-only", "Content-Type": "application/json"})
            with urlopen(request) as response:
                result = json.load(response)
            self.assertTrue(result["pre_execution_ready"])
            self.assertIsNone(result["verified_saving"])

    def test_invalid_v2_never_falls_back_to_legacy(self):
        request = Request(self.url, data=b'{"schema_version":"1"}', headers={"Authorization": "Bearer local-test-only", "Content-Type": "application/json"})
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "local-test-only"}):
            with self.assertRaises(HTTPError) as caught: urlopen(request)
            self.assertEqual(caught.exception.code, 422)

    def test_v3_additive_route_and_existing_versioned_dispatch(self):
        for route in ("/v3/evaluate", "/v2/evaluate"):
            request = Request(self.url.replace("/v2/evaluate", route), data=json.dumps(evidence_v3("BASELINE")).encode(), headers={"Authorization": "Bearer local-test-only", "Content-Type": "application/json"})
            with patch.dict("os.environ", {"ECONOMICS_TOKEN": "local-test-only"}):
                with urlopen(request) as response:
                    result = json.load(response)
            self.assertTrue(result["pre_execution_ready"])
            self.assertEqual(result["schema_version"], "3")

    def test_native_normalization_route_does_not_invent_contracted_cost(self):
        raw = evidence_v3("BASELINE")["baseline"]["billing_records"][0]["x_ProviderFields"]
        request = Request(self.url.replace("/v2/evaluate", "/v3/normalize"), data=json.dumps({"source_id": "source", "source_version": "version", "records": [raw]}).encode(), headers={"Authorization": "Bearer local-test-only", "Content-Type": "application/json"})
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "local-test-only"}):
            with urlopen(request) as response:
                result = json.load(response)
        self.assertIsNone(result["records"][0]["ContractedCost"])
        self.assertEqual(result["records"][0]["x_PricingBasis"], "UNBLENDED")


if __name__ == "__main__": unittest.main()
