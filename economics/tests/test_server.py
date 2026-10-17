import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from autopilot.server import Handler
from test_v2 import evidence


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
        request = Request(self.url, data=json.dumps(evidence("BASELINE")).encode(), headers={"Content-Type": "application/json"})
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "local-test-only"}):
            with self.assertRaises(HTTPError) as caught: urlopen(request)
            self.assertEqual(caught.exception.code, 401)
            request.add_header("Authorization", "Bearer local-test-only")
            with urlopen(request) as response:
                result = json.load(response)
            self.assertTrue(result["pre_execution_ready"])
            self.assertIsNone(result["verified_saving"])

    def test_invalid_v2_never_falls_back_to_legacy(self):
        request = Request(self.url, data=b'{"schema_version":"1"}', headers={"Authorization": "Bearer local-test-only", "Content-Type": "application/json"})
        with patch.dict("os.environ", {"ECONOMICS_TOKEN": "local-test-only"}):
            with self.assertRaises(HTTPError) as caught: urlopen(request)
            self.assertEqual(caught.exception.code, 422)


if __name__ == "__main__": unittest.main()
