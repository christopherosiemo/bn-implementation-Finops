"""Security regressions against an actual rendered chart, never values/secrets."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

RENDERED = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NATIVE_CHART_RENDERED")
if len(sys.argv) > 1:
    del sys.argv[1]
spec = importlib.util.spec_from_file_location("chart_boundary", Path(__file__).resolve().parents[1] / "check_chart.py")
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


@unittest.skipUnless(RENDERED, "supply the rendered native chart")
class NativeChartBoundaries(unittest.TestCase):
    def setUp(self):
        with open(RENDERED, encoding="utf-8-sig") as source:
            self.docs = [doc for doc in yaml.safe_load_all(source) if doc]

    def deployment(self, role):
        return next(doc for doc in self.docs if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "finops-" + role)["spec"]["template"]["spec"]["containers"][0]

    def check(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "rendered.yaml"
            file.write_text(yaml.safe_dump_all(self.docs), encoding="utf-8")
            boundary.check(file)

    def test_native_render_preserves_boundaries(self):
        self.check()

    def test_ingress_cannot_receive_private_reader_token(self):
        token = next(row for row in self.deployment("telemetry-reader")["env"] if row["name"] == "TELEMETRY_READER_TOKEN")
        self.deployment("telemetry-ingress")["env"].append(copy.deepcopy(token))
        with self.assertRaises(AssertionError):
            self.check()

    def test_native_transport_cannot_share_api_database_identity(self):
        api = next(row for row in self.deployment("api")["env"] if row["name"] == "DATABASE_URL")
        target = next(row for row in self.deployment("telemetry-reader")["env"] if row["name"] == "DATABASE_URL")
        target["valueFrom"] = copy.deepcopy(api["valueFrom"])
        with self.assertRaises(AssertionError):
            self.check()

    def test_native_cannot_gain_executor_token(self):
        token = next(row for row in self.deployment("executor")["env"] if row["name"] == "EXECUTOR_TOKEN")
        self.deployment("telemetry-reader")["env"].append(copy.deepcopy(token))
        with self.assertRaises(AssertionError):
            self.check()

    def test_native_reader_network_accepts_only_api(self):
        policy = next(doc for doc in self.docs if doc["kind"] == "NetworkPolicy" and doc["metadata"]["name"] == "finops-native-reader-ingress")
        policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["finops-role"] = "worker"
        with self.assertRaises(AssertionError):
            self.check()

    def test_native_https_cannot_become_world_open(self):
        policy = next(doc for doc in self.docs if doc["kind"] == "NetworkPolicy" and doc["metadata"]["name"] == "finops-native-egress")
        policy["spec"]["egress"].append({"ports": [{"protocol": "TCP", "port": 443}]})
        with self.assertRaises(AssertionError):
            self.check()


if __name__ == "__main__":
    unittest.main()
