"""Inspect the optional receipt observer's rendered isolation boundaries."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

RENDERED = sys.argv.pop(1) if len(sys.argv) > 1 else None
spec = importlib.util.spec_from_file_location("chart_boundary", Path(__file__).resolve().parents[1] / "check_chart.py")
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


@unittest.skipUnless(RENDERED, "supply an actual rendered fleet chart")
class ObserverChartBoundaries(unittest.TestCase):
    def setUp(self):
        with open(RENDERED, encoding="utf-8-sig") as source:
            self.docs = [doc for doc in yaml.safe_load_all(source) if doc]

    def env(self, role):
        deployment = next(d for d in self.docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "finops-" + role)
        return deployment["spec"]["template"]["spec"]["containers"][0]["env"]

    def check(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "rendered.yaml"
            file.write_text(yaml.safe_dump_all(self.docs), encoding="utf-8")
            boundary.check(file)

    def test_valid_receipt_observer(self):
        self.check()

    def test_observer_cannot_use_console_audience(self):
        next(e for e in self.env("deployment-observer") if e["name"] == "DEPLOYMENT_OIDC_AUDIENCE")["value"] = "finops"
        with self.assertRaises(AssertionError):
            self.check()

    def test_observer_cannot_sign_or_execute(self):
        executor = next(e for e in self.env("executor") if e["name"] == "EXECUTOR_TOKEN")
        self.env("deployment-observer").append(copy.deepcopy(executor))
        with self.assertRaises(AssertionError):
            self.check()

    def test_observer_cannot_share_worker_database(self):
        worker = next(e for e in self.env("worker") if e["name"] == "DATABASE_URL")
        observer = next(e for e in self.env("deployment-observer") if e["name"] == "DATABASE_URL")
        observer["valueFrom"] = copy.deepcopy(worker["valueFrom"])
        with self.assertRaises(AssertionError):
            self.check()

    def test_observer_cannot_gain_unrestricted_https(self):
        policy = next(d for d in self.docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "finops-deployment-observer-egress")
        policy["spec"]["egress"].append({"ports": [{"protocol": "TCP", "port": 443}]})
        with self.assertRaises(AssertionError):
            self.check()

    def test_observer_cannot_assume_aws_identity(self):
        account = next(d for d in self.docs if d["kind"] == "ServiceAccount" and d["metadata"]["name"] == "finops-deployment-observer")
        account["metadata"]["annotations"] = {"eks.amazonaws.com/role-arn": "arn:aws:iam::111122223333:role/forbidden"}
        with self.assertRaises(AssertionError):
            self.check()


if __name__ == "__main__":
    unittest.main()
