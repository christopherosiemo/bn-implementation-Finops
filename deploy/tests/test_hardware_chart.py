"""Positive and credential/network confusion tests on actual Helm output."""
import copy
import importlib.util
import os
import sys
import tempfile
import unittest
import yaml

spec = importlib.util.spec_from_file_location("chart_checker", os.path.join(os.path.dirname(__file__), "..", "check_chart.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
with open(sys.argv.pop(1), encoding="utf-8") as source:
    original = list(yaml.safe_load_all(source))

class HardwareChart(unittest.TestCase):
    def verify(self, manifests):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as destination:
            yaml.safe_dump_all(manifests, destination)
            filename = destination.name
        try:
            checker.check(filename)
        finally:
            os.unlink(filename)

    def test_actual_rendered_isolation(self):
        self.verify(original)

    def test_execution_signing_database_and_network_confusion_fail(self):
        for confusion in ("signing", "execution", "plain_execution_token", "plain_signing_key", "static_aws", "database", "irsa", "world_egress", "broad_https", "any_database", "public_database", "shared_database", "any_port"):
            with self.subTest(confusion=confusion):
                documents = copy.deepcopy(original)
                find = lambda kind, name: next(d for d in documents if d and d["kind"] == kind and d["metadata"]["name"] == name)
                env = find("Deployment", "finops-hardware-reader")["spec"]["template"]["spec"]["containers"][0]["env"]
                if confusion == "signing":
                    env.append({"name": "SIGNING_PRIVATE_KEY", "valueFrom": {"secretKeyRef": {"name": "wrong", "key": "SIGNING_PRIVATE_KEY"}}})
                elif confusion == "execution":
                    env.append({"name": "AWS_EXECUTION_ROLE_ARN", "value": "arn:aws:iam::123456789012:role/wrong"})
                elif confusion == "plain_execution_token":
                    env.append({"name": "EXECUTOR_TOKEN", "value": "fixture-invalid"})
                elif confusion == "plain_signing_key":
                    env.append({"name": "SIGNING_PRIVATE_KEY", "value": "fixture-invalid"})
                elif confusion == "static_aws":
                    env.append({"name": "AWS_ACCESS_KEY_ID", "value": "fixture-invalid"})
                elif confusion == "database":
                    next(e for e in env if e["name"] == "DATABASE_URL")["valueFrom"]["secretKeyRef"]["name"] = "finops-db-api"
                elif confusion == "irsa":
                    find("ServiceAccount", "finops-hardware-reader")["metadata"]["annotations"]["eks.amazonaws.com/role-arn"] = "arn:aws:iam::123456789012:role/finops-pilot-ingester"
                elif confusion == "world_egress":
                    find("NetworkPolicy", "finops-hardware-reader-egress")["spec"]["egress"][-1]["to"] = [{"ipBlock": {"cidr": "0.0.0.0/0"}}]
                elif confusion == "broad_https":
                    find("NetworkPolicy", "finops-dns-and-https")["spec"]["podSelector"]["matchExpressions"][0]["values"].remove("hardware-reader")
                elif confusion == "any_database":
                    find("NetworkPolicy", "finops-hardware-reader-egress")["spec"]["egress"][1].pop("to")
                elif confusion == "public_database":
                    find("NetworkPolicy", "finops-hardware-reader-egress")["spec"]["egress"][1]["to"] = [{"ipBlock": {"cidr": "8.8.8.0/24"}}]
                elif confusion == "shared_database":
                    find("NetworkPolicy", "finops-postgres-egress")["spec"]["podSelector"]["matchExpressions"][0]["values"].append("hardware-reader")
                elif confusion == "any_port":
                    find("NetworkPolicy", "finops-hardware-reader-egress")["spec"]["egress"][1].pop("ports")
                with self.assertRaises(AssertionError):
                    self.verify(documents)

if __name__ == "__main__":
    unittest.main()
