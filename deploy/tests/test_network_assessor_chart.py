"""Inspect existing default/optional Helm renders. No provider calls."""
import sys
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_chart import selector_matches

def load(path):
    with open(path, encoding="utf-8") as source:
        return [row for row in yaml.safe_load_all(source) if row]

default, enabled = map(load, sys.argv[1:3])
role, name = "network-assessor", "finops-network-assessor"
assert not any(row["metadata"]["name"].startswith(name) for row in default)
deployment = next(row for row in enabled if row["kind"] == "Deployment" and row["metadata"]["name"] == name)
account = next(row for row in enabled if row["kind"] == "ServiceAccount" and row["metadata"]["name"] == name)
pod = deployment["spec"]["template"]["spec"]
container = pod["containers"][0]
env = {row["name"]: row for row in container["env"]}
assert set(env) == {"APP_ROLE", "PORT", "FIXTURE_MODE", "DATABASE_URL", "ECONOMICS_URL", "ECONOMICS_TOKEN", "OBJECT_ENDPOINT", "OBJECT_REGION", "OBJECT_BUCKET_RAW", "OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY"}
assert env["APP_ROLE"]["value"] == role and env["FIXTURE_MODE"]["value"] == "false"
assert env["OBJECT_REGION"]["value"] == "eu-west-1"
assert env["OBJECT_ENDPOINT"]["value"] == "https://evidence.example.invalid"
assert env["ECONOMICS_URL"]["value"] == "http://finops-economics:8000"
database = env["DATABASE_URL"]["valueFrom"]["secretKeyRef"]
reader = env["OBJECT_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]
assert database == {"name": "finops-db-network-analyst", "key": "DATABASE_URL"}
assert reader == {"name": "finops-network-evidence-reader", "key": "OBJECT_ACCESS_KEY"}
assert env["OBJECT_SECRET_KEY"]["valueFrom"]["secretKeyRef"] == {"name": reader["name"], "key": "OBJECT_SECRET_KEY"}
assert env["ECONOMICS_TOKEN"]["valueFrom"]["secretKeyRef"] == {"name": "finops-economics", "key": "ECONOMICS_TOKEN"}
assert not container.get("envFrom") and not account["automountServiceAccountToken"] and not account["metadata"].get("annotations")
assert pod["serviceAccountName"] == name and pod["securityContext"]["runAsNonRoot"]
assert pod["securityContext"]["runAsUser"] == 10001
assert container["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
assert {row["name"] for row in pod["volumes"]} == {"tmp", "rds-ca"}
assert not any(row["kind"] == "Service" and row["metadata"]["name"] == name for row in enabled)
for row in enabled:
    if row["kind"] != "Deployment" or row["metadata"]["name"] == name:
        continue
    for other in row["spec"]["template"]["spec"]["containers"]:
        variables = {value["name"]: value for value in other.get("env", [])}
        if row["metadata"]["name"] == "finops-ingester":
            assert variables["AWS_NETWORK_READ_BINDINGS_JSON"]["valueFrom"]["secretKeyRef"] == {"name": "finops-network-read-bindings", "key": "AWS_NETWORK_READ_BINDINGS_JSON"}
            assert variables["NETWORK_READONLY_ENABLED"]["value"] == "true"
        else:
            assert "AWS_NETWORK_READ_BINDINGS_JSON" not in variables
        for value in variables.values():
            assert value.get("valueFrom", {}).get("secretKeyRef", {}).get("name") not in {database["name"], reader["name"]}
policies = {row["metadata"]["name"]: row for row in enabled if row["kind"] == "NetworkPolicy"}
egress = policies[name + "-egress"]["spec"]
assert egress["podSelector"] == {"matchLabels": {"finops-role": role}}
assert egress["egress"] == [
    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
    {"to": [{"podSelector": {"matchLabels": {"finops-role": "economics"}}}], "ports": [{"protocol": "TCP", "port": 8000}]},
    {"to": [{"ipBlock": {"cidr": "10.44.16.0/24"}}], "ports": [{"protocol": "TCP", "port": 443}]},
    {"to": [{"ipBlock": {"cidr": "10.44.32.0/24"}}], "ports": [{"protocol": "TCP", "port": 5432}]},
]
for policy in policies.values():
    spec = policy["spec"]
    if not selector_matches(spec.get("podSelector", {}), {"finops-role": role}):
        continue
    assert all(rule in egress["egress"] for rule in spec.get("egress", []))
    assert not spec.get("ingress")
print("Network assessor default-off, independent analytical identity and bounded read-only egress checks passed.")
