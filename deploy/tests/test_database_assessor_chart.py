"""Inspect actual default/optional renders; no Kubernetes or provider calls."""
import sys
import yaml


def load(path):
    with open(path, encoding="utf-8") as source:
        return [row for row in yaml.safe_load_all(source) if row]


default, enabled = map(load, sys.argv[1:3])
role = "database-assessor"
name = "finops-" + role
assert not any(row["metadata"]["name"].startswith(name) for row in default), "assessor must remain disabled by default"
deployment = next(row for row in enabled if row["kind"] == "Deployment" and row["metadata"]["name"] == name)
account = next(row for row in enabled if row["kind"] == "ServiceAccount" and row["metadata"]["name"] == name)
pod = deployment["spec"]["template"]["spec"]
container = pod["containers"][0]
env = {row["name"]: row for row in container["env"]}
assert set(env) == {"APP_ROLE", "PORT", "FIXTURE_MODE", "DATABASE_URL", "ECONOMICS_URL", "ECONOMICS_TOKEN", "OBJECT_ENDPOINT", "OBJECT_REGION", "OBJECT_BUCKET_RAW", "OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY"}
assert env["APP_ROLE"]["value"] == role
assert env["FIXTURE_MODE"]["value"] == "false"
assert env["OBJECT_REGION"]["value"] == "eu-west-1"
assert env["OBJECT_ENDPOINT"]["value"] == "https://evidence.example.invalid"
assert env["OBJECT_BUCKET_RAW"]["value"] == "finops-validation-raw"
assert env["ECONOMICS_URL"]["value"] == "http://finops-economics:8000"
database = env["DATABASE_URL"]["valueFrom"]["secretKeyRef"]
reader = env["OBJECT_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]
assert database == {"name": "finops-db-database-analyst", "key": "DATABASE_URL"}
assert reader == {"name": "finops-database-evidence-reader", "key": "OBJECT_ACCESS_KEY"}
assert env["OBJECT_SECRET_KEY"]["valueFrom"]["secretKeyRef"] == {"name": reader["name"], "key": "OBJECT_SECRET_KEY"}
assert env["ECONOMICS_TOKEN"]["valueFrom"]["secretKeyRef"] == {"name": "finops-economics", "key": "ECONOMICS_TOKEN"}
assert not container.get("envFrom")
assert not account["automountServiceAccountToken"]
assert not account["metadata"].get("annotations"), "assessor must not receive IRSA"
assert pod["serviceAccountName"] == name and pod["securityContext"]["runAsNonRoot"]
assert pod["securityContext"]["runAsUser"] == 10001
assert container["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
assert {row["name"] for row in pod["volumes"]} == {"tmp", "rds-ca"}
assert not any(row["kind"] == "Service" and row["metadata"]["name"] == name for row in enabled)
for row in enabled:
    if row["kind"] != "Deployment" or row["metadata"]["name"] == name:
        continue
    for other in row["spec"]["template"]["spec"]["containers"]:
        for value in other.get("env", []):
            assert value.get("valueFrom", {}).get("secretKeyRef", {}).get("name") not in {database["name"], reader["name"]}, "database evidence identity leaked to another process"
policies = {row["metadata"]["name"]: row for row in enabled if row["kind"] == "NetworkPolicy"}
egress = policies[name + "-egress"]["spec"]
assert egress["podSelector"] == {"matchLabels": {"finops-role": role}}
assert egress["policyTypes"] == ["Egress"]
assert egress["egress"] == [
    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
    {"to": [{"podSelector": {"matchLabels": {"finops-role": "economics"}}}], "ports": [{"protocol": "TCP", "port": 8000}]},
    {"to": [{"ipBlock": {"cidr": "10.44.16.0/24"}}], "ports": [{"protocol": "TCP", "port": 443}]},
    {"to": [{"ipBlock": {"cidr": "10.44.32.0/24"}}], "ports": [{"protocol": "TCP", "port": 5432}]},
]
general = policies["finops-dns-and-https"]["spec"]["podSelector"]["matchExpressions"]
assert any(row["key"] == "finops-role" and row["operator"] == "NotIn" and role in row["values"] for row in general), "general world HTTPS egress would widen the dedicated boundary"
ingress = policies["finops-economics-from-database-assessor"]["spec"]
assert ingress["ingress"] == [{"from": [{"podSelector": {"matchLabels": {"finops-role": role}}}], "ports": [{"protocol": "TCP", "port": 8000}]}]
print("Database assessor default-off, read-only credential and network isolation checks passed.")
