"""Inspect the optional machine-ingress identity; never contact a provider."""
import sys
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_chart import check, selector_matches

def load(path):
    return [item for item in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if item]

default, enabled = map(load, sys.argv[1:3])
for item in default:
    if item["kind"] == "Deployment":
        assert not any(value["name"].startswith("LAMBDA_PERFORMANCE_") for value in item["spec"]["template"]["spec"]["containers"][0].get("env", []))
check(sys.argv[2])
for item in enabled:
    if item["kind"] != "Deployment":
        continue
    role = item["metadata"]["name"].removeprefix("finops-")
    env = {value["name"]: value for value in item["spec"]["template"]["spec"]["containers"][0].get("env", [])}
    machine = {key: value for key, value in env.items() if key.startswith("LAMBDA_PERFORMANCE_")}
    if role != "activity-ingress":
        assert not machine
        continue
    assert machine["LAMBDA_PERFORMANCE_ENABLED"]["value"] == "true"
    assert machine["LAMBDA_PERFORMANCE_OIDC_AUDIENCE"]["value"] == "finops-lambda-performance"
    assert machine["LAMBDA_PERFORMANCE_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]["name"] == "finops-lambda-performance-writer"
    assert machine["LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"] == "finops-lambda-performance-analytics"
    assert not {"OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY", "CLICKHOUSE_PASSWORD", "AWS_READ_ROLE_ARN", "AWS_EXECUTION_ROLE_ARN", "SIGNER_TOKEN", "SIGNING_PRIVATE_KEY", "EXECUTOR_TOKEN"} & env.keys()
for item in enabled:
    if item["kind"] != "NetworkPolicy" or not selector_matches(item["spec"].get("podSelector", {}), {"finops-role": "activity-ingress"}):
        continue
    for rule in item["spec"].get("egress", []):
        for port in rule.get("ports", []):
            assert port["port"] in {53, 443, 5432, 8123}
            if port["port"] == 443:
                assert rule.get("to") == [{"ipBlock": {"cidr": "10.44.16.0/24"}}]
            if port["port"] == 8123:
                assert rule.get("to") == [{"podSelector": {"matchLabels": {"finops-role": "clickhouse"}}}]
print("Lambda performance ingress is default-off, machine-authenticated and separately credentialed.")
