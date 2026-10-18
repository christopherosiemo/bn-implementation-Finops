"""Check the rendered deployment's credential boundaries, independent of templates.

Usage: python deploy/check_chart.py rendered.yaml  (requires PyYAML)
This accepts only manifests; never pass a values file containing secret values.
"""
import sys
import yaml


def check(path):
    with open(path, encoding="utf-8") as source:
        manifests = [doc for doc in yaml.safe_load_all(source) if doc]
    deployments = {
        doc["metadata"]["name"].removeprefix("finops-"): doc
        for doc in manifests
        if doc["kind"] == "Deployment" and doc["metadata"]["name"].startswith("finops-")
    }
    accounts = {
        doc["metadata"]["name"].removeprefix("finops-"): doc
        for doc in manifests if doc["kind"] == "ServiceAccount"
    }
    required = {"api", "worker", "ingester", "signer", "executor", "activity-ingress", "economics", "web"}
    assert required <= deployments.keys(), "missing isolated application deployment"
    secret_keys = {}
    envs = {}
    for role in required:
        pod = deployments[role]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        assert pod["serviceAccountName"] == "finops-" + role
        assert accounts[role]["automountServiceAccountToken"] is False
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert not container.get("envFrom"), "broad secret injection defeats role isolation"
        envs[role] = {entry["name"]: entry for entry in container.get("env", [])}
        secret_keys[role] = {
            entry["name"]: entry["valueFrom"]["secretKeyRef"]
            for entry in container.get("env", [])
            if "secretKeyRef" in entry.get("valueFrom", {})
        }
        assert ("SIGNING_PRIVATE_KEY" in secret_keys[role]) == (role == "signer")
        assert ("SIGNER_TOKEN" in secret_keys[role]) == (role in {"worker", "signer"})
        assert ("EXECUTOR_TOKEN" in secret_keys[role]) == (role in {"worker", "executor"})
        assert ("CLICKHOUSE_PASSWORD" in secret_keys[role]) == (role == "ingester")
        assert ("ECONOMICS_TOKEN" in secret_keys[role]) == (role in {"api", "ingester", "economics"})
        if role != "worker":
            assert "WEBHOOK_SECRET" not in secret_keys[role]
            assert "WEBHOOK_URL" not in envs[role]
        if role not in {"ingester", "executor", "signer"}:
            assert "eks.amazonaws.com/role-arn" not in accounts[role]["metadata"].get("annotations", {})
        if role != "ingester":
            assert not any(key.startswith("OBJECT_") for key in envs[role])
            assert "AWS_READ_ROLE_ARN" not in envs[role]
            assert "AWS_SOURCE_READ_BINDINGS_JSON" not in envs[role]
        if role != "executor":
            assert "AWS_EXECUTION_ROLE_ARN" not in envs[role]
    go_roles = {"api", "worker", "ingester", "signer", "executor", "activity-ingress"}
    assert envs["activity-ingress"]["ACTIVITY_OIDC_AUDIENCE"]["value"] != envs["api"]["OIDC_AUDIENCE"]["value"]
    assert envs["activity-ingress"]["ACTIVITY_OIDC_ISSUER"]["value"] == envs["api"]["ACTIVITY_OIDC_ISSUER"]["value"], "collector registration and ingress must bind the same issuer"
    webhook_url = envs["worker"].get("WEBHOOK_URL", {}).get("value", "")
    assert ("WEBHOOK_SECRET" in secret_keys["worker"]) == bool(webhook_url)
    if webhook_url:
        assert webhook_url.startswith("https://"), "webhook destination must use HTTPS"
        assert secret_keys["worker"]["WEBHOOK_SECRET"] == {
            "name": secret_keys["worker"]["SIGNER_TOKEN"]["name"], "key": "WEBHOOK_SECRET"
        }, "webhook signing secret must come only from the worker secret"
    db_secrets = [secret_keys[role]["DATABASE_URL"]["name"] for role in go_roles]
    assert len(set(db_secrets)) == len(go_roles), "runtime database identities must remain separate"
    for doc in manifests:
        if doc["kind"] == "Service" and doc["metadata"]["name"] in {"finops-signer", "finops-executor"}:
            assert doc["spec"].get("type", "ClusterIP") == "ClusterIP"
    for role in ("signer", "executor"):
        policy = next(doc for doc in manifests if doc["kind"] == "NetworkPolicy" and doc["metadata"]["name"] == "finops-ingress-" + role)
        senders = policy["spec"]["ingress"][0]["from"]
        assert senders == [{"podSelector": {"matchLabels": {"finops-role": "worker"}}}]
    print("Rendered chart preserves ingestion, signing, execution, database and network boundaries.")


if __name__ == "__main__":
    check(sys.argv[1])
