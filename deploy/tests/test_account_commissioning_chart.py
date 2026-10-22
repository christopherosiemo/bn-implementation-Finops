"""The account preflight secret belongs only to the existing read ingester."""
import json
import sys
import yaml


def deployments(filename):
    with open(filename, encoding="utf-8") as stream:
        return {
            doc["metadata"]["name"]: doc
            for doc in yaml.safe_load_all(stream)
            if doc and doc.get("kind") == "Deployment"
        }


baseline, configured = map(deployments, sys.argv[1:])
assert set(baseline) == set(configured), "commissioning creates no process or identity"
for name, document in configured.items():
    pod = document["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {entry["name"]: entry for entry in container.get("env", [])}
    default = {
        entry["name"]: entry
        for entry in baseline[name]["spec"]["template"]["spec"]["containers"][0].get("env", [])
    }
    assert "AWS_ACCOUNT_READ_BINDINGS_JSON" not in default
    revision_mounts = [row for row in container.get("volumeMounts", []) if row["name"] == "configuration-revisions"]
    revision_volumes = [row for row in pod.get("volumes", []) if row["name"] == "configuration-revisions"]
    if name == "finops-api":
        assert json.loads(default["CONFIGURATION_REVISION_BINDINGS_JSON"]["value"]) == {}
        revisions = json.loads(env["CONFIGURATION_REVISION_BINDINGS_JSON"]["value"])
        assert set(revisions) == {"tenant-demo:approved-terraform"}
        assert revisions["tenant-demo:approved-terraform"]["repository_root"].startswith("/var/run/finops/configuration-revisions/")
        assert revision_mounts == [{"name": "configuration-revisions", "mountPath": "/var/run/finops/configuration-revisions", "readOnly": True}]
        assert revision_volumes == [{"name": "configuration-revisions", "persistentVolumeClaim": {"claimName": "finops-approved-repository-mirror", "readOnly": True}}]
    else:
        assert "CONFIGURATION_REVISION_BINDINGS_JSON" not in env
        assert "CONFIGURATION_REVISION_BINDINGS_JSON" not in default
        assert revision_mounts == revision_volumes == []
    if name == "finops-ingester":
        assert env["AWS_ACCOUNT_READ_BINDINGS_JSON"]["valueFrom"]["secretKeyRef"] == {
            "name": "finops-approved-account-read", "key": "AWS_ACCOUNT_READ_BINDINGS_JSON"
        }
    else:
        assert "AWS_ACCOUNT_READ_BINDINGS_JSON" not in env, name
    if name in ("finops-api", "finops-ingester"):
        approved = json.loads(env["AWS_ACCOUNT_APPROVED_BINDINGS_JSON"]["value"])
        binding = approved["ireland-read"]
        assert set(binding) == {
            "tenant_id", "account_id", "regions", "role_arn", "scope_mode", "external_id_configured"
        }
        assert binding["scope_mode"] == "ACCOUNT"
        assert binding["regions"] == ["eu-west-1"]
    else:
        assert "AWS_ACCOUNT_APPROVED_BINDINGS_JSON" not in env
print("Account commissioning role/secret boundaries passed")
