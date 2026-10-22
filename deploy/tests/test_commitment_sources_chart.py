"""Inspect actual default/opt-in renders; no Kubernetes or provider operations."""
import copy
import json
import sys
import unittest
from pathlib import Path

def load(path):
    with Path(path).open(encoding="utf-8") as source:
        if Path(path).suffix == ".json":
            return json.load(source)
        import yaml
        return [row for row in yaml.safe_load_all(source) if row]

DEFAULT, ENABLED = load(sys.argv.pop(1)), load(sys.argv.pop(1))
SELECTORS = {
    "AWS_SAVINGS_PLAN_QUOTE_TARGETS_JSON": "finops-commitment-quote-targets",
    "AWS_CONTROLLER_DISCOVERY_BINDINGS_JSON": "finops-controller-bindings",
    "AWS_OWNERSHIP_ARCHIVE_TARGETS_JSON": "finops-ownership-archive-targets",
}
BINDINGS = "finops-approved-source-bindings"
ALL_SELECTORS = {**SELECTORS, "AWS_SOURCE_READ_BINDINGS_JSON": BINDINGS}

def check(rows, enabled):
    deployments = [row for row in rows if row["kind"] == "Deployment"]
    assert deployments
    ingesters = [row for row in deployments if row["metadata"]["name"] == "finops-ingester"]
    assert len(ingesters) == 1
    selected = set()
    for deployment in deployments:
        pod = deployment["spec"]["template"]["spec"]
        for container in pod.get("containers", []) + pod.get("initContainers", []):
            env = {item["name"]: item for item in container.get("env", [])}
            assert len(env) == len(container.get("env", []))
            for key, secret in ALL_SELECTORS.items():
                value = env.get(key)
                if not enabled or deployment is not ingesters[0]:
                    assert value is None
                else:
                    assert value == {"name": key, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}
                    selected.add(key)
            # A name-only envFrom or whole-secret volume would expose keys
            # outside the explicitly selected target metadata.
            for value in container.get("envFrom", []):
                assert value.get("secretRef", {}).get("name") not in set(SELECTORS.values()) | {BINDINGS}
            assert env.get("AWS_EXECUTION_ROLE_ARN", {}).get("value", "") == ""
        for volume in pod.get("volumes", []):
            assert volume.get("secret", {}).get("secretName") not in set(SELECTORS.values()) | {BINDINGS}
    ingester = ingesters[0]["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item for item in ingester["env"]}
    if enabled:
        assert selected == set(ALL_SELECTORS)
        assert env["DATA_MODE"]["value"] == "aws"
        assert env["AWS_SOURCE_READ_BINDINGS_JSON"] == {"name": "AWS_SOURCE_READ_BINDINGS_JSON", "valueFrom": {"secretKeyRef": {"name": BINDINGS, "key": "AWS_SOURCE_READ_BINDINGS_JSON"}}}
    else:
        assert not selected
    # Target selection must not provision new Secrets, AWS execution identity,
    # or purchase/approval endpoints in the chart.
    assert all(row["kind"] != "Secret" or row["metadata"]["name"] not in set(SELECTORS.values()) | {BINDINGS} for row in rows)
    for account in (row for row in rows if row["kind"] == "ServiceAccount" and row["metadata"]["name"] in {"finops-signer", "finops-executor"}):
        assert "eks.amazonaws.com/role-arn" not in account["metadata"].get("annotations", {})

def invalid_values():
    values = {}
    fields = {"quotes": "commitmentQuoteTargetsSecret", "controller": "controllerBindingsSecret", "archive": "ownershipArchiveTargetsSecret"}
    for label, field in fields.items():
        target = {name: "" for name in fields.values()}
        target[field] = SELECTORS[next(key for key in SELECTORS if {"quotes": "QUOTE", "controller": "CONTROLLER", "archive": "ARCHIVE"}[label] in key)]
        values["fixture-" + label] = {"dataMode": "fixture", "sources": target}
        values["no-approved-read-binding-" + label] = {"sources": {**target, "readBindingsSecret": ""}}
    values["wrong-region"] = {"aws": {"region": "us-east-1"}}
    values["no-tenant"] = {"aws": {"tenantId": ""}}
    values["no-ingester-identity"] = {"aws": {"ingesterRoleArn": ""}}
    values["non-string-target"] = {"sources": {"commitmentQuoteTargetsSecret": {"source_id": "not-a-secret-name"}}}
    values["boolean-target"] = {"sources": {"controllerBindingsSecret": True}}
    values["raw-json-target"] = {"sources": {"ownershipArchiveTargetsSecret": '{"source_id":"not-a-secret-name"}'}}
    values["namespace-path-target"] = {"sources": {"commitmentQuoteTargetsSecret": "other-namespace/source-targets"}}
    values["oversized-secret-label"] = {"sources": {"controllerBindingsSecret": "a" * 64}}
    values["non-string-read-binding"] = {"sources": {"readBindingsSecret": True}}
    return values

class CommitmentSourceDeployment(unittest.TestCase):
    def test_actual_default_has_no_new_sources(self):
        check(DEFAULT, False)

    def test_actual_read_only_sources_are_ingester_only(self):
        check(ENABLED, True)

    def test_wrong_target_role_key_or_authority_is_detected(self):
        for label in ("non-ingester", "wrong-key", "whole-secret", "execution"):
            with self.subTest(label=label):
                rows = copy.deepcopy(ENABLED)
                pods = {row["metadata"]["name"]: row["spec"]["template"]["spec"] for row in rows if row["kind"] == "Deployment"}
                ingester = pods["finops-ingester"]["containers"][0]
                selected = next(item for item in ingester["env"] if item["name"] in SELECTORS)
                if label == "non-ingester":
                    pods["finops-api"]["containers"][0]["env"].append(copy.deepcopy(selected))
                elif label == "wrong-key":
                    selected["valueFrom"]["secretKeyRef"]["key"] = "SIGNING_PRIVATE_KEY"
                elif label == "whole-secret":
                    ingester["envFrom"] = [{"secretRef": {"name": next(iter(SELECTORS.values()))}}]
                else:
                    item = next(item for item in pods["finops-executor"]["containers"][0]["env"] if item["name"] == "AWS_EXECUTION_ROLE_ARN")
                    item["value"] = "arn:aws:iam::111122223333:role/unapproved-execution"
                with self.assertRaises((AssertionError, KeyError)):
                    check(rows, True)

if __name__ == "__main__":
    if "--write-negative-values" in sys.argv:
        offset = sys.argv.index("--write-negative-values")
        destination = Path(sys.argv[offset + 1])
        destination.mkdir(parents=True, exist_ok=True)
        del sys.argv[offset:offset + 2]
        for name, value in invalid_values().items():
            (destination / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    unittest.main()
