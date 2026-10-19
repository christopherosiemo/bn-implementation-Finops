"""Inspect rendered database-only analytical deployment, never a cluster."""
import copy
import ipaddress
import json
import re
import sys
import unittest
from pathlib import Path

ROLE, NAME = "fleet-decision", "finops-fleet-decision"
manifest_path = Path(sys.argv.pop(1))
with manifest_path.open(encoding="utf-8") as source:
    if manifest_path.suffix == ".json":
        # The local checker converts actual Helm YAML using a YAML parser.
        ORIGINAL = json.load(source)
        assert isinstance(ORIGINAL, list)
    else:
        import yaml
        ORIGINAL = [document for document in yaml.safe_load_all(source) if document]


def find(documents, kind):
    rows = [item for item in documents if item["kind"] == kind and item["metadata"]["name"] == NAME]
    assert len(rows) == 1
    return rows[0]


def matches(selector, labels):
    if any(labels.get(key) != value for key, value in selector.get("matchLabels", {}).items()):
        return False
    for expression in selector.get("matchExpressions", []):
        key, operator = expression["key"], expression["operator"]
        assert operator in ("In", "NotIn", "Exists", "DoesNotExist")
        if operator == "In" and labels.get(key) not in expression["values"]:
            return False
        if operator == "NotIn" and labels.get(key) in expression["values"]:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True


def check(documents):
    deployment, account = find(documents, "Deployment"), find(documents, "ServiceAccount")
    pod = deployment["spec"]["template"]["spec"]
    labels = deployment["spec"]["template"]["metadata"]["labels"]
    assert labels["finops-role"] == ROLE and pod["serviceAccountName"] == NAME
    assert account["automountServiceAccountToken"] is False
    assert pod["automountServiceAccountToken"] is False
    assert not account["metadata"].get("annotations")
    assert not any(pod.get(key) for key in ("hostNetwork", "hostPID", "hostIPC", "hostAliases", "initContainers"))
    security = pod["securityContext"]
    assert security["runAsNonRoot"] is True and security["runAsUser"] == security["fsGroup"] == 10001
    assert security["seccompProfile"]["type"] == "RuntimeDefault"
    assert len(pod["containers"]) == 1
    container = pod["containers"][0]
    assert container["command"] == ["/app/fleet-decision-worker"] and not container.get("args")
    assert container["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    assert not container.get("envFrom")
    env = {item["name"]: item["value"] for item in container["env"]}
    assert len(env) == len(container["env"]) == 4
    assert env["FLEET_DECISION_ENABLED"] == "true"
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", env["FLEET_DECISION_TENANT_ID"])
    assert env["FLEET_DECISION_DATABASE_FILE"] == "/run/secrets/group-decision-database"
    assert env["FLEET_DECISION_DATABASE_MODE"] == "HOSTED_TLS"
    mounts = {item["name"]: item for item in container["volumeMounts"]}
    volumes = {item["name"]: item for item in pod["volumes"]}
    assert set(mounts) == set(volumes) == {"tmp", "database", "database-ca"}
    assert mounts["database"] == {"name": "database", "mountPath": env["FLEET_DECISION_DATABASE_FILE"], "subPath": "DATABASE_URL", "readOnly": True}
    assert mounts["database-ca"] == {"name": "database-ca", "mountPath": "/run/ca/group-decision-root.crt", "subPath": "ca.crt", "readOnly": True}
    assert volumes["database"]["secret"]["defaultMode"] == 0o440
    assert volumes["database"]["secret"]["items"] == [{"key": "DATABASE_URL", "path": "DATABASE_URL"}]
    assert volumes["database-ca"]["configMap"]["items"] == [{"key": "ca.crt", "path": "ca.crt"}]
    assert volumes["tmp"]["emptyDir"]["sizeLimit"] == "16Mi"
    secret = volumes["database"]["secret"]["secretName"]
    for other in documents:
        if other["kind"] != "Deployment" or other["metadata"]["name"] == NAME:
            continue
        other_pod = other["spec"]["template"]["spec"]
        assert all(volume.get("secret", {}).get("secretName") != secret for volume in other_pod.get("volumes", []))
        for other_container in other_pod["containers"]:
            for item in other_container.get("env", []):
                assert item.get("valueFrom", {}).get("secretKeyRef", {}).get("name") != secret
    assert container["readinessProbe"]["httpGet"] == {"path": "/readyz", "port": "http"}
    policies = [item["spec"] for item in documents if item["kind"] == "NetworkPolicy" and matches(item["spec"].get("podSelector", {}), labels)]
    assert any(set(item.get("policyTypes", [])) == {"Ingress", "Egress"} and not item.get("ingress") and not item.get("egress") for item in policies)
    assert all(not policy.get("ingress") for policy in policies)
    observed = set()
    for policy in policies:
        for rule in policy.get("egress", []):
            assert rule.get("to") and rule.get("ports")
            for port in rule["ports"]:
                assert not port.get("endPort")
                number = port["port"]
                assert number in (53, 5432)
                observed.add(number)
                for target in rule["to"]:
                    if number == 53:
                        assert target == {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
                    else:
                        assert set(target) == {"ipBlock"} and set(target["ipBlock"]) == {"cidr"}
                        network = ipaddress.ip_network(target["ipBlock"]["cidr"])
                        assert network.version == 4 and network.prefixlen >= 16
                        assert any(network.subnet_of(ipaddress.ip_network(prefix)) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    assert observed == {53, 5432}


def invalid_values():
    return {
        "string-enabled": {"fleetDecision": {"enabled": "false"}},
        "numeric-enabled": {"fleetDecision": {"enabled": 1}},
        "no-default-deny": {"networkPolicy": {"enabled": False}},
        "no-tenant": {"fleetDecision": {"tenantId": ""}},
        "malformed-tenant": {"fleetDecision": {"tenantId": "../foreign"}},
        "shared-api-database": {"database": {"secrets": {ROLE: "finops-db-api"}}},
        "shared-capacity-database": {"database": {"secrets": {ROLE: "finops-db-group-capacity"}}},
        "signer-secret": {"database": {"secrets": {ROLE: "finops-signer"}}},
        "no-database": {"database": {"secrets": {ROLE: ""}}},
        "bad-secret-name": {"database": {"secrets": {ROLE: "../database"}}},
        "missing-ca": {"database": {"caConfigMap": ""}},
        "missing-cidr": {"fleetDecision": {"postgresEgressCidrs": []}},
        "world-cidr": {"fleetDecision": {"postgresEgressCidrs": ["0.0.0.0/0"]}},
        "broad-private": {"fleetDecision": {"postgresEgressCidrs": ["10.0.0.0/8"]}},
        "public-cidr": {"fleetDecision": {"postgresEgressCidrs": ["8.8.8.0/24"]}},
        "metadata-cidr": {"fleetDecision": {"postgresEgressCidrs": ["169.254.169.254/32"]}},
        "zero-replicas": {"fleetDecision": {"replicas": 0}},
        "fractional-replicas": {"fleetDecision": {"replicas": 1.5}},
        "many-cidrs": {"fleetDecision": {"postgresEgressCidrs": ["10.42.0.0/24"] * 17}},
    }


class DecisionDeployment(unittest.TestCase):
    def test_actual_rendered_boundary(self):
        check(ORIGINAL)

    def test_widened_credentials_tokens_and_network_reject(self):
        changes = {
            "ambient-cloud-key": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "AWS_ACCESS_KEY_ID", "value": "forged"}),
            "wrong-binary": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0].update(command=["/app/finops"]),
            "writable-root": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(readOnlyRootFilesystem=False),
            "token": lambda docs: find(docs, "ServiceAccount").update(automountServiceAccountToken=True),
            "irsa": lambda docs: find(docs, "ServiceAccount")["metadata"].update(annotations={"eks.amazonaws.com/role-arn": "forged"}),
            "plaintext": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"][3].update(value="LOCAL_PRIVATE"),
            "unscoped-egress": lambda docs: docs.append({"kind": "NetworkPolicy", "metadata": {"name": "bad"}, "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"ports": [{"port": 443}]}]}}),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                docs = copy.deepcopy(ORIGINAL)
                change(docs)
                with self.assertRaises((AssertionError, KeyError)):
                    check(docs)


if __name__ == "__main__":
    if "--write-negative-values" in sys.argv:
        offset = sys.argv.index("--write-negative-values")
        destination = Path(sys.argv[offset + 1])
        destination.mkdir(parents=True, exist_ok=True)
        del sys.argv[offset:offset + 2]
        for name, value in invalid_values().items():
            (destination / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    unittest.main()
