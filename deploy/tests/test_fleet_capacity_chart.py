"""Check actual rendered capacity worker boundaries; never contacts a cluster."""
import copy
import ipaddress
import json
import re
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_chart import selector_matches

ROLE, NAME = "fleet-capacity", "finops-fleet-capacity"
with open(sys.argv.pop(1), encoding="utf-8") as source:
    ORIGINAL = [item for item in yaml.safe_load_all(source) if item]


def find(documents, kind, name=NAME):
    rows = [item for item in documents if item["kind"] == kind and item["metadata"]["name"] == name]
    assert len(rows) == 1
    return rows[0]


def check(documents):
    deployment, account = find(documents, "Deployment"), find(documents, "ServiceAccount")
    pod = deployment["spec"]["template"]["spec"]
    labels = deployment["spec"]["template"]["metadata"]["labels"]
    assert labels["finops-role"] == ROLE and pod["serviceAccountName"] == NAME
    assert account["automountServiceAccountToken"] is False
    assert not any(pod.get(key) for key in ("hostNetwork", "hostPID", "hostIPC", "hostAliases", "initContainers"))
    assert type(deployment["spec"]["replicas"]) is int and 1 <= deployment["spec"]["replicas"] <= 3
    security = pod["securityContext"]
    assert security["runAsNonRoot"] is True and security["runAsUser"] == security["fsGroup"] == 10001
    assert security["seccompProfile"]["type"] == "RuntimeDefault"
    assert len(pod["containers"]) == 1
    container = pod["containers"][0]
    assert container["command"] == ["/app/fleet-capacity-worker"] and not container.get("args")
    assert container["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    assert not container.get("envFrom")
    env = {item["name"]: item["value"] for item in container["env"]}
    assert len(env) == len(container["env"]) == 14
    assert env["FLEET_CAPACITY_ENABLED"] == "true"
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", env["FLEET_CAPACITY_TENANT_ID"])
    assert env["FLEET_CAPACITY_DATABASE_FILE"] == "/run/secrets/group-capacity-database"
    assert env["FLEET_CAPACITY_ARCHIVE_MODE"] == "AWS_IRSA"
    assert env["FLEET_CAPACITY_ARCHIVE_REGION"] == env["AWS_REGION"] == "eu-west-1"
    assert env["AWS_STS_REGIONAL_ENDPOINTS"] == "regional"
    assert re.fullmatch(r"[0-9]{12}", env["FLEET_CAPACITY_ARCHIVE_BUCKET_OWNER"])
    assert env["FLEET_CAPACITY_ARCHIVE_BUCKET"]
    assert env["FLEET_CAPACITY_SERVICE_MODE"] == "PRIVATE_SERVICES"
    assert env["FLEET_CAPACITY_READER_URL"] == "http://finops-telemetry-reader:8080"
    assert env["FLEET_CAPACITY_MODEL_URL"] == "http://finops-economics:8000"
    assert env["FLEET_CAPACITY_READER_TOKEN_FILE"] == "/run/secrets/group-capacity-reader-token"
    assert env["FLEET_CAPACITY_MODEL_TOKEN_FILE"] == "/run/secrets/group-capacity-model-token"
    arn = account["metadata"]["annotations"]["eks.amazonaws.com/role-arn"]
    assert re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", arn)
    assert all(item["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn") != arn
               for item in documents if item["kind"] == "ServiceAccount" and item["metadata"]["name"] != NAME)
    mounts = {item["name"]: item for item in container["volumeMounts"]}
    assert set(mounts) == {"tmp", "database", "rds-ca", "reader-token", "model-token"}
    assert mounts["database"] == {"name": "database", "mountPath": env["FLEET_CAPACITY_DATABASE_FILE"], "subPath": "DATABASE_URL", "readOnly": True}
    assert mounts["rds-ca"]["readOnly"] is True
    volumes = {item["name"]: item for item in pod["volumes"]}
    assert set(volumes) == set(mounts)
    assert volumes["database"]["secret"]["defaultMode"] == 0o440
    assert volumes["database"]["secret"]["items"] == [{"key": "DATABASE_URL", "path": "DATABASE_URL"}]
    secret_name = volumes["database"]["secret"]["secretName"]
    for other in documents:
        if other["kind"] != "Deployment" or other["metadata"]["name"] == NAME:
            continue
        for other_container in other["spec"]["template"]["spec"]["containers"]:
            for item in other_container.get("env", []):
                assert item.get("valueFrom", {}).get("secretKeyRef", {}).get("name") != secret_name
    for name, key in (("reader-token", "TELEMETRY_READER_TOKEN"), ("model-token", "ECONOMICS_TOKEN")):
        assert mounts[name] == {"name": name, "mountPath": "/run/secrets/group-capacity-"+name, "subPath": key, "readOnly": True}
        assert volumes[name]["secret"]["defaultMode"] == 0o440
        assert volumes[name]["secret"]["items"] == [{"key": key, "path": key}]
        assert volumes[name]["secret"]["secretName"] != secret_name
    assert volumes["reader-token"]["secret"]["secretName"] != volumes["model-token"]["secret"]["secretName"]
    assert volumes["tmp"]["emptyDir"]["sizeLimit"] == "16Mi"
    assert container["readinessProbe"]["httpGet"] == {"path": "/readyz", "port": "http"}
    policies = [item["spec"] for item in documents if item["kind"] == "NetworkPolicy" and selector_matches(item["spec"].get("podSelector", {}), labels)]
    assert any(set(item.get("policyTypes", [])) == {"Ingress", "Egress"} and not item.get("ingress") and not item.get("egress") for item in policies)
    assert all(not item.get("ingress") for item in policies)
    observed_ports = set()
    for policy in policies:
        for rule in policy.get("egress", []):
            assert rule.get("to") and rule.get("ports"), "an overlapping policy widened egress"
            for port in rule["ports"]:
                assert not port.get("endPort")
                number = port["port"]
                assert number in (53, 443, 5432, 8080, 8000)
                observed_ports.add(number)
                for destination in rule["to"]:
                    if number == 53:
                        assert destination == {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
                    elif number in (8080, 8000):
                        expected = "telemetry-reader" if number == 8080 else "economics"
                        assert destination == {"podSelector": {"matchLabels": {"finops-role": expected}}}
                    else:
                        assert set(destination) == {"ipBlock"} and set(destination["ipBlock"]) == {"cidr"}
                        network = ipaddress.ip_network(destination["ipBlock"]["cidr"])
                        assert network.version == 4 and network.prefixlen >= 16
                        assert not network.is_loopback and not network.is_link_local and not network.is_multicast and not network.is_unspecified
                        if number == 5432:
                            assert any(network.subnet_of(ipaddress.ip_network(prefix)) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    assert observed_ports == {53, 443, 5432, 8080, 8000}


def invalid_values():
    return {
        "no-telemetry": {"telemetry": {"enabled": False}},
        "shared-assessor": {"fleetAssessment": {"enabled": True, "roleArn": "arn:aws:iam::123456789012:role/finops-group-capacity-reader"}},
        "shared-model-reader-token": {"telemetry": {"readerTokenSecret": "finops-economics"}},
        "signer-reader-token": {"telemetry": {"readerTokenSecret": "finops-signer"}},
        "fixture-mode": {"dataMode": "fixture"},
        "no-default-deny": {"networkPolicy": {"enabled": False}},
        "missing-role": {"fleetCapacity": {"roleArn": ""}},
        "wildcard-role": {"fleetCapacity": {"roleArn": "arn:aws:iam::123456789012:role/*"}},
        "shared-ingester": {"fleetCapacity": {"roleArn": "arn:aws:iam::123456789012:role/finops-pilot-ingester"}},
        "missing-owner": {"fleetCapacity": {"bucketOwner": ""}},
        "shared-database": {"database": {"secrets": {ROLE: "finops-db-api"}}},
        "signer-secret": {"database": {"secrets": {ROLE: "finops-signer"}}},
        "world-https": {"fleetCapacity": {"httpsEgressCidrs": ["0.0.0.0/0"]}},
        "metadata-https": {"fleetCapacity": {"httpsEgressCidrs": ["169.254.169.254/32"]}},
        "broad-https": {"fleetCapacity": {"httpsEgressCidrs": ["10.0.0.0/8"]}},
        "public-postgres": {"fleetCapacity": {"postgresEgressCidrs": ["8.8.8.0/24"]}},
        "no-https": {"fleetCapacity": {"httpsEgressCidrs": []}},
        "no-postgres": {"fleetCapacity": {"postgresEgressCidrs": []}},
        "no-replicas": {"fleetCapacity": {"replicas": 0}},
        "fractional-replicas": {"fleetCapacity": {"replicas": 1.5}},
        "unknown-tenant": {"aws": {"tenantId": "../tenant"}},
    }


class CapacityDeployment(unittest.TestCase):
    def test_actual_rendered_boundary(self):
        check(ORIGINAL)

    def test_widened_runtime_or_network_is_rejected(self):
        mutations = {
            "ambient-key": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "AWS_ACCESS_KEY_ID", "value": "forged"}),
            "different-binary": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0].update(command=["/app/finops"]),
            "writable-root": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(readOnlyRootFilesystem=False),
            "api-database": lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"]["volumes"][1]["secret"].update(secretName="finops-db-api"),
            "kubernetes-token": lambda docs: find(docs, "ServiceAccount").update(automountServiceAccountToken=True),
            "wide-overlap": lambda docs: docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "bad-overlap"}, "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"ports": [{"port": 443}]}]}}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                documents = copy.deepcopy(ORIGINAL)
                mutate(documents)
                with self.assertRaises((AssertionError, KeyError)):
                    check(documents)


if __name__ == "__main__":
    if "--write-negative-values" in sys.argv:
        at = sys.argv.index("--write-negative-values")
        destination = Path(sys.argv[at + 1])
        destination.mkdir(parents=True, exist_ok=True)
        del sys.argv[at:at + 2]
        for name, value in invalid_values().items():
            (destination / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    unittest.main()
