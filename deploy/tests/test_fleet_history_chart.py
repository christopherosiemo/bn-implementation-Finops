"""Adversarial checks of actual rendered optional Fleet history manifests.

Usage: python deploy/tests/test_fleet_history_chart.py rendered-history.yaml
No cluster, credentials, Docker socket or customer endpoint is used by this test.
Helm render/lint also independently rejects incomplete enabling values.
"""
import copy
import ipaddress
import json
from pathlib import Path
import re
import sys
import unittest

import yaml


ROLE = "fleet-history-reader"
NAME = "finops-" + ROLE
with open(sys.argv.pop(1), encoding="utf-8") as source:
    ORIGINAL = [document for document in yaml.safe_load_all(source) if document]


def invalid_values():
    """Public render-only overrides; every case must make Helm fail."""
    return {
        "fixture-mode": {"dataMode": "fixture"},
        "no-default-deny": {"networkPolicy": {"enabled": False}},
        "missing-irsa": {"fleetHistory": {"roleArn": ""}},
        "invalid-irsa": {"fleetHistory": {"roleArn": "arn:aws:iam::123456789012:role/*"}},
        "shared-ingester-irsa": {"fleetHistory": {"roleArn": "arn:aws:iam::123456789012:role/finops-pilot-ingester"}},
        "shared-native-irsa": {"telemetry": {"readerRoleArn": "arn:aws:iam::123456789012:role/finops-fleet-history-reader"}},
        "shared-hardware-irsa": {"hardware": {"roleArn": "arn:aws:iam::123456789012:role/finops-fleet-history-reader"}},
        "shared-api-irsa": {"aws": {"apiRoleArn": "arn:aws:iam::123456789012:role/finops-fleet-history-reader"}},
        "missing-targets": {"fleetHistory": {"targetsSecret": ""}},
        "missing-read-bindings": {"fleetHistory": {"readBindingsSecret": ""}},
        "shared-read-bindings": {"sources": {"readBindingsSecret": "finops-history-approved-read-bindings"}},
        "invalid-secret": {"fleetHistory": {"targetsSecret": "other-namespace:secret"}},
        "missing-database": {"database": {"secrets": {ROLE: ""}}},
        "shared-api-database": {"database": {"secrets": {ROLE: "finops-db-api"}}},
        "shared-migration-database": {"database": {"secrets": {ROLE: "finops-db-migrate"}}},
        "signer-bundle-database": {"database": {"secrets": {ROLE: "finops-signer"}}},
        "config-bundle-database": {"database": {"secrets": {ROLE: "finops-history-exact-registrations"}}},
        "missing-https": {"fleetHistory": {"httpsEgressCidrs": []}},
        "missing-postgres": {"fleetHistory": {"postgresEgressCidrs": []}},
        "world-https": {"fleetHistory": {"httpsEgressCidrs": ["0.0.0.0/0"]}},
        "broad-https": {"fleetHistory": {"httpsEgressCidrs": ["10.0.0.0/8"]}},
        "metadata-https": {"fleetHistory": {"httpsEgressCidrs": ["169.254.169.254/32"]}},
        "loopback-https": {"fleetHistory": {"httpsEgressCidrs": ["127.0.0.1/32"]}},
        "ipv6-https": {"fleetHistory": {"httpsEgressCidrs": ["::/0"]}},
        "invalid-address": {"fleetHistory": {"httpsEgressCidrs": ["999.0.0.0/24"]}},
        "invalid-prefix": {"fleetHistory": {"httpsEgressCidrs": ["10.0.0.0/33"]}},
        "world-postgres": {"fleetHistory": {"postgresEgressCidrs": ["0.0.0.0/0"]}},
        "public-postgres": {"fleetHistory": {"postgresEgressCidrs": ["8.8.8.0/24"]}},
        "broad-private-postgres": {"fleetHistory": {"postgresEgressCidrs": ["10.0.0.0/8"]}},
        "wrong-storage-region": {"objectStorage": {"endpoint": "https://s3.us-east-1.amazonaws.com"}},
        "plain-http-storage": {"objectStorage": {"endpoint": "http://s3.eu-west-1.amazonaws.com"}},
        "arbitrary-storage-host": {"objectStorage": {"endpoint": "https://evidence.example.invalid"}},
        "storage-query": {"objectStorage": {"endpoint": "https://s3.eu-west-1.amazonaws.com?override=true"}},
        "missing-tenant": {"aws": {"tenantId": ""}},
        "invalid-tenant": {"aws": {"tenantId": "../tenant"}},
        "missing-rds-ca": {"database": {"caConfigMap": ""}},
        "no-replicas": {"fleetHistory": {"replicas": 0}},
        "excess-replicas": {"fleetHistory": {"replicas": 4}},
        "fractional-replicas": {"fleetHistory": {"replicas": 1.5}},
    }


def matches(selector, labels):
    if any(labels.get(key) != value for key, value in selector.get("matchLabels", {}).items()):
        return False
    for expression in selector.get("matchExpressions", []):
        key, operator = expression["key"], expression["operator"]
        assert operator in {"In", "NotIn", "Exists", "DoesNotExist"}
        if operator == "In" and labels.get(key) not in expression["values"]:
            return False
        if operator == "NotIn" and labels.get(key) in expression["values"]:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True


def find(documents, kind, name=NAME):
    selected = [document for document in documents if document["kind"] == kind and document["metadata"]["name"] == name]
    assert len(selected) == 1, "one exact optional reader object required"
    return selected[0]


def check(documents):
    deployment = find(documents, "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    labels = deployment["spec"]["template"]["metadata"]["labels"]
    assert labels["finops-role"] == ROLE
    assert pod["serviceAccountName"] == NAME
    assert pod.get("automountServiceAccountToken", False) is False
    assert not any(pod.get(key) for key in ("hostNetwork", "hostPID", "hostIPC", "hostAliases", "initContainers"))
    assert 1 <= deployment["spec"]["replicas"] <= 3
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] == 10001
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert len(pod["containers"]) == 1
    container = pod["containers"][0]
    security = container["securityContext"]
    assert security["allowPrivilegeEscalation"] is False and security["readOnlyRootFilesystem"] is True
    assert security["capabilities"] == {"drop": ["ALL"]}
    assert not container.get("envFrom")
    entries = container["env"]
    env = {entry["name"]: entry for entry in entries}
    assert len(env) == len(entries), "duplicate variables cannot shadow protected identity"
    assert set(env) == {
        "APP_ROLE", "PORT", "DATA_MODE", "FIXTURE_MODE", "AWS_REGION", "AWS_TENANT_ID",
        "AWS_STS_REGIONAL_ENDPOINTS", "DATABASE_URL", "AWS_SOURCE_READ_BINDINGS_JSON",
        "AWS_FLEET_HISTORY_REGISTRATIONS_JSON", "OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW",
    }, "reader cannot receive signing, execution, analytics, static AWS or arbitrary credentials"
    for key, value in {"APP_ROLE": ROLE, "PORT": "8080", "DATA_MODE": "aws", "FIXTURE_MODE": "false", "AWS_REGION": "eu-west-1", "OBJECT_REGION": "eu-west-1", "AWS_STS_REGIONAL_ENDPOINTS": "regional"}.items():
        assert env[key] == {"name": key, "value": value}
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", env["AWS_TENANT_ID"]["value"])
    assert re.fullmatch(r"https://(s3\.eu-west-1\.amazonaws\.com|[a-z0-9.-]+\.s3\.eu-west-1\.vpce\.amazonaws\.com)/?", env["OBJECT_ENDPOINT"]["value"])
    assert env["OBJECT_BUCKET_RAW"]["value"]
    secret_keys = {}
    for key in ("DATABASE_URL", "AWS_SOURCE_READ_BINDINGS_JSON", "AWS_FLEET_HISTORY_REGISTRATIONS_JSON"):
        assert set(env[key]) == {"name", "valueFrom"}
        ref = env[key]["valueFrom"]["secretKeyRef"]
        assert ref["key"] == key and ref["name"]
        assert not ref.get("optional", False)
        secret_keys[key] = ref["name"]
    assert secret_keys["DATABASE_URL"] not in {secret_keys["AWS_SOURCE_READ_BINDINGS_JSON"], secret_keys["AWS_FLEET_HISTORY_REGISTRATIONS_JSON"]}
    for document in documents:
        if document["kind"] == "Deployment" and document["metadata"]["name"] != NAME:
            for other in document["spec"]["template"]["spec"]["containers"]:
                for entry in other.get("env", []):
                    if entry["name"] == "DATABASE_URL":
                        assert entry["valueFrom"]["secretKeyRef"]["name"] != secret_keys["DATABASE_URL"], "dedicated database secret required"
                    assert entry["name"] != "AWS_FLEET_HISTORY_REGISTRATIONS_JSON", "commissioned target list cannot spread to another service"
    account = find(documents, "ServiceAccount")
    assert account["automountServiceAccountToken"] is False
    arn = account["metadata"]["annotations"]["eks.amazonaws.com/role-arn"]
    assert re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", arn)
    for other in documents:
        if other["kind"] == "ServiceAccount" and other["metadata"]["name"] != NAME:
            assert other["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn") != arn, "IRSA cannot borrow another process identity"
        if other["kind"] in {"RoleBinding", "ClusterRoleBinding"}:
            assert not any(subject.get("kind") == "ServiceAccount" and subject.get("name") == NAME for subject in other.get("subjects", [])), "reader requires no Kubernetes API permissions"
    volumes = {volume["name"]: volume for volume in pod["volumes"]}
    assert set(volumes) == {"tmp", "rds-ca"}
    assert set(volumes["rds-ca"]) == {"name", "configMap"}
    assert set(volumes["tmp"]) == {"name", "emptyDir"}
    assert {mount["name"] for mount in container["volumeMounts"]} == set(volumes)
    assert next(mount for mount in container["volumeMounts"] if mount["name"] == "rds-ca")["readOnly"] is True
    assert container["ports"] == [{"name": "http", "containerPort": 8080}]
    for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert container[probe]["httpGet"] == {"path": "/healthz", "port": "http"}
    service = find(documents, "Service")
    assert service["spec"]["type"] == "ClusterIP"
    assert not service["spec"].get("externalIPs")
    policies = [document for document in documents if document["kind"] == "NetworkPolicy"]
    default = find(documents, "NetworkPolicy", "finops-default-deny")["spec"]
    assert default["podSelector"] == {} and set(default["policyTypes"]) == {"Ingress", "Egress"}
    assert not default.get("ingress") and not default.get("egress")
    allowed = {(53, "UDP"), (53, "TCP"), (443, "TCP"), (5432, "TCP")}
    observed = set()
    for policy in policies:
        spec = policy["spec"]
        if not matches(spec.get("podSelector", {}), labels):
            continue
        assert not spec.get("ingress"), "no other pod receives history-reader access"
        for rule in spec.get("egress", []):
            assert rule.get("to") and rule.get("ports"), "NetworkPolicy grants are additive: every selected rule needs explicit destination and port"
            for port in rule["ports"]:
                key = port.get("port"), port.get("protocol", "TCP")
                assert key in allowed and not port.get("endPort")
                observed.add(key)
                for peer in rule["to"]:
                    if key[0] == 53:
                        assert peer == {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
                    else:
                        assert set(peer) == {"ipBlock"} and set(peer["ipBlock"]) == {"cidr"}
                        network = ipaddress.ip_network(peer["ipBlock"]["cidr"])
                        assert network.version == 4 and network.prefixlen >= 16
                        assert not any(network.overlaps(ipaddress.ip_network(block)) for block in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"))
                        if key[0] == 5432:
                            assert any(network.subnet_of(ipaddress.ip_network(block)) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    assert observed == allowed, "reader requires precisely DNS, reviewed HTTPS and private database networks"


class FleetHistoryChart(unittest.TestCase):
    def test_actual_rendered_identity_and_network_isolation(self):
        check(ORIGINAL)

    def test_other_process_credentials_or_kubernetes_authority_fail(self):
        for confusion in ("signing", "executor", "static-aws", "analytics", "role", "database", "envfrom", "token", "privileged", "service", "rbac", "broad-dns-https", "broad-postgres", "broad-internal", "any-port", "any-target", "public-database", "metadata", "wrong-region"):
            with self.subTest(confusion=confusion):
                documents = copy.deepcopy(ORIGINAL)
                pod = find(documents, "Deployment")["spec"]["template"]["spec"]
                env = pod["containers"][0]["env"]
                policy = find(documents, "NetworkPolicy", NAME + "-egress")["spec"]
                if confusion in {"signing", "executor", "static-aws", "analytics"}:
                    key = {"signing": "SIGNING_PRIVATE_KEY", "executor": "EXECUTOR_TOKEN", "static-aws": "AWS_ACCESS_KEY_ID", "analytics": "CLICKHOUSE_PASSWORD"}[confusion]
                    env.append({"name": key, "value": "fixture-invalid"})
                elif confusion == "role":
                    find(documents, "ServiceAccount")["metadata"]["annotations"]["eks.amazonaws.com/role-arn"] = find(documents, "ServiceAccount", "finops-ingester")["metadata"]["annotations"]["eks.amazonaws.com/role-arn"]
                elif confusion == "database":
                    next(entry for entry in env if entry["name"] == "DATABASE_URL")["valueFrom"]["secretKeyRef"]["name"] = "finops-db-api"
                elif confusion == "envfrom":
                    pod["containers"][0]["envFrom"] = [{"secretRef": {"name": "finops-signer"}}]
                elif confusion == "token":
                    pod["automountServiceAccountToken"] = True
                elif confusion == "privileged":
                    pod["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = True
                elif confusion == "service":
                    find(documents, "Service")["spec"]["type"] = "LoadBalancer"
                elif confusion == "rbac":
                    documents.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "invalid-history-admin"}, "subjects": [{"kind": "ServiceAccount", "name": NAME}], "roleRef": {"kind": "ClusterRole", "name": "cluster-admin", "apiGroup": "rbac.authorization.k8s.io"}})
                elif confusion == "broad-dns-https":
                    find(documents, "NetworkPolicy", "finops-dns-and-https")["spec"]["podSelector"]["matchExpressions"][0]["values"].remove(ROLE)
                elif confusion == "broad-postgres":
                    find(documents, "NetworkPolicy", "finops-postgres-egress")["spec"]["podSelector"]["matchExpressions"][0]["values"].append(ROLE)
                elif confusion == "broad-internal":
                    find(documents, "NetworkPolicy", "finops-internal-egress")["spec"]["podSelector"]["matchExpressions"][0]["values"].append(ROLE)
                elif confusion == "any-port":
                    policy["egress"][1].pop("ports")
                elif confusion == "any-target":
                    policy["egress"][-1].pop("to")
                elif confusion in {"public-database", "metadata"}:
                    rule = policy["egress"][1 if confusion == "public-database" else 2]
                    rule["to"] = [{"ipBlock": {"cidr": "8.8.8.0/24" if confusion == "public-database" else "169.254.169.254/32"}}]
                elif confusion == "wrong-region":
                    next(entry for entry in env if entry["name"] == "OBJECT_ENDPOINT")["value"] = "https://s3.us-east-1.amazonaws.com"
                with self.assertRaises(AssertionError):
                    check(documents)


if __name__ == "__main__":
    # Optional CI helper: emit only these public test overrides into a new owned
    # directory, then run `helm template ... -f CASE.json` expecting nonzero.
    if "--write-negative-values" in sys.argv:
        at = sys.argv.index("--write-negative-values")
        directory = Path(sys.argv[at + 1])
        del sys.argv[at:at + 2]
        directory.mkdir(exist_ok=False)
        for name, values in invalid_values().items():
            (directory / (name + ".json")).write_text(json.dumps(values) + "\n", encoding="utf-8")
    unittest.main()
