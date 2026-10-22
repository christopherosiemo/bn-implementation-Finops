"""Inspect actual rendered optional portfolio manifests; never contacts a cluster."""
import copy
import ipaddress
import json
import re
import sys
import unittest
from pathlib import Path

import yaml

manifest = Path(sys.argv.pop(1))
with manifest.open(encoding="utf-8") as source:
    ORIGINAL = json.load(source) if manifest.suffix == ".json" else [row for row in yaml.safe_load_all(source) if row]
ANALYST, MODEL = "commitment-portfolio", "commitment-portfolio-model"

def find(rows, kind, role):
    matches = [row for row in rows if row["kind"] == kind and row["metadata"]["name"] == "finops-" + role]
    assert len(matches) == 1
    return matches[0]

def matches(selector, labels):
    if any(labels.get(k) != v for k, v in selector.get("matchLabels", {}).items()):
        return False
    for item in selector.get("matchExpressions", []):
        key, op = item["key"], item["operator"]
        assert op in ("In", "NotIn", "Exists", "DoesNotExist")
        if op == "In" and labels.get(key) not in item["values"] or op == "NotIn" and labels.get(key) in item["values"]:
            return False
        if op == "Exists" and key not in labels or op == "DoesNotExist" and key in labels:
            return False
    return True

def pod(rows, role):
    return find(rows, "Deployment", role)["spec"]["template"]["spec"]

def container(rows, role):
    return pod(rows, role)["containers"][0]

def check(rows):
    credentials = {}
    for role in (ANALYST, MODEL):
        account, specification = find(rows, "ServiceAccount", role), pod(rows, role)
        assert account["automountServiceAccountToken"] is False and not account["metadata"].get("annotations")
        assert specification["serviceAccountName"] == "finops-" + role and specification["automountServiceAccountToken"] is False
        assert not any(specification.get(key) for key in ("hostNetwork", "hostPID", "hostIPC", "hostAliases", "initContainers"))
        assert specification["securityContext"] == {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
        assert len(specification["containers"]) == 1
        c = container(rows, role)
        assert c["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        assert not c.get("envFrom") and not c.get("args")
        env = {entry["name"]: entry["value"] for entry in c["env"]}
        mounts, volumes = {v["name"]: v for v in c["volumeMounts"]}, {v["name"]: v for v in specification["volumes"]}
        assert len(env) == len(c["env"]) and volumes["tmp"]["emptyDir"] == {"sizeLimit": "16Mi"}
        assert mounts["model-token"] == {"name": "model-token", "mountPath": "/run/secrets/commitment-portfolio-model-token", "subPath": "token", "readOnly": True}
        assert volumes["model-token"]["secret"]["defaultMode"] == 0o440
        assert volumes["model-token"]["secret"]["items"] == [{"key": "token", "path": "token"}]
        credentials[role] = {name: value["secret"]["secretName"] for name, value in volumes.items() if "secret" in value}
        if role == ANALYST:
            assert c["command"] == ["/app/commitment-portfolio-worker"]
            assert set(env) == {"COMMITMENT_PORTFOLIO_" + suffix for suffix in ("ENABLED", "TENANT_ID", "DATABASE_FILE", "DATABASE_MODE", "MODEL_URL", "MODEL_TOKEN_FILE")}
            assert env["COMMITMENT_PORTFOLIO_ENABLED"] == "true" and env["COMMITMENT_PORTFOLIO_DATABASE_MODE"] == "HOSTED_TLS"
            assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", env["COMMITMENT_PORTFOLIO_TENANT_ID"])
            assert re.fullmatch(r"https://finops-commitment-portfolio-model\.[a-z0-9-]+\.svc\.cluster\.local:443", env["COMMITMENT_PORTFOLIO_MODEL_URL"])
            assert env["COMMITMENT_PORTFOLIO_DATABASE_FILE"] == "/run/secrets/commitment-portfolio-database" and env["COMMITMENT_PORTFOLIO_MODEL_TOKEN_FILE"] == "/run/secrets/commitment-portfolio-model-token"
            assert set(volumes) == set(mounts) == {"tmp", "database", "database-ca", "model-token", "model-ca"}
            assert mounts["database"] == {"name": "database", "mountPath": env["COMMITMENT_PORTFOLIO_DATABASE_FILE"], "subPath": "DATABASE_URL", "readOnly": True}
            assert volumes["database"]["secret"]["items"] == [{"key": "DATABASE_URL", "path": "DATABASE_URL"}] and volumes["database"]["secret"]["defaultMode"] == 0o440
            assert mounts["database-ca"] == {"name": "database-ca", "mountPath": "/run/ca/commitment-portfolio-root.crt", "subPath": "ca.crt", "readOnly": True}
            assert mounts["model-ca"] == {"name": "model-ca", "mountPath": "/run/ca/commitment-portfolio-model-root.crt", "subPath": "ca.crt", "readOnly": True}
            assert volumes["database-ca"]["configMap"]["name"] != volumes["model-ca"]["configMap"]["name"]
            assert c["readinessProbe"]["httpGet"] == {"path": "/readyz", "port": "http"}
        else:
            assert c["command"] == ["python", "-m", "autopilot.portfolio_server"] and env == {"COMMITMENT_PORTFOLIO_MODEL_MODE": "HOSTED_TLS"}
            assert set(volumes) == {"tmp", "model-token", "model-tls"} and set(mounts) == {"tmp", "model-token", "model-tls"}
            assert c["ports"] == [{"name": "https", "containerPort": 8443}]
            assert volumes["model-tls"]["secret"]["defaultMode"] == 0o440 and volumes["model-tls"]["secret"]["items"] == [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]
            tls_mounts = [v for v in c["volumeMounts"] if v["name"] == "model-tls"]
            assert tls_mounts == [{"name": "model-tls", "mountPath": "/run/tls/commitment-portfolio/tls.crt", "subPath": "tls.crt", "readOnly": True}, {"name": "model-tls", "mountPath": "/run/tls/commitment-portfolio/tls.key", "subPath": "tls.key", "readOnly": True}]
            for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
                assert c[probe]["httpGet"] == {"path": "/healthz", "port": "https", "scheme": "HTTPS"}
        policies = [row["spec"] for row in rows if row["kind"] == "NetworkPolicy" and matches(row["spec"].get("podSelector", {}), {"finops-role": role})]
        assert any(set(p.get("policyTypes", [])) == {"Ingress", "Egress"} and not p.get("ingress") and not p.get("egress") for p in policies)
        egress_seen, ingress_seen = set(), set()
        for policy in policies:
            for rule in policy.get("egress", []):
                assert role == ANALYST and rule.get("ports") and rule.get("to")
                for port in rule["ports"]:
                    number, protocol = port["port"], port.get("protocol", "TCP")
                    assert not port.get("endPort") and (number, protocol) in {(53, "UDP"), (53, "TCP"), (5432, "TCP"), (443, "TCP"), (8443, "TCP")}
                    egress_seen.add(number)
                    for target in rule["to"]:
                        if number == 53:
                            assert target == {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
                        elif number in (443, 8443):
                            assert target == {"podSelector": {"matchLabels": {"finops-role": MODEL}}}
                        else:
                            assert set(target) == {"ipBlock"} and set(target["ipBlock"]) == {"cidr"}
                            cidr = ipaddress.ip_network(target["ipBlock"]["cidr"])
                            assert cidr.version == 4 and cidr.prefixlen >= 16 and any(cidr.subnet_of(ipaddress.ip_network(parent)) for parent in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
            for rule in policy.get("ingress", []):
                assert role == MODEL and rule == {"from": [{"podSelector": {"matchLabels": {"finops-role": ANALYST}}}], "ports": [{"protocol": "TCP", "port": 8443}]}
                ingress_seen.add(8443)
        assert egress_seen == ({53, 443, 8443, 5432} if role == ANALYST else set())
        assert ingress_seen == ({8443} if role == MODEL else set())
    assert credentials[ANALYST]["model-token"] == credentials[MODEL]["model-token"]
    private_names = {credentials[ANALYST]["database"], credentials[ANALYST]["model-token"], credentials[MODEL]["model-tls"]}
    assert len(private_names) == 3
    for row in rows:
        if row["kind"] != "Deployment" or row["metadata"]["name"] in ("finops-" + ANALYST, "finops-" + MODEL):
            continue
        other = row["spec"]["template"]["spec"]
        assert all(v.get("secret", {}).get("secretName") not in private_names for v in other.get("volumes", []))
        for c in other["containers"]:
            assert all(e.get("valueFrom", {}).get("secretKeyRef", {}).get("name") not in private_names for e in c.get("env", []))
    service = find(rows, "Service", MODEL)["spec"]
    assert service == {"type": "ClusterIP", "selector": {"finops-role": MODEL}, "ports": [{"name": "https", "port": 443, "targetPort": "https"}]}


def invalid_values():
    return {
        "string-enabled": {"commitmentPortfolio": {"enabled": "false"}},
        "no-default-deny": {"networkPolicy": {"enabled": False}},
        "no-tenant": {"commitmentPortfolio": {"tenantId": ""}},
        "no-model-token": {"commitmentPortfolio": {"modelTokenSecret": ""}},
        "no-model-tls": {"commitmentPortfolio": {"modelTLSSecret": ""}},
        "no-model-ca": {"commitmentPortfolio": {"modelCAConfigMap": ""}},
        "shared-db": {"database": {"secrets": {ANALYST: "finops-db-api"}}},
        "shared-signing-token": {"commitmentPortfolio": {"modelTokenSecret": "finops-signer"}},
        "shared-model-token-tls": {"commitmentPortfolio": {"modelTLSSecret": "finops-portfolio-model-token"}},
        "shared-model-database-ca": {"commitmentPortfolio": {"modelCAConfigMap": "finops-rds-ca"}},
        "world-egress": {"commitmentPortfolio": {"postgresEgressCidrs": ["0.0.0.0/0"]}},
        "broad-private": {"commitmentPortfolio": {"postgresEgressCidrs": ["10.0.0.0/8"]}},
        "public-db": {"commitmentPortfolio": {"postgresEgressCidrs": ["8.8.8.0/24"]}},
        "metadata-db": {"commitmentPortfolio": {"postgresEgressCidrs": ["169.254.169.254/32"]}},
        "model-replicas-zero": {"commitmentPortfolio": {"modelReplicas": 0}},
    }


class PortfolioDeployment(unittest.TestCase):
    def test_actual_rendered_boundary(self):
        check(ORIGINAL)

    def test_widened_credentials_network_and_plaintext_rejected(self):
        mutations = {
            "model-db": lambda rows: pod(rows, MODEL)["volumes"].append(copy.deepcopy(next(v for v in pod(rows, ANALYST)["volumes"] if v["name"] == "database"))),
            "workload-token": lambda rows: find(rows, "ServiceAccount", ANALYST).update(automountServiceAccountToken=True),
            "plaintext": lambda rows: container(rows, MODEL)["env"][0].update(value="LOCAL_PRIVATE"),
            "http-under443": lambda rows: container(rows, MODEL)["ports"][0].update(containerPort=8000),
            "broad-egress": lambda rows: rows.append({"kind": "NetworkPolicy", "metadata": {"name": "unsafe"}, "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"ports": [{"port": 443}]}]}}),
            "public-service": lambda rows: find(rows, "Service", MODEL)["spec"].update(type="LoadBalancer"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                rows = copy.deepcopy(ORIGINAL)
                mutate(rows)
                with self.assertRaises((AssertionError, KeyError)):
                    check(rows)


if __name__ == "__main__":
    if "--write-negative-values" in sys.argv:
        offset = sys.argv.index("--write-negative-values")
        destination = Path(sys.argv[offset + 1])
        destination.mkdir(parents=True, exist_ok=True)
        del sys.argv[offset:offset + 2]
        for name, value in invalid_values().items():
            (destination / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    unittest.main()
