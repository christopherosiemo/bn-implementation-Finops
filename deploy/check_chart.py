"""Check the rendered deployment's credential boundaries, independent of templates.

Usage: python deploy/check_chart.py rendered.yaml  (requires PyYAML)
This accepts only manifests; never pass a values file containing secret values.
"""
import sys
import ipaddress
import yaml


def selector_matches(selector, labels):
    if any(labels.get(key) != value for key, value in selector.get("matchLabels", {}).items()):
        return False
    for expression in selector.get("matchExpressions", []):
        key, operator = expression["key"], expression["operator"]
        if operator == "In" and labels.get(key) not in expression["values"]:
            return False
        if operator == "NotIn" and labels.get(key) in expression["values"]:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
        assert operator in {"In", "NotIn", "Exists", "DoesNotExist"}
    return True


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
    native = {"telemetry-reader", "telemetry-ingress"}
    native_enabled = bool(native & deployments.keys())
    if native_enabled:
        assert native <= deployments.keys(), "native transports must both have separate deployments"
        required |= native
    observer_enabled = "deployment-observer" in deployments
    if observer_enabled:
        required.add("deployment-observer")
    hardware_enabled = "hardware-reader" in deployments
    if hardware_enabled:
        required.add("hardware-reader")
    lambda_performance = any(value.get("name") == "LAMBDA_PERFORMANCE_ENABLED" and value.get("value") == "true" for value in deployments["activity-ingress"]["spec"]["template"]["spec"]["containers"][0].get("env", []))
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
        if role != "signer":
            assert "SIGNING_PRIVATE_KEY" not in envs[role]
        if role not in {"worker", "signer"}:
            assert "SIGNER_TOKEN" not in envs[role]
        if role not in {"worker", "executor"}:
            assert "EXECUTOR_TOKEN" not in envs[role]
        assert ("CLICKHOUSE_PASSWORD" in secret_keys[role]) == (role in {"ingester"} | native)
        assert ("ECONOMICS_TOKEN" in secret_keys[role]) == (role in {"api", "ingester", "economics"})
        if role != "worker":
            assert "WEBHOOK_SECRET" not in secret_keys[role]
            assert "WEBHOOK_URL" not in envs[role]
        if role not in {"ingester", "executor", "signer", "hardware-reader"} | native:
            assert "eks.amazonaws.com/role-arn" not in accounts[role]["metadata"].get("annotations", {})
        if role not in {"ingester", "hardware-reader"} | native and not (role == "activity-ingress" and lambda_performance):
            assert not any(key.startswith("OBJECT_") for key in envs[role])
        if role == "activity-ingress" and lambda_performance:
            assert not {"OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY", "CLICKHOUSE_PASSWORD", "AWS_READ_ROLE_ARN", "AWS_EXECUTION_ROLE_ARN"} & envs[role].keys()
            assert envs[role]["OBJECT_REGION"]["value"] == "eu-west-1"
            assert envs[role]["LAMBDA_PERFORMANCE_OIDC_AUDIENCE"]["value"] not in {envs[role]["ACTIVITY_OIDC_AUDIENCE"]["value"], envs[role]["OIDC_AUDIENCE"]["value"]}
            assert secret_keys[role]["LAMBDA_PERFORMANCE_ACCESS_KEY"]["name"] != secret_keys[role]["LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD"]["name"]
        if role != "ingester":
            assert "AWS_READ_ROLE_ARN" not in envs[role]
        if role not in {"ingester", "hardware-reader"}:
            assert "AWS_SOURCE_READ_BINDINGS_JSON" not in envs[role]
        if role != "hardware-reader":
            assert "AWS_HARDWARE_TARGETS_JSON" not in envs[role]
        if role != "executor":
            assert "AWS_EXECUTION_ROLE_ARN" not in envs[role]
    go_roles = {"api", "worker", "ingester", "signer", "executor", "activity-ingress"}
    if hardware_enabled:
        go_roles.add("hardware-reader")
        hardware = envs["hardware-reader"]
        assert hardware["APP_ROLE"]["value"] == "hardware-reader"
        assert hardware["FIXTURE_MODE"]["value"] == "false"
        assert hardware["AWS_REGION"]["value"] == hardware["OBJECT_REGION"]["value"] == "eu-west-1"
        assert hardware["AWS_TENANT_ID"]["value"]
        assert set(secret_keys["hardware-reader"]) == {"DATABASE_URL", "AWS_SOURCE_READ_BINDINGS_JSON", "AWS_HARDWARE_TARGETS_JSON"}
        assert not {"OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AUDIT_ACCESS_KEY", "AUDIT_SECRET_KEY", "ECONOMICS_TOKEN", "CLICKHOUSE_PASSWORD"} & hardware.keys()
        assert hardware["OBJECT_ENDPOINT"]["value"].startswith("https://")
        arn = accounts["hardware-reader"]["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn")
        assert arn and arn not in {accounts[r]["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn") for r in required - {"hardware-reader"}}
        policies = {doc["metadata"]["name"]: doc for doc in manifests if doc["kind"] == "NetworkPolicy"}
        general = policies["finops-dns-and-https"]["spec"]["podSelector"]["matchExpressions"]
        assert any(rule["operator"] == "NotIn" and "hardware-reader" in rule["values"] for rule in general)
        # NetworkPolicy grants are additive. Inspect every policy selecting this
        # pod, including accidentally widened shared policies, not just its own.
        for policy in policies.values():
            spec = policy["spec"]
            if not selector_matches(spec.get("podSelector", {}), {"finops-role": "hardware-reader"}):
                continue
            for rule in spec.get("egress", []):
                assert rule.get("ports") and rule.get("to"), "hardware egress requires explicit ports and destinations"
                for port in rule["ports"]:
                    assert not port.get("endPort"), "hardware egress cannot expand a port range"
                    number, protocol = port.get("port"), port.get("protocol", "TCP")
                    assert (number, protocol) in {(53, "UDP"), (53, "TCP"), (443, "TCP"), (5432, "TCP")}
                    for peer in rule["to"]:
                        if number == 53:
                            assert peer == {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
                        else:
                            assert set(peer) == {"ipBlock"} and set(peer["ipBlock"]) == {"cidr"}
                            network = ipaddress.ip_network(peer["ipBlock"]["cidr"])
                            assert network.prefixlen > 0
                            if number == 5432:
                                assert any(network.subnet_of(private) for private in (
                                    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                                    ipaddress.ip_network("192.168.0.0/16"),
                                ) if private.version == network.version) or (network.version == 6 and network.subnet_of(ipaddress.ip_network("fc00::/7"))), "hardware PostgreSQL egress must stay in reviewed private networks"
    if observer_enabled:
        go_roles.add("deployment-observer")
        observer = envs["deployment-observer"]
        assert observer["APP_ROLE"]["value"] == "deployment-observer"
        reserved = {envs["api"]["OIDC_AUDIENCE"]["value"], envs["activity-ingress"]["ACTIVITY_OIDC_AUDIENCE"]["value"], "finops-telemetry"}
        if native_enabled:
            reserved.add(envs["telemetry-ingress"]["TELEMETRY_OIDC_AUDIENCE"]["value"])
        assert observer["DEPLOYMENT_OIDC_AUDIENCE"]["value"] not in reserved
        assert observer["DEPLOYMENT_OIDC_ISSUER"]["value"].startswith("https://")
        assert set(secret_keys["deployment-observer"]) == {"DATABASE_URL"}, "observer receives only its restricted database secret"
        assert not accounts["deployment-observer"]["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn")
        policies = {doc["metadata"]["name"]: doc for doc in manifests if doc["kind"] == "NetworkPolicy"}
        general = policies["finops-dns-and-https"]["spec"]["podSelector"]["matchExpressions"]
        assert any(rule["operator"] == "NotIn" and "deployment-observer" in rule["values"] for rule in general)
        for rule in policies["finops-deployment-observer-egress"]["spec"]["egress"]:
            if any(port.get("port") == 443 for port in rule.get("ports", [])):
                assert rule.get("to"), "observer HTTPS egress must target approved JWKS networks"
                assert all(ipaddress.ip_network(peer["ipBlock"]["cidr"]).prefixlen > 0 for peer in rule["to"])
        ingress = policies["finops-deployment-observer-ingress"]["spec"]["ingress"]
        assert ingress[0]["from"][0]["podSelector"]["matchLabels"], "observer requires an explicit local pipeline selector"
    if native_enabled:
        go_roles |= native
        assert envs["telemetry-ingress"]["TELEMETRY_OIDC_AUDIENCE"]["value"] not in {
            envs["api"]["OIDC_AUDIENCE"]["value"], envs["activity-ingress"]["ACTIVITY_OIDC_AUDIENCE"]["value"]
        }
        assert envs["telemetry-ingress"]["TELEMETRY_OIDC_ISSUER"]["value"] == envs["api"]["TELEMETRY_OIDC_ISSUER"]["value"]
        assert envs["api"]["TELEMETRY_READER_URL"]["value"] == "http://finops-telemetry-reader:8080"
        for role in required:
            assert ("TELEMETRY_READER_TOKEN" in secret_keys[role]) == (role in {"api", "telemetry-reader"})
            if role != "telemetry-reader":
                assert "TELEMETRY_READ_BINDINGS_JSON" not in envs[role]
            if role != "api":
                assert "TELEMETRY_BINDING_CATALOG_JSON" not in envs[role]
        native_arns = [accounts[role]["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn") for role in native]
        assert len(set(arn for arn in native_arns if arn)) == sum(bool(arn) for arn in native_arns), "native IRSA identities must differ"
        other_arns = {accounts[role]["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn") for role in {"signer", "executor", "ingester"}}
        assert not set(arn for arn in native_arns if arn) & other_arns
        policies = {doc["metadata"]["name"]: doc for doc in manifests if doc["kind"] == "NetworkPolicy"}
        reader_policy = policies["finops-native-reader-ingress"]
        reader_senders = [{"podSelector": {"matchLabels": {"finops-role": "api"}}}]
        if any(doc["kind"] == "Deployment" and doc["metadata"]["name"] == "finops-fleet-capacity" for doc in manifests):
            reader_senders.append({"podSelector": {"matchLabels": {"finops-role": "fleet-capacity"}}})
        assert reader_policy["spec"]["ingress"][0]["from"] == reader_senders
        general_https = policies["finops-dns-and-https"]["spec"]["podSelector"]["matchExpressions"]
        assert any(rule["operator"] == "NotIn" and native <= set(rule["values"]) for rule in general_https)
        for rule in policies["finops-native-egress"]["spec"]["egress"]:
            if any(port.get("port") == 443 for port in rule.get("ports", [])):
                assert rule.get("to"), "native HTTPS cannot be unrestricted"
                assert all(peer.get("ipBlock", {}).get("cidr", "").split("/")[-1] != "0" for peer in rule["to"])
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
        if doc["kind"] == "Service" and doc["metadata"]["name"] in {"finops-signer", "finops-executor", "finops-telemetry-reader", "finops-telemetry-ingress", "finops-deployment-observer", "finops-hardware-reader"}:
            assert doc["spec"].get("type", "ClusterIP") == "ClusterIP"
    for role in ("signer", "executor"):
        policy = next(doc for doc in manifests if doc["kind"] == "NetworkPolicy" and doc["metadata"]["name"] == "finops-ingress-" + role)
        senders = policy["spec"]["ingress"][0]["from"]
        assert senders == [{"podSelector": {"matchLabels": {"finops-role": "worker"}}}]
    print("Rendered chart preserves ingestion, signing, execution, database and network boundaries.")


if __name__ == "__main__":
    check(sys.argv[1])
