// Real local Kubernetes acceptance. The only GitOps controller here is the
// explicitly labelled LOCAL_GITOPS_TEST_DOUBLE; no hosted target is accepted.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { labKindPath } from './kubernetes-bootstrap.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cluster = 'finops-autopilot-lab', control = `${cluster}-control-plane`, ns = 'finops-k8s-lab';
const dir = path.join(root, 'work/kubernetes-lab'), repository = path.join(dir, 'repository');
const engine = 'LOCAL_GITOPS_TEST_DOUBLE', repositoryID = 'local:finops-kubernetes-lab';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const run = (program, args, input, options = {}) => execFileSync(program, args, { cwd: root, encoding: 'utf8', maxBuffer: 16 << 20, stdio: ['pipe', 'pipe', 'pipe'], ...(input === undefined ? {} : { input }), ...options });
const kube = (args, input) => run('docker', ['exec', '-i', control, 'kubectl', '--kubeconfig', '/etc/kubernetes/admin.conf', ...args], input);
const get = (kind, name, namespace = ns) => JSON.parse(kube(['get', kind, ...(name ? [name] : []), ...(namespace ? ['-n', namespace] : []), '-o', 'json']));
const apply = object => kube(['apply', '-f', '-'], JSON.stringify(object));
const git = args => run('git', ['-C', repository, ...args]).trim();
const head = () => git(['rev-parse', 'HEAD']);
let passed = 0;
const pass = message => { passed++; console.log(`Kubernetes lab: ${message}`); };

function cli(mode, object) {
  const result = run('docker', ['run', '--rm', '-i', '--network', 'kind', '-e', 'K8S_API_URL=https://finops-autopilot-lab-control-plane:6443', '-e', 'K8S_API_TOKEN_FILE=/lab/reader.token', '-e', 'K8S_API_CA_FILE=/lab/ca.crt', '-v', `${dir}:/lab:ro`, '--entrypoint', '/lab/k8s-safety', 'golang:1.27.2-bookworm', mode], JSON.stringify(object));
  return JSON.parse(result);
}
async function waitFor(check, message, timeout = 90000) { const deadline = Date.now() + timeout; while (Date.now() < deadline) { const value = check(); if (value) return value; await sleep(1000); } throw new Error(message); }

async function main() {
  assert.equal(process.argv.length, 2, 'No remote target, context, or namespace arguments are accepted');
  assert.ok(existsSync(path.join(dir, 'kubeconfig')), 'Run the verified local KIND bootstrap first');
  const inspected = JSON.parse(run('docker', ['inspect', control]))[0];
  assert.equal(inspected.Config.Labels['io.x-k8s.kind.cluster'], cluster);
  const nodes = get('nodes', '', '').items;
  assert.equal(nodes.length, 3); assert.ok(nodes.every(node => node.metadata.name.startsWith(cluster + '-')));
  const zones = new Set(nodes.map(node => node.metadata.labels['topology.kubernetes.io/zone']).filter(Boolean)); assert.deepEqual([...zones].sort(), ['lab-a', 'lab-b']);
  assert.ok(nodes.every(node => node.status.conditions.some(c => c.type === 'Ready' && c.status === 'True')));
  pass('exact isolated three-node KIND cluster and two Ready worker zones');

  const image = JSON.parse(run('docker', ['image', 'inspect', 'python:3.13-slim']))[0];
  assert.ok(image.RepoDigests.some(value => value.endsWith('sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f')), 'Expected pinned local Python digest');
  const archive = path.join(dir, 'python-amd64.tar');
  run('docker', ['image', 'save', '--platform', 'linux/amd64', '-o', archive, 'python:3.13-slim']);
  run(labKindPath(root), ['load', 'image-archive', archive, '--name', cluster]);
  mkdirSync(repository, { recursive: true, mode: 0o700 });
  apply({ apiVersion: 'v1', kind: 'Namespace', metadata: { name: ns, labels: { 'finops.autopilot/environment': 'NON_PRODUCTION', 'finops.autopilot/owner': 'local-lab-operator' } } });
  apply({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'gateway-code', namespace: ns }, data: { 'gateway.py': readFileSync(path.join(root, 'examples/telemetry/gateway.py'), 'utf8') } });
  apply({ apiVersion: 'v1', kind: 'ServiceAccount', metadata: { name: 'finops-k8s-reader', namespace: ns }, automountServiceAccountToken: false });
  const roleName = 'finops-local-k8s-reader';
  apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRole', metadata: { name: roleName }, rules: [{ apiGroups: [''], resources: ['namespaces'], resourceNames: ['kube-system', ns], verbs: ['get'] }, { apiGroups: [''], resources: ['nodes'], verbs: ['get', 'list'] }, { apiGroups: ['apiextensions.k8s.io'], resources: ['customresourcedefinitions'], verbs: ['get', 'list'] }] });
  apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRoleBinding', metadata: { name: roleName }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: roleName }, subjects: [{ kind: 'ServiceAccount', name: 'finops-k8s-reader', namespace: ns }] });
  const subject = { kind: 'ServiceAccount', name: 'finops-k8s-reader', namespace: ns };
  for (const namespace of [ns, 'kube-system']) {
    const rules = namespace === ns ? [{ apiGroups: ['apps'], resources: ['deployments', 'replicasets'], verbs: ['get', 'list'] }, { apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }, { apiGroups: [''], resources: ['configmaps'], resourceNames: ['gitops-ack'], verbs: ['get'] }, { apiGroups: ['policy'], resources: ['poddisruptionbudgets'], verbs: ['get', 'list'] }, { apiGroups: ['autoscaling'], resources: ['horizontalpodautoscalers'], verbs: ['get', 'list'] }, { apiGroups: ['autoscaling.k8s.io'], resources: ['verticalpodautoscalers'], verbs: ['get', 'list'] }] : [{ apiGroups: ['apps'], resources: ['deployments'], verbs: ['get', 'list'] }];
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role', metadata: { name: roleName, namespace }, rules });
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: roleName, namespace }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: roleName }, subjects: [subject] });
  }
  const token = kube(['create', 'token', 'finops-k8s-reader', '-n', ns, '--duration=30m']).trim();
  writeFileSync(path.join(dir, 'reader.token'), token, { mode: 0o600 });
  writeFileSync(path.join(dir, 'ca.crt'), kube(['get', 'configmap', 'kube-root-ca.crt', '-n', ns, '-o', 'jsonpath={.data.ca\\.crt}']), { mode: 0o600 });
  assert.equal(kube(['auth', 'can-i', 'get', 'pods', '--as', `system:serviceaccount:${ns}:finops-k8s-reader`, '-n', ns]).trim(), 'yes');
  for (const args of [['patch', 'deployments'], ['get', 'secrets']]) { let response; try { response = kube(['auth', 'can-i', ...args, '--as', `system:serviceaccount:${ns}:finops-k8s-reader`, '-n', ns]).trim(); } catch (error) { response = String(error.stdout || '').trim(); } assert.equal(response, 'no'); }
  pass('separate real Kubernetes reader can inventory but cannot mutate workloads or read Secrets');

  run('docker', ['run', '--rm', '-e', 'GOMAXPROCS=2', '-v', `${root}:/src`, '-v', 'finops-go-mod:/go/pkg/mod', '-v', 'finops-go-cache-127:/root/.cache/go-build', '-w', '/src', 'golang:1.27.2-bookworm', 'go', 'build', '-buildvcs=false', '-o', '/src/work/kubernetes-lab/k8s-safety', './internal/kubernetes/labcmd']);
  if (!existsSync(path.join(repository, '.git'))) { git(['init', '-q']); git(['config', 'user.name', 'FinOps local lab']); git(['config', 'user.email', 'local-lab@example.invalid']); }
  let manifest = JSON.parse(readFileSync(path.join(root, 'examples/kubernetes/deployment.json'), 'utf8'));
  const save = object => writeFileSync(path.join(repository, 'deployment.json'), JSON.stringify(object, null, 2) + '\n');
  const commit = message => { git(['add', 'deployment.json']); git(['commit', '--allow-empty', '-q', '-m', message]); return head(); };
  save(manifest); const initial = commit('Local lab: initial reviewed Deployment');
  const ack = (revision, ready, specHash = '') => apply({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'gitops-ack', namespace: ns }, data: { engine, repository: repositoryID, path: 'deployment.json', revision, ready: String(ready), synced: String(ready), deployment_spec_hash: specHash, observed_at: new Date().toISOString(), observed_generation: String(get('deployment', 'gateway').metadata.generation) } });
  function controllerApply(revision) { assert.equal(head(), revision, 'Git head changed before reconciliation'); const desired = JSON.parse(git(['show', revision + ':deployment.json'])); assert.equal(desired.metadata.namespace, ns); assert.equal(desired.metadata.name, 'gateway'); apply(desired); ack(revision, false); }
  controllerApply(initial);
  const pdb = minAvailable => ({ apiVersion: 'policy/v1', kind: 'PodDisruptionBudget', metadata: { name: 'gateway', namespace: ns }, spec: { minAvailable, selector: { matchLabels: { app: 'finops-k8s-gateway' } } } });
  apply(pdb(1)); kube(['rollout', 'status', 'deployment/gateway', '-n', ns, '--timeout=90s']);
  const clusterID = get('namespace', 'kube-system', '').metadata.uid, namespaceUID = get('namespace', ns, '').metadata.uid, deploymentUID = get('deployment', 'gateway').metadata.uid;
  const binding = { tenant_id: 'tenant-kubernetes-lab', workload_id: 'workload-kubernetes-lab', provider: 'LOCAL_KIND', cluster_id: clusterID, namespace: ns, namespace_uid: namespaceUID, deployment: 'gateway', deployment_uid: deploymentUID, owner: 'local-lab-operator', git: { engine, repository: repositoryID, path: 'deployment.json', controller_namespace: ns, controller_name: 'gitops-ack' } };
  const collect = () => cli('collect', binding);
  let snapshot = collect(); ack(initial, true, snapshot.deployment.spec_hash); snapshot = collect();
  assert.equal(snapshot.problems.length, 0); assert.equal(snapshot.pods.filter(pod => pod.ready).length, 2); assert.equal(new Set(snapshot.pods.filter(pod => pod.ready).map(pod => pod.zone)).size, 2);
  await waitFor(() => get('pdb', 'gateway').status.disruptionsAllowed === 1, 'PDB did not observe two healthy replicas');
  pass('actual two-replica gateway and two-zone readiness with independent native inventory hashes');

  const policy = () => ({ minimum_replicas: 2, maintenance_start: new Date(Date.now() - 60000).toISOString(), maintenance_end: new Date(Date.now() + 30 * 60000).toISOString(), rollout_budget_seconds: 45 });
  const assess = (s, change) => cli('assess', { snapshot: s, expected_git_revision: head(), change, policy: policy() });
  let plan = assess(collect(), { container: 'gateway', cpu_request_milli: 50, memory_request_bytes: 160 * 1048576 });
  assert.equal(plan.status, 'READY_FOR_GIT_PROPOSAL', plan.reason_codes.join(',')); assert.match(plan.financial_status, /UNAVAILABLE/);
  assert.equal(head(), plan.base_git_revision); manifest.spec = plan.desired_spec; save(manifest); const revision = commit('Local lab: approved memory request proposal 128Mi to 160Mi');
  assert.equal(cli('authorize', { plan, snapshot: collect() }).status, 'AUTHORIZED_FOR_GIT_RECONCILE');
  controllerApply(revision); kube(['rollout', 'status', 'deployment/gateway', '-n', ns, '--timeout=90s']); snapshot = collect(); ack(revision, true, snapshot.deployment.spec_hash); snapshot = collect();
  const verified = cli('verify', { plan, snapshot, revision }); assert.equal(verified.status, 'ACKNOWLEDGED');
  pass('reviewed exact Git commit reconciles to real successful Deployment rollout');

  apply(pdb(2)); await waitFor(() => get('pdb', 'gateway').status.disruptionsAllowed === 0, 'PDB failed to close disruption budget');
  const before = head(), blocked = assess(collect(), { container: 'gateway', cpu_request_milli: 50, memory_request_bytes: 176 * 1048576 });
  assert.equal(blocked.status, 'BLOCKED'); assert.ok(blocked.reason_codes.includes('K8S_PDB_BLOCKS_DISRUPTION')); assert.equal(head(), before); assert.equal(collect().deployment.containers[0].memory_request_bytes, 160 * 1048576);
  pass('zero-disruption PDB blocks before Git mutation or Deployment write');
  apply(pdb(1)); await waitFor(() => get('pdb', 'gateway').status.disruptionsAllowed === 1, 'PDB failed to reopen');

  // Explicit local fault injection: the production proposal permits only request
  // changes. The labelled controller double now serves a bad readiness endpoint
  // to prove genuine rollout failure and Git-based recovery, not new authority.
  const healthy = head(); manifest = JSON.parse(git(['show', healthy + ':deployment.json'])); manifest.spec.template.spec.containers[0].readinessProbe.httpGet.path = '/never-ready'; save(manifest); const bad = commit('LOCAL TEST FAULT: unavailable readiness endpoint');
  controllerApply(bad); let rolloutFailed = false; try { kube(['rollout', 'status', 'deployment/gateway', '-n', ns, '--timeout=40s']); } catch { rolloutFailed = true; } assert.ok(rolloutFailed, 'Fault-injected rollout unexpectedly became healthy');
  const during = collect(); assert.equal(during.git.ready, false); assert.equal(during.git.revision, bad); const badPlan = assess(during, { container: 'gateway', cpu_request_milli: 50, memory_request_bytes: 176 * 1048576 }); assert.equal(badPlan.status, 'BLOCKED');
  const restoredManifest = JSON.parse(git(['show', healthy + ':deployment.json'])); save(restoredManifest); const rollback = commit(`Local lab: rollback bad Git revision ${bad}`); assert.notEqual(rollback, healthy);
  controllerApply(rollback); kube(['rollout', 'status', 'deployment/gateway', '-n', ns, '--timeout=90s']); snapshot = collect(); ack(rollback, true, snapshot.deployment.spec_hash); snapshot = collect(); assert.equal(snapshot.deployment.ready_replicas, 2); assert.equal(snapshot.git.revision, rollback); assert.equal(snapshot.deployment.spec_hash, plan.desired_spec_hash);
  pass('real failed readiness rollout restores through a new exact Git rollback commit');

  const hpa = cli('hpa', { Replicas: 2, OldRequestMilli: 1000, NewRequestMilli: 700, ObservedUsageMilli: 490, TargetUtilizationPercent: 50, MinReplicas: 2, MaxReplicas: 10 }); assert.equal(hpa.predicted_replicas, 3); assert.equal(hpa.predicted_requested_milli, 2100); assert.equal(hpa.reason_code, 'K8S_HPA_TOTAL_REQUESTS_INCREASE');
  pass('exact HPA denominator simulation rejects a lower-request higher-total-capacity shortcut');
  writeFileSync(path.join(dir, 'acceptance.json'), JSON.stringify({ status: 'PASS', passed, cluster, namespace: ns, controller: engine, hosted: false, monetary_claim: false, image_digest: image.RepoDigests[0], cluster_id: clusterID, namespace_uid: namespaceUID, deployment_uid: deploymentUID, initial_revision: initial, successful_revision: revision, rejected_pdb_revision: before, failed_revision: bad, rollback_revision: rollback, final_snapshot: snapshot, observed_at: new Date().toISOString() }, null, 2));
  console.log(`Kubernetes local acceptance PASS (${passed} checks); controller=${engine}; hosted=false; monetary_claim=false`);
}
main().catch(error => { console.error(`Kubernetes local acceptance failed: ${error.message}`); process.exitCode = 1; });
