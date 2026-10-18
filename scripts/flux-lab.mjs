// Real Flux controllers on a new, owned, local-only KIND fixture. No hosted mode.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';
import { prepareFluxLab, pins, root, ownershipLabel, producerIdentity, validateOwnedGit } from './flux-bootstrap.mjs';
import { boundedRolloutSnapshot, waitForNativeRollout } from './lib/kubernetes-observation.mjs';

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const revision = value => typeof value === 'string' ? value.split('@sha1:')[1] : undefined;
const diagnostic = value => String(value || '').replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/((?:password|authorization|token)\s*[:=]\s*)\S+/gi, '$1[redacted]').slice(0, 1500);
const ready = object => object?.status?.observedGeneration >= object?.metadata?.generation
  && object.metadata.generation > 0
  && object.status.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True' && condition.observedGeneration >= object.metadata.generation)
  && !object.status.conditions?.some(condition => ['Reconciling', 'Stalled'].includes(condition.type) && condition.status === 'True');
export function nativeFluxReady(source, kustomization, expected) {
  return ready(source) && ready(kustomization) && revision(source.status.artifact?.revision) === expected
    && revision(kustomization.status.lastAppliedRevision) === expected && revision(kustomization.status.lastAttemptedRevision) === expected;
}
export function fixtureGitEnvironment(environment, home) {
  const clean = Object.fromEntries(Object.entries(environment).filter(([key]) => !key.toUpperCase().startsWith('GIT_')));
  return Object.assign(clean, { HOME: home, XDG_CONFIG_HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'file', GIT_NO_LAZY_FETCH: '1' });
}
export function fixtureReaderMounts(directory) {
  return [['k8s-safety', '/usr/local/bin/k8s-safety'], ['reader.token', '/fixture/reader.token'], ['ca.crt', '/fixture/ca.crt']].flatMap(([source, destination]) => ['-v', `${path.join(directory, source)}:${destination}:ro`]);
}
export function fixtureApplierRules() {
  return [
    { apiGroups: ['apps'], resources: ['deployments'], verbs: ['get', 'list', 'watch', 'create', 'patch', 'update'] },
    { apiGroups: [''], resources: ['configmaps'], verbs: ['get', 'list', 'watch', 'create', 'patch', 'update'] },
    { apiGroups: ['apps'], resources: ['replicasets'], verbs: ['get', 'list', 'watch'] },
    { apiGroups: [''], resources: ['pods'], verbs: ['get', 'list', 'watch'] },
  ];
}
export function assertBoundFixtureSpec(snapshot, expectedHash) {
  // The read-only Go collector normalizes equivalent Kubernetes quantities
  // while hashing the entire spec. A raw quantity spelling is not authority.
  assert.match(expectedHash, /^[a-f0-9]{64}$/);
  assert.deepEqual(snapshot?.problems, []);
  assert.equal(snapshot?.deployment?.spec_hash, expectedHash);
  assert.equal(snapshot?.git?.deployment_spec_hash, expectedHash);
}
export function fixtureWorkingSpec(plan) {
  // Fault commits must never mutate the approved plan retained for rollback.
  return structuredClone(plan.desired_spec);
}
async function waitFor(check, message, timeout = 120000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = check(); if (value) return value; await pause(1000); }
  throw new Error(message);
}

export async function runFluxLab() {
  const lab = await prepareFluxLab();
  const { state, directory, docker, kube, inspect, invoke } = lab;
  const ns = 'finops-flux-workload', controllerNS = 'finops-flux-system';
  const get = (kind, name, namespace = ns) => JSON.parse(kube(['get', kind, ...(name ? [name] : []), ...(namespace ? ['-n', namespace] : []), '-o', 'json']));
  const apply = object => kube(['apply', '-f', '-'], JSON.stringify(object));
  let passed = 0, result;
  const pass = text => { passed++; console.log('Actual local Flux: ' + text); };
  const repo = path.join(directory, 'producer'), bare = path.join(directory, 'repository.git'), home = path.join(directory, 'empty-home');
  const gitEnv = fixtureGitEnvironment(process.env, home);
  const git = args => invoke('git', ['-c', 'core.autocrlf=false', '-c', 'core.hooksPath=' + home, '-c', 'commit.gpgsign=false', '-c', 'user.name=FinOps local Flux fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'safe.directory=' + bare, '-C', repo, ...args], { env: gitEnv }).trim();
  const head = () => git(['rev-parse', 'HEAD']);
  const writeManifest = object => writeFileSync(path.join(repo, 'workload/deployment.json'), JSON.stringify(object, null, 2) + '\n');
  const pushCommit = message => { git(['add', '--', 'workload']); git(['commit', '--no-verify', '-q', '-m', message]); git(['push', '-q', bare, 'HEAD:refs/heads/main']); return head(); };
  let binding;
  const cli = (mode, object) => JSON.parse(docker(['run', '--rm', '-i', ...producerIdentity(), '--network', state.network, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '-e', `K8S_API_URL=https://${state.cluster}-control-plane:6443`, '-e', 'K8S_API_TOKEN_FILE=/fixture/reader.token', '-e', 'K8S_API_CA_FILE=/fixture/ca.crt', ...fixtureReaderMounts(directory), '--entrypoint', '/usr/local/bin/k8s-safety', pins.go, mode], { input: JSON.stringify(object) }));
  const collect = () => cli('collect', binding);
  const native = () => ({ source: get('gitrepositories.source.toolkit.fluxcd.io', 'workload', controllerNS), kustomization: get('kustomizations.kustomize.toolkit.fluxcd.io', 'workload', controllerNS) });
  const waitRevision = expected => waitFor(() => { const current = native(); return nativeFluxReady(current.source, current.kustomization, expected) && current; }, 'Flux did not acknowledge exact Git revision ' + expected);
  const observe = expected => waitForNativeRollout({ collect, expectedSpecHash: expected, onFailure: snapshot => writeFileSync(path.join(directory, 'observation-failure.json'), JSON.stringify(snapshot, null, 2) + '\n') });
  const policy = () => ({ minimum_replicas: 2, maintenance_start: new Date(Date.now() - 60000).toISOString(), maintenance_end: new Date(Date.now() + 30 * 60000).toISOString(), rollout_budget_seconds: 45 });
  const assess = change => cli('assess', { snapshot: collect(), expected_git_revision: head(), change, policy: policy() });
  const pdb = minimum => ({ apiVersion: 'policy/v1', kind: 'PodDisruptionBudget', metadata: { name: 'gateway', namespace: ns }, spec: { minAvailable: minimum, selector: { matchLabels: { app: 'finops-k8s-gateway' } } } });
  try {
    mkdirSync(repo, { mode: 0o700 }); mkdirSync(home, { mode: 0o700 });
    const manifests = JSON.parse(docker(['run', '--rm', '-i', ...producerIdentity(), '--network', 'none', '--read-only', '-v', `${path.join(directory, 'fluxsetup')}:/usr/local/bin/fluxsetup:ro`, '--entrypoint', '/usr/local/bin/fluxsetup', pins.go], { input: lab.exported }));
    apply(manifests);
    for (const component of ['source-controller', 'kustomize-controller']) kube(['rollout', 'status', 'deployment/' + component, '-n', controllerNS, '--timeout=120s']);
    apply({ apiVersion: 'v1', kind: 'Namespace', metadata: { name: ns, labels: { 'finops.autopilot/environment': 'NON_PRODUCTION', 'finops.autopilot/owner': 'local-flux-operator' } } });
    apply({ apiVersion: 'v1', kind: 'ServiceAccount', metadata: { name: 'workload-applier', namespace: controllerNS }, automountServiceAccountToken: false });
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role', metadata: { name: 'workload-applier', namespace: ns }, rules: fixtureApplierRules() });
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: 'workload-applier', namespace: ns }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'workload-applier' }, subjects: [{ kind: 'ServiceAccount', name: 'workload-applier', namespace: controllerNS }] });
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role', metadata: { name: 'workload-impersonation', namespace: controllerNS }, rules: [{ apiGroups: [''], resources: ['serviceaccounts'], resourceNames: ['workload-applier'], verbs: ['impersonate'] }] });
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: 'workload-impersonation', namespace: controllerNS }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'workload-impersonation' }, subjects: [{ kind: 'ServiceAccount', name: 'kustomize-controller', namespace: controllerNS }] });
    pass('real digest-pinned source/kustomize controllers Ready on a separately owned compatible cluster');

    // The bare repo and server were preflighted before creating any nodes.
    git(['-c', 'init.templateDir=', 'init', '--initial-branch=main', '-q']);
    mkdirSync(path.join(repo, 'workload'), { mode: 0o700 });
    const manifest = JSON.parse(readFileSync(path.join(root, 'examples/kubernetes/deployment.json'), 'utf8'));
    manifest.metadata.namespace = ns; manifest.spec.template.spec.containers[0].image = pins.application;
    // Read the API's nonpersistent defaulting result before committing it. Any
    // later admission mutation still fails the unchanged exact-spec verifier.
    const defaulted = JSON.parse(kube(['apply', '--dry-run=server', '-f', '-', '-o', 'json'], JSON.stringify(manifest)));
    manifest.spec = defaulted.spec;
    writeManifest(manifest);
    writeFileSync(path.join(repo, 'workload/kustomization.yaml'), JSON.stringify({ apiVersion: 'kustomize.config.k8s.io/v1beta1', kind: 'Kustomization', resources: ['deployment.json', 'gateway-code.json'] }) + '\n');
    writeFileSync(path.join(repo, 'workload/gateway-code.json'), JSON.stringify({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'gateway-code', namespace: ns }, data: { 'gateway.py': readFileSync(path.join(root, 'examples/telemetry/gateway.py'), 'utf8') } }) + '\n');
    const initial = pushCommit('Local Flux: initial immutable Git workload');
    // Share only this owned node's namespace; it has native CNI return
    // routes. This adds no host port, global route, privilege or admin mount.
    const node = inspect('container', state.cluster + '-control-plane');
    assert.equal(node.Id, state.control_plane_id);
    const ip = node.NetworkSettings.Networks[state.network].IPAddress;
    assert.equal(isIP(ip), 4); assert.equal(node.NetworkSettings.Networks[state.network].NetworkID, inspect('network', state.network).Id);
    docker(['run', '-d', '--name', state.git_container, ...producerIdentity(), '--network', 'container:' + state.control_plane_id, '--label', ownershipLabel + '=' + state.run_id, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=128m', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m', '-v', `${bare}:/fixture/repository.git:ro`, '-v', `${path.join(directory, 'gitfixture')}:/usr/local/bin/gitfixture:ro`, '--entrypoint', '/usr/local/bin/gitfixture', pins.go, '-repository', '/fixture/repository.git']);
    validateOwnedGit(inspect('container', state.git_container), state);
    const repositoryURL = `http://${ip}:8080/repository.git`;
    apply({ apiVersion: 'source.toolkit.fluxcd.io/v1', kind: 'GitRepository', metadata: { name: 'workload', namespace: controllerNS }, spec: { interval: '10s', timeout: '15s', url: repositoryURL, ref: { branch: 'main' } } });
    apply({ apiVersion: 'kustomize.toolkit.fluxcd.io/v1', kind: 'Kustomization', metadata: { name: 'workload', namespace: controllerNS }, spec: { interval: '1m', retryInterval: '5s', timeout: '45s', path: './workload', targetNamespace: ns, sourceRef: { kind: 'GitRepository', name: 'workload' }, serviceAccountName: 'workload-applier', wait: true, prune: false, deletionPolicy: 'Orphan' } });
    await waitRevision(initial);
    apply(pdb(1));

    apply({ apiVersion: 'v1', kind: 'ServiceAccount', metadata: { name: 'finops-k8s-reader', namespace: ns }, automountServiceAccountToken: false });
    const readerSubject = { kind: 'ServiceAccount', name: 'finops-k8s-reader', namespace: ns };
    const role = (namespace, name, rules) => {
      apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role', metadata: { name, namespace }, rules });
      apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name, namespace }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name }, subjects: [readerSubject] });
    };
    const clusterReader = 'finops-flux-native-reader';
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRole', metadata: { name: clusterReader }, rules: [{ apiGroups: [''], resources: ['namespaces'], resourceNames: ['kube-system', ns], verbs: ['get'] }, { apiGroups: [''], resources: ['nodes'], verbs: ['get', 'list'] }, { apiGroups: ['apiextensions.k8s.io'], resources: ['customresourcedefinitions'], verbs: ['get', 'list'] }] });
    apply({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRoleBinding', metadata: { name: clusterReader }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: clusterReader }, subjects: [readerSubject] });
    role(ns, clusterReader, [{ apiGroups: ['apps'], resources: ['deployments', 'replicasets'], verbs: ['get', 'list'] }, { apiGroups: [''], resources: ['pods'], verbs: ['get', 'list'] }, { apiGroups: ['policy'], resources: ['poddisruptionbudgets'], verbs: ['get', 'list'] }, { apiGroups: ['autoscaling'], resources: ['horizontalpodautoscalers'], verbs: ['get', 'list'] }]);
    role('kube-system', clusterReader, [{ apiGroups: ['apps'], resources: ['deployments'], verbs: ['get', 'list'] }]);
    role(controllerNS, clusterReader, [{ apiGroups: ['source.toolkit.fluxcd.io'], resources: ['gitrepositories'], resourceNames: ['workload'], verbs: ['get'] }, { apiGroups: ['kustomize.toolkit.fluxcd.io'], resources: ['kustomizations'], resourceNames: ['workload'], verbs: ['get'] }, { apiGroups: [''], resources: ['services/proxy'], resourceNames: ['source-controller:80'], verbs: ['get'] }]);
    writeFileSync(path.join(directory, 'reader.token'), kube(['create', 'token', 'finops-k8s-reader', '-n', ns, '--duration=30m']).trim(), { mode: 0o600 });
    writeFileSync(path.join(directory, 'ca.crt'), kube(['get', 'configmap', 'kube-root-ca.crt', '-n', ns, '-o', 'jsonpath={.data.ca\\.crt}']), { mode: 0o600 });
    const deny = (subject, verb, resource, namespace) => {
      let output; try { output = kube(['auth', 'can-i', verb, resource, '--as', subject, '-n', namespace]).trim(); } catch (error) { output = String(error.stdout || '').trim(); }
      assert.equal(output, 'no');
    };
    for (const [verb, resource, namespace] of [['patch', 'deployments', ns], ['get', 'secrets', ns], ['patch', 'kustomizations/status', controllerNS]]) deny(`system:serviceaccount:${ns}:finops-k8s-reader`, verb, resource, namespace);
    for (const args of [['get', 'services/not-the-source-controller:80', '--subresource=proxy'], ['create', 'services/source-controller:80', '--subresource=proxy']]) {
      let output; try { output = kube(['auth', 'can-i', ...args, '--as', `system:serviceaccount:${ns}:finops-k8s-reader`, '-n', controllerNS]).trim(); } catch (error) { output = String(error.stdout || '').trim(); }
      assert.equal(output, 'no');
    }
    deny(`system:serviceaccount:${controllerNS}:workload-applier`, 'patch', 'deployments', 'kube-system');
    deny(`system:serviceaccount:${controllerNS}:workload-applier`, 'get', 'secrets', ns);
    deny(`system:serviceaccount:${controllerNS}:workload-applier`, 'patch', 'replicasets', ns);
    deny(`system:serviceaccount:${controllerNS}:workload-applier`, 'delete', 'pods', ns);
    deny(`system:serviceaccount:${controllerNS}:kustomize-controller`, 'patch', 'deployments', ns);
    pass('separate real reader and namespace-limited impersonated applier cannot read Secrets or mutate unrelated workloads');

    const current = native();
    binding = { tenant_id: 'tenant-local-flux-fixture', workload_id: 'workload-local-flux-fixture', provider: 'LOCAL_KIND', cluster_id: get('namespace', 'kube-system', '').metadata.uid, namespace: ns, namespace_uid: get('namespace', ns, '').metadata.uid, deployment: 'gateway', deployment_uid: get('deployment', 'gateway').metadata.uid, owner: 'local-flux-operator', git: { engine: 'FLUX', repository: repositoryURL, path: './workload', controller_namespace: controllerNS, controller_name: 'workload', controller_uid: current.kustomization.metadata.uid, source_name: 'workload', source_uid: current.source.metadata.uid, manifest_path: 'workload/deployment.json', source_branch: 'main', apply_service_account: 'workload-applier' } };
    let snapshot = await observe();
    assert.equal(snapshot.problems.length, 0); assert.equal(snapshot.git.revision, initial); assert.ok(snapshot.git.artifact_hash); assert.equal(snapshot.git.deployment_spec_hash, snapshot.deployment.spec_hash);
    await waitFor(() => get('pdb', 'gateway').status.disruptionsAllowed === 1, 'PDB initial native status missing');
    pass('real controller revision and pinned source artifact independently prove exact live Git-owned spec');

    const change = { container: 'gateway', cpu_request_milli: 50, memory_request_bytes: 160 * 1048576 };
    const plan = assess(change);
    assert.equal(plan.status, 'READY_FOR_GIT_PROPOSAL', plan.reason_codes.join(','));
    assert.equal(head(), plan.base_git_revision);
    assert.equal(cli('authorize', { plan, snapshot: collect() }).status, 'AUTHORIZED_FOR_GIT_RECONCILE');
    manifest.spec = fixtureWorkingSpec(plan); writeManifest(manifest);
    const successful = pushCommit('Local Flux: reviewed memory request change');
    await waitRevision(successful); snapshot = await observe(plan.desired_spec_hash);
    assert.equal(cli('verify', { plan, snapshot, revision: successful }).status, 'ACKNOWLEDGED');
    pass('Git commit alone causes real Flux apply and strict successful two-zone rollout acknowledgement');

    apply(pdb(2)); await waitFor(() => get('pdb', 'gateway').status.disruptionsAllowed === 0, 'PDB did not close budget');
    const beforeBlocked = head(), blocked = assess({ ...change, memory_request_bytes: 176 * 1048576 });
    assert.equal(blocked.status, 'BLOCKED'); assert.ok(blocked.reason_codes.includes('K8S_PDB_BLOCKS_DISRUPTION')); assert.equal(head(), beforeBlocked);
    assertBoundFixtureSpec(collect(), plan.desired_spec_hash);
    pass('native zero-disruption PDB preflight blocks before a Git commit; no Deployment/PDB enforcement assumption');
    apply(pdb(1)); await waitFor(() => get('pdb', 'gateway').status.disruptionsAllowed === 1, 'PDB did not reopen');

    manifest.spec.template.spec.containers[0].readinessProbe.httpGet.path = '/never-ready'; writeManifest(manifest);
    const failed = pushCommit('LOCAL FIXTURE FAULT: readiness endpoint unavailable');
    const partial = await waitFor(() => { const state = native(); return revision(state.source.status.artifact?.revision) === failed && !nativeFluxReady(state.source, state.kustomization, failed) && state; }, 'Real partial Flux reconcile was not observed');
    const partialSnapshot = collect();
    assert.equal(partialSnapshot.git.synced, false);
    let acknowledged = true; try { cli('verify', { plan, snapshot: partialSnapshot, revision: failed }); } catch { acknowledged = false; } assert.equal(acknowledged, false);
    const failure = await waitFor(() => { const state = native(); return revision(state.kustomization.status.lastAttemptedRevision) === failed && state.kustomization.status.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'False' && condition.reason === 'HealthCheckFailed') && state; }, 'Flux did not report actual failed readiness', 120000);
    const failedSnapshot = collect(); assert.equal(failedSnapshot.git.ready, false); assert.equal(failedSnapshot.git.synced, false);
    assert.equal(assess({ ...change, memory_request_bytes: 176 * 1048576 }).status, 'BLOCKED');
    pass('actual partial reconciliation and controller HealthCheckFailed never become a false successful acknowledgement');

    // Revert precisely the owned fault commit; never kubectl-patch the workload.
    assert.equal(head(), failed);
    git(['revert', '--no-edit', failed]); git(['push', '-q', bare, 'HEAD:refs/heads/main']);
    const rollback = head(); assert.notEqual(rollback, successful); assert.notEqual(rollback, failed);
    await waitRevision(rollback); snapshot = await observe(plan.desired_spec_hash);
    assert.equal(cli('verify', { plan, snapshot, revision: rollback }).status, 'ACKNOWLEDGED');
    pass('owned Git revert reconciles through real Flux to exact healthy spec and two Ready worker zones');
    result = { status: 'PASS', passed, controller: 'FLUX', fixture: true, hosted: false, execution_authorized: false, monetary_claim: false, pins, cluster_id: binding.cluster_id, namespace_uid: binding.namespace_uid, deployment_uid: binding.deployment_uid, source_uid: binding.git.source_uid, controller_uid: binding.git.controller_uid, initial_revision: initial, successful_revision: successful, blocked_pdb_revision: beforeBlocked, failed_revision: failed, rollback_revision: rollback, partial_generation: partial.kustomization.metadata.generation, failure_reason: failure.kustomization.status.conditions.find(condition => condition.type === 'Ready').reason, final_snapshot: snapshot, observed_at: new Date().toISOString() };
  } catch (error) {
    let snapshot; try { if (binding) snapshot = boundedRolloutSnapshot(collect()); } catch { /* Preserve the first failure. */ }
    try {
      const pods = get('pods', '', controllerNS).items.slice(0, 20).map(pod => ({ name: pod.metadata.name, phase: pod.status.phase, containers: (pod.status.containerStatuses || []).map(container => ({ name: container.name, ready: container.ready, restart_count: container.restartCount, waiting_reason: container.state?.waiting?.reason, waiting_message: diagnostic(container.state?.waiting?.message), terminated_reason: container.state?.terminated?.reason, terminated_message: diagnostic(container.state?.terminated?.message) })) }));
      const controllers = ['source-controller', 'kustomize-controller'].map(name => { const deployment = get('deployment', name, controllerNS); return { name, generation: deployment.metadata.generation, status: deployment.status }; });
      const events = get('events', '', controllerNS).items.slice(-50).map(event => ({ reason: event.reason, type: event.type, object: event.involvedObject?.name, count: event.count, message: diagnostic(event.message) }));
      let gitops;
      try { gitops = Object.fromEntries(Object.entries(native()).map(([kind, object]) => [kind, { generation: object.metadata.generation, observed_generation: object.status?.observedGeneration, artifact_revision: object.status?.artifact?.revision, applied_revision: object.status?.lastAppliedRevision, attempted_revision: object.status?.lastAttemptedRevision, conditions: (object.status?.conditions || []).slice(0, 10).map(condition => ({ type: condition.type, status: condition.status, reason: condition.reason, message: diagnostic(condition.message) })) }])); } catch { /* Source may not yet exist. */ }
      writeFileSync(path.join(directory, 'controllers-failure.json'), JSON.stringify({ pods, controllers, events, gitops }, null, 2) + '\n');
    } catch { /* Native status unavailability cannot enable acceptance. */ }
    writeFileSync(path.join(directory, 'observation-failure.json'), JSON.stringify({ status: 'FAIL', passed, snapshot, reason: String(error.message).slice(0, 1000) }, null, 2) + '\n');
    throw error;
  } finally {
    const errors = lab.cleanup();
    if (errors.length) throw new Error(errors.join('; '));
    if (result) {
      result.cleanup_succeeded = true;
      writeFileSync(path.join(directory, 'acceptance.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
      writeFileSync(path.join(root, 'work/flux-lab/acceptance.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
    }
  }
  console.log(`Actual local Flux acceptance PASS (${passed} checks); hosted=false; monetary_claim=false; owned resources removed`);
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runFluxLab().catch(error => { console.error('Actual local Flux lab failed: ' + String(error.message).slice(0, 1500)); process.exitCode = 1; });
}
