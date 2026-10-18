import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { fixtureApplierRules, fixtureGitEnvironment, fixtureReaderMounts, nativeFluxReady } from '../flux-lab.mjs';
import { cacheLabel, importedManifestName, localhostAPIPort, normalizedImportedAliases, ownershipLabel, pins, prepareFluxCompilation, prepareFluxRepository, producerIdentity, validateOwnedGit, validateOwnedNetwork, validateOwnedNode } from '../flux-bootstrap.mjs';

test('private Linux mounts use exact invoking UID/GID while Windows keeps native mount semantics', () => {
  assert.deepEqual(producerIdentity('win32'), []);
  assert.deepEqual(producerIdentity('linux', 1001, 1002), ['--user', '1001:1002']);
  assert.deepEqual(producerIdentity('linux', 0, 0), ['--user', '0:0']);
  for (const [uid, gid] of [[null, 1], [1, null], [-1, 1], [1, 0.5], ['1001', 1001], [2147483648, 1]]) assert.throws(() => producerIdentity('linux', uid, gid));
});

test('Flux applier can observe ReplicaSet health without mutating children or gaining Secret access', () => {
  const rules = fixtureApplierRules();
  assert.deepEqual(rules.find(rule => rule.resources.includes('replicasets')), { apiGroups: ['apps'], resources: ['replicasets'], verbs: ['get', 'list', 'watch'] });
  assert.deepEqual(rules.find(rule => rule.resources.includes('pods')), { apiGroups: [''], resources: ['pods'], verbs: ['get', 'list', 'watch'] });
  assert.deepEqual(rules.flatMap(rule => rule.resources).sort(), ['configmaps', 'deployments', 'pods', 'replicasets']);
  for (const rule of rules.filter(rule => rule.verbs.some(verb => ['create', 'patch', 'update', 'delete'].includes(verb)))) assert.ok(rule.resources.every(resource => ['deployments', 'configmaps'].includes(resource)));
});

test('Git preflight never adopts a repository and checks actual startup offline with only read-only fixture mounts', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'finops-flux-repo-')), state = { run_id: '12345678-1234-1234-1234-123456789abc' };
  const calls = [], bare = path.join(directory, 'repository.git');
  const docker = command => {
    calls.push(command);
    if (command[0] === 'image') return JSON.stringify([{ Id: 'sha256:' + 'a'.repeat(64) }]);
    assert.equal(command[0], 'run'); assert.equal(command[command.indexOf('--network') + 1], 'none');
    if (command.includes('/usr/bin/git')) { mkdirSync(bare); writeFileSync(path.join(bare, 'config'), '[core]\nignorecase=true\n'); }
    if (command.includes('-check')) {
      assert.ok(!readFileSync(path.join(bare, 'config'), 'utf8').includes('ignorecase'));
      const mounts = command.filter((_, index) => command[index - 1] === '-v');
      assert.equal(mounts.length, 2); assert.ok(mounts.every(value => value.endsWith(':ro')));
      assert.ok(!command.includes('--env-file')); assert.ok(command.includes('--cap-drop=ALL'));
    }
    return '';
  };
  try {
    prepareFluxRepository(docker, directory, state);
    assert.equal(calls.filter(call => call[0] === 'run').length, 2);
    const before = readFileSync(path.join(bare, 'config'), 'utf8'); calls.length = 0;
    assert.throws(() => prepareFluxRepository(docker, directory, state), /fresh synthetic/);
    assert.equal(calls.length, 0); assert.equal(readFileSync(path.join(bare, 'config'), 'utf8'), before);
  } finally { assert.ok(path.resolve(directory).startsWith(path.resolve(os.tmpdir()) + path.sep)); rmSync(directory, { recursive: true, force: true }); }
});

test('cold Flux compilation downloads only lockfiles, builds offline, and removes only owned per-run caches', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'finops-flux-cold-'));
  const state = { run_id: '12345678-1234-1234-1234-123456789abc' }, volumes = new Map(), calls = [];
  const docker = command => {
    calls.push(command);
    if (command[0] === 'image') return JSON.stringify([{ Id: 'sha256:' + 'a'.repeat(64) }]);
    if (command[0] === 'run' || command[0] === 'ps') return '';
    if (command[0] === 'volume') {
      const name = command.at(-1);
      if (command[1] === 'create') { volumes.set(name, { Name: name, Driver: 'local', Options: null, Labels: { [cacheLabel]: state.run_id } }); return name; }
      if (command[1] === 'inspect') return JSON.stringify([volumes.get(name)]);
      if (command[1] === 'ls') { const selected = command[command.indexOf('--filter') + 1].slice('name=^'.length, -1); return volumes.has(selected) ? selected : ''; }
      if (command[1] === 'rm') { assert.ok(volumes.has(name)); volumes.delete(name); return name; }
    }
    throw new Error('Unexpected Docker call');
  };
  try {
    const cleanup = prepareFluxCompilation(docker, directory, state);
    assert.equal(volumes.size, 2);
    assert.deepEqual(readdirSync(path.join(directory, 'module-locks')).sort(), ['go.mod', 'go.sum']);
    const runs = calls.filter(command => command[0] === 'run');
    assert.equal(runs.length, producerIdentity().length ? 3 : 2);
    assert.equal(runs[0][runs[0].indexOf('--network') + 1], 'bridge');
    const outboundMounts = runs[0].filter((_, index) => runs[0][index - 1] === '--mount');
    assert.equal(outboundMounts.length, 2); assert.ok(outboundMounts[0].includes('module-locks'));
    assert.ok(!runs[0].some(value => value.includes('reader.token') || value.includes('kubeconfig') || value.includes(':/src')));
    const compile = runs.at(-1);
    assert.equal(compile[compile.indexOf('--network') + 1], 'none');
    assert.ok(compile.includes('--read-only')); assert.ok(compile.includes('GOTOOLCHAIN=local'));
    assert.ok(compile.includes('/go/pkg/mod:ro') || compile.some(value => value.endsWith(':/go/pkg/mod:ro')));
    if (producerIdentity().length) { assert.equal(compile[compile.indexOf('--user') + 1], producerIdentity()[1]); assert.deepEqual(runs[1].filter((_, index) => runs[1][index - 1] === '-v'), [runs[1].find(value => value.endsWith(':/cache'))]); assert.ok(runs[1].includes('--cap-add=CHOWN')); assert.equal(runs[1].at(-1), '/cache'); assert.ok(!runs[1].includes('-R')); }
    assert.ok(!runs.flat().some(value => value.includes('finops-go-mod:') || value.includes('finops-go-build:') || value === '--env-file'));
    cleanup(); assert.equal(volumes.size, 0); cleanup();
  } finally {
    chmodSync(path.join(directory, 'module-locks'), 0o700);
    assert.ok(path.resolve(directory).startsWith(path.resolve(os.tmpdir()) + path.sep));
    rmSync(directory, { recursive: true, force: true });
  }
});

test('runtime repository restoration requires the actual approved manifest, never another content or index digest', () => {
  const digest = pins.source.split('@')[1], source = 'import-2026-10-18@' + digest;
  const header = 'REF TYPE DIGEST SIZE PLATFORMS LABELS\n';
  const valid = `${source} application/vnd.oci.image.manifest.v1+json ${digest} 42MiB linux/amd64 -`;
  assert.equal(importedManifestName(header + valid, pins.source), source);
  assert.equal(importedManifestName(header + valid.replace(source, pins.source), pins.source), pins.source);
  assert.throws(() => importedManifestName(header + `${pins.source} application/vnd.oci.image.manifest.v1+json sha256:${'0'.repeat(64)} 42MiB linux/amd64 -`, pins.source));
  assert.throws(() => importedManifestName(header + valid.replaceAll(digest, 'sha256:' + 'f'.repeat(64)), pins.source));
  assert.throws(() => importedManifestName(header + valid.replace('image.manifest', 'image.index'), pins.source));
});

test('KIND API must have exactly one verified localhost-only published binding', () => {
  const object = { HostConfig: { PortBindings: { '6443/tcp': [{ HostIp: '127.0.0.1', HostPort: '' }] } }, NetworkSettings: { Ports: { '6443/tcp': [{ HostIp: '127.0.0.1', HostPort: '32123' }] } } };
  assert.equal(localhostAPIPort(object), 32123);
  for (const change of [d => d.HostConfig.PortBindings['6443/tcp'][0].HostIp = '0.0.0.0', d => d.NetworkSettings.Ports['6443/tcp'][0].HostIp = '::', d => d.NetworkSettings.Ports['6443/tcp'] = null, d => d.NetworkSettings.Ports['6443/tcp'][0].HostPort = '80', d => d.NetworkSettings.Ports['6443/tcp'][0].HostPort = '65536', d => d.NetworkSettings.Ports['6443/tcp'].push({ HostIp: '127.0.0.1', HostPort: '32124' }), d => d.HostConfig.PortBindings['8080/tcp'] = [{ HostIp: '127.0.0.1', HostPort: '32125' }]]) { const changed = structuredClone(object); change(changed); assert.throws(() => localhostAPIPort(changed)); }
});

test('CRI-normalized archive aliases retain actual object digests without relabelling an index as a manifest', () => {
  const digest = pins.source.split('@')[1], index = 'sha256:' + 'a'.repeat(64);
  const original = 'import-2026-10-18@', normalized = 'docker.io/library/' + original;
  const header = 'REF TYPE DIGEST SIZE PLATFORMS LABELS\n';
  const manifestRow = `${original}${digest} application/vnd.oci.image.manifest.v1+json ${digest} 42MiB linux/amd64 -`;
  const indexRow = `${original}${index} application/vnd.oci.image.index.v1+json ${index} 42MiB linux/amd64 -`;
  const status = { repoDigests: [pins.source, normalized + digest, normalized + index] };
  assert.deepEqual(normalizedImportedAliases(header + manifestRow + '\n' + indexRow, status, pins.source), [[original + digest, normalized + digest], [original + index, normalized + index]]);
  assert.deepEqual(normalizedImportedAliases(header + manifestRow.replace(original, normalized) + '\n' + indexRow.replace(original, normalized), status, pins.source), []);
  assert.throws(() => normalizedImportedAliases(header + manifestRow, status, pins.source));
  assert.throws(() => normalizedImportedAliases(header + manifestRow + '\n' + indexRow.replace(` ${index} `, ` ${digest} `), status, pins.source));
  assert.throws(() => normalizedImportedAliases(header + manifestRow + '\n' + indexRow, { repoDigests: [normalized + digest] }, pins.source));
});

test('actual Flux proof waits for matching source/applied/attempted revision and both current generations', () => {
  const commit = 'a'.repeat(40), rev = 'main@sha1:' + commit;
  const observed = { metadata: { generation: 2 }, status: { observedGeneration: 2, conditions: [{ type: 'Ready', status: 'True', observedGeneration: 2 }] } };
  const source = structuredClone(observed); source.status.artifact = { revision: rev };
  const k = structuredClone(observed); Object.assign(k.status, { lastAppliedRevision: rev, lastAttemptedRevision: rev });
  assert.equal(nativeFluxReady(source, k, commit), true);
  for (const change of [k => k.status.observedGeneration--, k => k.status.conditions[0].observedGeneration--, k => k.status.conditions[0].status = 'False', k => k.status.conditions.push({ type: 'Reconciling', status: 'True' }), k => k.status.lastAttemptedRevision = 'main@sha1:' + 'b'.repeat(40)]) {
    const changed = structuredClone(k); change(changed); assert.equal(nativeFluxReady(source, changed, commit), false);
  }
  const changed = structuredClone(source); changed.status.artifact.revision = 'main@sha1:' + 'b'.repeat(40);
  assert.equal(nativeFluxReady(changed, k, commit), false);
});

test('local Git producer cannot inherit another checkout, helper, trace or credential configuration', () => {
  const env = fixtureGitEnvironment({ PATH: '/tools', HOME: '/operator', GIT_DIR: '/unrelated/.git', GIT_WORK_TREE: '/unrelated', GIT_OBJECT_DIRECTORY: '/unrelated/objects', GIT_ALTERNATE_OBJECT_DIRECTORIES: '/other', GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'credential.helper', GIT_CONFIG_VALUE_0: 'evil', GIT_TRACE: '/operator/secret-log', git_dir: '/case-variant' }, '/fixture/empty-home');
  assert.equal(env.PATH, '/tools'); assert.equal(env.HOME, '/fixture/empty-home');
  assert.equal(env.GIT_CONFIG_GLOBAL, '/dev/null'); assert.equal(env.GIT_CONFIG_NOSYSTEM, '1'); assert.equal(env.GIT_ALLOW_PROTOCOL, 'file');
  for (const key of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT', 'GIT_TRACE', 'git_dir']) assert.equal(env[key], undefined);
});

test('native read-only collector receives only its binary and reader token/CA, never admin kubeconfig or run directory', () => {
  const args = fixtureReaderMounts('/private/fixture');
  assert.equal(args.length, 6);
  assert.ok(args.every((value, index) => index % 2 === 0 ? value === '-v' : value.endsWith(':ro') && !value.includes('kubeconfig')));
  assert.equal(args[1], path.join('/private/fixture', 'k8s-safety') + ':/usr/local/bin/k8s-safety:ro');
  assert.ok(!args.includes('/private/fixture:/lab:ro'));
});

test('cleanup refuses foreign labels, unexpected node names, public Git ports and broad credential mounts', () => {
  const state = { run_id: 'owned', network: 'finops-flux-nonce', cluster: 'finops-flux-nonce', git_container: 'finops-flux-git-nonce', control_plane_id: 'c'.repeat(64) };
  const network = { Name: state.network, Labels: { [ownershipLabel]: 'owned' }, Driver: 'bridge', Internal: false };
  validateOwnedNetwork(network, state);
  assert.throws(() => validateOwnedNetwork({ ...network, Internal: true }, state));
  assert.throws(() => validateOwnedNetwork({ ...network, Labels: { [ownershipLabel]: 'foreign' } }, state));
  const node = { Name: '/' + state.cluster + '-worker', Config: { Image: pins.node, Labels: { 'io.x-k8s.kind.cluster': state.cluster } } };
  validateOwnedNode(node, state);
  assert.throws(() => validateOwnedNode({ ...node, Name: '/finops-autopilot-lab-worker' }, state));
  const git = { Name: '/' + state.git_container, Config: { Image: pins.go, User: producerIdentity()[1] || '', Labels: { [ownershipLabel]: 'owned' } }, HostConfig: { Privileged: false, ReadonlyRootfs: true, NetworkMode: 'container:' + state.control_plane_id, PortBindings: {} }, Mounts: [{ Type: 'bind', Destination: '/fixture/repository.git', RW: false }, { Type: 'bind', Destination: '/usr/local/bin/gitfixture', RW: false }] };
  validateOwnedGit(git, state);
  assert.throws(() => validateOwnedGit({ ...git, HostConfig: { ...git.HostConfig, PortBindings: { '8080/tcp': [] } } }, state));
  assert.throws(() => validateOwnedGit({ ...git, Mounts: [...git.Mounts, { Destination: '/lab', Type: 'bind', RW: false }] }, state));
  for (const NetworkMode of ['host', 'bridge', state.network, 'container:' + 'd'.repeat(64)]) assert.throws(() => validateOwnedGit({ ...git, HostConfig: { ...git.HostConfig, NetworkMode } }, state));
});
