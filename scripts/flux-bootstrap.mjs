// Fixture-only Flux tooling and cluster ownership. No existing cluster is adopted.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { localDockerEndpoint } from './kubernetes-bootstrap.mjs';
import { createFixtureGoCache, prepareFixtureGoModules, removeFixtureGoCache } from './lib/fixture-go-modules.mjs';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const pins = Object.freeze({
  kind: 'v0.33.0',
  node: 'kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d',
  go: 'golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61',
  // Exact linux/amd64 child manifests of the approved upstream release indexes.
  application: 'docker.io/library/python@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024',
  source: 'ghcr.io/fluxcd/source-controller@sha256:d10ea2ebeb475de80a6d3caf792578b1eaaa0366c55442d20d7e5f6f78fad3ec',
  kustomize: 'ghcr.io/fluxcd/kustomize-controller@sha256:cdab039ed285bfcac5605b92b2f0799c2bff24639b0dc4208671c7b3e828891a',
  flux: 'v2.9.6',
  fluxArchiveHash: 'b4d22673e9246cbd628881f1a9ef3b090085dced291e42d804555cee8e8d42c5',
});
const kindAssets = {
  linux: { name: 'kind-linux-amd64', hash: 'aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d' },
  win32: { name: 'kind-windows-amd64', hash: '4b22adaa135368c5a465d56bbd8e520cbea87272a06ca00b6078e7b81515c9fc' },
};
export const ownershipLabel = 'finops.autopilot/flux-fixture-run';
export const cacheLabel = 'finops.local-flux.run';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function producerIdentity(platform = process.platform, uid = process.getuid?.(), gid = process.getgid?.()) {
  if (platform === 'win32') return [];
  assert.equal(platform, 'linux');
  for (const value of [uid, gid]) assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= 2147483647, 'Exact invoking Linux UID/GID required');
  return ['--user', uid + ':' + gid];
}
export function prepareFluxCompilation(docker, directory, state) {
  const suffix = state.run_id.replaceAll('-', '').slice(0, 12);
  const moduleVolume = 'finops-flux-mod-' + suffix, buildVolume = 'finops-flux-build-' + suffix;
  const downloadContainer = 'finops-flux-download-' + suffix, buildContainer = 'finops-flux-compile-' + suffix;
  const imageID = JSON.parse(docker(['image', 'inspect', pins.go]))[0].Id;
  const cleanup = () => {
    for (const [name, network] of [[downloadContainer, 'bridge'], [buildContainer, 'none'], ['finops-flux-cache-owner-' + suffix, 'none'], ['finops-flux-repository-' + suffix, 'none'], ['finops-flux-gitcheck-' + suffix, 'none']]) {
      const names = docker(['ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).split('\n');
      if (!names.includes(name)) continue;
      const container = JSON.parse(docker(['inspect', '--type', 'container', name]))[0];
      assert.equal(container.Name?.replace(/^\//, ''), name);
      assert.equal(container.Config?.Labels?.[cacheLabel], state.run_id);
      assert.equal(container.Config?.Image, imageID);
      assert.equal(container.HostConfig?.NetworkMode, network);
      assert.equal(container.HostConfig?.Privileged, false);
      assert.equal(Object.keys(container.HostConfig?.PortBindings || {}).length, 0);
      docker(['rm', '--force', name]);
    }
    for (const name of [buildVolume, moduleVolume]) removeFixtureGoCache(docker, name, cacheLabel, state.run_id);
  };
  try {
    for (const name of [moduleVolume, buildVolume]) createFixtureGoCache(docker, name, cacheLabel, state.run_id);
    prepareFixtureGoModules(docker, { imageID, sourceDirectory: root, privateDirectory: directory, moduleVolume, labelKey: cacheLabel, runID: state.run_id, containerName: downloadContainer });
    const identity = producerIdentity();
    if (identity.length) docker(['run', '--rm', '--name', 'finops-flux-cache-owner-' + suffix, '--label', cacheLabel + '=' + state.run_id, '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop=ALL', '--cap-add=CHOWN', '--security-opt=no-new-privileges', '--pids-limit=16', '--memory=32m', '-v', `${buildVolume}:/cache`, '--entrypoint', '/usr/bin/chown', imageID, identity[1], '/cache']);
    // No cluster/admin/reader credentials exist yet. Compilation has no egress;
    // only the preceding public-lockfile preparation step uses the bridge.
    docker(['run', '--rm', '--name', buildContainer, ...identity, '--label', cacheLabel + '=' + state.run_id, '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=1024m', '--cpus=2', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,mode=1777,size=384m', '-e', 'GOMAXPROCS=2', '-e', 'GOTOOLCHAIN=local', '-e', 'GOCACHE=/cache', '-v', `${root}:/src:ro`, '-v', `${directory}:/out`, '-v', `${moduleVolume}:/go/pkg/mod:ro`, '-v', `${buildVolume}:/cache`, '-w', '/src', imageID, 'sh', '-ec', 'go build -buildvcs=false -o /out/k8s-safety ./internal/kubernetes/labcmd; go build -buildvcs=false -o /out/gitfixture ./internal/kubernetes/gitfixture/cmd; go build -buildvcs=false -o /out/fluxsetup ./internal/kubernetes/fluxsetup/cmd'], { timeout: 300000 });
    return cleanup;
  } catch (error) {
    try { cleanup(); } catch (cleanupError) { throw new Error('Flux cold compilation failed and owned cache cleanup was not confirmed: ' + String(cleanupError.message).slice(0, 300)); }
    throw error;
  }
}
export function prepareFluxRepository(docker, directory, state) {
  const bare = path.join(directory, 'repository.git');
  assert.equal(existsSync(bare), false, 'Only a fresh synthetic bare repository may be initialized');
  const suffix = state.run_id.replaceAll('-', '').slice(0, 12);
  const imageID = JSON.parse(docker(['image', 'inspect', pins.go]))[0].Id;
  const common = [...producerIdentity(), '--label', cacheLabel + '=' + state.run_id, '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=128m', '-e', 'HOME=/nonexistent', '-e', 'XDG_CONFIG_HOME=/nonexistent', '-e', 'GIT_CONFIG_NOSYSTEM=1', '-e', 'GIT_CONFIG_SYSTEM=/dev/null', '-e', 'GIT_CONFIG_GLOBAL=/dev/null'];
  docker(['run', '--rm', '--name', 'finops-flux-repository-' + suffix, ...common, '-v', `${directory}:/fixture`, '--entrypoint', '/usr/bin/git', imageID, '-c', 'init.templateDir=', 'init', '--bare', '--initial-branch=main', '/fixture/repository.git']);
  // Native init may detect Windows filesystem settings. This newly created
  // synthetic repo gets exact allowed config; existing repos are never adopted.
  writeFileSync(path.join(bare, 'config'), '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n', { mode: 0o600 });
  chmodSync(path.join(bare, 'config'), 0o600);
  docker(['run', '--rm', '--name', 'finops-flux-gitcheck-' + suffix, ...common, '-v', `${bare}:/fixture/repository.git:ro`, '-v', `${path.join(directory, 'gitfixture')}:/usr/local/bin/gitfixture:ro`, '--entrypoint', '/usr/local/bin/gitfixture', imageID, '-check', '-repository', '/fixture/repository.git'], { timeout: 30000 });
}
export function localhostAPIPort(object) {
  const configured = object.HostConfig?.PortBindings, observed = object.NetworkSettings?.Ports;
  assert.deepEqual(Object.keys(configured || {}).sort(), ['6443/tcp']);
  assert.equal(configured['6443/tcp']?.length, 1); assert.equal(configured['6443/tcp'][0].HostIp, '127.0.0.1');
  const published = Object.entries(observed || {}).filter(([, entries]) => entries?.length);
  assert.equal(published.length, 1); assert.equal(published[0][0], '6443/tcp');
  assert.equal(published[0][1].length, 1); const binding = published[0][1][0];
  assert.equal(binding.HostIp, '127.0.0.1'); assert.match(binding.HostPort, /^[1-9]\d{0,4}$/);
  const port = Number(binding.HostPort); assert.ok(port >= 1024 && port <= 65535);
  return port;
}
export function importedManifestName(output, reference) {
  assert.match(reference, /^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$/);
  const lines = output.trim().split(/\r?\n/);
  assert.match(lines[0], /^REF\s+TYPE\s+DIGEST\s+/);
  const rows = lines.slice(1).map(line => line.trim().split(/\s+/));
  const expectedDigest = reference.split('@')[1];
  const named = rows.find(row => row[0] === reference);
  if (named) {
    assert.equal(named[2], expectedDigest, 'Existing runtime name has wrong content digest');
    assert.equal(named[1], 'application/vnd.oci.image.manifest.v1+json');
    return reference;
  }
  const imported = rows.find(row => row[2] === expectedDigest && row[1] === 'application/vnd.oci.image.manifest.v1+json');
  assert.ok(imported, 'Approved platform manifest was not imported');
  return imported[0];
}
export function normalizedImportedAliases(output, status, reference) {
  assert.ok(status?.repoDigests?.includes(reference), 'CRI must first resolve the approved manifest');
  const lines = output.trim().split(/\r?\n/);
  assert.match(lines[0], /^REF\s+TYPE\s+DIGEST\s+/);
  const rows = lines.slice(1).map(line => line.trim().split(/\s+/));
  return status.repoDigests.flatMap(name => {
    if (!/^docker\.io\/library\/import-\d{4}-\d{2}-\d{2}@sha256:[a-f0-9]{64}$/.test(name)) return [];
    const original = name.slice('docker.io/library/'.length), expected = name.split('@')[1];
    const existing = rows.find(row => row[0] === name), imported = rows.find(row => row[0] === original);
    const row = existing || imported;
    assert.ok(row, 'CRI import alias must have an actual containerd object');
    assert.equal(row[2], expected, 'Import alias must preserve its actual content digest');
    assert.ok(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.oci.image.index.v1+json'].includes(row[1]));
    return existing ? [] : [[original, name]];
  });
}

export function privateDirectory(base, relative) {
  const directory = path.join(base, relative);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(directory), parent = realpathSync(base), suffix = path.relative(parent, resolved);
  assert.ok(suffix && suffix !== '..' && !suffix.startsWith('..' + path.sep) && !path.isAbsolute(suffix), 'Fixture path must stay inside its workspace');
  assert.ok(!resolved.includes(',') && !resolved.includes('\n') && !resolved.includes('\r'), 'Unsafe Docker mount path');
  return resolved;
}
export function validateOwnedNetwork(object, state) {
  assert.equal(object.Name, state.network);
  assert.equal(object.Labels?.[ownershipLabel], state.run_id);
  assert.equal(object.Driver, 'bridge'); assert.equal(object.Internal, false);
}
export function validateOwnedNode(object, state) {
  const name = object.Name?.replace(/^\//, '');
  assert.ok([state.cluster + '-control-plane', state.cluster + '-worker', state.cluster + '-worker2'].includes(name), 'Unknown cluster member');
  assert.equal(object.Config?.Labels?.['io.x-k8s.kind.cluster'], state.cluster);
  assert.equal(object.Config?.Image, pins.node);
}
export function validateOwnedGit(object, state) {
  assert.equal(object.Name?.replace(/^\//, ''), state.git_container);
  assert.equal(object.Config?.Labels?.[ownershipLabel], state.run_id);
  assert.equal(object.Config?.Image, pins.go);
  assert.equal(object.Config?.User || '', producerIdentity()[1] || '');
  assert.equal(object.HostConfig?.Privileged, false);
  assert.equal(object.HostConfig?.ReadonlyRootfs, true);
  assert.match(state.control_plane_id, /^[a-f0-9]{64}$/);
  assert.equal(object.HostConfig?.NetworkMode, 'container:' + state.control_plane_id);
  assert.equal(Object.keys(object.HostConfig?.PortBindings || {}).length, 0);
  assert.deepEqual((object.Mounts || []).map(mount => mount.Destination).sort(), ['/fixture/repository.git', '/usr/local/bin/gitfixture']);
  assert.ok(object.Mounts.every(mount => mount.Type === 'bind' && mount.RW === false));
}
async function download(url, file, expectedHash, maximum = 64 << 20) {
  if (!existsSync(file)) {
    const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
    assert.equal(response.status, 200, 'Pinned official release artifact unavailable');
    const reader = response.body.getReader(), chunks = []; let total = 0;
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      total += value.byteLength;
      if (total > maximum) { await reader.cancel(); throw new Error('Release artifact size invalid'); }
      chunks.push(Buffer.from(value));
    }
    const bytes = Buffer.concat(chunks, total);
    assert.ok(bytes.length > 0, 'Release artifact size invalid');
    assert.equal(sha(bytes), expectedHash, 'Official release artifact checksum mismatch');
    writeFileSync(file, bytes, { flag: 'wx', mode: 0o700 });
  }
  const existing = lstatSync(file);
  assert.ok(existing.isFile() && !existing.isSymbolicLink() && existing.size > 0 && existing.size <= maximum, 'Cached release artifact shape invalid');
  assert.equal(sha(readFileSync(file)), expectedHash, 'Existing fixture tool checksum mismatch');
}

export async function prepareFluxLab() {
  assert.equal(process.argv.length, 2, 'No cloud, remote-context or existing-cluster arguments accepted');
  assert.equal(process.arch, 'x64'); assert.ok(kindAssets[process.platform], 'Only verified Windows/Linux x64 binaries supported');
  const invoke = (program, args, options = {}) => execFileSync(program, args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 300000, maxBuffer: 16 << 20, ...options });
  const contextName = invoke('docker', ['context', 'show']).trim();
  const context = JSON.parse(invoke('docker', ['context', 'inspect', contextName]))[0];
  const endpoint = process.env.DOCKER_HOST || context.Endpoints?.docker?.Host;
  assert.ok(localDockerEndpoint(endpoint), 'Only a local Docker named pipe or Unix socket is accepted');
  const docker = (args, options = {}) => invoke('docker', ['--host', endpoint, ...args], options);
  const daemon = JSON.parse(docker(['info', '--format', '{{json .}}']));
  assert.ok(daemon.OSType === 'linux' && ['x86_64', 'amd64'].includes(daemon.Architecture), 'Only a local Linux amd64 Docker daemon is accepted');
  assert.ok(daemon.DriverStatus?.some(pair => pair[0] === 'driver-type' && pair[1] === 'io.containerd.snapshotter.v1'), 'This digest-preserving fixture requires the Docker containerd image store; it never changes daemon settings');
  const runID = randomUUID(), suffix = runID.replaceAll('-', '').slice(0, 12);
  const directory = privateDirectory(root, 'work/flux-lab/' + runID);
  const state = { run_id: runID, cluster: 'finops-flux-' + suffix, network: 'finops-flux-' + suffix, git_container: 'finops-flux-git-' + suffix, directory, node: pins.node, created_at: new Date().toISOString() };
  writeFileSync(path.join(directory, 'ownership.json'), JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
  const tools = privateDirectory(root, 'work/tools/flux-v2.9.6-kind-v0.33.0');
  const kind = path.join(tools, process.platform === 'win32' ? 'kind.exe' : 'kind');
  const asset = kindAssets[process.platform];
  await download(`https://github.com/kubernetes-sigs/kind/releases/download/${pins.kind}/${asset.name}`, kind, asset.hash);
  if (process.platform !== 'win32') chmodSync(kind, 0o700);
  await download(`https://github.com/fluxcd/flux2/releases/download/${pins.flux}/flux_2.9.6_linux_amd64.tar.gz`, path.join(tools, 'flux.tar.gz'), pins.fluxArchiveHash);
  const inspect = (kind, name) => JSON.parse(docker(['inspect', '--type', kind, name]))[0];
  const image = reference => {
    const digest = reference.split('@')[1];
    let found;
    try { found = JSON.parse(docker(['image', 'inspect', reference]))[0]; } catch { /* Pull exactly the approved digest. */ }
    if (!found?.RepoDigests?.some(value => value.endsWith('@' + digest))) {
      docker(['pull', '--platform', 'linux/amd64', reference], { stdio: 'inherit' });
      found = JSON.parse(docker(['image', 'inspect', reference]))[0];
    }
    assert.ok(found.RepoDigests.some(value => value.endsWith('@' + digest)), 'Unpinned image rejected');
  };
  for (const reference of [pins.go, pins.node, pins.application, pins.source, pins.kustomize]) image(reference);
  // Check the Docker VM rather than host RAM; preserve other active labs/jobs.
  const memory = docker(['run', '--rm', '--network', 'none', '--read-only', '--entrypoint', 'cat', pins.go, '/proc/meminfo']);
  const availableKiB = Number(/^MemAvailable:\s+(\d+) kB$/m.exec(memory)?.[1]);
  assert.ok(Number.isSafeInteger(availableKiB) && availableKiB >= 2621440, 'The separate three-node Flux fixture requires at least 2.5 GiB available Docker VM memory');
  writeFileSync(path.join(directory, 'memory-preflight.json'), JSON.stringify({ available_kib: availableKiB, minimum_kib: 2621440 }, null, 2) + '\n');
  docker(['run', '--rm', ...producerIdentity(), '--network', 'none', '-v', `${tools}:/tools`, '--entrypoint', 'tar', pins.go, '-xzf', '/tools/flux.tar.gz', '-C', '/tools', 'flux']);
  const exported = docker(['run', '--rm', ...producerIdentity(), '--network', 'none', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m', '-v', `${path.join(tools, 'flux')}:/tools/flux:ro`, '--entrypoint', '/tools/flux', pins.go, 'install', '--export', '--namespace=finops-flux-system', '--components=source-controller,kustomize-controller', '--watch-all-namespaces=false', '--network-policy=false']);
  writeFileSync(path.join(directory, 'controllers-upstream.yaml'), exported, { mode: 0o600 });
  const env = { ...process.env, DOCKER_HOST: endpoint, KIND_EXPERIMENTAL_DOCKER_NETWORK: state.network };
  delete env.DOCKER_CONTEXT;
  env.KUBECONFIG = path.join(directory, 'kubeconfig');
  const kindRun = (args, options = {}) => invoke(kind, args, { env, stdio: 'inherit', ...options });
  const createKind = args => new Promise((resolve, reject) => {
    const child = spawn(kind, args, { cwd: root, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '', size = 0, timedOut = false, oversized = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, 600000);
    const capture = (bytes, stream) => {
      size += bytes.length;
      if (size > 4 << 20) { oversized = true; child.kill(); return; }
      stream.write(bytes);
      stderr += bytes.toString('utf8');
    };
    child.stdout.on('data', bytes => capture(bytes, process.stdout));
    child.stderr.on('data', bytes => capture(bytes, process.stderr));
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (status, signal) => {
      clearTimeout(timer);
      if (status === 0 && !timedOut && !oversized) return resolve();
      const error = new Error(timedOut ? 'Owned KIND creation timed out' : oversized ? 'Owned KIND creation output exceeded bound' : 'Owned KIND creation failed');
      Object.assign(error, { status, signal, stderr, timedOut, oversized }); reject(error);
    });
  });
  const kubeconfig = path.join(directory, 'kubeconfig');
  const config = path.join(directory, 'kind.yaml');
  let networkCreated = false, clusterCreated = false, compilationCleanup;
  const cleanup = () => {
    const errors = [];
    const present = name => docker(['ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).trim().split('\n').includes(name);
    try { if (present(state.git_container)) { validateOwnedGit(inspect('container', state.git_container), state); docker(['rm', '--force', state.git_container]); } } catch { errors.push('Git fixture ownership/cleanup failed'); }
    if (clusterCreated) {
      try {
        const names = docker(['ps', '--all', '--filter', 'label=io.x-k8s.kind.cluster=' + state.cluster, '--format', '{{.Names}}']).trim().split('\n').filter(Boolean);
        for (const name of names) validateOwnedNode(inspect('container', name), state);
        kindRun(['delete', 'cluster', '--name', state.cluster, '--kubeconfig', kubeconfig]);
      } catch { errors.push('Owned local cluster cleanup failed'); }
    }
    if (networkCreated) {
      try { const network = inspect('network', state.network); validateOwnedNetwork(network, state); assert.equal(Object.keys(network.Containers || {}).length, 0); docker(['network', 'rm', state.network]); } catch { errors.push('Owned fixture network cleanup failed'); }
    }
    if (compilationCleanup) { try { compilationCleanup(); } catch { errors.push('Owned compilation cache cleanup failed'); } }
    if (!errors.length) for (const name of ['reader.token', 'ca.crt', 'kubeconfig']) if (existsSync(path.join(directory, name))) unlinkSync(path.join(directory, name));
    return errors;
  };
  try {
    compilationCleanup = prepareFluxCompilation(docker, directory, state);
    prepareFluxRepository(docker, directory, state);
    console.log('Owned Flux fixture: actual Linux bare-repository/server initialization verified before node creation');
    const beforeNodes = docker(['run', '--rm', '--network', 'none', '--read-only', '--entrypoint', 'cat', pins.go, '/proc/meminfo']);
    const beforeNodesKiB = Number(/^MemAvailable:\s+(\d+) kB$/m.exec(beforeNodes)?.[1]);
    assert.ok(Number.isSafeInteger(beforeNodesKiB) && beforeNodesKiB >= 2621440, 'Insufficient Docker VM memory after cold compilation; no nodes created');
    docker(['network', 'create', '--driver', 'bridge', '--label', ownershipLabel + '=' + runID, state.network]); networkCreated = true;
    const network = inspect('network', state.network);
    validateOwnedNetwork(network, state);
    // Standard KIND routing is needed for real cross-node CNI/Service traffic.
    // This fixture bridge permits outbound traffic; it is not an isolation or
    // production security boundary. Its address scope must remain private.
    const gateway = network.IPAM?.Config?.find(config => isIP(config.Gateway) === 4)?.Gateway;
    assert.ok(gateway && /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(gateway), 'Owned bridge gateway must be private IPv4');
    writeFileSync(config, JSON.stringify({ kind: 'Cluster', apiVersion: 'kind.x-k8s.io/v1alpha4', networking: { apiServerAddress: '127.0.0.1' }, nodes: [{ role: 'control-plane' }, { role: 'worker', labels: { 'topology.kubernetes.io/zone': 'lab-a' } }, { role: 'worker', labels: { 'topology.kubernetes.io/zone': 'lab-b' } }] }, null, 2) + '\n', { mode: 0o600 });
    clusterCreated = true; // Include partial, test-owned creations in guarded cleanup.
    await createKind(['create', 'cluster', '--name', state.cluster, '--image', pins.node, '--config', config, '--kubeconfig', kubeconfig, '--wait', '120s', '--retain']);
    const localPort = localhostAPIPort(inspect('container', state.cluster + '-control-plane'));
    const text = readFileSync(kubeconfig, 'utf8');
    assert.ok(text.split(/\r?\n/).some(line => line.trim() === 'server: https://127.0.0.1:' + localPort));
    state.api_binding = { address: '127.0.0.1', port: localPort };
    assert.ok(text.includes('current-context: kind-' + state.cluster));
    const control = state.cluster + '-control-plane';
    const kube = (args, input) => docker(['exec', '-i', control, 'kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', ...args], { ...(input === undefined ? {} : { input }) });
    for (const suffix of ['control-plane', 'worker', 'worker2']) validateOwnedNode(inspect('container', state.cluster + '-' + suffix), state);
    state.control_plane_id = inspect('container', control).Id;
    assert.match(state.control_plane_id, /^[a-f0-9]{64}$/);
    writeFileSync(path.join(directory, 'ownership.json'), JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
    for (const [key, reference] of Object.entries({ application: pins.application, source: pins.source, kustomize: pins.kustomize })) {
      const archive = path.join(directory, key + '.tar');
      docker(['image', 'save', '--platform', 'linux/amd64', '-o', archive, reference]);
      kindRun(['load', 'image-archive', archive, '--name', state.cluster]);
      // Digest-only Docker archives can lose repository names. Restore only a
      // name whose actual imported manifest digest is exactly the approved one;
      // never attach an index digest to different single-platform content.
      for (const suffix of ['control-plane', 'worker', 'worker2']) {
        const node = state.cluster + '-' + suffix;
        const imported = importedManifestName(docker(['exec', node, 'ctr', '--namespace=k8s.io', 'images', 'list']), reference);
        if (imported !== reference) docker(['exec', node, 'ctr', '--namespace=k8s.io', 'images', 'tag', imported, reference]);
        // Observe successful native CRI responses while its image-event cache
        // catches up with containerd metadata. Transport/command errors still
        // fail immediately; no failed operation is blanket-retried.
        const deadline = Date.now() + 30000;
        while (true) {
          const inventory = JSON.parse(docker(['exec', node, 'crictl', 'images', '-o', 'json'], { timeout: 15000 }));
          if (inventory.images?.some(image => image.repoDigests?.includes(reference))) break;
          assert.ok(Date.now() < deadline, 'CRI did not observe the approved manifest before the bounded deadline');
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        const observed = JSON.parse(docker(['exec', node, 'crictl', 'inspecti', reference]));
        assert.ok(observed.status.repoDigests.includes(reference), 'CRI cannot resolve the exact approved platform manifest');
        // CRI normalizes unnamed Docker-archive imports to docker.io/library/.
        // Containerd's checkpoint check resolves that normalized name again.
        // Preserve each existing object's own digest (including any real archive
        // index), rather than assigning an approved index digest to a manifest.
        const aliases = normalizedImportedAliases(docker(['exec', node, 'ctr', '--namespace=k8s.io', 'images', 'list']), observed.status, reference);
        for (const [original, normalized] of aliases) docker(['exec', node, 'ctr', '--namespace=k8s.io', 'images', 'tag', original, normalized]);
      }
      console.log('Owned Flux fixture: exact ' + key + ' manifest verified on all three nodes');
    }
    return { state, directory, tools, docker, inspect, kube, kindRun, cleanup, invoke, exported };
  } catch (error) {
    // Retain only until bounded diagnostics are captured, then remove the exact
    // owned resources. No admin config, environment or credentials enter logs.
    if (clusterCreated) for (const suffix of ['control-plane', 'worker', 'worker2']) {
      const name = state.cluster + '-' + suffix;
      try {
        validateOwnedNode(inspect('container', name), state);
        const logs = spawnSync('docker', ['--host', endpoint, 'logs', '--tail', '150', name], { encoding: 'utf8', timeout: 10000, maxBuffer: 1 << 20, windowsHide: true });
        writeFileSync(path.join(directory, suffix + '-startup.log'), String(logs.stdout || '') + String(logs.stderr || ''));
      } catch { /* A node may not have been created. Guarded cleanup still runs. */ }
    }
    const failures = cleanup();
    if (failures.length) console.error(failures.join('; '));
    throw error;
  }
}
