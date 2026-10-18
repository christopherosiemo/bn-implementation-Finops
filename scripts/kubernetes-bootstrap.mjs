// Reproducible local-only Kubernetes lab. No cloud CLI, profile or credentials.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const cluster = 'finops-autopilot-lab';
export const nodeImage = 'kindest/node:v1.34.0';
export const nodeDigest = 'sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a';
export const applicationImage = 'python:3.13-slim';
export const applicationDigest = 'sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f';
const versions = {
  win32: { filename: 'kind.exe', artifact: 'kind-windows-amd64', sha256: 'a75fed2b6964d877461cc145b37e997ac0f59a63bd02a750134ac25378f78ce7' },
  linux: { filename: 'kind', artifact: 'kind-linux-amd64', sha256: '517ab7fc89ddeed5fa65abf71530d90648d9638ef0c4cde22c2c11f8097b8889' },
};
export function localDockerEndpoint(host) {
  return typeof host === 'string' && (host.startsWith('unix:///') || /^npipe:\/\/\/\/\.\/pipe\/[A-Za-z0-9_.-]+$/.test(host));
}
export function labKindPath(base = root, platform = process.platform) {
  assert.ok(versions[platform], 'The pinned lab bootstrap supports Windows/Linux x64 only');
  return path.join(base, 'work', 'tools', versions[platform].filename);
}
const run = (program, args, options = {}) => execFileSync(program, args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 180_000, maxBuffer: 8 << 20, ...options });
function ownedDirectory(relative) {
  const directory = path.join(root, relative);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(directory), workspace = realpathSync(root);
  const suffix = path.relative(workspace, resolved);
  assert.ok(suffix && suffix !== '..' && !suffix.startsWith('..' + path.sep) && !path.isAbsolute(suffix), 'Lab files must stay inside this workspace');
  return resolved;
}
export async function bootstrap() {
  assert.equal(process.argv.length, 2, 'No remote target, context or cloud arguments are accepted');
  assert.equal(process.arch, 'x64', 'No unverified architecture binary may be substituted');
  const version = versions[process.platform];
  assert.ok(version, 'Only the pinned Windows/Linux x64 binaries are supported');
  if (process.env.DOCKER_HOST) assert.ok(localDockerEndpoint(process.env.DOCKER_HOST), 'DOCKER_HOST must use a local named pipe or Unix socket');
  const contextName = run('docker', ['context', 'show']).trim();
  const context = JSON.parse(run('docker', ['context', 'inspect', contextName]))[0];
  assert.ok(localDockerEndpoint(context.Endpoints?.docker?.Host), 'The Kubernetes lab refuses remote Docker contexts');
  const tools = ownedDirectory('work/tools');
  const dir = ownedDirectory('work/kubernetes-lab');
  const binary = path.join(tools, version.filename);
  if (!existsSync(binary)) {
    const url = `https://github.com/kubernetes-sigs/kind/releases/download/v0.30.0/${version.artifact}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
    assert.equal(response.status, 200, 'The official pinned KIND release must be available');
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.ok(bytes.length < 64 << 20, 'Unexpected KIND artifact size');
    assert.equal(createHash('sha256').update(bytes).digest('hex'), version.sha256, 'KIND release digest mismatch');
    writeFileSync(binary, bytes, { flag: 'wx', mode: 0o700 });
  }
  assert.equal(createHash('sha256').update(readFileSync(binary)).digest('hex'), version.sha256, 'Existing KIND binary does not match the pinned release');
  if (process.platform !== 'win32') chmodSync(binary, 0o700);
  const inspectImage = () => { try { return JSON.parse(run('docker', ['image', 'inspect', nodeImage]))[0]; } catch { return null; } };
  let image = inspectImage();
  if (!image?.RepoDigests?.some(value => value.endsWith('@' + nodeDigest))) {
    run('docker', ['pull', `${nodeImage}@${nodeDigest}`], { stdio: 'inherit' });
    run('docker', ['tag', `${nodeImage}@${nodeDigest}`, nodeImage]);
    image = inspectImage();
  }
  assert.ok(image?.RepoDigests?.some(value => value.endsWith('@' + nodeDigest)), 'The exact Kubernetes node image digest is required');
  let application;
  try { application = JSON.parse(run('docker', ['image', 'inspect', applicationImage]))[0]; } catch { /* A fresh local lab must pull the pinned image. */ }
  if (!application?.RepoDigests?.some(value => value.endsWith('@' + applicationDigest))) {
    const reference = `python@${applicationDigest}`;
    run('docker', ['pull', '--platform', 'linux/amd64', reference], { stdio: 'inherit' });
    run('docker', ['tag', reference, applicationImage]);
    application = JSON.parse(run('docker', ['image', 'inspect', applicationImage]))[0];
  }
  assert.ok(application?.RepoDigests?.some(value => value.endsWith('@' + applicationDigest)), 'The exact instrumented application base image is required');
  const kubeconfig = path.join(dir, 'kubeconfig');
  const config = path.join(dir, 'kind.yaml');
  const clusters = run(binary, ['get', 'clusters']).trim().split(/\r?\n/);
  if (!clusters.includes(cluster)) {
    assert.ok(!existsSync(kubeconfig), 'An existing private kubeconfig requires inspection before replacing this lab');
    writeFileSync(config, 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  apiServerAddress: 127.0.0.1\nnodes:\n- role: control-plane\n- role: worker\n  labels:\n    topology.kubernetes.io/zone: lab-a\n- role: worker\n  labels:\n    topology.kubernetes.io/zone: lab-b\n', { mode: 0o600 });
    run(binary, ['create', 'cluster', '--name', cluster, '--image', nodeImage, '--config', config, '--kubeconfig', kubeconfig, '--wait', '120s'], { stdio: 'inherit' });
  }
  assert.ok(existsSync(kubeconfig), 'A matching private lab kubeconfig is required; an unrelated named cluster cannot be adopted');
  const text = readFileSync(kubeconfig, 'utf8');
  assert.match(text, /server: https:\/\/127\.0\.0\.1:\d+/);
  assert.match(text, /current-context: kind-finops-autopilot-lab/);
  const names = run(binary, ['get', 'nodes', '--name', cluster]).trim().split(/\r?\n/).sort();
  assert.deepEqual(names, [`${cluster}-control-plane`, `${cluster}-worker`, `${cluster}-worker2`]);
  for (const name of names) {
    const container = JSON.parse(run('docker', ['inspect', name]))[0];
    assert.equal(container.Config.Labels['io.x-k8s.kind.cluster'], cluster);
  }
  const control = `${cluster}-control-plane`;
  const kube = args => run('docker', ['exec', control, 'kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', ...args]);
  kube(['label', 'node', `${cluster}-worker`, 'topology.kubernetes.io/zone=lab-a', '--overwrite']);
  kube(['label', 'node', `${cluster}-worker2`, 'topology.kubernetes.io/zone=lab-b', '--overwrite']);
  kube(['wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=60s']);
  console.log('Pinned local KIND lab ready: three nodes, two worker zones, loopback API and private workspace kubeconfig. No cloud resources.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  bootstrap().catch(error => { console.error(`Local Kubernetes bootstrap failed: ${error.message}`); process.exitCode = 1; });
}
