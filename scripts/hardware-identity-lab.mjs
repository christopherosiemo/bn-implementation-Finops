// Actual new local PostgreSQL/MinIO resources; native AWS transport is a double.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { localDockerEndpoint } from './kubernetes-bootstrap.mjs';
import { validateRecoverySources } from './postgres-recovery-lab.mjs';
import { createFixtureGoCache, prepareFixtureGoModules, removeFixtureGoCache } from './lib/fixture-go-modules.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const label = 'finops.local-hardware-identity.run';
const goImage = 'golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61';
const testName = 'TestHardwareIdentityActualPostgresVersionedMinIOReadbackAndReplay';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const environment = object => Object.fromEntries((object.Config?.Env || []).map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));

export function validateHardwareIdentitySources(sources, workspace) {
  validateRecoverySources(sources.api, sources.postgres, workspace);
  const minio = sources.minio;
  assert.equal(minio?.State?.Running, true);
  assert.equal(minio.Config?.Labels?.['com.docker.compose.service'], 'minio');
  assert.equal(path.resolve(minio.Config?.Labels?.['com.docker.compose.project.working_dir'] || ''), path.resolve(workspace));
  assert.equal(minio.Config?.Labels?.['com.docker.compose.project'], sources.api.Config.Labels['com.docker.compose.project']);
  assert.match(minio.Image, /^sha256:[a-f0-9]{64}$/);
  assert.ok(!Object.keys(environment(minio)).some(key => /^(AWS_|AZURE_|GOOGLE_|GCP_|ARM_)/.test(key)));
}
export function validateHardwareIdentityMinioImage(image, expectedID) {
  assert.equal(image.Id, expectedID);
  assert.equal(image.Config?.Labels?.['org.opencontainers.image.source'], 'https://github.com/minio/minio');
  assert.equal(image.Config?.Labels?.['org.opencontainers.image.revision'], '0d7408fc9969caf07de6a8c3a84f9fbb10a6739e');
  assert.equal(image.Config?.Labels?.['org.opencontainers.image.version'], 'RELEASE.2025-04-22T22-12-26Z');
}
export function hardwareIdentityEnvironment(pgPassword, s3User, s3Secret) {
  for (const value of [pgPassword, s3User, s3Secret]) assert.ok(typeof value === 'string' && /^[a-zA-Z0-9]{20,128}$/.test(value));
  return {
    postgres: 'POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=' + pgPassword + '\nPOSTGRES_DB=postgres\nPGDATA=/var/lib/postgresql/data\n',
    minio: 'MINIO_ROOT_USER=' + s3User + '\nMINIO_ROOT_PASSWORD=' + s3Secret + '\nHOME=/tmp\n',
    test: 'TEST_HARDWARE_IDENTITY_STORAGE=owned-local\nTEST_DATABASE_URL=postgres://postgres:' + pgPassword + '@postgres:5432/postgres?sslmode=disable\nTEST_HARDWARE_IDENTITY_S3_ENDPOINT=http://minio:9000\nTEST_HARDWARE_IDENTITY_S3_ACCESS_KEY=' + s3User + '\nTEST_HARDWARE_IDENTITY_S3_SECRET_KEY=' + s3Secret + '\nAWS_EC2_METADATA_DISABLED=true\nGOTOOLCHAIN=local\nGOMAXPROCS=2\nGOMEMLIMIT=768MiB\n',
  };
}
export function validateHardwareIdentityObject(object, id, kind, name, network, image) {
  assert.equal((object.Config?.Labels || object.Labels || {})[label], id);
  assert.equal(object.Name?.replace(/^\//, ''), name);
  assert.ok(name.startsWith('finops-identity-' + id.replaceAll('-', '') + '-'));
  if (kind === 'network') {
    assert.equal(name, network); assert.equal(object.Internal, true); assert.equal(object.Driver, 'bridge');
    // Docker may serialize its ordinary IPv4-on/IPv6-off defaults as options.
    // No custom bridge interface, routing or host-binding option is accepted.
    for (const [key, value] of Object.entries(object.Options || {})) assert.ok(key === 'com.docker.network.enable_ipv4' && value === 'true' || key === 'com.docker.network.enable_ipv6' && value === 'false');
    if (Object.hasOwn(object, 'EnableIPv4')) assert.equal(object.EnableIPv4, true);
    if (Object.hasOwn(object, 'EnableIPv6')) assert.equal(object.EnableIPv6, false);
  } else {
    assert.equal(object.Image, image);
    assert.equal(object.HostConfig?.NetworkMode, network);
    assert.equal(object.HostConfig?.Privileged, false);
    assert.equal(object.HostConfig?.ReadonlyRootfs, true);
    assert.equal(Object.keys(object.HostConfig?.PortBindings || {}).length, 0);
    assert.deepEqual(object.HostConfig?.CapAdd || [], []);
    assert.ok(object.HostConfig?.CapDrop?.includes('ALL'));
    assert.ok(object.HostConfig?.SecurityOpt?.includes('no-new-privileges'));
  }
}
function privateDirectory(id) {
  const directory = path.join(root, 'work', 'private', 'hardware-identity', id);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(directory), relative = path.relative(realpathSync(root), resolved);
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative)); chmodSync(resolved, 0o700);
  if (process.platform === 'win32') {
    const account = execFileSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).trim();
    assert.match(account, /^[^\r\n]+\\[^\r\n]+$/);
    execFileSync('icacls.exe', [resolved, '/inheritance:r', '/grant:r', account + ':(OI)(CI)F'], { windowsHide: true, stdio: 'pipe' });
  }
  return resolved;
}
function snapshot(directory) {
  const target = path.join(directory, 'source'); mkdirSync(target, { mode: 0o700 });
  const files = {};
  const copy = relative => {
    const original = path.join(root, relative), stat = lstatSync(original), resolved = realpathSync(original), suffix = path.relative(realpathSync(root), resolved);
    assert.ok(suffix && !suffix.startsWith('..') && !path.isAbsolute(suffix) && !stat.isSymbolicLink());
    if (stat.isDirectory()) {
      mkdirSync(path.join(target, relative), { recursive: true, mode: 0o700 });
      for (const name of readdirSync(original)) if ((!name.startsWith('.') && lstatSync(path.join(original, name)).isDirectory()) || /^[A-Za-z0-9_]+\.go$/.test(name) || path.join(relative, name) === path.join('internal', 'provider', 'testdata', 'hardware_capture.bin')) copy(path.join(relative, name));
      chmodSync(path.join(target, relative), 0o555);
    } else {
      assert.ok(stat.isFile()); copyFileSync(original, path.join(target, relative)); chmodSync(path.join(target, relative), 0o444);
      files[relative.split(path.sep).join('/')] = sha(readFileSync(path.join(target, relative)));
    }
  };
  copy('go.mod'); copy('go.sum'); copy('internal'); mkdirSync(path.join(target, 'migrations'), { mode: 0o700 });
  const migrations = {};
  for (const name of readdirSync(path.join(root, 'migrations')).sort()) {
    const match = /^(\d{3})_[a-z0-9_]+\.sql$/.exec(name);
    if (match && Number(match[1]) <= 26) { copy(path.join('migrations', name)); migrations[name] = sha(readFileSync(path.join(target, 'migrations', name))); }
  }
  assert.ok(Object.hasOwn(migrations, '025_fleet_history.sql')); assert.ok(Object.keys(migrations).some(name => /^026_[a-z0-9_]+\.sql$/.test(name)));
  chmodSync(path.join(target, 'migrations'), 0o555); chmodSync(target, 0o555);
  const manifest = Object.fromEntries(Object.entries(files).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
  writeFileSync(path.join(directory, 'source-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
  return { source: target, migrations, sourceManifestHash: sha(JSON.stringify(manifest)), sourceFileCount: Object.keys(manifest).length };
}

export async function hardwareIdentityLab() {
  assert.equal(process.argv.length, 2, 'No alternate endpoints, credentials, images, contexts or cloud arguments accepted');
  const invoke = (args, options = {}) => execFileSync('docker', args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 8 << 20, stdio: ['pipe', 'pipe', 'pipe'], ...options }).trim();
  const contextName = invoke(['context', 'show']), context = JSON.parse(invoke(['context', 'inspect', contextName]))[0];
  const endpoint = process.env.DOCKER_HOST || context.Endpoints?.docker?.Host;
  assert.ok(localDockerEndpoint(endpoint), 'Remote Docker daemon refused');
  const run = (args, options) => invoke(['--host', endpoint, ...args], options);
  const daemonID = run(['info', '--format', '{{.ID}}']); assert.ok(daemonID);
  const inspect = (kind, name) => JSON.parse(run(['inspect', '--type', kind, name]))[0];
  const sources = {};
  for (const service of ['api', 'postgres', 'minio']) {
    const id = run(['compose', 'ps', '-q', service]); assert.match(id, /^[a-f0-9]{64}$/); sources[service] = inspect('container', id);
  }
  validateHardwareIdentitySources(sources, root);
  validateHardwareIdentityMinioImage(inspect('image', sources.minio.Image), sources.minio.Image);
  let go;
  try { go = inspect('image', goImage); } catch { run(['pull', goImage], { timeout: 300000 }); go = inspect('image', goImage); }
  assert.match(go.Id, /^sha256:[a-f0-9]{64}$/);
  const pgUID = run(['exec', sources.postgres.Id, 'id', '-u', 'postgres']), pgGID = run(['exec', sources.postgres.Id, 'id', '-g', 'postgres']);
  for (const value of [pgUID, pgGID]) assert.match(value, /^[1-9][0-9]{0,4}$/);
  const id = randomUUID(), prefix = 'finops-identity-' + id.replaceAll('-', ''), directory = privateDirectory(id), { source, migrations, sourceManifestHash, sourceFileCount } = snapshot(directory);
  const network = prefix + '-private', postgres = prefix + '-postgres', minio = prefix + '-minio', test = prefix + '-test';
  const moduleCache = prefix + '-gomod', buildCache = prefix + '-gobuild', owned = [], caches = [], envFiles = {};
  const env = hardwareIdentityEnvironment(randomBytes(32).toString('hex'), 'history' + randomBytes(16).toString('hex'), randomBytes(32).toString('hex'));
  for (const [name, body] of Object.entries(env)) { const file = path.join(directory, name + '.env'); writeFileSync(file, body, { flag: 'wx', mode: 0o600 }); chmodSync(file, 0o600); envFiles[name] = file; }
  let passed = false, evidence, stage = 'DEPENDENCY_PREPARATION';
  const base = (name, alias, memory) => ['--detach', '--name', name, '--label', label + '=' + id, '--pull', 'never', '--network', network, '--network-alias', alias, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256', '--memory', memory, '--cpus=1'];
  const check = (kind, name, image) => validateHardwareIdentityObject(inspect(kind, name), id, kind, name, network, image);
  try {
    for (const cache of [moduleCache, buildCache]) { caches.push(cache); createFixtureGoCache(run, cache, label, id); }
    prepareFixtureGoModules(run, { imageID: go.Id, sourceDirectory: source, privateDirectory: directory, moduleVolume: moduleCache, labelKey: label, runID: id, containerName: prefix + '-modules' });
    stage = 'OWNED_NETWORK';
    owned.push(['network', network]); run(['network', 'create', '--internal', '--driver=bridge', '--label', label + '=' + id, network]); check('network', network);
    stage = 'OWNED_POSTGRESQL';
    owned.push(['container', postgres, sources.postgres.Image]);
    run(['run', ...base(postgres, 'postgres', '384m'), '--user', pgUID + ':' + pgGID, '--env-file', envFiles.postgres, '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=768m,uid=' + pgUID + ',gid=' + pgGID + ',mode=0700', '--tmpfs', '/var/run/postgresql:rw,nosuid,nodev,size=16m,uid=' + pgUID + ',gid=' + pgGID + ',mode=0700', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,uid=' + pgUID + ',gid=' + pgGID, sources.postgres.Image]); check('container', postgres, sources.postgres.Image);
    stage = 'OWNED_MINIO';
    owned.push(['container', minio, sources.minio.Image]);
    run(['run', ...base(minio, 'minio', '384m'), '--user=10001:10001', '--env-file', envFiles.minio, '--tmpfs', '/data:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,uid=10001,gid=10001', sources.minio.Image, 'server', '/data', '--console-address', ':9001']); check('container', minio, sources.minio.Image);
    stage = 'SERVICE_READINESS';
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) { try { run(['exec', postgres, 'pg_isready', '-U', 'postgres', '-d', 'postgres']); ready = true; break; } catch { assert.equal(inspect('container', postgres).State?.Running, true); await sleep(500); } }
    assert.ok(ready, 'Owned PostgreSQL did not become ready'); assert.equal(inspect('container', minio).State?.Running, true);
    stage = 'ACTUAL_STORAGE_ACCEPTANCE';
    const command = 'for attempt in $(seq 1 60); do if curl --silent --fail http://minio:9000/minio/health/ready >/dev/null; then break; fi; sleep 1; done; curl --silent --fail http://minio:9000/minio/health/ready >/dev/null; go test -p 2 ./internal/source -count=1 -v -run "^' + testName + '$"; go vet -p 2 ./internal/source';
    owned.push(['container', test, go.Id]);
    const output = run(['run', '--rm', '--name', test, '--label', label + '=' + id, '--pull', 'never', '--network', network, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=1024m', '--cpus=2', '--env-file', envFiles.test, '--mount', 'type=bind,src=' + source + ',dst=/src,readonly', '--mount', 'type=volume,src=' + moduleCache + ',dst=/go/pkg/mod', '--mount', 'type=volume,src=' + buildCache + ',dst=/root/.cache/go-build', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=512m', '--workdir=/src', go.Id, 'sh', '-ec', command], { timeout: 600000 });
    writeFileSync(path.join(directory, 'acceptance.log'), output + '\n', { mode: 0o600 });
    assert.ok(output.includes('--- PASS: ' + testName + ' ')); assert.ok(!output.includes('--- SKIP:'), 'Actual storage acceptance cannot skip');
    assert.ok(output.includes('actual restricted PostgreSQL + pinned hardware MinIO readback + identity replay'));
    passed = true;
    evidence = { schema_version: '1', status: 'PASS', run_id: id, observed_at: new Date().toISOString(), test: testName, go_image_id: go.Id, postgres_image_id: sources.postgres.Image, minio_image_id: sources.minio.Image, migrations, source_manifest_sha256: sourceManifestHash, source_file_count: sourceFileCount, main_schema_modified: false, owned_internal_network: true, cold_module_and_build_caches: true, credential_free_module_preflight: true, storage: 'ACTUAL_NEW_POSTGRESQL_AND_VERSIONED_MINIO', native_calls: 'PROVIDER_SHAPED_DOUBLES', encryption_claim: false, original_v1_preserved: true, incarnation_authority: 'UNKNOWN', historical_interval_ownership: false, execution_authorized: false, verified_saving: null };
  } catch (error) {
    const text = value => typeof value === 'string' ? value : Buffer.isBuffer(value) ? value.toString('utf8') : '';
    const diagnostic = text(error.stdout) + '\n' + text(error.stderr);
    if (diagnostic.trim()) writeFileSync(path.join(directory, 'failure.log'), diagnostic, { mode: 0o600 });
    const message = String(error.message || '').replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/((?:password|authorization|token)\s*[:=]\s*)\S+/gi, '$1[redacted]').slice(0, 1500);
    writeFileSync(path.join(directory, 'failure.json'), JSON.stringify({ status: 'FAIL', stage, error_name: error.name, error_code: error.code, message }, null, 2) + '\n', { mode: 0o600 });
    throw new Error('Hardware identity storage acceptance failed; diagnostics remain in the private run directory.');
  } finally {
    const cleanupErrors = [];
    assert.equal(run(['info', '--format', '{{.ID}}']), daemonID, 'Docker daemon changed; cleanup refused');
    for (const [kind, name, image] of owned.reverse()) {
      try {
        const present = run(kind === 'container' ? ['ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'] : ['network', 'ls', '--filter', 'name=^' + name + '$', '--format', '{{.Name}}']).split('\n');
        if (!present.includes(name)) continue;
        const object = inspect(kind, name); validateHardwareIdentityObject(object, id, kind, name, network, image);
        if (kind === 'container') run(['rm', '--force', name]); else { assert.equal(Object.keys(object.Containers || {}).length, 0); run(['network', 'rm', name]); }
      } catch { cleanupErrors.push(kind); }
    }
    for (const cache of caches.reverse()) { try { removeFixtureGoCache(run, cache, label, id); } catch { cleanupErrors.push('volume'); } }
    if (cleanupErrors.length) throw new Error('Owned history cleanup refused or failed; inspect private diagnostics.');
    for (const file of Object.values(envFiles)) unlinkSync(file);
    if (!passed) console.error('No Hardware identity acceptance recorded; only exact newly owned fixture resources were considered for cleanup.');
  }
  assert.equal(run(['ps', '--all', '--filter', 'label=' + label + '=' + id, '--format', '{{.ID}}']), '');
  assert.equal(run(['network', 'ls', '--filter', 'label=' + label + '=' + id, '--format', '{{.ID}}']), '');
  assert.equal(run(['volume', 'ls', '--filter', 'label=' + label + '=' + id, '--format', '{{.Name}}']), '');
  evidence.cleanup_succeeded = true;
  writeFileSync(path.join(directory, 'acceptance.json'), JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  console.log('Hardware identity lab PASS: actual isolated PostgreSQL + versioned MinIO + process replay; AWS transport double; execution and financial authority remain absent.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) hardwareIdentityLab().catch(() => { console.error('Hardware identity lab failed; credentials, native bodies and private logs are not printed.'); process.exitCode = 1; });
