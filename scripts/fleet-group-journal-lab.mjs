// Append-only file journal fixture component only: no application DB, API, AWS,
// native attestation, real-clock health windows or savings claims.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, chownSync, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { localDockerEndpoint } from './kubernetes-bootstrap.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = 'examples/fleet-group-journal-fixture';
const label = 'finops.fleet-group-journal.run';
const hash = value => createHash('sha256').update(value).digest('hex');
const images = Object.freeze({
  terraform: 'hashicorp/terraform:1.16.0@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e',
  go: 'golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61',
});

export function validateFleetTooling(body) {
  const lines = body.replaceAll('\r\n', '\n').split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  assert.deepEqual(lines, ['FROM ' + images.terraform + ' AS terraform', 'FROM ' + images.go, 'COPY --from=terraform /bin/terraform /usr/local/bin/terraform', 'USER 10001:10001']);
  return images;
}

export function fleetLabMountSource(value, platform = process.platform) {
  assert.ok(typeof value === 'string' && value.length > 0 && !/[\0\r\n]/.test(value));
  let normalized = value.replaceAll('\\', '/');
  if (platform === 'win32') {
    const drive = normalized.match(/^([A-Za-z]):\/(.+)$/);
    if (drive) normalized = '/run/desktop/mnt/host/' + drive[1].toLowerCase() + '/' + drive[2];
  }
  assert.ok(normalized.startsWith('/') && !normalized.split('/').includes('..'));
  return normalized.replace(/\/$/, '');
}

export function validateFleetLabContainer(object, runID, imageID, uid, sources) {
  assert.match(runID, /^[a-f0-9-]{36}$/);
  assert.equal(object.Name, '/finops-fleet-group-journal-' + runID.replaceAll('-', '') + '-test');
  assert.equal(object.Config?.Labels?.[label], runID);
  assert.equal(object.Image, imageID);
  assert.equal(object.Config?.User, uid + ':' + uid);
  assert.equal(object.HostConfig?.NetworkMode, 'none');
  assert.equal(object.HostConfig?.ReadonlyRootfs, true);
  assert.equal(object.HostConfig?.Privileged, false);
  assert.deepEqual(object.HostConfig?.CapDrop, ['ALL']);
  assert.ok(object.HostConfig?.SecurityOpt?.includes('no-new-privileges'));
  assert.equal(Object.keys(object.HostConfig?.PortBindings || {}).length, 0);
  assert.equal(Object.keys(object.HostConfig?.Devices || {}).length, 0);
  assert.deepEqual(Object.keys(sources).sort(), ['/results','/secrets/key','/src']);
  const mounts = (object.Mounts || []).map(m => [m.Destination, m.Type, fleetLabMountSource(m.Source), m.RW]).sort((a,b) => a[0].localeCompare(b[0]));
  assert.deepEqual(mounts, [['/results', 'bind', fleetLabMountSource(sources['/results']), true], ['/secrets/key', 'bind', fleetLabMountSource(sources['/secrets/key']), false], ['/src', 'bind', fleetLabMountSource(sources['/src']), false]]);
  const env = object.Config?.Env || [];
  assert.ok(!env.some(v => /^(AWS_|AZURE_|ARM_|GOOGLE_|GCP_|DOCKER_|TF_TOKEN_|GIT_CONFIG_COUNT=)/.test(v)));
}

export function verifyJournalCiphertext(object, ciphertext, key, runID) {
  assert.deepEqual(Object.keys(object).sort(), ['aad','child_id','cipher_sha256','kind','path','plain_sha256','plain_size']);
  for (const value of [object.child_id,object.kind]) assert.match(value,/^[a-z0-9-]{1,128}$/);
  assert.equal(object.path,object.child_id+'.'+object.kind+'.aesgcm');
  for(const value of [object.cipher_sha256,object.plain_sha256]) assert.match(value,/^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(object.plain_size)&&object.plain_size>0&&object.plain_size<=64*1024*1024);
  assert.equal(ciphertext.length,object.plain_size+28); assert.equal(hash(ciphertext),object.cipher_sha256);
  const aad=JSON.parse(object.aad);
  assert.deepEqual(Object.keys(aad).sort(),['child_id','kind','plain_sha256','realm','run_id','schema_version']);
  assert.deepEqual(aad,{schema_version:'1',realm:'ISOLATED_FIXTURE',run_id:runID,child_id:object.child_id,kind:object.kind,plain_sha256:object.plain_sha256});
  assert.equal(key.length,32);
  const decipher=createDecipheriv('aes-256-gcm',key,ciphertext.subarray(0,12));
  decipher.setAAD(Buffer.from(object.aad));decipher.setAuthTag(ciphertext.subarray(ciphertext.length-16));
  const plaintext=Buffer.concat([decipher.update(ciphertext.subarray(12,-16)),decipher.final()]);
  assert.equal(plaintext.length,object.plain_size);assert.equal(hash(plaintext),object.plain_sha256);
}

function privateDirectory(runID, uid) {
  const directory = path.join(root, 'work', 'private', 'fleet-group-journal', runID);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(directory), relative = path.relative(realpathSync(root), resolved);
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  chmodSync(resolved, 0o700);
  if (process.platform === 'win32') {
    const account = execFileSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).trim();
    assert.match(account, /^[^\r\n]+\\[^\r\n]+$/);
    execFileSync('icacls.exe', [resolved, '/inheritance:r', '/grant:r', account + ':(OI)(CI)F'], { windowsHide: true, stdio: 'pipe' });
  } else if (process.getuid?.() === 0) chownSync(resolved, uid, uid);
  return resolved;
}

function snapshot(directory) {
  const source = path.join(directory, 'source');
  mkdirSync(source, { mode: 0o755 });
  const manifest = {};
  const copy = relative => {
    const origin = path.join(root, relative), info = lstatSync(origin);
    const within = path.relative(realpathSync(root), realpathSync(origin));
    assert.ok(info.isFile() && !info.isSymbolicLink() && within && !within.startsWith('..') && !path.isAbsolute(within));
    const target = path.join(source, relative);
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
    copyFileSync(origin, target); chmodSync(target, 0o444);
    manifest[relative.replaceAll('\\', '/')] = hash(readFileSync(target));
  };
  // The selected package and fixture use the standard library only. A minimal
  // module avoids fetching unrelated repository dependencies or credentials.
  writeFileSync(path.join(source, 'go.mod'), 'module github.com/christopherosiemo/bn-implementation-Finops\n\ngo 1.26.0\n', { mode: 0o444 });
  for (const name of readdirSync(path.join(root, 'internal', 'fleetgroup')).sort()) {
    if (/^[a-z_]+\.go$/.test(name) && !name.endsWith('_test.go')) copy(path.join('internal', 'fleetgroup', name));
  }
  for (const name of ['main.go', 'journal_file.go', 'journal_flow.go', 'Dockerfile']) copy(path.join(fixture, name));
  validateFleetTooling(readFileSync(path.join(source, fixture, 'Dockerfile'), 'utf8'));
  return { source, manifest };
}

export async function fleetGroupJournalLab() {
  assert.equal(process.argv.length, 2, 'No alternate target, source, daemon, credentials or cloud arguments accepted');
  assert.ok(!process.env.BUILDKIT_HOST && !process.env.BUILDX_BUILDER, 'External builder overrides refused');
  const invoke = (args, options = {}) => execFileSync('docker', args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 120_000, maxBuffer: 4 << 20, stdio: ['pipe', 'pipe', 'pipe'], ...options }).trim();
  if (process.env.DOCKER_HOST) assert.ok(localDockerEndpoint(process.env.DOCKER_HOST), 'Remote Docker endpoint refused');
  const context = JSON.parse(invoke(['context', 'inspect', invoke(['context', 'show'])]))[0];
  const endpoint = context.Endpoints?.docker?.Host;
  assert.ok(localDockerEndpoint(endpoint), 'Only a local Docker daemon is allowed');
  const run = (args, options) => invoke(['--host', endpoint, ...args], options);
  const daemonID = run(['info', '--format', '{{.ID}}']); assert.ok(daemonID);
  // The default daemon-local builder is the only supported build path; pin
  // its daemon identity as well as the runtime endpoint before building.
  const builder = run(['buildx', 'inspect', 'default']);
  assert.match(builder, /^Driver:\s+docker\s*$/m);
  const builderEndpoints = [...builder.matchAll(/^Endpoint:\s+([^\r\n]+)\s*$/gm)].map(m => m[1].trim());
  assert.equal(builderEndpoints.length, 1);
  const buildEndpoint = builderEndpoints[0];
  if (localDockerEndpoint(buildEndpoint)) assert.equal(invoke(['--host', buildEndpoint, 'info', '--format', '{{.ID}}']), daemonID);
  else {
    const selected = JSON.parse(invoke(['context', 'inspect', buildEndpoint]))[0];
    assert.ok(localDockerEndpoint(selected.Endpoints?.docker?.Host));
    assert.equal(invoke(['--host', selected.Endpoints.docker.Host, 'info', '--format', '{{.ID}}']), daemonID);
  }
  const runID = randomUUID(), compact = runID.replaceAll('-', ''), name = 'finops-fleet-group-journal-' + compact + '-test';
  const uid = process.getuid?.() > 0 ? process.getuid() : 10001;
  const directory = privateDirectory(runID, uid), { source, manifest } = snapshot(directory);
  const output = path.join(directory, 'encrypted'); mkdirSync(output, { mode: 0o700 });
  const key = path.join(directory, 'local-fixture.key'); writeFileSync(key, randomBytes(32), { flag: 'wx', mode: 0o600 });
  if (process.platform !== 'win32' && process.getuid?.() === 0) { chownSync(output, uid, uid); chownSync(key, uid, uid); }
  const tag = 'finops-fleet-group-journal-' + compact + ':tooling';
  const mountSources = {'/src':realpathSync(source),'/results':realpathSync(output),'/secrets/key':realpathSync(key)};
  let imageID, result, failure;
  try {
    run(['build', '--builder', 'default', '--network', 'none', '--pull=false', '--label', label + '=' + runID, '--tag', tag, '--file', path.join(source, fixture, 'Dockerfile'), source], { timeout: 300_000 });
    const image = JSON.parse(run(['image', 'inspect', tag]))[0];
    assert.equal(image.Config?.Labels?.[label], runID); assert.match(image.Id, /^sha256:[a-f0-9]{64}$/); imageID = image.Id;
    assert.equal(run(['info', '--format', '{{.ID}}']), daemonID);
    run(['create', '--name', name, '--label', label + '=' + runID, '--pull', 'never', '--network', 'none', '--user', uid + ':' + uid, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--memory', '512m', '--cpus', '1',
      '-e', 'HOME=/tmp/home', '-e', 'GOCACHE=/tmp/go-cache', '-e', 'GOPATH=/tmp/go', '-e', 'GOPROXY=off', '-e', 'GOSUMDB=off', '-e', 'GOTOOLCHAIN=local', '-e', 'GOMAXPROCS=1', '-e', 'GOMEMLIMIT=384MiB', '-e', 'CHECKPOINT_DISABLE=1', '-e', 'TF_IN_AUTOMATION=1', '-e', 'GIT_CONFIG_NOSYSTEM=1', '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_CONFIG_SYSTEM=/dev/null', '-e', 'GIT_TERMINAL_PROMPT=0', '-e', 'GIT_NO_LAZY_FETCH=1', '-e', 'FLEET_JOURNAL_FIXTURE_RUN_ID=' + runID, '-e', 'FLEET_JOURNAL_FIXTURE_IMAGE_ID=' + imageID,
      '--mount', 'type=bind,src=' + source + ',dst=/src,readonly', '--mount', 'type=bind,src=' + output + ',dst=/results', '--mount', 'type=bind,src=' + key + ',dst=/secrets/key,readonly', '--tmpfs', '/workspace:rw,nosuid,nodev,size=192m,uid=' + uid + ',gid=' + uid + ',mode=0700', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=384m,uid=' + uid + ',gid=' + uid + ',mode=0700', '--workdir', '/src', imageID, 'go', 'run', './examples/fleet-group-journal-fixture']);
    validateFleetLabContainer(JSON.parse(run(['inspect', name]))[0], runID, imageID, uid, mountSources);
    const logs = run(['start', '--attach', name], { timeout: 600_000 });
    const completed = JSON.parse(run(['inspect', name]))[0]; validateFleetLabContainer(completed, runID, imageID, uid, mountSources);
    assert.equal(completed.State?.ExitCode, 0, 'Actual fixture process failed');
    writeFileSync(path.join(directory, 'acceptance.log'), logs + '\n', { mode: 0o600 });
    assert.ok(lstatSync(path.join(output,'component-result.json')).size<=64*1024);
    result = JSON.parse(readFileSync(path.join(output, 'component-result.json'), 'utf8'));
    assert.equal(result.status, 'PASS'); assert.equal(result.exact_saved_plan_applies, 7); assert.equal(result.git_owned_manifest, true);
    assert.equal(result.customer_native_execution, false); assert.equal(result.customer_verified_savings, false); assert.equal(result.real_clock_health_accepted, false);
    assert.equal(result.forward_saved_plan_applies,4);assert.equal(result.owned_child_inverse_applies,3);
    assert.equal(result.whole_program_rollback_accepted,false);assert.equal(result.fixture_top_effects_consumed,3);
    assert.equal(result.durable_current_ownership_service,false);assert.equal(result.file_journal_process_reopen,true);
    assert.equal(result.pg_runtime_acceptance,false);assert.equal(result.customer_pipeline_oidc_acceptance,false);
    for(const field of ['precommand_journal_authorization','actual_git_cas_cutpoint','terminal_applied_reconciled_without_reapply','unresolved_unknown_held','duplicate_callback_idempotent','conflicting_callback_rejected','consumed_effect_cannot_revive','torn_tail_rejected','concurrent_writer_rejected','git_only_repair_zero_apply','git_only_repair_new_commit','git_only_repair_kept_previous_effects','forward_permanently_aborted','stale_preparation_rejected_before_cas','stale_finalization_rejected_before_delivery']) assert.equal(result[field],true,field);
    assert.equal(result.synthetic_refs_resolved_from_025_027,false);
    assert.equal(result.expired_forward_preparation_boundary_probe_rejected,true);
    assert.equal(result.expiry_probes_use_logical_negative_time_only,true);
    assert.ok(Number.isSafeInteger(result.encrypted_objects)&&result.encrypted_objects>0&&result.encrypted_objects<=512);
    const retained = readdirSync(output);
    assert.equal(retained.filter(value => value.endsWith('.aesgcm')).length, result.encrypted_objects);
    assert.ok(retained.every(value => ['component-result.json','object-index.jsonl'].includes(value) || /^[a-z0-9-]+\.[a-z0-9-]+\.aesgcm$/.test(value)), 'Unexpected plaintext or artifact file retained');
    assert.ok(lstatSync(path.join(output,'object-index.jsonl')).size<=1024*1024);
    const index = readFileSync(path.join(output,'object-index.jsonl'),'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(index.length,result.encrypted_objects);
    const objectPaths=new Set();const localKey=readFileSync(key);
    for (const object of index) {
      assert.match(object.path,/^[a-z0-9-]+\.[a-z0-9-]+\.aesgcm$/);assert.ok(!objectPaths.has(object.path));objectPaths.add(object.path);
      const file=path.join(output,object.path),info=lstatSync(file);assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.size<=64*1024*1024+28);
      verifyJournalCiphertext(object,readFileSync(file),localKey,runID);
    }
    result.retained_authenticated_readback_after_process_exit=true;
    result.encrypted_object_index_sha256 = hash(readFileSync(path.join(output,'object-index.jsonl')));
  } catch (error) { failure = error; const raw = String(error.stdout || '') + '\n' + String(error.stderr || '') + '\n' + String(error.message || ''); writeFileSync(path.join(directory, 'failure.log'), raw, { mode: 0o600 }); }
  finally {
    assert.equal(run(['info', '--format', '{{.ID}}']), daemonID, 'Daemon changed before cleanup');
    const present = run(['ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']).split('\n');
    if (present.includes(name)) { const object = JSON.parse(run(['inspect', name]))[0]; validateFleetLabContainer(object, runID, imageID, uid, mountSources); run(['rm', '--force', name]); }
    const tagged = run(['image','ls','--filter','reference=' + tag,'--format','{{.Repository}}:{{.Tag}}']).split('\n');
    if (tagged.includes(tag)) { const image = JSON.parse(run(['image', 'inspect', tag]))[0]; if(imageID) assert.equal(image.Id, imageID); assert.equal(image.Config?.Labels?.[label], runID); run(['image', 'rm', tag]); }
    assert.equal(run(['ps', '--all', '--filter', 'label=' + label + '=' + runID, '--format', '{{.ID}}']), '', 'Owned containers remain');
    assert.equal(run(['image','ls','--filter','reference=' + tag,'--format','{{.Repository}}:{{.Tag}}']), '', 'Owned tooling tag remains');
  }
  if (failure) throw new Error('Fleet fixture lab failed; private diagnostics retained, no acceptance recorded.');
  writeFileSync(path.join(directory, 'acceptance.json'), JSON.stringify({ schema_version: '1', ...result, run_id: runID, tooling_image_id: imageID, tooling_bases: images, runner_sha256: hash(readFileSync(fileURLToPath(import.meta.url))), harness_dependencies_sha256:{'scripts/kubernetes-bootstrap.mjs':hash(readFileSync(path.join(root,'scripts/kubernetes-bootstrap.mjs')))}, source_sha256: manifest, cleanup_succeeded: true, main_stack_accessed: false, artifact_storage: 'LOCAL_PRIVATE_AES_256_GCM_FIXTURE_KEY' }, null, 2) + '\n', { mode: 0o600 });
  console.log('File journal fixture PASS: preparation plus three actual owned forward effects and three LIFO inverse commits; exact saved-plan applies, process reopen, held uncertainty and encrypted cleanup checked. PostgreSQL/runtime, customer pipeline and real-clock health remain unaccepted.');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) fleetGroupJournalLab().catch(() => { console.error('Git 5.1 fleet fixture failed; plans, state and key are not printed.'); process.exitCode = 1; });
