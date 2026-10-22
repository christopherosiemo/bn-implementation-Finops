// Fixture-only acceptance against real local Compose processes and Temporal.
// Run serially: this restarts worker + API, which briefly affects every local tenant.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertMigrationManifest, assertStoppedOccurrence, parseImageMigrationManifest, recoveryDockerEndpoint, stoppedOccurrenceSQL, upgradeComposeOverride, upgradeKindLabel, upgradeLabel, validatePendingMigrations, validateUpgradeContainer, validateUpgradeFixtureSources } from './lib/recovery-upgrade.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const arguments_ = process.argv.slice(2);
assert.ok(arguments_.length === 0 || arguments_.length === 1 && arguments_[0] === '--migrate-before-restart', 'only the explicit local fixture migration-recovery option is supported');
const migrateBeforeRestart = arguments_.length === 1;
const envFile = path.join(root, '.env');
const env = Object.fromEntries(readFileSync(envFile, 'utf8').split(/\r?\n/).flatMap(line => {
  const value = line.trim();
  if (!value || value.startsWith('#') || !value.includes('=')) return [];
  const index = value.indexOf('=');
  return [[value.slice(0, index).trim(), value.slice(index + 1).trim().replace(/^(['"])(.*)\1$/, '$2')]];
}));
const api = (process.env.API_URL || `http://localhost:${env.API_PORT || 8080}`).replace(/\/$/, '');
const issuer = (process.env.OIDC_ISSUER || `http://localhost:${env.KEYCLOAK_PORT || 8081}/realms/finops`).replace(/\/$/, '');
const password = process.env.FINOPS_RECOVERY_PASSWORD || env.DEMO_PASSWORD;
const username = 'other';
for (const address of [api, issuer]) {
  let hostname;
  try { hostname = new URL(address).hostname; } catch { throw new Error('A valid local fixture endpoint is required'); }
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(hostname), 'process-recovery acceptance targets only the local fixture stack');
}
assert.notEqual(process.env.FIXTURE_MODE || env.FIXTURE_MODE, 'false', 'process recovery never runs with live AWS mode configured');
assert.ok(password, 'configure DEMO_PASSWORD in .env before running fixture recovery');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const checks = [];
const passed = label => { checks.push(label); console.log(`PASS ${label}`); };
class ApiFailure extends Error { constructor(status, message) { super(message); this.status = status; } }
class TerminalExecutionError extends Error {}

async function waitFor(fn, label, timeout = 120_000, poll = 500) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try { const value = await fn(); if (value) return value; }
    catch (error) {
      if (error instanceof TerminalExecutionError || error?.name === 'AssertionError') throw error;
      if (error instanceof ApiFailure && error.status >= 400 && error.status < 500) throw error;
      last = error;
    }
    await delay(poll);
  }
  throw new Error(`${label} timed out${last ? `: ${last.message}` : ''}`);
}

let frozenDocker;
let upgrade;
function docker(args, timeout = 60_000) {
  const environment = { ...process.env };
  if (frozenDocker) for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete environment[key];
  const result = spawnSync('docker', [...(frozenDocker ? ['--host', frozenDocker.endpoint] : []), ...args], { cwd: root, env: environment, encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 2 << 20 });
  if (migrateBeforeRestart) {
    assert.ok(!result.error && result.status === 0, 'The selected local migration-recovery Docker operation failed; raw commands, environment and database data are withheld');
    return result.stdout.trim();
  }
  if (result.error) throw new Error(`Docker ${args[0]} failed: ${result.error.message}`);
  assert.equal(result.status, 0, `Docker ${args[0]} failed: ${(result.stderr || '').trim()}`);
  return result.stdout.trim();
}
function compose(args, pinned = false) {
  assert.ok(!pinned || upgrade?.overrideFile, 'The reviewed migration image override is required');
  return docker(['compose', '--project-directory', root, '--env-file', envFile, '-f', path.join(root, 'compose.yaml'), ...(pinned ? ['-f', upgrade.overrideFile] : []), ...args]);
}
const inspect = target => JSON.parse(docker(['inspect', '--type', 'container', target]))[0];
function assertDaemon() {
  assert.ok(frozenDocker && docker(['info', '--format', '{{.ID}}']) === frozenDocker.daemonID, 'Docker daemon identity changed during the fixture upgrade');
  assert.ok(configurationHash() === frozenDocker.configurationHash, 'Compose configuration changed during the reviewed fixture upgrade');
}
const configurationHash = () => createHash('sha256').update(readFileSync(path.join(root, 'compose.yaml'))).update(readFileSync(envFile)).digest('hex');
const fixtureFetch = (address, options = {}) => fetch(address, { ...options, redirect: migrateBeforeRestart ? 'error' : 'follow' });
function upgradeSources() {
  const objects = {};
  for (const service of ['api', 'worker', 'executor', 'temporal', 'postgres', 'keycloak']) {
    const id = compose(['ps', '-q', service]);
    assert.match(id, /^[a-f0-9]{64}$/, 'Exactly one inspected fixture service is required');
    objects[service] = inspect(id);
  }
  return objects;
}
function freezeUpgradeTarget() {
  const contextName = docker(['context', 'show']);
  const context = JSON.parse(docker(['context', 'inspect', contextName]))[0];
  const endpoint = recoveryDockerEndpoint(contextName, context, process.env.DOCKER_HOST);
  frozenDocker = { endpoint };
  frozenDocker.configurationHash = configurationHash();
  frozenDocker.daemonID = docker(['info', '--format', '{{.ID}}']);
  assert.ok(frozenDocker.daemonID && frozenDocker.daemonID.length < 256, 'The local daemon identity is required');
  frozenDocker.sources = upgradeSources();
  Object.assign(frozenDocker, validateUpgradeFixtureSources(frozenDocker.sources, root, api, issuer));
}
function containerState(service) {
  const id = compose(['ps', '-q', service]);
  assert.ok(id && !id.includes('\n'), `exactly one running ${service} container is required`);
  const state = JSON.parse(docker(['inspect', '--format', '{{json .State}}', id]));
  assert.equal(state.Running, true, `${service} must be running`);
  const image = docker(['inspect', '--format', '{{.Image}}', id]);
  return { id, startedAt: state.StartedAt, image };
}
function migrationState() {
  const raw = docker(['exec', frozenDocker.sources.postgres.Id, 'psql', '-X', '-w', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'finops', '-Atq', '-c', 'SELECT jsonb_object_agg(filename,sha256)::text FROM schema_migrations']);
  return JSON.parse(raw);
}
function helperDescriptor(kind, image, runID) {
  return { kind, image, runID, name: `finops-recovery-upgrade-${kind === 'image-manifest' ? 'manifest' : 'migrate'}-${runID.replaceAll('-', '')}`, project: frozenDocker.project, network: frozenDocker.network };
}
function cleanupHelper(descriptor) {
  if (!descriptor) return;
  if (!descriptor.id && descriptor.attempted) {
    const found = docker(['ps', '-a', '-q', '--no-trunc', '--filter', 'name=^/' + descriptor.name + '$']);
    if (!found) { descriptor.attempted = false; return; }
    assert.match(found, /^[a-f0-9]{64}$/, 'Only one exact owned helper may be selected');
    descriptor.id = found;
  }
  if (!descriptor.id) return;
  assertDaemon();
  let object = inspect(descriptor.id);
  validateUpgradeContainer(object, descriptor);
  if (object.State.Running) {
    docker(['stop', '-t', '2', descriptor.id]);
    object = inspect(descriptor.id);
    validateUpgradeContainer(object, descriptor);
  }
  assert.ok(!object.State.Running, 'Owned helper must stop before exact cleanup');
  docker(['rm', descriptor.id]);
  descriptor.id = null;
  descriptor.attempted = false;
}
function imageMigrationManifest(image, runID) {
  const descriptor = helperDescriptor('image-manifest', image, runID);
  try {
    descriptor.attempted = true;
    descriptor.id = docker(['create', '--name', descriptor.name, '--label', `${upgradeLabel}=${runID}`, '--label', `${upgradeKindLabel}=image-manifest`, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '32', '--memory', '128m', '--cpus', '0.25', '--entrypoint', '/bin/sh', image, '-c', 'cd /app/migrations && for f in *.sql; do sha256sum -- "$f" || exit 1; done']);
    validateUpgradeContainer(inspect(descriptor.id), descriptor);
    const manifest = parseImageMigrationManifest(docker(['start', '-a', descriptor.id]));
    const finished = inspect(descriptor.id);
    validateUpgradeContainer(finished, descriptor);
    assert.ok(!finished.State.Running && finished.State.ExitCode === 0, 'Isolated image manifest inspection must complete successfully');
    return manifest;
  } finally { cleanupHelper(descriptor); }
}
function writeUpgradeOverride(prepared) {
  const base = path.join(root, 'work', 'private', 'recovery-upgrade');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(base), relative = path.relative(realpathSync(root), resolved);
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'Upgrade artifacts must remain in this workspace');
  const directory = mkdtempSync(path.join(resolved, 'run-'));
  chmodSync(directory, 0o700);
  const marker = path.join(directory, 'owner.json'), overrideFile = path.join(directory, 'image.override.json');
  writeFileSync(marker, JSON.stringify({ runID: prepared.runID, workspace: realpathSync(root) }), { flag: 'wx', mode: 0o600 });
  writeFileSync(overrideFile, JSON.stringify(upgradeComposeOverride(prepared.image)), { flag: 'wx', mode: 0o600 });
  Object.assign(prepared, { directory, marker, overrideFile });
}
function cleanupOverride() {
  if (!upgrade?.directory) return;
  const relative = path.relative(realpathSync(root), realpathSync(upgrade.directory));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative) && path.basename(upgrade.directory).startsWith('run-'), 'Only this workspace upgrade directory may be cleaned');
  const owner = JSON.parse(readFileSync(upgrade.marker, 'utf8'));
  assert.ok(owner.runID === upgrade.runID && owner.workspace === realpathSync(root), 'Upgrade artifact ownership differs');
  for (const file of [upgrade.overrideFile, upgrade.marker]) {
    assert.ok(path.dirname(file) === upgrade.directory && lstatSync(file).isFile() && !lstatSync(file).isSymbolicLink(), 'Only exact owned regular artifact files may be removed');
    unlinkSync(file);
  }
  rmdirSync(upgrade.directory);
  upgrade.directory = null;
}
function pendingMigrationUpgrade(before) {
  const files = Object.fromEntries(readdirSync(path.join(root, 'migrations')).filter(name => name.endsWith('.sql')).map(name => [name, createHash('sha256').update(readFileSync(path.join(root, 'migrations', name))).digest('hex')]));
  const applied = migrationState();
  const pending = validatePendingMigrations(files, applied);
  const image = docker(['image', 'inspect', '--format', '{{.Id}}', 'cloud-cost-autopilot-go:local']);
  assert.match(image, /^sha256:[a-f0-9]{64}$/);
  for (const service of ['api', 'worker']) assert.notEqual(before[service].image, image, 'prepare a distinct reviewed upgrade image before exercising migration recovery');
  const runID = randomUUID();
  assertMigrationManifest(imageMigrationManifest(image, runID), files);
  const prepared = { files, pending, image, runID };
  upgrade = prepared;
  writeUpgradeOverride(prepared);
  return prepared;
}
function originalStoppedProof(expected) {
  const raw = docker(['exec', frozenDocker.sources.postgres.Id, 'psql', '-X', '-w', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'finops', '-Atq', '-c', stoppedOccurrenceSQL(expected)]);
  assert.ok(raw, 'The original stopped occurrence must remain present');
  return JSON.parse(raw);
}
function applyPreparedMigration() {
  assertDaemon();
  const descriptor = helperDescriptor('migrator', upgrade.image, upgrade.runID);
  upgrade.migrator = descriptor;
  // Compose prepares the actual migration environment, but initially launches
  // only an inert bounded shell. No DDL starts until its exact image, scope,
  // role, network and labels have been independently inspected.
  descriptor.attempted = true;
  descriptor.id = compose(['run', '-d', '--no-deps', '--entrypoint', '/bin/sh', '--name', descriptor.name, '--label', `${upgradeLabel}=${upgrade.runID}`, '--label', `${upgradeKindLabel}=migrator`, '-e', 'MIGRATIONS_DIR=/app/migrations', 'migrate', '-c', 'sleep 180'], true);
  validateUpgradeContainer(inspect(descriptor.id), descriptor);
  docker(['exec', descriptor.id, '/app/finops', '-mode', 'migrate'], 120_000);
  const finished = inspect(descriptor.id);
  validateUpgradeContainer(finished, descriptor);
  assert.ok(finished.State.Running, 'The inspected bounded migration helper must remain available for exact cleanup');
  cleanupHelper(descriptor);
}
async function login() {
  const response = await fixtureFetch(`${issuer}/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, signal: AbortSignal.timeout(10_000),
    body: new URLSearchParams({ grant_type: 'password', client_id: 'console', username, password }),
  });
  assert.equal(response.status, 200, 'fixture other-tenant OIDC sign-in');
  const result = await response.json();
  assert.ok(result.access_token, 'OIDC access token is required');
  return result.access_token;
}
async function request(token, method, url, body, version) {
  const headers = { Authorization: `Bearer ${token}` };
  if (method === 'POST') { headers['Content-Type'] = 'application/json'; headers['Idempotency-Key'] = randomUUID(); }
  if (version !== undefined) headers['If-Match'] = `"${version}"`;
  const response = await fixtureFetch(api + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : undefined; } catch { throw new Error(`${method} ${url} returned unreadable JSON (${response.status})`); }
  if (!response.ok) throw new ApiFailure(response.status, `${method} ${url}: ${response.status} ${JSON.stringify(data)}`);
  return data;
}
const fixtureDashboard = async token => {
  const dashboard = await request(token, 'GET', '/v1/dashboard');
  assert.equal(dashboard.fixture, true, 'refuse mutations unless the authenticated API confirms fixture mode');
  return dashboard;
};
const occurrenceEvents = (dashboard, executionId, action) => dashboard.audit.filter(event => event.action === action && event.details?.execution_id === executionId);
const checkTerminal = execution => {
  if (['FAILED', 'SKIPPED', 'CANCELLED'].includes(execution.status)) throw new TerminalExecutionError(`execution ${execution.id} became ${execution.status}: ${execution.reason_code || execution.error || ''}`);
};

let token;
let execution;
let restarted = false;
try {
  // Both modes target the same inspected local fixture. Image/DDL/ownership
  // SQL requirements remain exclusive to the explicit migration option.
  freezeUpgradeTarget();
  compose(['version']);
  await waitFor(async () => (await fixtureFetch(api + '/healthz', { signal: AbortSignal.timeout(3000) })).ok, 'API readiness');
  await waitFor(async () => (await fixtureFetch(issuer + '/.well-known/openid-configuration', { signal: AbortSignal.timeout(3000) })).ok, 'OIDC readiness');
  token = await login();
  let dashboard = await fixtureDashboard(token);
  const tenantId = dashboard.org.id;
  assert.equal(tenantId, 'tenant-other', 'the fixture recovery user must be isolated from the owner tenant');
  assert.ok(!dashboard.executions.some(item => item.restoration_owned || !['COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED'].includes(item.status)), 'finish any existing other-tenant recovery obligation before resetting the fixture');
  passed('authenticated other-tenant fixture guard');

  // All local-target and immutable-image/DDL checks precede fixture mutation.
  if (migrateBeforeRestart) upgrade = pendingMigrationUpgrade(Object.fromEntries(['api', 'worker'].map(service => [service, { image: frozenDocker.sources[service].Image }])));

  // The reset endpoint retains append-only audit and financial evidence.
  await request(token, 'POST', '/v1/demo/reset', {});
  dashboard = await fixtureDashboard(token);
  assert.equal(dashboard.org.id, tenantId, 'fixture reset preserves tenant identity');
  await request(token, 'POST', '/v1/demo/scenario', { scenario: 'healthy' });
  dashboard = await fixtureDashboard(token);
  const workload = dashboard.workloads.find(item => item.id === 'workload-dev');
  const recommendation = await waitFor(async () => {
    const generated = await request(token, 'POST', '/v1/recommendations', { workload_id: 'workload-dev' });
    return generated.recommendations.find(item => item.status === 'VALIDATED' && item.pre_execution_ready === true);
  }, 'immutable baseline readiness before recovery occurrence');
  const schedule = dashboard.schedules.find(item => item.id === 'schedule-dev');
  assert.ok(workload && recommendation && schedule, 'seeded fixture workload, recommendation, and schedule are required');
  await request(token, 'POST', `/v1/workloads/${workload.id}/signals`, { incident: 'CLEAR', deployment: 'CLEAR', job: 'CLEAR' }, workload.version);
  passed('fresh safety signals and seeded eligible workload');

  // Capture process start times before plan creation so Docker inspection cannot
  // consume the short fixture stop window after the occurrence has begun.
  const before = Object.fromEntries(['worker', 'api', 'temporal', 'postgres', 'executor'].map(service => [service, containerState(service)]));
  if (upgrade) {
    assertDaemon();
    const currentSources = upgradeSources();
    validateUpgradeFixtureSources(currentSources, root, api, issuer);
    for (const service of Object.keys(currentSources)) assert.ok(currentSources[service].Id === frozenDocker.sources[service].Id && currentSources[service].Image === frozenDocker.sources[service].Image, 'Fixture service changed after upgrade preflight');
  }
  const plan = await request(token, 'POST', '/v1/change-plans', { recommendation_id: recommendation.id, schedule_id: schedule.id, memory_state_acknowledged: true, public_ip_change_acknowledged: true });
  const approval = await request(token, 'POST', '/v1/approvals', { change_plan_id: plan.id }, plan.version);
  execution = await request(token, 'POST', '/v1/executions', { change_plan_id: plan.id }, approval.change_plan.version);
  assert.ok(execution.id, 'execution ID is required');

  const stopped = await waitFor(async () => {
    const current = await request(token, 'GET', `/v1/executions/${execution.id}`);
    checkTerminal(current);
    return current.stage === 'STOPPED' && current.restoration_owned === true ? current : false;
  }, 'persisted STOPPED occurrence with restoration ownership', 60_000, 100);
  assert.equal(stopped.resource_id, recommendation.resource_id, 'the approved fixture resource was stopped');
  let restartRequestedAt;
  if (upgrade) {
    // The eight-second fixture window is not extended. Stop promptly before
    // extra audit queries; independently fail before DDL if restoration raced.
    restarted = true;
    restartRequestedAt = Date.now();
    // The explicit daemon and complete original identities were checked just
    // before dispatch. Avoid Compose discovery in this short critical window;
    // use only the exact frozen process IDs on that pinned daemon, then repeat
    // daemon/configuration and stopped-ownership checks before any DDL.
    docker(['stop', '-t', '0', before.worker.id, before.api.id]);
    assertDaemon();
    for (const service of ['worker', 'api']) {
      const object = inspect(before[service].id);
      assert.ok(object.Id === frozenDocker.sources[service].Id && object.State.Running === false && object.Image === before[service].image, 'The original fixture process must be stopped before migration');
    }
    const expected = { tenantID: tenantId, executionID: execution.id, planID: plan.id, resourceID: recommendation.resource_id, payload: plan.payload };
    const originalHash = assertStoppedOccurrence(originalStoppedProof(expected), expected);
    passed('real provider fixture stopped once with durable ownership');
    applyPreparedMigration();
    assertMigrationManifest(migrationState(), upgrade.files);
    assertStoppedOccurrence(originalStoppedProof(expected), expected, originalHash);
    compose(['up', '-d', '--no-build', '--no-deps', 'worker', 'api'], true);
    passed('additive migration applied while original stopped-instance ownership survived the API/worker upgrade');
  } else {
    dashboard = await fixtureDashboard(token);
    assert.equal(occurrenceEvents(dashboard, execution.id, 'provider.stop').length, 1, 'one provider stop was committed before process interruption');
    assert.equal(occurrenceEvents(dashboard, execution.id, 'provider.start').length, 0, 'restart begins before restoration');
    passed('real provider fixture stopped once with durable ownership');
    restarted = true;
    restartRequestedAt = Date.now();
    assertDaemon();
    compose(['restart', 'worker', 'api']);
  }
  const after = Object.fromEntries(['worker', 'api', 'temporal', 'postgres', 'executor'].map(service => [service, containerState(service)]));
  for (const service of ['worker', 'api']) assert.notEqual(after[service].startedAt, before[service].startedAt, `${service} process actually restarted`);
  if (upgrade) for (const service of ['worker', 'api']) assert.equal(after[service].image, upgrade.image, `${service} must run the reviewed upgrade image`);
  for (const service of ['temporal', 'postgres', 'executor']) {
    assert.equal(after[service].id, before[service].id, `${service} container was preserved`);
    assert.equal(after[service].startedAt, before[service].startedAt, `${service} process was not restarted`);
  }
  passed('worker and API actually restarted; Temporal, PostgreSQL, and executor stayed running');

  await waitFor(async () => (await fixtureFetch(api + '/healthz', { signal: AbortSignal.timeout(3000) })).ok, 'API readiness after restart');
  token = await login();
  dashboard = await fixtureDashboard(token);
  assert.equal(dashboard.org.id, tenantId, 'the authenticated tenant survives API restart');
  const completed = await waitFor(async () => {
    const current = await request(token, 'GET', `/v1/executions/${execution.id}`);
    checkTerminal(current);
    return current.status === 'COMPLETED' ? current : false;
  }, 'Temporal resumes persisted history and completes restoration', 120_000);
  assert.equal(completed.restoration_owned, false, 'restoration ownership is released only after readiness');
  assert.ok(Date.parse(completed.completed_at) >= Date.parse(after.worker.startedAt), 'completion was persisted by the restarted worker');
  passed('Temporal recovered the occurrence and completed mandatory readiness checks');

  dashboard = await fixtureDashboard(token);
  const resource = dashboard.resources.find(item => item.id === completed.resource_id);
  assert.equal(resource?.state, 'running', 'the owned fixture instance is running after recovery');
  const stops = occurrenceEvents(dashboard, execution.id, 'provider.stop');
  const starts = occurrenceEvents(dashboard, execution.id, 'provider.start');
  assert.equal(stops.length, 1, 'replay did not dispatch a duplicate provider stop');
  assert.equal(starts.length, 1, 'replay did not dispatch a duplicate provider start');
  assert.equal(stops[0].resource, completed.resource_id);
  assert.equal(starts[0].resource, completed.resource_id);
  assert.ok(Date.parse(starts[0].timestamp) >= restartRequestedAt, 'restoration happened after process interruption began');
  assert.ok(dashboard.audit.some(event => event.action === 'execution.stage_changed' && event.resource === execution.id && event.actor === 'temporal-worker' && event.details?.status === 'COMPLETED'), 'recovered completion is present in the immutable audit trail');
  passed('running resource and exactly one audited provider stop/start after replay');
  console.log(`\n${checks.length} process-recovery checks passed. Fixture only; worker and API were restarted while the instance was stopped. No live AWS action was performed.`);
} catch (error) {
  // A failed test must still make recovery possible. Restart only the same two
  // selected services and request restoration for this test's owned occurrence.
  let migrationStopped = true;
  if (upgrade?.migrator?.attempted) {
    try { cleanupHelper(upgrade.migrator); }
    catch { migrationStopped = false; console.error('Recovery cleanup cannot verify the owned migrator is stopped; API/worker restart withheld for operator attention.'); }
  }
  if (restarted && migrationStopped) {
    try {
      assertDaemon();
      if (upgrade) {
        // Start only already-created original or pinned replacement processes.
        // A failed upgrade must not silently create services from a moved tag.
        for (const service of ['worker', 'api']) {
          const selected = compose(['ps', '-a', '-q', service]);
          assert.match(selected, /^[a-f0-9]{64}$/);
          const object = inspect(selected);
          assert.ok([frozenDocker.sources[service].Image, upgrade.image].includes(object.Image) && object.Config.Labels['com.docker.compose.service'] === service && object.Config.Labels['com.docker.compose.project'] === frozenDocker.project, 'Only the selected original or reviewed replacement process may resume');
        }
      }
      compose(['start', 'worker', 'api'], !!upgrade);
    }
    catch (cleanupError) { console.error(`Recovery cleanup could not start worker/API: ${cleanupError.message}`); }
  }
  if (execution?.id && token && (!migrateBeforeRestart || migrationStopped)) {
    try {
      await waitFor(async () => (await fixtureFetch(api + '/healthz', { signal: AbortSignal.timeout(3000) })).ok, 'cleanup API readiness', 20_000);
      token = await login();
      await fixtureDashboard(token);
      const current = await request(token, 'GET', `/v1/executions/${execution.id}`);
      if (current.restoration_owned || !['COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED'].includes(current.status)) {
        await request(token, 'POST', `/v1/executions/${execution.id}/start-now`, {}, current.version);
        console.error(`Requested immediate durable restoration for failed test occurrence ${execution.id}.`);
      }
    } catch (cleanupError) { console.error(`Recovery cleanup needs operator attention: ${cleanupError.message}`); }
  }
  console.error(`FAIL process recovery: ${error.message}`);
  process.exitCode = 1;
} finally {
  try { cleanupOverride(); }
  catch { console.error('Recovery upgrade artifact cleanup needs operator attention; only this run-owned directory was selected.'); process.exitCode = 1; }
}
