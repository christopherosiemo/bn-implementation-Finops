// Fixture-only acceptance against real local Compose processes and Temporal.
// Run serially: this restarts worker + API, which briefly affects every local tenant.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
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
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(new URL(address).hostname), 'process-recovery acceptance targets only the local fixture stack');
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

function docker(args) {
  const result = spawnSync('docker', args, { cwd: root, encoding: 'utf8', timeout: 60_000, windowsHide: true });
  if (result.error) throw new Error(`Docker ${args[0]} failed: ${result.error.message}`);
  assert.equal(result.status, 0, `Docker ${args[0]} failed: ${(result.stderr || '').trim()}`);
  return result.stdout.trim();
}
function compose(args) {
  return docker(['compose', '--project-directory', root, '--env-file', envFile, '-f', path.join(root, 'compose.yaml'), ...args]);
}
function containerState(service) {
  const id = compose(['ps', '-q', service]);
  assert.ok(id && !id.includes('\n'), `exactly one running ${service} container is required`);
  const state = JSON.parse(docker(['inspect', '--format', '{{json .State}}', id]));
  assert.equal(state.Running, true, `${service} must be running`);
  return { id, startedAt: state.StartedAt };
}
async function login() {
  const response = await fetch(`${issuer}/protocol/openid-connect/token`, {
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
  const response = await fetch(api + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
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
  compose(['version']);
  await waitFor(async () => (await fetch(api + '/healthz', { signal: AbortSignal.timeout(3000) })).ok, 'API readiness');
  await waitFor(async () => (await fetch(issuer + '/.well-known/openid-configuration', { signal: AbortSignal.timeout(3000) })).ok, 'OIDC readiness');
  token = await login();
  let dashboard = await fixtureDashboard(token);
  const tenantId = dashboard.org.id;
  assert.equal(tenantId, 'tenant-other', 'the fixture recovery user must be isolated from the owner tenant');
  assert.ok(!dashboard.executions.some(item => item.restoration_owned || !['COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED'].includes(item.status)), 'finish any existing other-tenant recovery obligation before resetting the fixture');
  passed('authenticated other-tenant fixture guard');

  // The reset endpoint retains append-only audit and financial evidence.
  await request(token, 'POST', '/v1/demo/reset', {});
  dashboard = await fixtureDashboard(token);
  assert.equal(dashboard.org.id, tenantId, 'fixture reset preserves tenant identity');
  await request(token, 'POST', '/v1/demo/scenario', { scenario: 'healthy' });
  dashboard = await fixtureDashboard(token);
  const workload = dashboard.workloads.find(item => item.id === 'workload-dev');
  const recommendation = dashboard.recommendations.find(item => item.status === 'VALIDATED');
  const schedule = dashboard.schedules.find(item => item.id === 'schedule-dev');
  assert.ok(workload && recommendation && schedule, 'seeded fixture workload, recommendation, and schedule are required');
  await request(token, 'POST', `/v1/workloads/${workload.id}/signals`, { incident: 'CLEAR', deployment: 'CLEAR', job: 'CLEAR' }, workload.version);
  passed('fresh safety signals and seeded eligible workload');

  // Capture process start times before plan creation so Docker inspection cannot
  // consume the short fixture stop window after the occurrence has begun.
  const before = Object.fromEntries(['worker', 'api', 'temporal', 'postgres', 'executor'].map(service => [service, containerState(service)]));
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
  dashboard = await fixtureDashboard(token);
  assert.equal(occurrenceEvents(dashboard, execution.id, 'provider.stop').length, 1, 'one provider stop was committed before process interruption');
  assert.equal(occurrenceEvents(dashboard, execution.id, 'provider.start').length, 0, 'restart begins before restoration');
  passed('real provider fixture stopped once with durable ownership');

  restarted = true;
  const restartRequestedAt = Date.now();
  compose(['restart', 'worker', 'api']);
  const after = Object.fromEntries(['worker', 'api', 'temporal', 'postgres', 'executor'].map(service => [service, containerState(service)]));
  for (const service of ['worker', 'api']) assert.notEqual(after[service].startedAt, before[service].startedAt, `${service} process actually restarted`);
  for (const service of ['temporal', 'postgres', 'executor']) {
    assert.equal(after[service].id, before[service].id, `${service} container was preserved`);
    assert.equal(after[service].startedAt, before[service].startedAt, `${service} process was not restarted`);
  }
  passed('worker and API actually restarted; Temporal, PostgreSQL, and executor stayed running');

  await waitFor(async () => (await fetch(api + '/healthz', { signal: AbortSignal.timeout(3000) })).ok, 'API readiness after restart');
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
  if (restarted) {
    try { compose(['start', 'worker', 'api']); }
    catch (cleanupError) { console.error(`Recovery cleanup could not start worker/API: ${cleanupError.message}`); }
  }
  if (execution?.id && token) {
    try {
      await waitFor(async () => (await fetch(api + '/healthz', { signal: AbortSignal.timeout(3000) })).ok, 'cleanup API readiness', 20_000);
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
}
