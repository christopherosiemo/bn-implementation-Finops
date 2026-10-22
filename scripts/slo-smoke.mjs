// Local fixture SLO API/ingress acceptance. No plans or executions are created.
// Run after activity-smoke.mjs, which synchronizes an older local fixture realm.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = Object.fromEntries(readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/)
  .filter(line => line && !line.startsWith('#') && line.includes('='))
  .map(line => { const n = line.indexOf('='); return [line.slice(0, n), line.slice(n + 1)]; }));
assert.equal(env.FIXTURE_MODE, 'true', 'SLO acceptance requires the local fixture environment');
assert.ok(env.DEMO_PASSWORD && env.ACTIVITY_CLIENT_SECRET, 'Ignored .env fixture credentials are required');
for (const key of ['API_PORT', 'KEYCLOAK_PORT', 'ACTIVITY_PORT']) {
  if (env[key]) {
    assert.match(env[key], /^[0-9]{2,5}$/, `${key} must be a local port`);
    assert.ok(Number(env[key]) > 0 && Number(env[key]) <= 65535, `${key} is outside the port range`);
  }
}
// API/OIDC/ingress URL environment overrides are intentionally unsupported.
const api = `http://localhost:${env.API_PORT || 8080}`;
const issuer = `http://localhost:${env.KEYCLOAK_PORT || 8081}/realms/finops`;
const ingress = `http://localhost:${env.ACTIVITY_PORT || 8093}`;
const resourceID = 'resource-dev-api';
const evaluationPath = `/v1/resources/${resourceID}/slo-evaluation`;
const checks = [];
function passed(name) { checks.push(name); console.log(`PASS ${name}`); }

async function request(base, token, method, url, body, options = {}) {
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  let raw;
  if (method === 'POST') {
    headers['content-type'] = 'application/json';
    headers['idempotency-key'] = options.key || randomUUID();
    raw = typeof body === 'string' ? body : JSON.stringify(body);
  }
  if (options.version !== undefined) headers['if-match'] = `"${options.version}"`;
  const response = await fetch(base + url, { method, headers, body: raw, redirect: 'error', signal: AbortSignal.timeout(15_000) });
  assert.equal(response.status, options.status ?? 200, `${method} ${url} returned HTTP ${response.status}; response body not logged`);
  return response.json();
}

async function login(body, tenant) {
  const response = await fetch(issuer + '/protocol/openid-connect/token', {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body),
  });
  assert.equal(response.status, 200, 'Fixture OIDC login failed; run activity-smoke first for older local volumes');
  const { access_token: token } = await response.json();
  assert.ok(typeof token === 'string' && token.length > 0, 'Fixture OIDC did not return an access token');
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(claims.tenant_id, tenant, 'Unexpected fixture token tenant');
  assert.ok(claims.sub, 'Fixture identity needs a machine/user subject');
  return { token, claims };
}

const health = await request(api, null, 'GET', '/healthz');
assert.equal(health.fixture, true, 'Refusing to run outside fixture mode');
assert.equal(health.role, 'api');
assert.equal((await request(ingress, null, 'GET', '/healthz')).role, 'activity-ingress');
passed('local fixture API and dedicated ingress are healthy');

const owner = await login({ grant_type: 'password', client_id: 'console', username: env.DEMO_USERNAME || 'owner', password: env.DEMO_PASSWORD }, 'tenant-demo');
const other = await login({ grant_type: 'password', client_id: 'console', username: 'other', password: env.DEMO_PASSWORD }, 'tenant-other');
const machine = await login({ grant_type: 'client_credentials', client_id: 'activity-collector', client_secret: env.ACTIVITY_CLIENT_SECRET }, 'tenant-demo');
assert.ok([machine.claims.aud].flat().includes('finops-activity'), 'Dedicated machine audience required');
assert.ok(![machine.claims.aud].flat().includes('finops'), 'Machine identity must not carry the control-plane audience');
const dashboard = await request(api, owner.token, 'GET', '/v1/dashboard');
assert.equal(dashboard.fixture, true);
const resource = dashboard.resources.find(item => item.id === resourceID);
assert.ok(resource?.workload_id, 'Existing fixture resource/workload mapping required');
passed('human registration and machine observation identities stay separated');

const objectivePath = `/v1/workloads/${encodeURIComponent(resource.workload_id)}/slo-objectives`;
const initial = await request(api, owner.token, 'GET', objectivePath);
assert.ok(Number.isInteger(initial.version) && initial.version >= 0);
// Current observations occur outside this explicitly configured fixture window.
const closedDay = (new Date().getUTCDay() + 3) % 7;
const policy = {
  schema_version: '1',
  limits: { max_error_rate_ppm: 10_000, min_availability_ppm: 990_000, max_p95_latency_ms: 180, max_p99_latency_ms: 250, min_latency_samples: 100 },
  evaluation_minutes: 2,
  availability: { mode: 'WINDOWS', timezone: 'UTC', windows: [{ days: [closedDay], start_time: '09:00', end_time: '17:00' }] },
  regression: { enabled: false, max_percent: 15 },
};
const objective = await request(api, owner.token, 'POST', objectivePath, policy, { version: initial.version, status: 201 });
assert.equal(objective.version, initial.version + 1);
assert.ok(objective.id && objective.hash);
assert.equal((await request(api, owner.token, 'GET', objectivePath)).latest.id, objective.id);
passed('objective CAS appends the first or next immutable policy version');

const missingSource = await request(api, owner.token, 'GET', evaluationPath);
assert.equal(missingSource.evaluation.status, 'BLOCKED');
assert.ok(missingSource.evaluation.reason_codes.includes('SLO_SOURCE_REQUIRED'));
passed('an objective without a registered source remains blocked');

const source = await request(api, owner.token, 'POST', '/v1/slo-sources', { objective_id: objective.id, resource_id: resourceID, subject: machine.claims.sub }, { status: 201 });
assert.equal(source.objective_id, objective.id);
assert.equal(source.subject, machine.claims.sub);
assert.equal(source.tenant_id, 'tenant-demo');
for (const field of ['provider_resource_id', 'account_id', 'region', 'workload_id']) assert.equal(source[field], resource[field]);
passed('source registration binds the actual resource and machine subject');

const empty = await request(api, owner.token, 'GET', evaluationPath);
assert.equal(empty.evaluation.status, 'BLOCKED');
assert.ok(empty.evaluation.reason_codes.includes('SLO_COVERAGE_GAP'));
assert.equal(empty.evaluation.observed_intervals, 0);
passed('missing minute observations cannot become healthy zero demand');

assert.ok(!(await request(api, other.token, 'GET', '/v1/slo-sources')).some(item => item.id === source.id));
const otherEvaluation = await request(api, other.token, 'GET', evaluationPath);
assert.notEqual(otherEvaluation.objective?.id, objective.id);
assert.notEqual(otherEvaluation.source?.id, source.id);
passed('another tenant cannot read this source or evaluation authority');

await request(api, machine.token, 'GET', '/v1/dashboard', undefined, { status: 401 });
await request(ingress, null, 'POST', '/v1/slo/intervals', {}, { status: 401 });
await request(ingress, owner.token, 'POST', '/v1/slo/intervals', {}, { status: 401 });
passed('machine/control-plane and console/observation audiences cannot substitute');

const minute = 60_000;
// Leave enough time to submit and inspect a complete current evaluation window.
if (Date.now() % minute > 45_000) await new Promise(resolve => setTimeout(resolve, minute - Date.now() % minute + 100));
const end = Math.floor(Date.now() / minute) * minute;
function interval(right) {
  return {
    schema_version: '1', source_id: source.id, objective_id: objective.id, workload_id: resource.workload_id, resource_id: resourceID,
    sequence: right / minute, interval_start: new Date(right - minute).toISOString(), interval_end: new Date(right).toISOString(),
    request_count: 0, error_count: 0, availability_good_seconds: 0, availability_total_seconds: 60,
    latency: { unit: 'milliseconds', sample_count: 0, buckets: [{ upper_bound_ms: 180, count: 0 }, { upper_bound_ms: null, count: 0 }] },
  };
}
const probe = interval(end);
const unknown = await request(ingress, machine.token, 'POST', '/v1/slo/intervals', { ...probe, source_id: `missing-${randomUUID()}` }, { status: 403 });
assert.equal(unknown.reason_code, 'SLO_SOURCE_NOT_AUTHORIZED');
const mismatch = await request(ingress, machine.token, 'POST', '/v1/slo/intervals', { ...probe, workload_id: 'unregistered-workload' }, { status: 403 });
assert.equal(mismatch.reason_code, 'SLO_SOURCE_NOT_AUTHORIZED');
passed('unknown sources and mismatched resource/workload bindings are rejected');

const receipts = [];
let latest;
for (const right of [end - minute, end]) {
  const body = JSON.stringify(interval(right));
  const key = createHash('sha256').update(body).digest('hex');
  const accepted = await request(ingress, machine.token, 'POST', '/v1/slo/intervals', body, { key, status: 201 });
  assert.equal(accepted.replayed, false);
  assert.equal(accepted.receipt.writer_role, 'finops_activity');
  assert.equal(accepted.receipt.binding.tenant_id, 'tenant-demo');
  assert.equal(accepted.receipt.binding.resource_id, resourceID);
  assert.ok(accepted.receipt.id && accepted.receipt.body_sha256);
  receipts.push(accepted.receipt.id);
  latest = { body, key, receipt: accepted.receipt };
}
passed('two complete current minutes persist as immutable machine receipts');

const replay = await request(ingress, machine.token, 'POST', '/v1/slo/intervals', latest.body, { key: latest.key });
assert.equal(replay.replayed, true);
assert.equal(replay.receipt.id, latest.receipt.id);
passed('exact observation replay returns the existing receipt');

const changed = JSON.parse(latest.body);
changed.request_count = 1; changed.latency.sample_count = 1; changed.latency.buckets[0].count = 1;
const conflict = await request(ingress, machine.token, 'POST', '/v1/slo/intervals', changed, { key: latest.key, status: 409 });
assert.equal(conflict.reason_code, 'SLO_REPLAY_OR_WINDOW_CONFLICT');
passed('changed observation content cannot reuse receipt identity');

const current = await request(api, owner.token, 'GET', evaluationPath);
assert.equal(current.evaluation.status, 'CLEAR');
assert.equal(current.evaluation.coverage_ppm, 1_000_000);
assert.equal(current.evaluation.observed_intervals, 2);
assert.equal(current.evaluation.latency_status, 'NO_DEMAND');
assert.equal(current.evaluation.p95_latency_ms, null);
assert.equal(current.evaluation.p99_latency_ms, null);
assert.equal(current.evaluation.error_rate_ppm, null);
assert.equal(current.evaluation.availability_ppm, null);
assert.deepEqual([...current.evaluation.receipt_ids].sort(), [...receipts].sort());
passed('closed-window no-demand evaluates CLEAR without invented percentiles or availability');

const always = await request(api, owner.token, 'POST', objectivePath, { ...policy, availability: { mode: 'ALWAYS', timezone: 'UTC', windows: [] } }, { version: objective.version, status: 201 });
assert.equal(always.version, objective.version + 1);
assert.notEqual(always.id, objective.id);
const superseded = await request(api, owner.token, 'GET', evaluationPath);
assert.equal(superseded.objective.id, always.id);
assert.equal(superseded.source, null);
assert.equal(superseded.evaluation.status, 'BLOCKED');
assert.ok(superseded.evaluation.reason_codes.includes('SLO_SOURCE_REQUIRED'));
passed('policy revision invalidates the old source and current evaluation authority');

const relabelled = await request(ingress, machine.token, 'POST', '/v1/slo/intervals', { ...probe, objective_id: always.id }, { status: 403 });
assert.equal(relabelled.reason_code, 'SLO_SOURCE_NOT_AUTHORIZED');
passed('old machine receipts cannot be relabelled to authorize a new objective');

console.log(`PASS trusted SLO fixture API/ingress acceptance (${checks.length} checks). No reset, plan, approval or execution was created; retained schema-2 fixture flow is unchanged.`);
