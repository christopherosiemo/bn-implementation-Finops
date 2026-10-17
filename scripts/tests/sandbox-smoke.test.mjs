import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runSandboxSmoke } from '../sandbox-smoke.mjs';
const instant = Date.parse('2026-10-17T12:00:00Z');
function fixture() {
  const iso = offset => new Date(instant + offset).toISOString();
  const env = { FINOPS_API_URL: 'https://sandbox.example.invalid', FINOPS_API_TOKEN: 'h.' + Buffer.from(JSON.stringify({ exp: instant / 1000 + 7200 })).toString('base64url') + '.s', FINOPS_SANDBOX_TENANT_ID: 'tenant-test', FINOPS_SANDBOX_ACCOUNT_ID: '111122223333', FINOPS_SANDBOX_REGION: 'eu-west-1', FINOPS_SANDBOX_INSTANCE_ID: 'i-0123456789abcdef0', FINOPS_APPROVED_PLAN_ID: 'plan-test', FINOPS_LIVE_ACK: 'STOP_AND_RESTORE_THIS_SANDBOX_INSTANCE' };
  const resource = { id: 'resource-test', provider: 'AWS', provider_resource_id: env.FINOPS_SANDBOX_INSTANCE_ID, account_id: env.FINOPS_SANDBOX_ACCOUNT_ID, region: env.FINOPS_SANDBOX_REGION, workload_id: 'workload-test', environment: 'NON_PRODUCTION', runtime_stop_start_delegated: true, commitment_known: true, uncovered_on_demand: true };
  const workload = { id: 'workload-test', environment: 'NON_PRODUCTION', incident: 'CLEAR', deployment: 'CLEAR', job: 'CLEAR', signals_at: iso(-1000) };
  const rec = { id: 'rec-test', resource_id: resource.id, workload_id: workload.id, pre_execution_ready: true };
  const dashboard = { fixture: false, org: { id: env.FINOPS_SANDBOX_TENANT_ID }, resources: [resource], workloads: [workload], recommendations: [rec] };
  const readiness = { id: 'ready-test', status: 'READY', pre_execution_ready: true, checked_at: iso(-1000), expires_at: iso(240_000), baseline_id: 'baseline-test', measurement_id: 'measurement-test', activation_at: iso(-500), binding: { tenant_id: env.FINOPS_SANDBOX_TENANT_ID, resource_id: resource.id, provider_resource_id: resource.provider_resource_id, account_id: resource.account_id, region: resource.region } };
  const op = { resource_id: resource.id, provider_resource_id: resource.provider_resource_id, account_id: resource.account_id, region: resource.region };
  const schedule = { id: 'schedule-test', workload_id: workload.id, paused: false, version: 7 };
  const plan = { id: env.FINOPS_APPROVED_PLAN_ID, version: 2, status: 'APPROVED', fixture: false, schedule_id: schedule.id, resource_id: resource.id, workload_id: workload.id, recommendation_id: rec.id, payload: { id: env.FINOPS_APPROVED_PLAN_ID, schema_version: '2', tenant_id: env.FINOPS_SANDBOX_TENANT_ID, fixture: false, schedule_id: schedule.id, workload_id: workload.id, recommendation_id: rec.id, readiness_id: readiness.id, baseline_id: readiness.baseline_id, measurement_id: readiness.measurement_id, activation_at: readiness.activation_at, stop_at: iso(0), restore_at: iso(3_600_000), expires_at: iso(900_000), operations: [{ ...op, type: 'EC2_STOP' }, { ...op, type: 'EC2_START' }] } };
  const calls = []; let polls = 0;
  const fetchImpl = async (url, options) => {
    calls.push({ path: url.pathname, ...options }); let body;
    if (url.pathname === '/v1/dashboard') body = dashboard;
    else if (url.pathname === '/v1/change-plans/plan-test') body = plan;
    else if (url.pathname === '/v1/resources/resource-test/readiness') body = readiness;
    else if (url.pathname === '/v1/executions' && options.method === 'POST') body = { id: 'execution-test' };
    else if (url.pathname.endsWith('/start-now')) body = {};
    else if (url.pathname === '/v1/executions/execution-test') body = { id: 'execution-test', change_plan_id: plan.id, version: 1, status: polls++ ? 'COMPLETED' : 'RUNNING', stage: 'STOPPED', restoration_owned: polls === 1 };
    else if (url.pathname === '/v1/schedules/schedule-test' && options.method === 'GET') body = schedule;
    else if (url.pathname === '/v1/schedules/schedule-test/pause' && options.method === 'POST') {
      assert.ok(polls >= 2, 'schedule pause must follow completed restoration');
      assert.equal(options.headers['If-Match'], '"7"'); assert.deepEqual(JSON.parse(options.body), { paused: true });
      schedule.paused = true; schedule.version++; body = schedule;
    }
    else throw new Error('Unexpected mock route');
    return { ok: true, status: 200, json: async () => structuredClone(body) };
  };
  return { env, resource, workload, rec, dashboard, readiness, plan, schedule, calls, fetchImpl, now: () => instant, sleep: async () => {}, log: () => {} };
}
test('default inspection: one GET, no workload/economics/execution prerequisites', async () => {
  const f = fixture(); delete f.env.FINOPS_LIVE_ACK; delete f.env.FINOPS_APPROVED_PLAN_ID; f.dashboard.workloads = []; f.dashboard.recommendations = []; delete f.resource.workload_id; delete f.resource.commitment_known;
  assert.equal((await runSandboxSmoke({ ...f, args: [] })).mode, 'inspection'); assert.equal(f.calls.length, 1); assert.ok(f.calls.every(c => c.method === 'GET'));
});
test('explicit execution: approved plan, owned restoration, then confirmed schedule pause', async () => {
  const f = fixture(); const result = await runSandboxSmoke({ ...f, args: ['--execute'] }); assert.equal(result.executionId, 'execution-test'); assert.equal(result.schedulePaused, true); assert.equal(f.schedule.paused, true);
  const writes = f.calls.filter(c => c.method === 'POST'); assert.deepEqual(writes.map(c => c.path), ['/v1/executions', '/v1/executions/execution-test/start-now', '/v1/schedules/schedule-test/pause']);
  assert.equal(writes[0].headers['If-Match'], '"2"'); assert.ok(writes.every(c => c.headers['Idempotency-Key'])); assert.ok(f.calls.every(c => c.redirect === 'error'));
});
for (const [name, mutate] of [
  ['wrong tenant', f => { f.dashboard.org.id = 'other'; }], ['wrong account', f => { f.resource.account_id = '999988887777'; }],
  ['wrong region', f => { f.resource.region = 'us-east-1'; }], ['wrong instance', f => { f.resource.provider_resource_id = 'i-aaaaaaaaaaaaaaaaa'; }],
  ['fixture mode', f => { f.dashboard.fixture = true; }], ['missing acknowledgement', f => { delete f.env.FINOPS_LIVE_ACK; }],
  ['unapproved plan', f => { f.plan.status = 'AWAITING_APPROVAL'; }], ['wrong signed tenant', f => { f.plan.payload.tenant_id = 'other'; }],
  ['legacy plan', f => { delete f.plan.payload.schema_version; }], ['extra operation', f => { f.plan.payload.operations.push(f.plan.payload.operations[0]); }],
  ['missing signed schedule', f => { delete f.plan.payload.schedule_id; }], ['mismatched signed schedule', f => { f.plan.payload.schedule_id = 'other'; }],
  ['wrong signed target', f => { f.plan.payload.operations[1].account_id = '999988887777'; }], ['not-ready recommendation', f => { f.rec.pre_execution_ready = false; }],
  ['active incident', f => { f.workload.incident = 'ACTIVE'; }], ['stale signals', f => { f.workload.signals_at = new Date(instant - 360_000).toISOString(); }],
  ['blocked readiness', f => { f.readiness.pre_execution_ready = false; }], ['stale readiness', f => { f.readiness.checked_at = new Date(instant - 360_000).toISOString(); }],
  ['expired readiness', f => { f.readiness.expires_at = new Date(instant - 1).toISOString(); }], ['readiness target mismatch', f => { f.readiness.binding.provider_resource_id = 'i-aaaaaaaaaaaaaaaaa'; }],
  ['measurement mismatch', f => { f.readiness.measurement_id = 'other'; }], ['missing readiness identity', f => { delete f.plan.payload.readiness_id; }],
  ['short-lived token', f => { f.env.FINOPS_API_TOKEN = 'h.' + Buffer.from(JSON.stringify({ exp: instant / 1000 + 1200 })).toString('base64url') + '.s'; }],
  ['insecure API URL', f => { f.env.FINOPS_API_URL = 'http://public.example.invalid'; }]
]) test(`fails before POST: ${name}`, async () => { const f = fixture(); mutate(f); await assert.rejects(runSandboxSmoke({ ...f, args: ['--execute'] })); assert.ok(f.calls.every(c => c.method === 'GET')); });
test('HTTP failure never logs bearer token or response body', async () => {
  const f = fixture(); const logs = []; f.log = value => logs.push(value); f.fetchImpl = async () => ({ ok: false, status: 401, json: async () => ({ secret: f.env.FINOPS_API_TOKEN }) });
  await assert.rejects(runSandboxSmoke({ ...f, args: [] }), e => !e.message.includes(f.env.FINOPS_API_TOKEN)); assert.ok(!logs.join('').includes(f.env.FINOPS_API_TOKEN));
});
test('real local mock API receives one authenticated inspection GET', async () => {
  const f = fixture(); const methods = [];
  const server = createServer((request, response) => {
    methods.push(request.method);
    assert.equal(request.url, '/v1/dashboard'); assert.equal(request.headers.authorization, `Bearer ${f.env.FINOPS_API_TOKEN}`);
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(f.dashboard));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    f.env.FINOPS_API_URL = `http://127.0.0.1:${server.address().port}`;
    await runSandboxSmoke({ ...f, fetchImpl: fetch, args: [] }); assert.deepEqual(methods, ['GET']);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
test('timeout preserves execution ID and never starts an unowned instance', async () => {
  const f = fixture(); const original = f.fetchImpl; let clock = instant;
  f.now = () => clock; f.sleep = async () => { clock += 600_000; };
  f.fetchImpl = async (url, options) => url.pathname === '/v1/executions/execution-test'
    ? { ok: true, json: async () => ({ id: 'execution-test', change_plan_id: f.plan.id, status: 'RUNNING', stage: 'PRECHECK', restoration_owned: false }) }
    : original(url, options);
  await assert.rejects(runSandboxSmoke({ ...f, args: ['--execute'] }), /execution-test timed out/);
  assert.ok(!f.calls.some(call => call.path.endsWith('/start-now')));
  assert.ok(!f.calls.some(call => call.path.endsWith('/pause')));
});
test('already completed durable restoration does not receive a redundant start request', async () => {
  const f = fixture(); const original = f.fetchImpl;
  f.fetchImpl = async (url, options) => url.pathname === '/v1/executions/execution-test'
    ? { ok: true, json: async () => ({ id: 'execution-test', change_plan_id: f.plan.id, status: 'COMPLETED', stage: 'STOPPED', restoration_owned: false }) }
    : original(url, options);
  // An operator may already have paused this schedule during restoration.
  f.schedule.paused = true;
  assert.equal((await runSandboxSmoke({ ...f, args: ['--execute'] })).executionId, 'execution-test');
  assert.ok(!f.calls.some(call => call.path.endsWith('/start-now')));
  assert.ok(!f.calls.some(call => call.path.endsWith('/pause')));
});
test('restored execution cannot report acceptance if schedule pause conflicts', async () => {
  const f = fixture(); const original = f.fetchImpl;
  f.fetchImpl = async (url, options) => url.pathname.endsWith('/pause') ? { ok: false, status: 409 } : original(url, options);
  await assert.rejects(runSandboxSmoke({ ...f, args: ['--execute'] }), /execution-test restored, but schedule schedule-test pause is not confirmed/);
  assert.equal(f.schedule.paused, false);
});
test('schedule with a different workload is never paused', async () => {
  const f = fixture(); f.schedule.workload_id = 'other';
  await assert.rejects(runSandboxSmoke({ ...f, args: ['--execute'] }), /Schedule no longer matches/);
  assert.ok(!f.calls.some(call => call.path.endsWith('/pause')));
});
test('real local mock API confirms one canary then schedule pause with fresh version', async () => {
  const f = fixture();
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.headers.authorization, `Bearer ${f.env.FINOPS_API_TOKEN}`);
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      const headers = { ...request.headers, 'If-Match': request.headers['if-match'] };
      const result = await f.fetchImpl(new URL(request.url, f.env.FINOPS_API_URL), { method: request.method, headers, body: chunks.length ? Buffer.concat(chunks).toString() : undefined });
      response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(await result.json()));
    } catch { response.statusCode = 500; response.end('{}'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    f.env.FINOPS_API_URL = `http://127.0.0.1:${server.address().port}`;
    const result = await runSandboxSmoke({ ...f, fetchImpl: fetch, args: ['--execute'] });
    assert.equal(result.schedulePaused, true); assert.equal(f.schedule.paused, true);
    assert.equal(f.calls.filter(call => call.path === '/v1/schedules/schedule-test' && call.method === 'GET').length, 2);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
