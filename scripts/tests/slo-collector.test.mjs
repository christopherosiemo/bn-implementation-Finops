import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildSLOInterval } from '../slo-collector.mjs';
import { collectorConfiguration, run } from '../activity-collector.mjs';

const instant = Date.parse('2026-10-18T12:01:20Z');
const config = { source_id: 'registered-source', resource_id: 'resource', workload_id: 'workload', objective_id: 'objective' };
const sample = {
  interval_start: '2026-10-18T12:00:00Z', interval_end: '2026-10-18T12:01:00Z', request_count: 3, error_count: 1,
  availability_good_seconds: 59, availability_total_seconds: 60,
  latency: { unit: 'milliseconds', sample_count: 3, buckets: [{ upper_bound_ms: 180, count: 3 }, { upper_bound_ms: null, count: 0 }] },
};
const build = (value = sample, binding = config, sequence = 1, now = instant) => buildSLOInterval(value, binding, sequence, new Date(now));

test('SLO collector preserves observed counts, disjoint histogram and registered identity', () => {
  const result = build();
  for (const key of ['source_id', 'resource_id', 'workload_id', 'objective_id']) assert.equal(result[key], config[key]);
  for (const key of ['request_count', 'error_count', 'availability_good_seconds', 'availability_total_seconds', 'latency']) assert.deepEqual(result[key], sample[key]);
  assert.equal(result.schema_version, '1'); assert.equal(result.sequence, 1);
  result.latency.buckets[0].count = 0;
  assert.equal(sample.latency.buckets[0].count, 3, 'the persisted interval must not alias caller histogram memory');
});
test('SLO collector preserves explicitly observed zero without inferring health', () => {
  const value = structuredClone(sample);
  value.request_count = value.error_count = value.latency.sample_count = 0;
  value.latency.buckets[0].count = 0;
  const result = build(value);
  assert.equal(result.request_count, 0); assert.equal(result.latency.sample_count, 0);
  assert.ok(!Object.hasOwn(result, 'status') && !Object.hasOwn(result, 'p95_latency_ms'));
});
test('SLO collector rejects every absent observation or histogram field', () => {
  for (const key of Object.keys(sample)) { const value = structuredClone(sample); delete value[key]; assert.throws(() => build(value)); }
  for (const key of Object.keys(sample.latency)) { const value = structuredClone(sample); delete value.latency[key]; assert.throws(() => build(value)); }
  assert.throws(() => build(null)); assert.throws(() => build([]));
});
test('SLO collector rejects invalid counts and mismatched denominators', () => {
  for (const key of ['request_count', 'error_count', 'availability_good_seconds', 'availability_total_seconds']) {
    for (const invalid of [null, -1, 0.5, '0', Number.NaN, 1_000_000_000_001]) assert.throws(() => build({ ...sample, [key]: invalid }));
  }
  for (const mutate of [v => { v.error_count = 4; }, v => { v.availability_total_seconds = 59; }, v => { v.availability_good_seconds = 61; }, v => { v.latency.sample_count = 2; }]) {
    const value = structuredClone(sample); mutate(value); assert.throws(() => build(value));
  }
});
test('SLO collector rejects stale, incomplete, future or non-UTC minutes', () => {
  assert.throws(() => build(sample, config, 1, instant + 180_000));
  assert.throws(() => build(sample, config, 1, instant - 30_000));
  assert.throws(() => build({ ...sample, interval_start: '2026-10-18T12:00:01Z' }));
  assert.throws(() => build({ ...sample, interval_end: 'invalid' }));
  assert.throws(() => build({ ...sample, interval_start: '2026-10-18T13:00:00+01:00', interval_end: '2026-10-18T13:01:00+01:00' }));
});
test('SLO collector rejects cumulative or malformed histogram representations', () => {
  for (const mutate of [
    v => { v.latency.unit = 'seconds'; }, v => { v.latency.buckets = []; },
    v => { v.latency.buckets.pop(); }, v => { v.latency.buckets.reverse(); },
    v => { v.latency.buckets = [{ upper_bound_ms: 180, count: 2 }, { upper_bound_ms: 170, count: 1 }, { upper_bound_ms: null, count: 0 }]; },
    v => { v.latency.buckets[1].count = 3; }, v => { delete v.latency.buckets[0].count; },
    v => { v.latency.buckets[0].upper_bound_ms = 0.5; }, v => { v.latency.buckets[0].upper_bound_ms = 86_400_001; },
  ]) { const value = structuredClone(sample); mutate(value); assert.throws(() => build(value)); }
});
test('SLO collector never accepts supplied percentiles or authority fields', () => {
  for (const key of ['p95_latency_ms', 'p99_latency_ms', 'source_id', 'objective_id', 'status']) assert.throws(() => build({ ...sample, [key]: 1 }));
  const value = structuredClone(sample); value.latency.p95_latency_ms = 120;
  assert.throws(() => build(value));
});
test('SLO collector requires all configured bindings and a monotonic sequence value', () => {
  for (const key of Object.keys(config)) { const value = { ...config }; delete value[key]; assert.throws(() => build(sample, value)); }
  for (const invalid of [0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => build(sample, config, invalid));
});

async function fixture(t, kind = 'slo') {
  const parent = await realpath(tmpdir());
  const prefix = 'finops-slo-collector-';
  const directory = await realpath(await mkdtemp(path.join(parent, prefix)));
  t.after(async () => {
    assert.equal(path.dirname(directory), parent, 'cleanup must stay inside the owned temporary parent');
    assert.ok(path.basename(directory).startsWith(prefix));
    await rm(directory, { recursive: true, force: true });
  });
  const secretFile = path.join(directory, 'client-secret');
  await writeFile(secretFile, 'fixture-client-only', { mode: 0o600 });
  const env = {
    ACTIVITY_OBSERVATION_KIND: kind, ACTIVITY_SLO_OBJECTIVE_ID: config.objective_id,
    ACTIVITY_SOURCE_ID: config.source_id, ACTIVITY_RESOURCE_ID: config.resource_id, ACTIVITY_WORKLOAD_ID: config.workload_id,
    ACTIVITY_METRIC_ID: 'requests', ACTIVITY_METRIC_VERSION: '1', ACTIVITY_METRIC_UNIT: 'request',
    ACTIVITY_OBSERVATION_URL: 'https://observer.example.invalid/closed-minute',
    ACTIVITY_INGRESS_URL: `https://ingress.example.invalid/v1/${kind}/intervals`, ACTIVITY_OIDC_ISSUER: 'https://identity.example.invalid/realms/fixture',
    ACTIVITY_CLIENT_ID: 'fixture-collector', ACTIVITY_CLIENT_SECRET_FILE: secretFile, ACTIVITY_STATE_FILE: path.join(directory, 'state.json'), ACTIVITY_ONCE: 'true',
  };
  const f = { env, calls: [], logs: [], errors: [], observation: structuredClone(sample), posts: [], tokens: 0, observed: 0, status: 201 };
  f.fetchImpl = async (url, options) => {
    f.calls.push({ url: url.href, ...options });
    assert.equal(options.redirect, 'error');
    let value;
    if (url.pathname.endsWith('/.well-known/openid-configuration')) value = { token_endpoint: 'https://identity.example.invalid/token' };
    else if (url.pathname === '/token') { f.tokens++; value = { access_token: `fixture-token-${f.tokens}`, expires_in: 3600 }; }
    else if (url.pathname === '/closed-minute') { f.observed++; value = f.observation; }
    else if (url.pathname.endsWith('/intervals')) {
      const state = JSON.parse(await readFile(env.ACTIVITY_STATE_FILE, 'utf8'));
      assert.equal(state.pending.body, options.body, 'bytes must be durable before dispatch');
      assert.equal(state.pending.key, options.headers['idempotency-key']);
      f.posts.push({ body: options.body, key: options.headers['idempotency-key'], authorization: options.headers.authorization });
      const status = typeof f.status === 'function' ? f.status() : f.status;
      return { ok: status >= 200 && status < 300, status, json: async () => ({ receipt: { id: 'receipt-test' }, replayed: status === 200 }) };
    } else throw new Error('Unexpected fixture transport URL');
    return { ok: true, status: 200, json: async () => structuredClone(value) };
  };
  f.run = () => run({ env, fetchImpl: f.fetchImpl, now: () => instant, sleep: async () => {}, log: value => f.logs.push(value), logError: value => f.errors.push(value) });
  return f;
}

test('collector SLO mode uses existing OIDC transport and persists bound receipt bytes', async t => {
  const f = await fixture(t); await f.run();
  assert.equal(f.tokens, 1); assert.equal(f.posts.length, 1);
  const sent = JSON.parse(f.posts[0].body);
  assert.equal(sent.objective_id, config.objective_id); assert.deepEqual(sent.latency, sample.latency);
  const state = JSON.parse(await readFile(f.env.ACTIVITY_STATE_FILE, 'utf8'));
  assert.equal(JSON.parse(state.source_binding).observation_kind, 'slo');
  assert.equal(JSON.parse(state.source_binding).objective_id, config.objective_id);
  assert.equal(state.sequence, 1); assert.ok(!state.pending);
  assert.equal(JSON.parse(f.logs[0]).event, 'slo_receipted');
  assert.ok(!f.logs.concat(f.errors).join('').includes('fixture-client-only'));
  assert.ok(!f.logs.concat(f.errors).join('').includes('fixture-token-'));
});
test('collector retries an uncertain SLO response with identical persisted bytes and key', async t => {
  const f = await fixture(t); f.status = 503; await f.run();
  assert.ok(JSON.parse(await readFile(f.env.ACTIVITY_STATE_FILE, 'utf8')).pending);
  f.status = 200; await f.run();
  assert.equal(f.observed, 1, 'pending replay must not request a different observation');
  assert.equal(f.posts.length, 2); assert.equal(f.posts[0].body, f.posts[1].body); assert.equal(f.posts[0].key, f.posts[1].key);
  assert.equal(JSON.parse(f.logs[0]).replayed, true);
});
test('collector refreshes a rejected SLO token without changing pending observation bytes', async t => {
  const f = await fixture(t); f.env.ACTIVITY_ONCE = 'false';
  f.status = () => { if (f.posts.length === 1) return 401; f.env.ACTIVITY_ONCE = 'true'; return 201; };
  await f.run();
  assert.equal(f.tokens, 2); assert.equal(f.observed, 1); assert.equal(f.posts.length, 2);
  assert.equal(f.posts[0].body, f.posts[1].body); assert.equal(f.posts[0].key, f.posts[1].key);
  assert.notEqual(f.posts[0].authorization, f.posts[1].authorization);
});
test('collector durable state cannot cross SLO objective or observation kind', async t => {
  const f = await fixture(t); f.status = 503; await f.run();
  f.env.ACTIVITY_SLO_OBJECTIVE_ID = 'another-objective';
  await assert.rejects(f.run(), /different observation kind, objective or registered source/);
  f.env.ACTIVITY_OBSERVATION_KIND = 'activity';
  await assert.rejects(f.run(), /different observation kind, objective or registered source/);
  assert.equal(f.posts.length, 1);
});
test('default activity mode preserves exact legacy source binding and pending bytes', async t => {
  const f = await fixture(t, 'activity'); delete f.env.ACTIVITY_OBSERVATION_KIND;
  f.observation = { interval_start: sample.interval_start, interval_end: sample.interval_end, accepted: 3, completed: 2, rejected: 0, backlog: 0, inflight: 1, heartbeat: true, incident: 'CLEAR', deployment: 'CLEAR', job: 'CLEAR' };
  f.status = 503; await f.run();
  const state = JSON.parse(await readFile(f.env.ACTIVITY_STATE_FILE, 'utf8'));
  const legacyBinding = JSON.stringify(collectorConfiguration(f.env).config);
  assert.equal(state.source_binding, legacyBinding);
  f.status = 200; await f.run();
  const sent = JSON.parse(f.posts[1].body);
  assert.equal(sent.accepted, 3); assert.equal(sent.completed, 2); assert.equal(sent.metric_definition.unit, 'request');
  assert.ok(!Object.hasOwn(sent, 'objective_id') && !Object.hasOwn(sent, 'latency'));
  assert.equal(f.posts[0].body, f.posts[1].body); assert.equal(f.posts[0].key, f.posts[1].key);
  assert.equal(JSON.parse(await readFile(f.env.ACTIVITY_STATE_FILE, 'utf8')).source_binding, legacyBinding);
  assert.equal(JSON.parse(f.logs[0]).event, 'activity_receipted');
});
test('collector malformed SLO telemetry never obtains a token or submits a receipt', async t => {
  const f = await fixture(t); delete f.observation.request_count; await f.run();
  assert.equal(f.tokens, 0); assert.equal(f.posts.length, 0); assert.equal(f.errors.length, 1);
});
test('collector rejects unselected modes, missing objective and unbound nonempty state', async t => {
  const f = await fixture(t); delete f.env.ACTIVITY_SLO_OBJECTIVE_ID;
  await assert.rejects(f.run(), /configuration required/); assert.equal(f.calls.length, 0);
  f.env.ACTIVITY_OBSERVATION_KIND = 'unknown'; await assert.rejects(f.run(), /must be activity or slo/);
  f.env.ACTIVITY_OBSERVATION_KIND = 'slo'; f.env.ACTIVITY_SLO_OBJECTIVE_ID = config.objective_id;
  await writeFile(f.env.ACTIVITY_STATE_FILE, JSON.stringify({ sequence: 1, pending: { body: '{}', key: 'other' } }));
  await assert.rejects(f.run(), /no registered source binding/); assert.equal(f.posts.length, 0);
});
