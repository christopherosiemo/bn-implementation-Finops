import assert from 'node:assert/strict';
import test from 'node:test';
import { assertIncompleteHistory, encodeObservedRequests, fixturePorts, varint } from '../native-smoke.mjs';
test('local smoke cannot select a live/remote target or malformed local port', () => {
  assert.throws(() => fixturePorts({ FIXTURE_MODE: 'false' }));
  assert.throws(() => fixturePorts({ FIXTURE_MODE: 'true', API_PORT: 'http://elsewhere' }));
  assert.throws(() => fixturePorts({ FIXTURE_MODE: 'true', API_PORT: '99999' }));
  assert.deepEqual(fixturePorts({ FIXTURE_MODE: 'true' }), { API_PORT: '8080', KEYCLOAK_PORT: '8081', TELEMETRY_PORT: '8094' });
});
test('OTLP wire encoder preserves exact uint64 and positive cumulative epoch', () => {
  assert.equal(varint(9007199254740993n).toString('hex'), '8180808080808010');
  assert.throws(() => varint(-1)); assert.throws(() => varint(1n << 64n));
  const binding = { account_id: '123456789012', region: 'eu-west-1', provider_resource_id: 'i-0123456789abcdef0', resource_id: 'resource', tenant_id: 'tenant' };
  const raw = encodeObservedRequests({ binding, metric: 'test.requests', epoch: 1000n, at: 2000n, count: 9007199254740993n });
  const expected = Buffer.alloc(8); expected.writeBigUInt64LE(9007199254740993n); assert.ok(raw.includes(expected));
  assert.ok(raw.includes(Buffer.from('finops.tenant.id'))); assert.ok(raw.includes(Buffer.from('i-0123456789abcdef0')));
  assert.throws(() => encodeObservedRequests({ binding, metric: 'test.requests', epoch: 2000n, at: 1000n, count: 1 }));
});
test('retained partial native history stays blocked across a calendar-day boundary', () => {
  const absent = { status: 'BLOCKED', coverage_ppm: 0, unknown_duration_ns: 1209600000000000, observed_samples: 0, p50: null, p90: null, p95: null, p99: null, p999: null, maximum: null, total: null };
  const evaluation = row => ({ status: 'BLOCKED', metrics: [row] });
  assertIncompleteHistory(evaluation(absent));
  assertIncompleteHistory(evaluation({ ...absent, coverage_ppm: 5000, observed_samples: 4, maximum: '0.333333333333', total: '20' }));
  assertIncompleteHistory(evaluation({ ...absent, coverage_ppm: 5000, observed_samples: 4, maximum: '0', total: '0' }));
  assert.throws(() => assertIncompleteHistory(evaluation({ ...absent, maximum: '0' })));
  assert.throws(() => assertIncompleteHistory(evaluation({ ...absent, unknown_duration_ns: 0 })));
  assert.throws(() => assertIncompleteHistory(evaluation({ ...absent, coverage_ppm: 1000000 })));
  assert.throws(() => assertIncompleteHistory({ status: 'READY', metrics: [absent] }));
});
