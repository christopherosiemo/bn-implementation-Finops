import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeObservedRequests, fixturePorts, varint } from '../native-smoke.mjs';
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
