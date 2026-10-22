import test from 'node:test';
import assert from 'node:assert/strict';
import { buildInterval } from '../activity-collector.mjs';

const config = { source_id: 'registered-gateway', resource_id: 'resource-dev', workload_id: 'workload-dev', metric_definition: { id: 'requests', version: '1', unit: 'request' } };
const sample = { interval_start: '2026-10-18T12:00:00Z', interval_end: '2026-10-18T12:01:00Z', accepted: 3, completed: 2, rejected: 0, backlog: 0, inflight: 1, heartbeat: true, incident: 'CLEAR', deployment: 'CLEAR', job: 'CLEAR' };
const now = new Date('2026-10-18T12:01:20Z');
test('collector preserves independent demand and registered metric semantics', () => {
  const interval = buildInterval(sample, config, 2, now);
  assert.equal(interval.accepted, 3); assert.equal(interval.completed, 2); assert.equal(interval.inflight, 1);
  assert.deepEqual(interval.metric_definition, config.metric_definition); assert.equal(interval.sequence, 2);
});
test('collector never manufactures zero from missing or unavailable observations', () => {
  for (const key of ['accepted', 'completed', 'rejected', 'backlog', 'inflight', 'heartbeat', 'incident', 'deployment', 'job']) {
    const missing = { ...sample }; delete missing[key]; assert.throws(() => buildInterval(missing, config, 1, now));
  }
  assert.throws(() => buildInterval({ ...sample, accepted: null }, config, 1, now));
  assert.throws(() => buildInterval({ ...sample, accepted: -1 }, config, 1, now));
  assert.throws(() => buildInterval({ ...sample, accepted: 0.5 }, config, 1, now));
});
test('collector refuses historical backfill and incomplete intervals', () => {
  assert.throws(() => buildInterval(sample, config, 1, new Date('2026-10-18T12:05:00Z')));
  assert.throws(() => buildInterval(sample, config, 1, new Date('2026-10-18T12:00:59Z')));
  assert.throws(() => buildInterval({ ...sample, interval_start: '2026-10-18T12:00:01Z' }, config, 1, now));
});
