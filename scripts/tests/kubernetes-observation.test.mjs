import assert from 'node:assert/strict';
import test from 'node:test';
import { boundedRolloutSnapshot, rolloutObservation, waitForNativeRollout } from '../lib/kubernetes-observation.mjs';

const now = Date.parse('2026-10-18T17:00:00Z');
const healthy = () => ({ collected_at: new Date(now).toISOString(), problems: [], deployment: { generation: 2, observed_generation: 2, replicas: 2, ready_replicas: 2, updated_replicas: 2, unavailable_replicas: 0, spec_hash: 'reviewed' }, pods: [{ uid: 'a', node: 'node-a', zone: 'a', ready: true, terminating: false }, { uid: 'b', node: 'node-b', zone: 'b', ready: true, terminating: false }] });

test('native observation requires live nonterminating exact replicas in two zones', () => {
  assert.equal(rolloutObservation(healthy(), now, 'reviewed').ready, true);
  for (const mutate of [s => { s.pods[1].zone = 'a'; }, s => { s.pods[1].terminating = true; }, s => { s.pods[1].ready = false; }, s => { s.deployment.observed_generation = 1; }, s => { s.collected_at = new Date(now - 120001).toISOString(); }, s => { s.pods[1].uid = 'a'; }, s => { s.pods.push({ uid: 'old', zone: 'a', ready: true, terminating: false }); }]) {
    const snapshot = healthy(); mutate(snapshot); assert.equal(rolloutObservation(snapshot, now, 'reviewed').ready, false);
  }
});

test('native wait retries status convergence and returns actual healthy snapshot', async () => {
  let calls = 0, clock = now;
  const result = await waitForNativeRollout({ collect: () => { calls++; const s = healthy(); if (calls === 1) s.pods[1].terminating = true; return s; }, now: () => clock, sleep: async ms => { clock += ms; }, expectedSpecHash: 'reviewed' });
  assert.equal(calls, 2); assert.equal(result.pods[1].terminating, false);
});

test('native wait never retries auth/transport errors or identity/spec problems', async () => {
  for (const collect of [() => { throw new Error('transport unavailable'); }, () => ({ ...healthy(), problems: ['K8S_IDENTITY_CHANGED'] }), () => ({ ...healthy(), deployment: { ...healthy().deployment, spec_hash: 'wrong' } })]) {
    let sleeps = 0;
    await assert.rejects(waitForNativeRollout({ collect, now: () => now, sleep: async () => { sleeps++; }, expectedSpecHash: 'reviewed' }));
    assert.equal(sleeps, 0);
  }
});

test('topology timeout keeps only bounded safe native evidence', async () => {
  let clock = now, evidence;
  const snapshot = healthy(); snapshot.pods[1].zone = 'a'; snapshot.token = 'must-not-export'; snapshot.deployment.spec = { arbitrary: 'must-not-export' };
  await assert.rejects(waitForNativeRollout({ collect: () => snapshot, timeout: 2000, now: () => clock, sleep: async ms => { clock += ms; }, onFailure: s => { evidence = s; } }), /TOPOLOGY_TIMEOUT/);
  assert.equal(evidence.pods.length, 2); assert.equal(JSON.stringify(evidence).includes('must-not-export'), false);
  assert.equal(JSON.stringify(boundedRolloutSnapshot(snapshot)).includes('must-not-export'), false);
});
