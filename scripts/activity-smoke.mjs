// Local fixture acceptance only. Never contacts AWS or accepts a remote target.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = Object.fromEntries(readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/).filter(line => line && !line.startsWith('#')).map(line => { const n = line.indexOf('='); return [line.slice(0, n), line.slice(n + 1)]; }));
assert.equal(env.FIXTURE_MODE, 'true', 'This acceptance requires the local fixture environment');
for (const key of ['API_PORT', 'KEYCLOAK_PORT', 'ACTIVITY_PORT']) if (env[key]) assert.match(env[key], /^[0-9]{2,5}$/);
const api = `http://localhost:${env.API_PORT || 8080}`;
const issuer = `http://localhost:${env.KEYCLOAK_PORT || 8081}/realms/finops`;
const ingress = `http://localhost:${env.ACTIVITY_PORT || 8093}/v1/activity/intervals`;
assert.equal((await (await fetch(api + '/healthz')).json()).fixture, true);

async function token(body, realm = 'finops') {
  return fetch(issuer.replace('/realms/finops', `/realms/${realm}`) + '/protocol/openid-connect/token', { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
}
let machine = await token({ grant_type: 'client_credentials', client_id: 'activity-collector', client_secret: env.ACTIVITY_CLIENT_SECRET });
if (!machine.ok) {
  // Existing local volumes do not re-import new clients. Repair just this
  // fixture client from the ignored bootstrap file, after checking the realm.
  const login = await token({ grant_type: 'password', client_id: 'admin-cli', username: 'local-admin', password: env.KEYCLOAK_ADMIN_PASSWORD }, 'master');
  assert.ok(login.ok, 'Local fixture administrator authentication failed');
  const admin = (await login.json()).access_token;
  const base = issuer.replace('/realms/finops', '/admin/realms/finops');
  const headers = { authorization: `Bearer ${admin}`, 'content-type': 'application/json' };
  const realm = await (await fetch(base, { headers })).json();
  assert.ok(realm.displayName?.includes('local fixture'), 'Refusing to modify a non-fixture realm');
  const desired = JSON.parse(readFileSync(path.join(root, 'work/keycloak/finops-realm.json'), 'utf8')).clients.find(client => client.clientId === 'activity-collector');
  assert.ok(desired?.serviceAccountsEnabled && !desired.standardFlowEnabled);
  const existing = await (await fetch(base + '/clients?clientId=activity-collector', { headers })).json();
  const response = await fetch(base + '/clients' + (existing.length ? '/' + encodeURIComponent(existing[0].id) : ''), { method: existing.length ? 'PUT' : 'POST', headers, body: JSON.stringify(desired) });
  assert.ok(response.ok, 'Local fixture machine client synchronization failed');
  machine = await token({ grant_type: 'client_credentials', client_id: 'activity-collector', client_secret: env.ACTIVITY_CLIENT_SECRET });
}
assert.ok(machine.ok, 'Fixture machine OIDC authentication failed');
const machineToken = (await machine.json()).access_token;
const subject = JSON.parse(Buffer.from(machineToken.split('.')[1], 'base64url')).sub;
const login = await token({ grant_type: 'password', client_id: 'console', username: env.DEMO_USERNAME, password: env.DEMO_PASSWORD });
assert.ok(login.ok);
const consoleToken = (await login.json()).access_token;
const headers = { authorization: `Bearer ${consoleToken}`, 'content-type': 'application/json' };
const sources = await (await fetch(api + '/v1/activity-sources', { headers })).json();
let source = sources.find(item => item.resource_id === 'resource-dev-api');
if (!source) {
  const response = await fetch(api + '/v1/activity-sources', { method: 'POST', headers: { ...headers, 'idempotency-key': randomUUID() }, body: JSON.stringify({ resource_id: 'resource-dev-api', subject, metric_definition: { id: 'fixture-accepted-work', version: '1', unit: 'requests' } }) });
  assert.equal(response.status, 201);
  source = await response.json();
}
assert.equal(source.subject, subject);
const minute = 60_000;
if (Date.now() % minute > 55_000) await new Promise(resolve => setTimeout(resolve, minute - Date.now() % minute + 100));
const end = Math.floor(Date.now() / minute) * minute;
let latest;
for (let n = 0; n < 2; n++) {
  const right = end - (1 - n) * minute;
  const body = JSON.stringify({ schema_version: '1', source_id: source.id, resource_id: source.resource_id, workload_id: source.workload_id, sequence: right / minute, interval_start: new Date(right - minute).toISOString(), interval_end: new Date(right).toISOString(), metric_definition: source.metric_definition, accepted: 0, completed: 0, rejected: 0, backlog: 0, inflight: 0, heartbeat: true, incident: 'CLEAR', deployment: 'CLEAR', job: 'CLEAR' });
  const machineHeaders = { authorization: `Bearer ${machineToken}`, 'content-type': 'application/json', 'idempotency-key': createHash('sha256').update(body).digest('hex') };
  const response = await fetch(ingress, { method: 'POST', headers: machineHeaders, body });
  assert.ok(response.status === 201 || response.status === 200, 'Guarded minute receipt rejected');
  const receipt = await response.json();
  assert.ok(receipt.receipt.id);
  latest = { body, machineHeaders, receipt };
}
const replay = await fetch(ingress, { method: 'POST', headers: latest.machineHeaders, body: latest.body });
assert.equal(replay.status, 200);
assert.equal((await replay.json()).receipt.id, latest.receipt.receipt.id);
const changed = await fetch(ingress, { method: 'POST', headers: latest.machineHeaders, body: latest.body.replace('"accepted":0', '"accepted":1') });
assert.equal(changed.status, 409);
const humanIngress = await fetch(ingress, { method: 'POST', headers: { ...latest.machineHeaders, authorization: `Bearer ${consoleToken}` }, body: latest.body });
assert.equal(humanIngress.status, 401);
assert.equal((await fetch(api + '/v1/dashboard', { headers: { authorization: `Bearer ${machineToken}` } })).status, 401);
console.log('PASS machine OIDC, guarded minute receipts, exact replay, conflict rejection, console-audience denial and machine/control-plane isolation (6 checks).');
