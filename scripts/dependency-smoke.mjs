// Local fixture acceptance only. Mutations belong exclusively to tenant-other.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = Object.fromEntries(readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/)
  .filter(line => line && !line.startsWith('#') && line.includes('='))
  .map(line => { const n = line.indexOf('='); return [line.slice(0, n), line.slice(n + 1)]; }));
assert.equal(env.FIXTURE_MODE, 'true', 'Dependency acceptance requires the local fixture environment');
assert.ok(env.DEMO_PASSWORD, 'The ignored local .env must contain DEMO_PASSWORD');
for (const key of ['API_PORT', 'KEYCLOAK_PORT']) {
  if (env[key]) {
    assert.match(env[key], /^[0-9]{2,5}$/, `${key} must be a local port`);
    assert.ok(Number(env[key]) > 0 && Number(env[key]) <= 65535, `${key} is outside the port range`);
  }
}
// Deliberately ignore API_URL/OIDC_ISSUER overrides: this script cannot target AWS.
const api = `http://localhost:${env.API_PORT || 8080}`;
const issuer = `http://localhost:${env.KEYCLOAK_PORT || 8081}/realms/finops`;
const resourceID = 'resource-dev-api';
const resourcePath = `/v1/resources/${resourceID}`;
const reviewPath = `${resourcePath}/dependency-reviews`;
const checks = [];
function passed(name) { checks.push(name); console.log(`PASS ${name}`); }

async function request(token, method, url, body, options = {}) {
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  if (method === 'POST') {
    headers['content-type'] = 'application/json';
    headers['idempotency-key'] = options.key || randomUUID();
  }
  if (options.version !== undefined) headers['if-match'] = `"${options.version}"`;
  const response = await fetch(api + url, {
    method, headers, redirect: 'error', signal: AbortSignal.timeout(15_000),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  // Do not include response bodies or authentication material in diagnostics.
  assert.equal(response.status, options.status ?? 200, `${method} ${url} returned HTTP ${response.status}`);
  return response.json();
}

async function login(username, tenant) {
  const response = await fetch(`${issuer}/protocol/openid-connect/token`, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15_000),
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'console', username, password: env.DEMO_PASSWORD }),
  });
  assert.equal(response.status, 200, `Local fixture login failed for ${username}`);
  const { access_token: token } = await response.json();
  assert.ok(typeof token === 'string' && token.length > 0, 'Fixture login did not return an access token');
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(claims.tenant_id, tenant, 'Refusing to use credentials for a different fixture tenant');
  return token;
}

const health = await request(null, 'GET', '/healthz');
assert.equal(health.fixture, true, 'Refusing mutations outside fixture mode');
assert.equal(health.role, 'api');
passed('local API explicitly identifies fixture mode');

const other = await login('other', 'tenant-other');
const viewer = await login('viewer', 'tenant-demo');
const dashboard = await request(other, 'GET', '/v1/dashboard');
assert.equal(dashboard.fixture, true, 'Authenticated API must also identify fixture mode');
const target = dashboard.resources.find(item => item.id === resourceID);
assert.ok(target?.workload_id, 'Seeded fixture target must have an actual workload mapping');
passed('separate fixture tenant authenticated without resetting the owner loop');

let mutationStarted = false;
let cleanupComplete = false;
async function declareEmpty(reason) {
  const head = await request(other, 'GET', '/v1/resource-graph');
  assert.ok(Number.isInteger(head.version) && head.version >= 0, 'Graph head requires an integer version');
  const graph = await request(other, 'POST', '/v1/resource-graph', { edges: [], reason }, { version: head.version, status: 201 });
  assert.equal(graph.version, head.version + 1);
  assert.equal(graph.status, 'DECLARED');
  assert.ok(graph.edges.every(edge => edge.source === 'DISCOVERED_MAPPING'), 'Cleanup must retain only discovered mappings');
  return graph;
}
async function createReview(graph, note) {
  const resource = await request(other, 'GET', resourcePath);
  return request(other, 'POST', reviewPath, {
    graph_version: graph.version,
    valid_until: new Date(Date.now() + 60 * 60_000).toISOString(),
    acknowledgement: 'REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES',
    note,
  }, { version: resource.version, status: 201 });
}

try {
  const initial = await request(other, 'GET', '/v1/resource-graph');
  assert.ok(Number.isInteger(initial.version) && initial.version >= 0);
  assert.ok(initial.nodes.some(node => node.id === `resource:${resourceID}` && node.resource_id === resourceID));
  assert.ok(initial.nodes.some(node => node.id === `workload:${target.workload_id}` && node.workload_id === target.workload_id));
  passed('graph nodes come from current tenant inventory');

  const body = { edges: [], reason: 'Local tenant-other acceptance: explicitly declare no additional fixture dependencies.' };
  const key = randomUUID();
  mutationStarted = true;
  const graph = await request(other, 'POST', '/v1/resource-graph', body, { version: initial.version, key, status: 201 });
  assert.equal(graph.version, initial.version + 1);
  assert.equal(graph.status, 'DECLARED');
  assert.ok(graph.edges.some(edge => edge.from === `workload:${target.workload_id}` && edge.to === `resource:${resourceID}` && edge.type === 'RUNS_ON' && edge.source === 'DISCOVERED_MAPPING'));
  passed('graph declaration uses current CAS version and retains discovered RUNS_ON');

  const replay = await request(other, 'POST', '/v1/resource-graph', body, { version: initial.version, key, status: 201 });
  assert.equal(replay.version, graph.version);
  assert.equal(replay.graph_hash, graph.graph_hash);
  assert.equal((await request(other, 'GET', '/v1/resource-graph')).version, graph.version);
  passed('exact idempotency replay cannot append a second graph revision');

  await request(viewer, 'POST', '/v1/resource-graph', body, { version: graph.version, status: 403 });
  passed('viewer cannot declare graph authority');

  const reviewed = await createReview(graph, 'Reviewed the isolated tenant-other fixture inventory and external dependencies.');
  assert.equal(reviewed.status, 'READY');
  assert.equal(reviewed.graph_version, graph.version);
  assert.equal(reviewed.graph_hash, graph.graph_hash);
  assert.equal(reviewed.inventory_hash, graph.inventory_hash);
  assert.ok(reviewed.id && reviewed.reviewed_by);
  assert.ok(Date.parse(reviewed.expires_at) > Date.now() && Date.parse(reviewed.expires_at) <= Date.now() + 60 * 60_000);
  passed('explicit one-hour review binds current resource, graph and inventory');

  const current = await request(other, 'GET', reviewPath);
  assert.equal(current.status, 'READY');
  assert.equal(current.latest.id, reviewed.id);
  assert.ok(current.reviews.some(item => item.id === reviewed.id));
  passed('review history reports the currently ready immutable review');

  // The owner credential is used only for this read of the same seeded resource ID.
  const owner = await login(env.DEMO_USERNAME || 'owner', 'tenant-demo');
  const ownerReviews = await request(owner, 'GET', reviewPath);
  assert.ok(!(ownerReviews.reviews || []).some(item => item.id === reviewed.id));
  assert.notEqual(ownerReviews.latest?.id, reviewed.id);
  passed('owner tenant cannot see the other tenant review');

  const consumer = await request(other, 'POST', '/v1/workloads', {
    name: `Dependency smoke external consumer ${randomUUID()}`,
    owner: 'other@fixture.invalid', environment: 'NON_PRODUCTION', timezone: 'UTC',
    health_url: 'fixture://dependency-smoke/health',
  }, { status: 201 });
  assert.ok(consumer.id && consumer.id !== target.workload_id);
  const stale = await request(other, 'GET', reviewPath);
  assert.equal(stale.status, 'BLOCKED');
  assert.equal(stale.latest.id, reviewed.id);
  assert.ok(stale.reasons.includes('DEPENDENCY_GRAPH_CHANGED'));
  passed('inventory change invalidates an unexpired ready review');

  const changedInventory = await request(other, 'GET', '/v1/resource-graph');
  assert.notEqual(changedInventory.inventory_hash, graph.inventory_hash);
  const consumerNode = changedInventory.nodes.find(node => node.workload_id === consumer.id && node.kind === 'WORKLOAD');
  const targetNode = changedInventory.nodes.find(node => node.resource_id === resourceID && node.kind === 'RESOURCE');
  assert.ok(consumerNode && targetNode, 'Only returned graph endpoints may be submitted');
  const external = await request(other, 'POST', '/v1/resource-graph', {
    edges: [{ from: consumerNode.id, to: targetNode.id, type: 'DEPENDS_ON' }],
    reason: 'Local acceptance: this declared external workload consumes the fixture target.',
  }, { version: changedInventory.version, status: 201 });
  assert.equal(external.version, changedInventory.version + 1);
  assert.ok(external.edges.some(edge => edge.from === consumerNode.id && edge.to === targetNode.id && edge.type === 'DEPENDS_ON' && edge.source === 'OPERATOR_DECLARED'));
  passed('typed external consumer advances the graph head');

  const blocked = await createReview(external, 'External fixture consumer is declared and must block a new stop.');
  assert.equal(blocked.status, 'BLOCKED');
  assert.ok(blocked.reasons.includes('BLOCKED_DEPENDENCY_HARD_CONSUMER'));
  const blockedCurrent = await request(other, 'GET', reviewPath);
  assert.equal(blockedCurrent.status, 'BLOCKED');
  assert.equal(blockedCurrent.latest.id, blocked.id);
  passed('operator acknowledgement cannot waive an external consumer blocker');

  const unknown = await request(other, 'POST', '/v1/resource-graph', {
    edges: [{ from: `workload:missing-${randomUUID()}`, to: targetNode.id, type: 'DEPENDS_ON' }],
    reason: 'Local negative acceptance: unresolved endpoints must be rejected.',
  }, { version: external.version, status: 422 });
  assert.equal(unknown.error, 'BLOCKED_DEPENDENCY_ENDPOINT_UNKNOWN');
  assert.equal((await request(other, 'GET', '/v1/resource-graph')).version, external.version);
  passed('unknown endpoints are rejected without changing the graph');

  const ownNode = changedInventory.nodes.find(node => node.workload_id === target.workload_id && node.kind === 'WORKLOAD');
  assert.ok(ownNode);
  const cycle = await request(other, 'POST', '/v1/resource-graph', {
    edges: [{ from: targetNode.id, to: ownNode.id, type: 'DEPENDS_ON' }],
    reason: 'Local negative acceptance: reverse dependency would cycle with discovered RUNS_ON.',
  }, { version: external.version, status: 422 });
  assert.equal(cycle.error, 'BLOCKED_DEPENDENCY_CYCLE');
  assert.equal((await request(other, 'GET', '/v1/resource-graph')).version, external.version);
  passed('cycle through discovered RUNS_ON is rejected without a new graph revision');

  await declareEmpty('Local tenant-other acceptance cleanup: remove only these fixture-declared edges; leave immutable review history and the named consumer.');
  cleanupComplete = true;
  assert.equal((await request(other, 'GET', reviewPath)).status, 'BLOCKED', 'Cleanup must not auto-review the new graph');
  passed('fixture cleanup retains inventory/history and grants no fresh review or execution');
} finally {
  if (mutationStarted && !cleanupComplete) {
    await declareEmpty('Local tenant-other acceptance failure cleanup: remove fixture-declared edges without issuing a review or execution.');
    console.log('Fixture dependency graph cleanup completed after a failed acceptance check.');
  }
}

console.log(`PASS dependency graph/review fixture acceptance (${checks.length} checks). No plans, approvals or executions were created.`);
