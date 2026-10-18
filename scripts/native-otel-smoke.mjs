// Optional real official-collector acceptance against only the local fixture.
// Run after bootstrap and native-smoke. No customer credentials or AWS calls.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { fixturePorts } from './native-smoke.mjs';

assert.equal(process.argv.length, 2, 'Local collector acceptance accepts no remote target');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = Object.fromEntries(readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/).filter(line => line && !line.startsWith('#')).map(line => { const n = line.indexOf('='); return [line.slice(0, n), line.slice(n + 1)]; }));
const ports = fixturePorts(env), api = `http://localhost:${ports.API_PORT}`, issuer = `http://localhost:${ports.KEYCLOAK_PORT}/realms/finops`;
const fetch = (url, options = {}) => globalThis.fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(60000) });
assert.equal((await (await fetch(api + '/healthz')).json()).fixture, true);
const token = body => fetch(issuer + '/protocol/openid-connect/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
const machine = await token({ grant_type: 'client_credentials', client_id: 'telemetry-collector', client_secret: env.TELEMETRY_CLIENT_SECRET }); assert.ok(machine.ok, 'Run local native-smoke to synchronize the fixture machine client first');
const claims = JSON.parse(Buffer.from((await machine.json()).access_token.split('.')[1], 'base64url')); assert.equal(claims.tenant_id, 'tenant-demo');
const login = await token({ grant_type: 'password', client_id: 'console', username: env.DEMO_USERNAME, password: env.DEMO_PASSWORD }); assert.ok(login.ok); const human = (await login.json()).access_token;
const headers = { authorization: `Bearer ${human}`, 'content-type': 'application/json' };
const mutate = async (url, body, version) => { const r = await fetch(api + url, { method: 'POST', headers: { ...headers, 'idempotency-key': randomUUID(), ...(version === undefined ? {} : { 'if-match': `"${version}"` }) }, body: JSON.stringify(body) }); assert.ok(r.ok, `${url}: ${r.status}`); return r.json(); };
const connection = await mutate('/v1/telemetry-connections', { resource_id: 'resource-dev-api', kind: 'OTLP', subject: claims.sub, definitions: [
  { id: 'otel-served-requests', version: '1', metric: 'request_count', name: 'finops_gateway_requests_total', unit: 'requests', type: 'SUM', monotonic: true, cadence_seconds: 15, max_gap_seconds: 30, attributes: {}, resource_attributes: {} },
  { id: 'otel-latency', version: '1', metric: 'request_latency', name: 'finops_gateway_request_duration_seconds', unit: 's', type: 'HISTOGRAM', monotonic: false, cadence_seconds: 15, max_gap_seconds: 30, attributes: {}, resource_attributes: {} },
  { id: 'otel-epoch', version: '1', metric: 'process_start_epoch', name: 'process_start_time_seconds', unit: 's', type: 'GAUGE', monotonic: false, cadence_seconds: 15, max_gap_seconds: 30, attributes: {}, resource_attributes: {} },
] });
const image = 'otel/opentelemetry-collector-contrib:0.162.0@sha256:39923a8e431bd1f57be82411999d389fcfe40857492e4365456d97a4c1f74be6';
const id = randomUUID(), name = 'finops-native-otel-' + id, directory = path.join(root, 'work', 'native-otel', id);
mkdirSync(directory, { recursive: true, mode: 0o700 }); chmodSync(directory, 0o700);
const credential = path.join(directory, 'client-secret'); writeFileSync(credential, env.TELEMETRY_CLIENT_SECRET, { mode: 0o644 });
// Directory is owner-only on the host; this one file is readable by the
// collector's unprivileged UID through its dedicated read-only bind mount.
chmodSync(credential, 0o644);
const template = readFileSync(path.join(root, 'examples/telemetry/otel-collector.yaml'), 'utf8');
const context = { FINOPS_ACCOUNT_ID: connection.binding.account_id, FINOPS_PROVIDER_RESOURCE_ID: connection.binding.provider_resource_id, FINOPS_RESOURCE_ID: connection.binding.resource_id, FINOPS_TENANT_ID: connection.binding.tenant_id, FINOPS_CONNECTION_ID: connection.id, FINOPS_CONFIG_HASH: connection.config_hash };
const rendered = template.replace(/\$\{env:([A-Z_]+)\}/g, (_, key) => { assert.ok(key in context); return context[key]; });
const configuration = path.join(directory, 'collector.yaml'); writeFileSync(configuration, rendered, { mode: 0o644 });
const docker = args => execFileSync('docker', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 20 });
let started = false;
try {
  // Pull by reviewed immutable digest when missing. No Docker credentials,
  // daemon socket, execution token or signing key enter this container.
  try { docker(['image', 'inspect', image]); } catch { docker(['pull', image]); }
  const network = (env.COMPOSE_PROJECT_NAME || 'cloud-cost-autopilot') + '_private'; assert.match(network, /^[a-z0-9_-]+$/);
  docker(['run', '-d', '--rm', '--name', name, '--network', network, '--read-only', '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL', '--memory', '256m', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '--mount', `type=bind,src=${configuration},dst=/etc/otelcol-contrib/config.yaml,readonly`, '--mount', `type=bind,src=${credential},dst=/run/secrets/telemetry-client-secret,readonly`, image, '--config=/etc/otelcol-contrib/config.yaml']); started = true;
  let receipt;
  for (let n = 0; n < 36; n++) {
    const response = await fetch(api + `/v1/telemetry-connections/${connection.id}/receipts?limit=100`, { headers }); assert.ok(response.ok);
    receipt = (await response.json()).items.find(row => row.sample_count === 3 && row.rejection_count === 0 && row.warning_count === 0);
    if (receipt) break;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  assert.ok(receipt?.active_source, 'No clean actual collector receipt within72seconds; inspect local collector logs without exposing credentials');
  assert.ok(receipt.raw_checkpoint?.version_id && receipt.analytics_checkpoint?.canonical_version_id);
  assert.equal(receipt.source_kind, 'OTLP'); assert.equal(receipt.writer_role, 'finops_telemetry_ingress');
  assert.equal(receipt.binding.provider_resource_id, connection.binding.provider_resource_id);
  console.log('PASS official pinned OpenTelemetry collector: real Prometheus scrape, OAuth2 machine token, preserved native units/epochs/histograms, restricted ingress and versioned persistence (5 checks).');
} finally {
  if (started) { try { docker(['stop', name]); } catch { /* Already exited; receipt/history is retained. */ } }
  await mutate(`/v1/telemetry-connections/${connection.id}/revoke`, { reason: 'Local official collector acceptance finished' }, connection.version);
}
