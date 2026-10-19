// Real local transport acceptance. No AWS calls, source backfills, or fake
// historical timestamps. Only the bootstrap-created fixture stack is accepted.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export function varint(value) {
  let n = BigInt(value); assert.ok(n >= 0n && n <= 0xffffffffffffffffn, 'uint64 required');
  const out = []; do { let byte = Number(n & 127n); n >>= 7n; if (n) byte |= 128; out.push(byte); } while (n);
  return Buffer.from(out);
}
const field = (number, value) => Buffer.concat([varint(BigInt(number) * 8n + 2n), varint(value.length), value]);
const text = (number, value) => field(number, Buffer.from(value));
const fixed = (number, value) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(value)); return Buffer.concat([varint(BigInt(number) * 8n + 1n), b]); };
const integer = (number, value) => Buffer.concat([varint(BigInt(number) * 8n), varint(value)]);
const attribute = (key, value) => Buffer.concat([text(1, key), field(2, text(1, value))]);

// Explicit official OTLP wire fields; no JSON-to-protobuf translation service
// or browser authority. Counts/times remain uint64 through this encoder.
export function encodeObservedRequests({ binding, metric, epoch, at, count }) {
  assert.ok(BigInt(at) > BigInt(epoch));
  assert.ok(BigInt(count)>=0n&&BigInt(count)<=0x7fffffffffffffffn,'OTLP sum AsInt requires nonnegative int64');
  const attrs = { 'cloud.provider': 'aws', 'cloud.account.id': binding.account_id, 'cloud.region': binding.region, 'host.id': binding.provider_resource_id, 'finops.resource.id': binding.resource_id, 'finops.tenant.id': binding.tenant_id };
  const resource = Buffer.concat(Object.entries(attrs).map(([k, v]) => field(1, attribute(k, v))));
  const point = Buffer.concat([fixed(2, epoch), fixed(3, at), fixed(6, count)]);
  const sum = Buffer.concat([field(1, point), integer(2, 2), integer(3, 1)]); // CUMULATIVE, monotonic
  const definition = Buffer.concat([text(1, metric), text(3, 'count'), field(7, sum)]);
  const scope = Buffer.concat([field(1, text(1, 'native-local-acceptance')), field(2, definition)]);
  return field(1, Buffer.concat([field(1, resource), field(2, scope)]));
}
export function fixturePorts(env) {
  assert.equal(env.FIXTURE_MODE, 'true', 'Local fixture configuration required');
  const out = {};
  for (const [key, fallback] of Object.entries({ API_PORT: '8080', KEYCLOAK_PORT: '8081', TELEMETRY_PORT: '8094' })) {
    const value = env[key] || fallback; assert.match(value, /^[0-9]{2,5}$/); assert.ok(Number(value) <= 65535); out[key] = value;
  }
  return out;
}
// A retained local service can have genuine samples from a preceding calendar
// day. Partial observations keep their measured values; absent intervals do not
// become zero or turn an incomplete fourteen-day window into ready history.
export function assertIncompleteHistory(evaluation) {
  assert.equal(evaluation.status, 'BLOCKED', 'Local history is incomplete');
  assert.ok(evaluation.metrics.length > 0, 'Expected registered native metrics');
  for (const row of evaluation.metrics) {
    assert.equal(row.status, 'BLOCKED');
    assert.ok(row.coverage_ppm >= 0 && row.coverage_ppm < 1000000);
    assert.ok(row.unknown_duration_ns > 0, 'Missing historical intervals remain unknown');
    assert.ok(Number.isInteger(row.observed_samples) && row.observed_samples >= 0);
    if (row.observed_samples === 0) {
      for (const field of ['p50', 'p90', 'p95', 'p99', 'p999', 'maximum', 'total']) {
        assert.equal(row[field], null, 'Absent historical source data must not become zero');
      }
    }
  }
}
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const fetch=(url,options={})=>globalThis.fetch(url,{...options,signal:options.signal??AbortSignal.timeout(120000)});
  assert.equal(process.argv.length, 2, 'This local acceptance accepts no remote target arguments');
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const env = Object.fromEntries(readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/).filter(line => line && !line.startsWith('#')).map(line => { const n = line.indexOf('='); return [line.slice(0, n), line.slice(n + 1)]; }));
  const ports = fixturePorts(env), api = `http://localhost:${ports.API_PORT}`, issuer = `http://localhost:${ports.KEYCLOAK_PORT}/realms/finops`, ingress = `http://localhost:${ports.TELEMETRY_PORT}/v1/metrics`;
  assert.equal((await (await fetch(api + '/healthz')).json()).fixture, true, 'Refusing a non-fixture API');
  const token = (body, realm = 'finops') => fetch(issuer.replace('/realms/finops', `/realms/${realm}`) + '/protocol/openid-connect/token', { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
  let machine = await token({ grant_type: 'client_credentials', client_id: 'telemetry-collector', client_secret: env.TELEMETRY_CLIENT_SECRET });
  if (!machine.ok) {
    const response = await token({ grant_type: 'password', client_id: 'admin-cli', username: 'local-admin', password: env.KEYCLOAK_ADMIN_PASSWORD }, 'master');
    assert.ok(response.ok, 'Local fixture administrator authentication failed'); const admin = (await response.json()).access_token;
    const base = issuer.replace('/realms/finops', '/admin/realms/finops'), headers = { authorization: `Bearer ${admin}`, 'content-type': 'application/json' };
    const realm = await (await fetch(base, { headers, redirect: 'error' })).json(); assert.ok(realm.displayName?.includes('local fixture'), 'Non-fixture realm rejected');
    const desired = JSON.parse(readFileSync(path.join(root, 'work/keycloak/finops-realm.json'), 'utf8')).clients.find(client => client.clientId === 'telemetry-collector');
    assert.ok(desired?.serviceAccountsEnabled && !desired.standardFlowEnabled && !desired.directAccessGrantsEnabled);
    const existing = await (await fetch(base + '/clients?clientId=telemetry-collector', { headers, redirect: 'error' })).json();
    const synced = await fetch(base + '/clients' + (existing.length ? '/' + encodeURIComponent(existing[0].id) : ''), { method: existing.length ? 'PUT' : 'POST', headers, redirect: 'error', body: JSON.stringify(desired) }); assert.ok(synced.ok, 'Local machine client synchronization failed');
    machine = await token({ grant_type: 'client_credentials', client_id: 'telemetry-collector', client_secret: env.TELEMETRY_CLIENT_SECRET });
  }
  assert.ok(machine.ok, 'Native machine authentication failed'); const machineToken = (await machine.json()).access_token;
  const claims = JSON.parse(Buffer.from(machineToken.split('.')[1], 'base64url')); assert.equal(claims.tenant_id, 'tenant-demo'); assert.ok([claims.aud].flat().includes('finops-telemetry'));
  console.log('Native acceptance: machine OIDC ready.');
  const login = await token({ grant_type: 'password', client_id: 'console', username: env.DEMO_USERNAME, password: env.DEMO_PASSWORD }); assert.ok(login.ok); const human = (await login.json()).access_token;
  const otherLogin = await token({ grant_type: 'password', client_id: 'console', username: 'other', password: env.DEMO_PASSWORD }); assert.ok(otherLogin.ok); const other = (await otherLogin.json()).access_token;
  const headers = { authorization: `Bearer ${human}`, 'content-type': 'application/json' };
  async function get(url, bearer = human) { const response = await fetch(api + url, { headers: { authorization: `Bearer ${bearer}` }, redirect: 'error' }); assert.ok(response.ok, `GET ${url}: ${response.status}`); return response.json(); }
  async function mutate(url, body, version) { const response = await fetch(api + url, { method: 'POST', redirect: 'error', headers: { ...headers, 'idempotency-key': randomUUID(), ...(version === undefined ? {} : { 'if-match': `"${version}"` }) }, body: JSON.stringify(body) }); assert.ok(response.ok, `POST ${url}: ${response.status} ${(await response.clone().text()).slice(0, 300)}`); return response.json(); }
  const dashboard = await get('/v1/dashboard'), resource = dashboard.resources.find(row => row.id === 'resource-dev-api'); assert.ok(resource);
  const created = await mutate('/v1/telemetry-connections', { resource_id: resource.id, kind: 'OTLP', subject: claims.sub, definitions: [{ id: 'observed-requests', version: '1', metric: 'workload_activity', name: 'smoke.completed_requests', unit: 'count', type: 'SUM', monotonic: true, cadence_seconds: 15, max_gap_seconds: 30, attributes: {}, resource_attributes: {} }] });
  const binding = created.binding, metric = created.definitions[0].name;
  console.log('Native acceptance: exact resource registration ready.');
  const docker = (code, input = {}) => {
    try { return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'telemetry-gateway', 'python', '-c', code], { cwd: root, input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 1 << 20, stdio: ['pipe', 'pipe', 'pipe'] })); }
    catch { throw new Error('Local container acceptance helper failed; inspect fixture service health'); }
  };
  const epoch = BigInt(Date.now()) * 1000000n;
  const served = docker('import json,urllib.request\nresponses=[urllib.request.urlopen("http://127.0.0.1:8096/work").read() for _ in range(5)]\nprint(json.dumps({"completed":len(responses)}))'); assert.equal(served.completed, 5);
  const at = BigInt(Date.now()) * 1000000n, raw = encodeObservedRequests({ binding, metric, epoch, at, count: served.completed }), key = createHash('sha256').update(raw).digest('hex');
  const machineHeaders = { authorization: `Bearer ${machineToken}`, 'content-type': 'application/x-protobuf', 'x-finops-connection-id': created.id, 'x-finops-config-hash': created.config_hash, 'idempotency-key': key };
  const send = (body, changed = {}) => fetch(ingress, { method: 'POST', redirect: 'error', headers: { ...machineHeaders, ...changed }, body });
  let response = await send(raw); assert.equal(response.status, 200, 'Native current receipt rejected'); const receiptID = response.headers.get('x-finops-receipt-id'); assert.ok(receiptID); assert.equal((await response.arrayBuffer()).byteLength, 0, 'Current point should have no partial rejection');
  response = await send(raw); assert.equal(response.status, 200); assert.equal(response.headers.get('x-finops-receipt-id'), receiptID);
  response = await send(encodeObservedRequests({ binding, metric, epoch, at, count: served.completed + 1 })); assert.equal(response.status, 409);
  assert.equal((await send(raw, { authorization: `Bearer ${human}` })).status, 401);
  assert.equal((await fetch(api + '/v1/dashboard', { headers: { authorization: `Bearer ${machineToken}` } })).status, 401);
  assert.ok([403, 404].includes((await fetch(api + `/v1/telemetry-connections/${created.id}`, { headers: { authorization: `Bearer ${other}` } })).status));
  const receiptPage = await get(`/v1/telemetry-connections/${created.id}/receipts`), receipt = receiptPage.items.find(row => row.id === receiptID); assert.ok(receipt?.active_source); assert.equal(receipt.sample_count, 1);
  const persistence = docker(String.raw`import sys,json,hashlib,hmac,datetime,urllib.parse,urllib.request
p=json.load(sys.stdin);r=p['receipt'];ref=r['raw_checkpoint'];host='minio:9000';region='eu-west-1'
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');day=stamp[:8];empty=hashlib.sha256(b'').hexdigest()
uri='/'+ref['bucket']+'/'+urllib.parse.quote(ref['key'],safe='/-_.~');query=urllib.parse.urlencode({'versionId':ref['version_id']},quote_via=urllib.parse.quote)
head='host:'+host+'\n'+'x-amz-content-sha256:'+empty+'\n'+'x-amz-date:'+stamp+'\n';signed='host;x-amz-content-sha256;x-amz-date'
canonical='GET\n'+uri+'\n'+query+'\n'+head+'\n'+signed+'\n'+empty
scope=day+'/'+region+'/s3/aws4_request';string='AWS4-HMAC-SHA256\n'+stamp+'\n'+scope+'\n'+hashlib.sha256(canonical.encode()).hexdigest()
def mac(key,text):return hmac.new(key,text.encode(),hashlib.sha256).digest()
k=mac(mac(mac(mac(('AWS4'+p['secret']).encode(),day),region),'s3'),'aws4_request');signature=hmac.new(k,string.encode(),hashlib.sha256).hexdigest()
headers={'x-amz-date':stamp,'x-amz-content-sha256':empty,'Authorization':'AWS4-HMAC-SHA256 Credential='+p['access']+'/'+scope+', SignedHeaders='+signed+', Signature='+signature}
body=urllib.request.urlopen(urllib.request.Request('http://'+host+uri+'?'+query,headers=headers)).read()
assert hashlib.sha256(body).hexdigest()==ref['body_sha256']
assert r['batch_id'].replace('-','').isalnum() and r['binding']['tenant_id']=='tenant-demo'
sql="SELECT uniqExact(sample_id) FROM finops.native_metric_samples WHERE tenant_id='tenant-demo' AND batch_id='"+r['batch_id']+"'"
req=urllib.request.Request('http://clickhouse:8123/',data=sql.encode(),headers={'X-ClickHouse-User':'finops','X-ClickHouse-Key':p['ch']})
count=int(urllib.request.urlopen(req).read())
print(json.dumps({'raw_version_pinned':True,'raw_hash_matches':True,'native_samples':count}))`, { receipt, access: env.MINIO_ROOT_USER, secret: env.MINIO_ROOT_PASSWORD, ch: env.CLICKHOUSE_PASSWORD });
  assert.deepEqual(persistence, { raw_version_pinned: true, raw_hash_matches: true, native_samples: 1 });
  console.log('Native acceptance: OTLP identity, replay and physical persistence passed.');
  const connections = await get('/v1/telemetry-connections?limit=100');
  let prometheus = connections.items.find(row => row.kind === 'PROMETHEUS' && row.read_binding_id === 'fixture-prometheus-dev-api' && !row.revoked);
  if (!prometheus) prometheus = await mutate('/v1/telemetry-connections', { resource_id: resource.id, kind: 'PROMETHEUS', read_binding_id: 'fixture-prometheus-dev-api', definitions: [{ id: 'served-requests', version: '1', metric: 'request_count', name: 'finops_gateway_requests_total', unit: 'requests', type: 'SUM', monotonic: true, cadence_seconds: 15, max_gap_seconds: 30, epoch_metric: 'process_start_time_seconds', attributes: {}, resource_attributes: {} }] });
  let current;
  for (let n = 0; n < 45; n++) { const rows = await get(`/v1/telemetry-connections/${prometheus.id}/receipts?limit=100`); current = rows.items.find(row => row.sample_count >= 2 && row.rejection_count === 0 && row.warning_count === 0); if (current) break; if (n % 5 === 0) docker('import json,urllib.request\nprint(json.dumps({"served":bool(urllib.request.urlopen("http://127.0.0.1:8096/work").read())}))'); await pause(2000); }
  assert.ok(current, 'No actual Prometheus raw-range observations were persisted within 90 seconds');
  const sync = await mutate(`/v1/telemetry-connections/${prometheus.id}/sync`, {}, prometheus.version); assert.ok([14, 30, 90].includes(sync.history_days));
  let completed;
  for (let n = 0; n < 60; n++) { completed = await get(`/v1/telemetry-connections/${prometheus.id}/sync/${sync.id}`); if (['COMPLETED', 'BLOCKED'].includes(completed.status)) break; await pause(2000); }
  assert.equal(completed.status, 'COMPLETED', 'Historical query transport did not durably finish'); assert.ok(completed.receipt_ids.length >= sync.history_days); assert.equal(completed.lease_token, undefined);
  const history = await mutate(`/v1/telemetry-connections/${prometheus.id}/evaluate`, { mode: 'history' }, prometheus.version);
  assert.ok(history.receipt_ids.length > 0); assertIncompleteHistory(history.evaluation);
  await mutate(`/v1/telemetry-connections/${created.id}/revoke`, { reason: 'Local native transport acceptance finished' }, created.version);
  assert.equal((await send(raw)).status, 403, 'Revoked source retained new ingress authority');
  console.log('PASS native machine OIDC, current OTLP, exact replay/conflict, tenant/audience denial, versioned raw+analytics persistence, real Prometheus samples, durable history transport, incomplete-history fail-closed, revocation (10 checks).');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(error => { console.error(`Native local acceptance failed: ${error.message}`); process.exitCode = 1; });
