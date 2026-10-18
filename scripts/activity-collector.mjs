// Run on a gateway/queue observer which remains available while EC2 is stopped.
// The observation endpoint supplies closed-minute counters, never CPU/runtime.
import { readFile, open, rename, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

export function buildInterval(observation, config, sequence, now = new Date()) {
  const required = ['interval_start', 'interval_end', 'accepted', 'completed', 'rejected', 'backlog', 'inflight', 'heartbeat', 'incident', 'deployment', 'job'];
  if (required.some(key => !Object.hasOwn(observation, key))) throw new Error('observation is incomplete');
  const start = new Date(observation.interval_start), end = new Date(observation.interval_end);
  if (!Number.isFinite(start.getTime()) || end - start !== 60_000 || start.getTime() % 60_000 || end > now || now - end > 120_000) throw new Error('observation is not a recent complete minute');
  for (const key of ['accepted', 'completed', 'rejected', 'backlog', 'inflight']) if (!Number.isSafeInteger(observation[key]) || observation[key] < 0) throw new Error('counts must be explicit nonnegative safe integers');
  if (typeof observation.heartbeat !== 'boolean') throw new Error('heartbeat must be explicit');
  for (const key of ['incident', 'deployment', 'job']) if (!['CLEAR', 'ACTIVE', 'UNKNOWN'].includes(observation[key])) throw new Error('explicit operational state required');
  for (const key of ['source_id', 'resource_id', 'workload_id']) if (!config[key]) throw new Error('registered source binding required');
  if (!config.metric_definition?.id || !config.metric_definition?.version || !config.metric_definition?.unit) throw new Error('registered metric definition required');
  return { schema_version: '1', source_id: config.source_id, resource_id: config.resource_id, workload_id: config.workload_id, sequence, metric_definition: config.metric_definition, ...Object.fromEntries(required.map(key => [key, observation[key]])), interval_start: start.toISOString(), interval_end: end.toISOString() };
}

async function request(url, options = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && process.env.ACTIVITY_ALLOW_LOCAL_HTTP !== 'true') throw new Error('HTTPS required outside explicit local development');
  if (parsed.username || parsed.password) throw new Error('credentials in URLs are forbidden');
  return fetch(parsed, { ...options, redirect: 'error', signal: AbortSignal.timeout(15_000) });
}
export async function run() {
  const env = process.env;
  const config = { source_id: env.ACTIVITY_SOURCE_ID, resource_id: env.ACTIVITY_RESOURCE_ID, workload_id: env.ACTIVITY_WORKLOAD_ID, metric_definition: { id: env.ACTIVITY_METRIC_ID, version: env.ACTIVITY_METRIC_VERSION, unit: env.ACTIVITY_METRIC_UNIT } };
  if (!env.ACTIVITY_OBSERVATION_URL || !env.ACTIVITY_INGRESS_URL || !env.ACTIVITY_OIDC_ISSUER || !env.ACTIVITY_CLIENT_ID || !env.ACTIVITY_CLIENT_SECRET_FILE || !env.ACTIVITY_STATE_FILE) throw new Error('collector endpoint, identity and durable state configuration required');
  const secret = (await readFile(env.ACTIVITY_CLIENT_SECRET_FILE, 'utf8')).trim();
  if (!secret) throw new Error('machine client secret file is empty');
  const discovery = await request(`${env.ACTIVITY_OIDC_ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`);
  if (!discovery.ok) throw new Error('machine issuer discovery failed');
  const metadata = await discovery.json();
  const statePath = resolve(env.ACTIVITY_STATE_FILE);
  let state;
  try { state = JSON.parse(await readFile(statePath, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; state = { sequence: 0 }; }
  if (!Number.isSafeInteger(state.sequence) || state.sequence < 0) throw new Error('collector sequence state is invalid');
  await mkdir(dirname(statePath), { recursive: true });
  const binding = JSON.stringify(config);
  if (state.source_binding && state.source_binding !== binding) throw new Error('durable state belongs to a different registered source');
  state.source_binding = binding;
  const save = async () => {
    const temporary = `${statePath}.${randomUUID()}.tmp`;
    const file = await open(temporary, 'wx', 0o600);
    try { await file.writeFile(`${JSON.stringify(state)}\n`); await file.sync(); } finally { await file.close(); }
    await rename(temporary, statePath);
  };
  let stopped = false;
  process.once('SIGTERM', () => { stopped = true; });
  process.once('SIGINT', () => { stopped = true; });
  let token = '', tokenUntil = 0;
  while (!stopped) {
    try {
      if (!state.pending) {
        const observed = await request(env.ACTIVITY_OBSERVATION_URL);
        if (!observed.ok) throw new Error('independent activity observation unavailable');
        const interval = buildInterval(await observed.json(), config, state.sequence + 1);
        if (interval.interval_end === state.last_interval_end) { await new Promise(resolve => setTimeout(resolve, 5_000)); continue; }
        state.pending = { body: JSON.stringify(interval), key: randomUUID(), interval_end: interval.interval_end };
        state.sequence = interval.sequence;
        await save(); // Persist bytes before dispatch; uncertain responses replay exactly.
      }
      if (Date.now() >= tokenUntil) {
        const auth = await request(metadata.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: env.ACTIVITY_CLIENT_ID, client_secret: secret }) });
        if (!auth.ok) throw new Error('machine authentication failed');
        const result = await auth.json();
        if (!result.access_token || !Number.isFinite(result.expires_in)) throw new Error('machine token response invalid');
        token = result.access_token; tokenUntil = Date.now() + Math.max(1, result.expires_in - 30) * 1000;
      }
      const response = await request(env.ACTIVITY_INGRESS_URL, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'idempotency-key': state.pending.key }, body: state.pending.body });
      if (response.status === 401) { tokenUntil = 0; throw new Error('machine authentication rejected'); }
      if (response.status === 409 || response.status === 403 || response.status === 422) throw Object.assign(new Error('activity rejected; inspect source binding, freshness or durable sequence state'), { terminal: true });
      if (!response.ok) throw new Error('activity ingress unavailable');
      const result = await response.json();
      if (!result.receipt?.id) throw new Error('activity receipt acknowledgement missing');
      state.last_interval_end = state.pending.interval_end; delete state.pending; await save();
      console.log(JSON.stringify({ event: 'activity_receipted', receipt_id: result.receipt.id, sequence: state.sequence, replayed: result.replayed === true }));
    } catch (error) {
      console.error(JSON.stringify({ event: 'activity_collection_failed', reason: error.message }));
      if (error.terminal) throw error;
    }
    if (env.ACTIVITY_ONCE === 'true') break;
    await new Promise(resolve => setTimeout(resolve, 5_000));
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) run().catch(() => { process.exitCode = 1; });
