// Inspection uses GET only. --execute submits an already approved plan and
// requests owned restoration, then pauses its signed schedule after completion.
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const FRESH_MS = 300_000, POLL_MS = 1_800_000, TOKEN_MS = 2_700_000;
function insist(ok, message) { if (!ok) throw new Error(message); }
function timestamp(value, name) {
  const result = Date.parse(value);
  insist(typeof value === 'string' && Number.isFinite(result), `${name} missing or invalid`);
  return result;
}
function version(value) { insist(Number.isSafeInteger(value) && value > 0, 'Current entity version required'); return value; }
export function tokenExpiry(token) {
  try {
    const parts = token.split('.');
    insist(parts.length === 3, 'JWT required');
    const exp = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')).exp;
    insist(Number.isFinite(exp), 'JWT expiry required');
    return exp * 1000;
  } catch { throw new Error('Bearer JWT needs valid exp; token contents were not logged'); }
}
export async function runSandboxSmoke({ env = process.env, args = process.argv.slice(2), fetchImpl = fetch, now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), log = console.log } = {}) {
  insist(args.every(arg => arg === '--execute') && args.length <= 1, 'Only optional --execute is supported');
  const execute = args.includes('--execute');
  for (const name of ['FINOPS_API_URL', 'FINOPS_API_TOKEN', 'FINOPS_SANDBOX_TENANT_ID', 'FINOPS_SANDBOX_ACCOUNT_ID', 'FINOPS_SANDBOX_REGION', 'FINOPS_SANDBOX_INSTANCE_ID']) insist(env[name], `${name} required`);
  const base = new URL(env.FINOPS_API_URL);
  insist(!base.username && !base.password && !base.search && !base.hash, 'API URL must not contain credentials, query or fragment');
  insist(base.protocol === 'https:' || (base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)), 'Use HTTPS or authenticated local port-forward');
  const tenant = env.FINOPS_SANDBOX_TENANT_ID, account = env.FINOPS_SANDBOX_ACCOUNT_ID, region = env.FINOPS_SANDBOX_REGION, instance = env.FINOPS_SANDBOX_INSTANCE_ID;
  insist(/^[0-9]{12}$/.test(account), 'Exact 12-digit sandbox account required');
  insist(region === 'eu-west-1', 'Sandbox region must be eu-west-1');
  insist(/^i-([a-f0-9]{8}|[a-f0-9]{17})$/.test(instance), 'Exact sandbox EC2 instance ID required');
  const expiry = tokenExpiry(env.FINOPS_API_TOKEN);
  insist(expiry - now() >= (execute ? TOKEN_MS : 60_000), execute ? 'Token needs 45 minutes remaining: 30-minute supervised poll plus recovery margin' : 'Token needs one minute remaining');
  async function call(path, body, entityVersion) {
    insist(expiry > now() + 10_000, 'Token expiring; preserve execution ID and supervise restoration using the operations runbook');
    const headers = { Authorization: `Bearer ${env.FINOPS_API_TOKEN}` };
    if (body !== undefined) {
      insist(execute, 'Inspection cannot mutate');
      headers['Content-Type'] = 'application/json';
      headers['Idempotency-Key'] = createHash('sha256').update(JSON.stringify({ tenant, path, body, version: entityVersion })).digest('hex');
    }
    if (entityVersion !== undefined) headers['If-Match'] = `"${version(entityVersion)}"`;
    const response = await fetchImpl(new URL(path, base), { method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(30_000) });
    insist(response.ok, `${path}: HTTP ${response.status}; response body and bearer token not logged`);
    try { return await response.json(); } catch { throw new Error(`${path}: invalid JSON response; body not logged`); }
  }
  const dashboard = await call('/v1/dashboard');
  insist(dashboard.fixture === false, 'Deliberately configured live sandbox required');
  insist(dashboard.org?.id === tenant, 'Unexpected tenant');
  const matches = (dashboard.resources || []).filter(r => r.provider === 'AWS' && r.provider_resource_id === instance && r.account_id === account && r.region === region);
  insist(matches.length === 1, 'Expected account/region/instance must identify exactly one discovered AWS resource');
  const resource = matches[0];
  insist(typeof resource.id === 'string' && resource.id, 'Discovered resource needs a stable API identity');
  if (!execute) {
    log(`Inspected ${tenant}/${account}/${region}/${instance}. No mutation occurred; execution readiness and economics were not required.`);
    return { mode: 'inspection', resourceId: resource.id };
  }
  insist(env.FINOPS_LIVE_ACK === 'STOP_AND_RESTORE_THIS_SANDBOX_INSTANCE', 'Explicit FINOPS_LIVE_ACK required');
  insist(env.FINOPS_APPROVED_PLAN_ID, 'Review and approve a concrete ChangePlan first');
  const workload = (dashboard.workloads || []).find(w => w.id === resource.workload_id);
  insist(resource.environment === 'NON_PRODUCTION' && workload?.environment === 'NON_PRODUCTION', 'Resource and mapped workload must be NON_PRODUCTION');
  insist(resource.runtime_stop_start_delegated === true && resource.commitment_known === true && resource.uncovered_on_demand === true, 'Runtime delegation and uncovered on-demand evidence required');
  for (const signal of ['incident', 'deployment', 'job']) insist(workload[signal] === 'CLEAR', `Workload ${signal} must be CLEAR`);
  const signalsAt = timestamp(workload.signals_at, 'signals_at');
  insist(now() - signalsAt <= FRESH_MS && signalsAt <= now() + 30_000, 'Workload signals must be fresh within five minutes');
  const plan = await call('/v1/change-plans/' + encodeURIComponent(env.FINOPS_APPROVED_PLAN_ID));
  insist(plan.id === env.FINOPS_APPROVED_PLAN_ID && plan.status === 'APPROVED' && plan.fixture === false && plan.resource_id === resource.id && plan.workload_id === workload.id, 'Approved plan must bind exact live resource/workload');
  const rec = (dashboard.recommendations || []).find(r => r.id === plan.recommendation_id);
  insist(rec?.pre_execution_ready === true && rec.resource_id === resource.id && rec.workload_id === workload.id, 'Exact recommendation must be pre-execution ready');
  const payload = plan.payload;
  insist(payload?.schema_version === '2' && payload.id === plan.id && payload.tenant_id === tenant && payload.fixture === false && payload.workload_id === workload.id && payload.recommendation_id === rec.id, 'Evidence schema v2 and exact signed plan identity required');
  insist(typeof payload.schedule_id === 'string' && payload.schedule_id && plan.schedule_id === payload.schedule_id, 'Exact signed schedule identity required');
  insist(Array.isArray(payload.operations) && payload.operations.length === 2 && payload.operations.filter(o => o.type === 'EC2_STOP').length === 1 && payload.operations.filter(o => o.type === 'EC2_START').length === 1, 'Plan requires exactly one stop and one restoration');
  for (const op of payload.operations) insist(op.resource_id === resource.id && op.provider_resource_id === instance && op.account_id === account && op.region === region, 'Every signed operation must bind explicit sandbox target');
  const stopAt = timestamp(payload.stop_at, 'signed stop_at');
  insist(Math.abs(stopAt - now()) <= 900_000, 'Approved stop window must be within fifteen minutes');
  insist(timestamp(payload.restore_at, 'signed restore_at') > stopAt && timestamp(payload.expires_at, 'signed expires_at') > now(), 'Invalid plan restoration/expiry window');
  const readiness = await call('/v1/resources/' + encodeURIComponent(resource.id) + '/readiness');
  insist(readiness.status === 'READY' && readiness.pre_execution_ready === true, 'Fresh readiness must explicitly permit execution');
  const checkedAt = timestamp(readiness.checked_at, 'readiness checked_at');
  insist(now() - checkedAt <= FRESH_MS && checkedAt <= now() + 30_000 && timestamp(readiness.expires_at, 'readiness expires_at') > now() + 30_000, 'Readiness must be fresh within five minutes and valid for submission');
  const binding = readiness.binding;
  insist(binding?.tenant_id === tenant && binding.resource_id === resource.id && binding.provider_resource_id === instance && binding.account_id === account && binding.region === region, 'Readiness target binding mismatch');
  for (const key of ['baseline_id', 'measurement_id', 'activation_at']) insist(typeof readiness[key] === 'string' && readiness[key] && payload[key] === readiness[key], `Signed ${key} must match readiness`);
  insist(payload.readiness_id && payload.readiness_id === readiness.id, 'Signed readiness_id must match readiness');
  insist(now() - signalsAt <= FRESH_MS && Math.abs(stopAt - now()) <= 900_000 && timestamp(payload.expires_at, 'signed expires_at') > now(), 'Signals or approved plan window became stale during inspection');
  insist(expiry - now() >= TOKEN_MS, 'Token lifetime below execution margin before submission');
  const execution = await call('/v1/executions', { change_plan_id: plan.id }, version(plan.version));
  insist(typeof execution.id === 'string' && execution.id, 'Execution response needs durable ID');
  log(`Submitted sandbox execution ${execution.id}. Supervise restoration; retain this ID if disconnected.`);
  const deadline = now() + POLL_MS;
  let requested = false;
  while (now() < deadline) {
    const current = await call('/v1/executions/' + encodeURIComponent(execution.id));
    insist(current.id === execution.id && current.change_plan_id === plan.id, 'Execution identity changed');
    if (current.status === 'COMPLETED') {
      insist(current.restoration_owned === false, 'Completion must clear stop ownership');
      const schedulePath = '/v1/schedules/' + encodeURIComponent(payload.schedule_id);
      const checkSchedule = schedule => insist(schedule.id === payload.schedule_id && schedule.workload_id === payload.workload_id, 'Schedule no longer matches the signed plan/workload');
      try {
        const schedule = await call(schedulePath);
        checkSchedule(schedule);
        if (schedule.paused !== true) {
          const paused = await call(schedulePath + '/pause', { paused: true }, version(schedule.version));
          checkSchedule(paused);
          insist(paused.paused === true && version(paused.version) > schedule.version, 'Schedule pause was not acknowledged at a newer version');
          const confirmed = await call(schedulePath);
          checkSchedule(confirmed);
          insist(confirmed.paused === true && version(confirmed.version) >= paused.version, 'Schedule pause was not confirmed');
        }
      } catch (error) {
        throw new Error(`Execution ${execution.id} restored, but schedule ${payload.schedule_id} pause is not confirmed: ${error.message}. Pause it before another window.`);
      }
      log(`Execution ${execution.id} restored with backend health checks; schedule ${payload.schedule_id} is paused. Savings remain provisional.`);
      return { mode: 'execution', executionId: execution.id, scheduleId: payload.schedule_id, schedulePaused: true };
    }
    if (!requested && (current.stage === 'STOPPED' || current.restoration_owned === true)) {
      await call('/v1/executions/' + encodeURIComponent(execution.id) + '/start-now', {}, version(current.version));
      requested = true;
    }
    insist(!['FAILED', 'SKIPPED'].includes(current.status), `Execution ${execution.id} ${current.status}; supervise pending restoration using docs/operations.md`);
    await sleep(5000);
  }
  throw new Error(`Execution ${execution.id} timed out; supervise restoration using docs/operations.md. Keep durable recovery running.`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) runSandboxSmoke().catch(error => { console.error(`Sandbox acceptance stopped: ${error.message}`); process.exitCode = 1; });
