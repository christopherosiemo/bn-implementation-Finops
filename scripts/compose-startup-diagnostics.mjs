import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const allowedCodes = new Set([
  'MINIO_CONFIGURATION_INVALID', 'MINIO_READINESS_UNAVAILABLE',
  'MINIO_RAW_BUCKET_CREATE_FAILED', 'MINIO_RAW_VERSIONING_FAILED',
  'MINIO_AUDIT_BUCKET_CREATE_FAILED', 'MINIO_AUDIT_RETENTION_FAILED',
  ...['RAW', 'AUDIT', 'ASSESSOR', 'CAPACITY'].flatMap(scope =>
    ['POLICY_FAILED', 'USER_FAILED', 'POLICY_ATTACH_FAILED', 'CONFIGURATION_INVALID'].map(code => `MINIO_${scope}_${code}`)),
]);
function capture(directory, name, args) {
  let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0);
  let incomplete = false;
  try {
    stdout = execFileSync('docker', args, {stdio: ['ignore', 'pipe', 'pipe'], timeout: 5_000, maxBuffer: 1 << 20});
  } catch (error) {
    stdout = Buffer.from(error.stdout ?? '');
    stderr = Buffer.from(error.stderr ?? '');
    incomplete = true;
  }
  fs.writeFileSync(path.join(directory, `${name}.private.log`), Buffer.concat([stdout, stderr]), {mode: 0o600});
  return {text: stdout.toString('utf8'), incomplete};
}
export function summarizeComposeDiagnostics(statusText, logs, incomplete = false) {
  const reasons = new Set(incomplete ? ['COMPOSE_DIAGNOSTIC_CAPTURE_INCOMPLETE'] : []);
  const states = new Set(['created', 'running', 'restarting', 'removing', 'paused', 'exited', 'dead']);
  const healths = new Set(['starting', 'healthy', 'unhealthy']);
  const services = new Map();
  for (const line of statusText.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const value = JSON.parse(line);
      const rows = Array.isArray(value) ? value : [value];
      for (const row of rows) {
        if (!['minio', 'buckets'].includes(row.Service)) continue;
        const state = String(row.State).toLowerCase(), health = String(row.Health).toLowerCase();
        services.set(row.Service, {service: row.Service, state: states.has(state) ? state : 'unknown', health: healths.has(health) ? health : 'none', exit_code: Number.isInteger(row.ExitCode) && row.ExitCode >= 0 && row.ExitCode <= 255 ? row.ExitCode : null});
      }
    } catch { reasons.add('COMPOSE_DIAGNOSTIC_STATUS_INVALID'); }
  }
  for (const line of logs.split(/\r?\n/)) {
    const code = line.slice(line.lastIndexOf('|') + 1).trim();
    if (allowedCodes.has(code)) reasons.add(code);
  }
  return {schema_version: '1', stage: 'COMPOSE_DIAGNOSTICS', services: [...services.values()].sort((a,b) => a.service.localeCompare(b.service)), reason_codes: [...reasons].sort(), raw_logs_public: false};
}
if (process.argv[1] && path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1])) {
  const directory = path.resolve('work/private/compose-startup');
  fs.mkdirSync(directory, {recursive: true, mode: 0o700});
  const status = capture(directory, 'status', ['compose', 'ps', '--all', '--format', 'json']);
  const logs = capture(directory, 'services', ['compose', 'logs', '--no-color', '--tail=150']);
  console.log(JSON.stringify(summarizeComposeDiagnostics(status.text, logs.text, status.incomplete || logs.incomplete)));
}
