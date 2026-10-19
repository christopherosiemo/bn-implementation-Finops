import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {summarizeComposeDiagnostics} from '../compose-startup-diagnostics.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const shell = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/sh';
const sentinel = 'fixture-only-sensitive-output';
function run(overrides = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'minio-startup-test-'));
  const executable = (name, body) => fs.writeFileSync(path.join(directory, name), `#!/bin/sh\nset -eu\n${body}\n`, {mode: 0o700});
  executable('mc', `
printf '%s\\n' '${sentinel}'
printf '%s\\n' '${sentinel}' >&2
printf '%s %s %s\\n' "$1" "\${2:-}" "\${3:-}" >> "$CASE_DIR/calls"
if [ "$1" = alias ]; then
  count=0
  if [ -f "$CASE_DIR/attempts" ]; then count=$(cat "$CASE_DIR/attempts"); fi
  count=$((count + 1)); printf '%s\\n' "$count" > "$CASE_DIR/attempts"
  if [ "$ALIAS_SUCCEED_AT" -eq 0 ] || [ "$count" -lt "$ALIAS_SUCCEED_AT" ]; then exit 1; fi
fi
if [ "\${FAIL_MODE:-}" = policy ] && [ "$1" = admin ] && [ "\${2:-}" = policy ]; then exit 1; fi
`);
  executable('timeout', `
test "$1" = --signal=TERM && test "$2" = --kill-after=1s
case "$3" in 3s|15s) ;; *) exit 98 ;; esac
printf '%s\\n' "$3" >> "$CASE_DIR/timeouts"
shift 3
exec "$@"
`);
  executable('sleep', `test "$1" = 2; printf '%s\\n' "$1" >> "$CASE_DIR/sleeps"`);
  executable('launch', `
case "$CASE_DIR" in [A-Za-z]:*) CASE_DIR=$(cygpath -u "$CASE_DIR"); INIT_SCRIPT=$(cygpath -u "$INIT_SCRIPT");; esac
export CASE_DIR INIT_SCRIPT
export PATH="$CASE_DIR:/usr/bin:/bin"
exec /bin/sh "$INIT_SCRIPT"
`);
  const env = {...process.env, CASE_DIR: directory, INIT_SCRIPT: path.join(root, 'config/minio/init-buckets.sh'), ALIAS_SUCCEED_AT: '1', MINIO_ROOT_USER: 'fixture-root', MINIO_ROOT_PASSWORD: 'fixture-root-secret', OBJECT_ACCESS_KEY: 'fixture-raw', OBJECT_SECRET_KEY: 'fixture-raw-secret', AUDIT_ACCESS_KEY: 'fixture-audit', AUDIT_SECRET_KEY: 'fixture-audit-secret', ASSESSMENT_ACCESS_KEY: 'fixture-assessor', ASSESSMENT_SECRET_KEY: 'fixture-assessor-secret', CAPACITY_ACCESS_KEY: 'fixture-capacity', CAPACITY_SECRET_KEY: 'fixture-capacity-secret', ...overrides};
  const result = spawnSync(shell, [path.join(directory, 'launch')], {env, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 15_000, maxBuffer: 128 << 10});
  const read = name => fs.existsSync(path.join(directory, name)) ? fs.readFileSync(path.join(directory, name), 'utf8').trim().split(/\r?\n/) : [];
  const evidence = {...result, calls: read('calls'), sleeps: read('sleeps'), timeouts: read('timeouts')};
  fs.rmSync(directory, {recursive: true, force: true});
  assert.equal(evidence.error, undefined);
  assert.equal((evidence.stdout + evidence.stderr).includes(sentinel), false);
  return evidence;
}

test('real shell completes every fixed provisioning operation without exposing mc output', () => {
  const result = run();
  assert.equal(result.status, 0);
  assert.equal(result.stdout + result.stderr, '');
  assert.equal(result.calls.length, 17);
  assert.equal(result.sleeps.length, 0);
  assert.deepEqual(result.timeouts, ['3s', ...Array(16).fill('15s')]);
});
test('real shell retries readiness only, with fixed backoff before successful provisioning', () => {
  const result = run({ALIAS_SUCCEED_AT: '3'});
  assert.equal(result.status, 0);
  assert.equal(result.calls.filter(x => x === 'alias set local').length, 3);
  assert.deepEqual(result.sleeps, ['2', '2']);
  assert.equal(result.calls.length, 19);
});
test('real shell stops after exactly twelve failed readiness attempts and never provisions', () => {
  const result = run({ALIAS_SUCCEED_AT: '0'});
  assert.equal(result.status, 1);
  assert.equal(result.stderr, 'MINIO_READINESS_UNAVAILABLE\n');
  assert.deepEqual(result.calls, Array(12).fill('alias set local'));
  assert.deepEqual(result.sleeps, Array(11).fill('2'));
});
test('real shell fails closed at a provisioning error without re-running a failed command', () => {
  const result = run({FAIL_MODE: 'policy'});
  assert.equal(result.status, 1);
  assert.equal(result.stderr, 'MINIO_RAW_POLICY_FAILED\n');
  assert.equal(result.calls.at(-1), 'admin policy create');
  assert.equal(result.calls.length, 6);
});
test('partial optional credentials fail closed without passing an empty secret to mc', () => {
  const result = run({ASSESSMENT_SECRET_KEY: ''});
  assert.equal(result.status, 1);
  assert.equal(result.stderr, 'MINIO_ASSESSOR_CONFIGURATION_INVALID\n');
  assert.equal(result.calls.length, 11);
});
test('missing required credentials refuse before any external command', () => {
  const result = run({MINIO_ROOT_PASSWORD: ''});
  assert.equal(result.status, 1);
  assert.equal(result.stderr, 'MINIO_CONFIGURATION_INVALID\n');
  assert.equal(result.calls.length, 0);
});
test('one-shot Compose initializer and CI startup have independent finite bounds', () => {
  const compose = fs.readFileSync(path.join(root, 'compose.yaml'), 'utf8');
  const block = compose.slice(compose.indexOf('  buckets:\n'), compose.indexOf('\n  economics:'));
  assert.match(block, /entrypoint: \[timeout, --signal=TERM, --kill-after=2s, 180s, \/bin\/sh, \/config\/init-buckets.sh\]/);
  assert.match(block, /restart: 'no'/);
  assert.doesNotMatch(block, /restart: on-failure/);
  const ci = fs.readFileSync(path.join(root, '.github/workflows/ci.yaml'), 'utf8');
  assert.match(ci, /timeout --signal=TERM --kill-after=10s 240s docker compose up --no-build -d/);
  assert.match(ci, /if: \$\{\{ failure\(\) \|\| cancelled\(\) \}\}\n        run: node scripts\/compose-startup-diagnostics.mjs/);
  assert.doesNotMatch(ci, /run: docker compose logs --no-color --tail=150/);
});
test('actual GNU timeout terminates a hung command rather than merely counting attempts', () => {
  const result = spawnSync(shell, ['-c', '/usr/bin/timeout --signal=TERM --kill-after=1s 0.1s /usr/bin/sleep 5'], {stdio: ['ignore', 'pipe', 'pipe'], timeout: 5_000});
  assert.equal(result.error, undefined);
  assert.equal(result.status, 124);
});
test('public diagnostic projection excludes arbitrary service errors, command, URL and credential text', () => {
  const sensitive = 'fixture-sensitive-url-and-secret';
  const summary = summarizeComposeDiagnostics(JSON.stringify({Service: 'buckets', State: 'restarting', Health: '', ExitCode: 1, Command: sensitive, Names: sensitive}), `buckets | ${sensitive}\nbuckets | MINIO_RAW_POLICY_FAILED\nbuckets | MINIO_UNKNOWN_${sensitive}\n`, true);
  assert.deepEqual(summary.services, [{service: 'buckets', state: 'restarting', health: 'none', exit_code: 1}]);
  assert.deepEqual(summary.reason_codes, ['COMPOSE_DIAGNOSTIC_CAPTURE_INCOMPLETE', 'MINIO_RAW_POLICY_FAILED']);
  assert.equal(JSON.stringify(summary).includes(sensitive), false);
  assert.equal(summary.raw_logs_public, false);
});
test('diagnostic public output stays bounded when Docker repeats rows or supplies unknown services', () => {
  const rows = Array.from({length: 1000}, (_, i) => JSON.stringify({Service: ['minio', 'buckets', 'unrelated'][i % 3], State: 'running', Health: '', ExitCode: 0})).join('\n');
  const summary = summarizeComposeDiagnostics(rows, '');
  assert.equal(summary.services.length, 2);
  assert.ok(Buffer.byteLength(JSON.stringify(summary)) < 2048);
});
