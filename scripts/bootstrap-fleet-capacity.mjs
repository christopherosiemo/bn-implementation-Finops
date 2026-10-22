// Explicit local opt-in. Secrets remain in ignored owner-only host directories.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
assert.equal(process.argv.length, 2, 'No alternate bootstrap arguments accepted');
const result = spawnSync(process.execPath, [fileURLToPath(new URL('./bootstrap.mjs', import.meta.url))], {
  env: {...process.env, FINOPS_BOOTSTRAP_FLEET_CAPACITY: 'true'},
  stdio: 'inherit', windowsHide: true,
});
if (result.error) throw new Error('Optional capacity credential bootstrap failed');
process.exitCode = result.status ?? 1;
