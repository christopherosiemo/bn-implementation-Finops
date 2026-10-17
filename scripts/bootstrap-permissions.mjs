// Linux permission regression: run as root in the Node 22 build container.
// The repository is read-only; every generated artifact lives in an owned temp tree.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'linux') {
  console.log('SKIP bootstrap permissions: Linux POSIX permissions are required; run this regression in the Node 22 Docker image.');
  process.exit(0);
}
assert.equal(process.getuid(), 0, 'run the regression as root inside the Node 22 Docker image so the child can switch to UID 1000');

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporaryParent = realpathSync(tmpdir());
const prefix = 'finops-bootstrap-permissions-';
const temporaryRoot = mkdtempSync(path.join(temporaryParent, prefix));
const originalUmask = process.umask(0o022);
const generatedEnv = path.join(temporaryRoot, '.env');
const generatedRealm = path.join(temporaryRoot, 'work', 'keycloak', 'finops-realm.json');
const copiedBootstrap = path.join(temporaryRoot, 'scripts', 'bootstrap.mjs');
const mode = file => statSync(file).mode & 0o777;

function bootstrap() {
  const result = spawnSync(process.execPath, [copiedBootstrap], { cwd: temporaryRoot, encoding: 'utf8', timeout: 15_000 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `isolated bootstrap failed: ${result.stderr}`);
}
function probeAsKeycloak(expectRealmReadable) {
  const code = `
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    assert.equal(process.getuid(), 1000, 'probe must actually execute as Keycloak UID 1000');
    assert.equal(process.getgid(), 1000);
    const [realm, env, readable] = process.argv.slice(1);
    if (readable === 'true') {
      assert.equal(JSON.parse(fs.readFileSync(realm, 'utf8')).realm, 'finops');
    } else {
      assert.throws(() => fs.readFileSync(realm, 'utf8'), { code: 'EACCES' }, 'legacy 0600 realm reproduces the CI permission failure');
    }
    assert.throws(() => fs.readFileSync(env, 'utf8'), { code: 'EACCES' }, 'UID 1000 must never read service secrets');
  `;
  const result = spawnSync(process.execPath, ['-e', code, generatedRealm, generatedEnv, String(expectRealmReadable)], { cwd: temporaryRoot, uid: 1000, gid: 1000, encoding: 'utf8', timeout: 15_000 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `unprivileged permission probe failed: ${result.stderr}`);
}

try {
  // mkdtemp creates 0700. Permit traversal so the probe tests the actual file
  // permissions rather than failing on the temporary directory itself.
  chmodSync(temporaryRoot, 0o755);
  mkdirSync(path.dirname(copiedBootstrap), { mode: 0o755 });
  copyFileSync(path.join(repository, 'scripts', 'bootstrap.mjs'), copiedBootstrap);
  chmodSync(copiedBootstrap, 0o644);

  bootstrap();
  assert.equal(statSync(generatedRealm).uid, 0);
  assert.equal(statSync(generatedEnv).uid, 0);
  assert.equal(mode(generatedRealm), 0o644, 'public fixture realm must be readable by the container UID');
  assert.equal(mode(generatedEnv), 0o600, 'service-secret .env must remain owner-only');
  const originalSecrets = readFileSync(generatedEnv);
  console.log('PASS bootstrap creates a 0644 fixture realm and a 0600 secret file');

  probeAsKeycloak(true);
  console.log('PASS actual UID 1000 reads the fixture realm and receives EACCES for .env');

  chmodSync(generatedRealm, 0o600);
  assert.equal(mode(generatedRealm), 0o600);
  probeAsKeycloak(false);
  console.log('PASS legacy 0600 realm reproduces the Linux permission denial');

  bootstrap();
  assert.equal(mode(generatedRealm), 0o644, 'rerunning bootstrap must repair an existing 0600 realm');
  assert.equal(mode(generatedEnv), 0o600, 'realm permission repair must not expose .env');
  assert.deepEqual(readFileSync(generatedEnv), originalSecrets, 'rerunning bootstrap must preserve existing service secrets');
  probeAsKeycloak(true);
  console.log('PASS rerunning bootstrap repairs realm permissions without changing or exposing secrets');
  console.log('\n4 Linux bootstrap permission checks passed. Isolated temporary artifacts only.');
} finally {
  process.umask(originalUmask);
  const resolved = realpathSync(temporaryRoot);
  assert.equal(path.dirname(resolved), temporaryParent, 'cleanup target must stay inside the original temporary parent');
  assert.ok(path.basename(resolved).startsWith(prefix), 'cleanup target must be this regression\'s owned directory');
  rmSync(resolved, { recursive: true, force: true });
}
