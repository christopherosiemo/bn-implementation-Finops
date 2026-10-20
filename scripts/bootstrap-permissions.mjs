// Linux permission regression: run as root in the Node 22 build container.
// The repository is read-only; every generated artifact lives in an owned temp tree.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
const assessmentDirectory = path.join(temporaryRoot, 'work', 'private', 'fleet-assessment-secrets');
const assessmentFiles = ['database', 'access-key', 'secret-key'].map(name => path.join(assessmentDirectory, name));
const copiedBootstrap = path.join(temporaryRoot, 'scripts', 'bootstrap.mjs');
const mode = file => statSync(file).mode & 0o777;

function bootstrap(capacity = false, storage = false, objectStorage = false, s3Readonly = false) {
  const result = spawnSync(process.execPath, [copiedBootstrap], { cwd: temporaryRoot, env: {...process.env, FINOPS_BOOTSTRAP_FLEET_CAPACITY: String(capacity), FINOPS_BOOTSTRAP_STORAGE_ASSESSOR: String(storage), FINOPS_BOOTSTRAP_OBJECT_STORAGE_ASSESSOR: String(objectStorage), FINOPS_BOOTSTRAP_S3_READONLY: String(s3Readonly)}, encoding: 'utf8', timeout: 15_000 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `isolated bootstrap failed: ${result.stderr}`);
}
function probeAsKeycloak(expectRealmReadable) {
  const code = `
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    assert.equal(process.getuid(), 1000, 'probe must actually execute as Keycloak UID 1000');
    assert.equal(process.getgid(), 1000);
    const [realm, env, readable, ...assessmentFiles] = process.argv.slice(1);
    if (readable === 'true') {
      assert.equal(JSON.parse(fs.readFileSync(realm, 'utf8')).realm, 'finops');
    } else {
      assert.throws(() => fs.readFileSync(realm, 'utf8'), { code: 'EACCES' }, 'legacy 0600 realm reproduces the CI permission failure');
    }
    assert.throws(() => fs.readFileSync(env, 'utf8'), { code: 'EACCES' }, 'UID 1000 must never read service secrets');
    for (const file of assessmentFiles) assert.throws(() => fs.readFileSync(file, 'utf8'), { code: 'EACCES' }, 'UID 1000 must never read assessment secrets');
  `;
  const result = spawnSync(process.execPath, ['-e', code, generatedRealm, generatedEnv, String(expectRealmReadable), ...assessmentFiles], { cwd: temporaryRoot, uid: 1000, gid: 1000, encoding: 'utf8', timeout: 15_000 });
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
  assert.ok(!readFileSync(generatedEnv, 'utf8').includes('DB_GROUP_CAPACITY_PASSWORD='), 'ordinary bootstrap must not enable a capacity LOGIN');
  for (const key of ['DB_STORAGE_ANALYST_PASSWORD', 'STORAGE_ASSESSOR_ACCESS_KEY', 'STORAGE_ASSESSOR_SECRET_KEY']) assert.ok(!readFileSync(generatedEnv, 'utf8').includes(key+'='), 'ordinary bootstrap must not commission storage advice');
  for (const key of ['DB_OBJECT_STORAGE_ANALYST_PASSWORD', 'OBJECT_STORAGE_ASSESSOR_ACCESS_KEY', 'OBJECT_STORAGE_ASSESSOR_SECRET_KEY']) assert.ok(!readFileSync(generatedEnv, 'utf8').includes(key+'='), 'ordinary bootstrap must not commission S3 advice');
  for (const key of ['S3_OBJECT_IDENTITY_KEY_HEX', 'S3_OBJECT_IDENTITY_KEY_VERSION']) assert.ok(!readFileSync(generatedEnv, 'utf8').includes(key+'='), 'ordinary bootstrap must not commission object HMAC identity');
  assert.equal(existsSync(path.join(temporaryRoot, 'work', 'private', 'fleet-capacity-secrets')), false);
  assert.equal(statSync(generatedRealm).uid, 0);
  assert.equal(statSync(generatedEnv).uid, 0);
  assert.equal(mode(generatedRealm), 0o644, 'public fixture realm must be readable by the container UID');
  assert.equal(mode(generatedEnv), 0o600, 'service-secret .env must remain owner-only');
  assert.equal(mode(path.join(temporaryRoot, 'work')), 0o755, 'shared work directory must permit public realm traversal');
  assert.equal(mode(path.dirname(assessmentDirectory)), 0o700, 'private evidence subtree remains owner-only');
  assert.equal(mode(assessmentDirectory), 0o700, 'assessment source-secret directory remains owner-only');
  for (const file of assessmentFiles) assert.equal(mode(file), 0o444, 'private source secret is read-only for copying into Linux files');
  const originalAssessmentSecrets = assessmentFiles.map(file => readFileSync(file));
  const originalSecrets = readFileSync(generatedEnv);
  const realm = JSON.parse(readFileSync(generatedRealm, 'utf8'));
  const approver = realm.users.filter(user => user.username === 'approver');
  assert.equal(approver.length, 1, 'one distinct fixture approver is installed');
  assert.deepEqual(approver[0].realmRoles, ['APPROVER'], 'independent approver receives no owner or execution role');
  assert.deepEqual(approver[0].attributes.tenant_id, ['tenant-demo']);
  assert.notEqual(approver[0].username, realm.users[0].username);
  const profile = JSON.parse(realm.components['org.keycloak.userprofile.UserProfileProvider'][0].config['kc.user.profile.config'][0]);
  const tenant = profile.attributes.filter(attribute => attribute.name === 'tenant_id');
  assert.equal(tenant.length, 1);
  assert.deepEqual(tenant[0].permissions, { view: ['admin'], edit: ['admin'] }, 'users cannot edit the token tenant binding');
  assert.equal(tenant[0].multivalued, false);
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
  assert.deepEqual(assessmentFiles.map(file => readFileSync(file)), originalAssessmentSecrets, 'rerunning bootstrap preserves assessment secret values');
  probeAsKeycloak(true);
  console.log('PASS rerunning bootstrap repairs realm permissions without changing or exposing secrets');
  bootstrap(true);
  const capacityDirectory = path.join(temporaryRoot, 'work', 'private', 'fleet-capacity-secrets');
  const capacityFiles = ['database', 'access-key', 'secret-key', 'reader-token', 'model-token'].map(name => path.join(capacityDirectory, name));
  assert.equal(mode(capacityDirectory), 0o700);
  for (const file of capacityFiles) assert.equal(mode(file), 0o444);
  const capacitySecrets = capacityFiles.map(file => readFileSync(file));
  assert.notDeepEqual(capacitySecrets[0], originalAssessmentSecrets[0], 'capacity database login must be distinct');
  assert.notDeepEqual(capacitySecrets[1], originalAssessmentSecrets[1], 'capacity archive principal must be distinct');
  assert.notDeepEqual(capacitySecrets[2], originalAssessmentSecrets[2], 'capacity archive secret must be distinct');
  assert.notDeepEqual(capacitySecrets[3], capacitySecrets[4], 'reader and model credentials must differ');
  const denied = spawnSync(process.execPath, ['-e', `const fs=require('node:fs'),assert=require('node:assert/strict');assert.equal(process.getuid(),1000);for(const file of process.argv.slice(1))assert.throws(()=>fs.readFileSync(file),{code:'EACCES'});`, ...capacityFiles], {cwd:temporaryRoot,uid:1000,gid:1000,encoding:'utf8',timeout:15_000});
  assert.equal(denied.status, 0, 'actual UID 1000 must not read optional capacity source secrets');
  bootstrap(true);
  assert.deepEqual(capacityFiles.map(file => readFileSync(file)), capacitySecrets);
  assert.deepEqual(assessmentFiles.map(file => readFileSync(file)), originalAssessmentSecrets);
  probeAsKeycloak(true);
  console.log('PASS optional capacity credentials are distinct, private and stable; ordinary bootstrap leaves them absent');
  const beforeStorage = readFileSync(generatedEnv, 'utf8');
  bootstrap(true, true);
  const withStorage = readFileSync(generatedEnv, 'utf8');
  assert.ok(withStorage.startsWith(beforeStorage), 'storage commissioning must preserve all existing credentials');
  const values = Object.fromEntries(withStorage.trim().split('\n').map(line => { const at=line.indexOf('='); return [line.slice(0,at),line.slice(at+1)]; }));
  assert.ok(values.DB_STORAGE_ANALYST_PASSWORD && values.STORAGE_ASSESSOR_SECRET_KEY);
  assert.equal(values.STORAGE_ASSESSOR_ACCESS_KEY, 'storage-assessor');
  assert.notEqual(values.DB_STORAGE_ANALYST_PASSWORD, values.DB_DATABASE_ANALYST_PASSWORD);
  assert.notEqual(values.STORAGE_ASSESSOR_ACCESS_KEY, values.DATABASE_ASSESSOR_ACCESS_KEY);
  assert.notEqual(values.STORAGE_ASSESSOR_SECRET_KEY, values.DATABASE_ASSESSOR_SECRET_KEY);
  assert.equal(mode(generatedEnv), 0o600);
  bootstrap(true, true);
  assert.equal(readFileSync(generatedEnv, 'utf8'), withStorage, 'storage credentials must remain stable on explicit replay');
  probeAsKeycloak(true);
  console.log('PASS optional storage credentials are independent, owner-only and stable; ordinary bootstrap leaves them absent');
  bootstrap(true, true, false, true);
  const withS3Readonly = readFileSync(generatedEnv, 'utf8');
  assert.ok(withS3Readonly.startsWith(withStorage));
  const identityValues = Object.fromEntries(withS3Readonly.trim().split('\n').map(line => { const at=line.indexOf('='); return [line.slice(0,at),line.slice(at+1)]; }));
  assert.match(identityValues.S3_OBJECT_IDENTITY_KEY_HEX, /^[a-f0-9]{64}$/);
  assert.equal(identityValues.S3_OBJECT_IDENTITY_KEY_VERSION, '1');
  assert.ok(!withS3Readonly.includes('DB_OBJECT_STORAGE_ANALYST_PASSWORD='), 'S3 source identity commissioning cannot enable the analytical LOGIN');
  assert.equal(mode(generatedEnv), 0o600);
  bootstrap(true, true, false, true);
  assert.equal(readFileSync(generatedEnv, 'utf8'), withS3Readonly, 'explicit S3 source replay preserves object identity key/version');
  const incompleteIdentity = withS3Readonly.replace(/^S3_OBJECT_IDENTITY_KEY_HEX=.*\n/m, '');
  writeFileSync(generatedEnv, incompleteIdentity, { mode: 0o600 });
  const refusedIdentity = spawnSync(process.execPath, [copiedBootstrap], { cwd: temporaryRoot, env: {...process.env, FINOPS_BOOTSTRAP_FLEET_CAPACITY: 'false', FINOPS_BOOTSTRAP_STORAGE_ASSESSOR: 'false', FINOPS_BOOTSTRAP_OBJECT_STORAGE_ASSESSOR: 'false', FINOPS_BOOTSTRAP_S3_READONLY: 'true'}, encoding: 'utf8', timeout: 15_000 });
  assert.equal(refusedIdentity.status, 1); assert.match(refusedIdentity.stderr, /S3_OBJECT_IDENTITY_CONFIGURATION_INCOMPLETE/);
  assert.equal(readFileSync(generatedEnv, 'utf8'), incompleteIdentity, 'partial identity must not silently rotate a key under an existing version');
  writeFileSync(generatedEnv, withS3Readonly, { mode: 0o600 });
  probeAsKeycloak(true);
  console.log('PASS optional S3 object identity is privately generated, replay stable and independent of analytical commissioning');
  bootstrap(true, true, true, true);
  const withObjectStorage = readFileSync(generatedEnv, 'utf8');
  assert.ok(withObjectStorage.startsWith(withStorage), 'S3 commissioning preserves all existing credentials');
  const objectValues = Object.fromEntries(withObjectStorage.trim().split('\n').map(line => { const at=line.indexOf('='); return [line.slice(0,at),line.slice(at+1)]; }));
  assert.ok(objectValues.DB_OBJECT_STORAGE_ANALYST_PASSWORD && objectValues.OBJECT_STORAGE_ASSESSOR_SECRET_KEY);
  assert.equal(objectValues.OBJECT_STORAGE_ASSESSOR_ACCESS_KEY, 'object-storage-assessor');
  for (const earlier of ['DB_API_PASSWORD', 'DB_STORAGE_ANALYST_PASSWORD', 'DB_DATABASE_ANALYST_PASSWORD']) assert.notEqual(objectValues.DB_OBJECT_STORAGE_ANALYST_PASSWORD, objectValues[earlier]);
  for (const earlier of ['OBJECT_ACCESS_KEY', 'AUDIT_ACCESS_KEY', 'STORAGE_ASSESSOR_ACCESS_KEY', 'DATABASE_ASSESSOR_ACCESS_KEY']) assert.notEqual(objectValues.OBJECT_STORAGE_ASSESSOR_ACCESS_KEY, objectValues[earlier]);
  for (const earlier of ['OBJECT_SECRET_KEY', 'AUDIT_SECRET_KEY', 'STORAGE_ASSESSOR_SECRET_KEY', 'DATABASE_ASSESSOR_SECRET_KEY']) assert.notEqual(objectValues.OBJECT_STORAGE_ASSESSOR_SECRET_KEY, objectValues[earlier]);
  assert.equal(mode(generatedEnv), 0o600);
  bootstrap(true, true, true, true);
  assert.equal(readFileSync(generatedEnv, 'utf8'), withObjectStorage, 'S3 credentials remain stable on explicit replay');
  probeAsKeycloak(true);
  console.log('PASS optional S3 credentials are distinct, owner-only and replay stable; no ordinary installation enables them');
  console.log('\n8 Linux bootstrap permission checks passed. Isolated temporary artifacts only.');
} finally {
  process.umask(originalUmask);
  const resolved = realpathSync(temporaryRoot);
  assert.equal(path.dirname(resolved), temporaryParent, 'cleanup target must stay inside the original temporary parent');
  assert.ok(path.basename(resolved).startsWith(prefix), 'cleanup target must be this regression\'s owned directory');
  rmSync(resolved, { recursive: true, force: true });
}
