import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { assertMigrationManifest, assertStoppedOccurrence, parseImageMigrationManifest, recoveryDockerEndpoint, stoppedOccurrenceSQL, upgradeComposeOverride, upgradeKindLabel, upgradeLabel, validatePendingMigrations, validateUpgradeContainer, validateUpgradeFixtureSources } from '../lib/recovery-upgrade.mjs';

const image = 'sha256:' + 'a'.repeat(64), network = 'b'.repeat(64), workspace = path.resolve('fixture-workspace');
const runID = '12345678-1234-1234-1234-123456789abc';
const api = 'http://localhost:8080', issuer = 'http://localhost:8081/realms/finops';
const clone = value => structuredClone(value);
function sources() {
  const result = {};
  for (const [index, service] of ['api', 'worker', 'executor', 'temporal', 'postgres', 'keycloak'].entries()) {
    const env = [];
    if (['api', 'worker', 'executor'].includes(service)) env.push('FIXTURE_MODE=true', 'APP_ROLE=' + service, 'OIDC_ISSUER=' + issuer, 'OIDC_AUDIENCE=finops', `DATABASE_URL=postgres://finops_${service}:fixture-password@postgres:5432/finops?sslmode=disable`);
    if (service === 'worker') env.push('TEMPORAL_ADDRESS=temporal:7233');
    if (service === 'temporal') env.push('POSTGRES_SEEDS=postgres');
    if (service === 'postgres') env.push('POSTGRES_DB=finops', 'POSTGRES_USER=postgres');
    if (service === 'keycloak') env.push('KC_HOSTNAME=http://localhost:8081');
    result[service] = { Id: String(index + 1).repeat(64), Image: image, State: { Running: true }, Config: { Env: env, Labels: { 'com.docker.compose.service': service, 'com.docker.compose.project': 'fixture-project', 'com.docker.compose.project.working_dir': workspace } }, HostConfig: { NetworkMode: 'fixture_private' }, NetworkSettings: { Networks: { fixture_private: { NetworkID: network } }, Ports: ['api', 'keycloak'].includes(service) ? { '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: service === 'api' ? '8080' : '8081' }] } : {} } };
  }
  return result;
}
test('freeze only the exact selected local Docker transport', () => {
  const context = { Name: 'local-fixture', Endpoints: { docker: { Host: 'unix:///var/run/docker.sock' } } };
  assert.equal(recoveryDockerEndpoint(context.Name, context), context.Endpoints.docker.Host);
  assert.equal(recoveryDockerEndpoint(context.Name, context, 'npipe:////./pipe/dockerDesktopLinuxEngine'), 'npipe:////./pipe/dockerDesktopLinuxEngine');
  for (const remote of ['tcp://127.0.0.1:2375', 'ssh://host', 'tcp://customer:2376']) {
    assert.throws(() => recoveryDockerEndpoint(context.Name, context, remote));
    const changed = clone(context); changed.Endpoints.docker.Host = remote;
    assert.throws(() => recoveryDockerEndpoint(context.Name, changed));
  }
  assert.throws(() => recoveryDockerEndpoint('other', context));
});

test('bind HTTP issuer/API to inspected fixture processes, project, network and database roles', () => {
  const accepted = sources();
  assert.deepEqual(validateUpgradeFixtureSources(accepted, workspace, api, issuer), { project: 'fixture-project', network });
  const bad = {
    'live API': value => { value.api.Config.Env[0] = 'FIXTURE_MODE=false'; },
    'live executor': value => { value.executor.Config.Env.push('DATA_MODE=aws'); },
    'different DB': value => { value.api.Config.Env.push('DATABASE_URL=postgres://finops_api:fixture@elsewhere/finops?sslmode=disable'); },
    'different role': value => { value.worker.Config.Env.push('DATABASE_URL=postgres://postgres:fixture@postgres/finops?sslmode=disable'); },
    'different database': value => { value.executor.Config.Env.push('DATABASE_URL=postgres://finops_executor:fixture@postgres/customer?sslmode=disable'); },
    'different workspace': value => { value.postgres.Config.Labels['com.docker.compose.project.working_dir'] = path.resolve('customer'); },
    'different project': value => { value.postgres.Config.Labels['com.docker.compose.project'] = 'customer'; },
    'wrong service': value => { value.api.Config.Labels['com.docker.compose.service'] = 'customer'; },
    'different network': value => { value.executor.NetworkSettings.Networks.fixture_private.NetworkID = 'c'.repeat(64); },
    'extra network': value => { value.worker.NetworkSettings.Networks.other = { NetworkID: 'c'.repeat(64) }; },
    'external publication': value => { value.api.NetworkSettings.Ports['8080/tcp'][0].HostIp = '0.0.0.0'; },
    'wrong API port': value => { value.api.NetworkSettings.Ports['8080/tcp'][0].HostPort = '9090'; },
    'wrong issuer port': value => { value.keycloak.NetworkSettings.Ports['8080/tcp'][0].HostPort = '9090'; },
    'unrelated issuer': value => { value.api.Config.Env.push('OIDC_ISSUER=http://localhost:9999/realms/finops'); },
    'wrong Keycloak hostname': value => { value.keycloak.Config.Env.push('KC_HOSTNAME=http://localhost:9999'); },
    'stopped service': value => { value.postgres.State.Running = false; },
    'published PostgreSQL': value => { value.postgres.NetworkSettings.Ports['5432/tcp'] = [{ HostIp: '127.0.0.1', HostPort: '5432' }]; },
  };
  for (const [label, change] of Object.entries(bad)) { const value = sources(); change(value); assert.throws(() => validateUpgradeFixtureSources(value, workspace, api, issuer), undefined, label); }
  for (const query of ['host=customer&sslmode=disable', 'sslmode=disable&dbname=customer', 'sslmode=disable&user=postgres', 'sslmode=disable&sslmode=require', 'sslmode=disable&options=-crole=postgres', 'sslmode=disable#other']) {
    const value = sources(); value.api.Config.Env.push('DATABASE_URL=postgres://finops_api:fixture-secret@postgres/finops?' + query);
    assert.throws(() => validateUpgradeFixtureSources(value, workspace, api, issuer));
  }
  for (const wrong of ['http://localhost:9999', 'http://127.0.0.2:8080', 'http://localhost:8080/proxy', 'https://localhost:8080', 'http://u:secret@localhost:8080']) assert.throws(() => validateUpgradeFixtureSources(sources(), workspace, wrong, issuer));
});

test('pinned override is exactly three image-only service entries and cannot use a mutable tag', () => {
  const override = upgradeComposeOverride(image);
  assert.deepEqual(Object.keys(override.services).sort(), ['api', 'migrate', 'worker']);
  for (const service of Object.values(override.services)) assert.deepEqual(service, { image, pull_policy: 'never' });
  assert.ok(!JSON.stringify(override).includes('environment'));
  for (const reference of ['cloud-cost-autopilot-go:local', 'latest', 'sha256:bad', '']) assert.throws(() => upgradeComposeOverride(reference));
});

test('image and applied migration manifests preserve exact contents, file set and a real pending upgrade', () => {
  const before = { '026_hardware_identity.sql': 'c'.repeat(64) };
  const expected = { ...before, '027_fleet_configuration.sql': 'd'.repeat(64) };
  assert.deepEqual(validatePendingMigrations(expected, before), ['027_fleet_configuration.sql']);
  assertMigrationManifest(parseImageMigrationManifest(Object.entries(expected).map(([name, value]) => value + '  ' + name).join('\n')), expected);
  assert.throws(() => validatePendingMigrations(expected, expected));
  assert.throws(() => validatePendingMigrations(expected, { '026_hardware_identity.sql': 'e'.repeat(64) }));
  assert.throws(() => assertMigrationManifest({ ...expected, '028_unreviewed.sql': 'e'.repeat(64) }, expected));
  assert.throws(() => assertMigrationManifest(before, expected));
  assert.throws(() => parseImageMigrationManifest('c'.repeat(64) + '  unexpected.sql'));
  assert.throws(() => parseImageMigrationManifest(('c'.repeat(64) + '  026_hardware_identity.sql\n').repeat(2)));
});

function descriptor(kind) { return { kind, runID, image, name: `finops-recovery-upgrade-${kind === 'image-manifest' ? 'manifest' : 'migrate'}-${runID.replaceAll('-', '')}`, project: 'fixture-project', network }; }
function owned(kind) {
  const d = descriptor(kind);
  return { Id: 'f'.repeat(64), Name: '/' + d.name, Image: image, State: { Running: true }, Mounts: [], Config: { User: '10001:10001', Labels: { [upgradeLabel]: runID, [upgradeKindLabel]: kind, 'com.docker.compose.service': 'migrate', 'com.docker.compose.project': 'fixture-project' }, Env: kind === 'image-manifest' ? ['PATH=/usr/bin'] : ['FIXTURE_MODE=true', 'APP_ROLE=migrate', 'MIGRATIONS_DIR=/app/migrations', 'DATABASE_URL=postgres://postgres:fixture-password@postgres:5432/finops?sslmode=disable'], Entrypoint: ['/bin/sh'], Cmd: ['-c', 'sleep 180'] }, HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, CapDrop: ['ALL'] }, NetworkSettings: { Networks: { fixture_private: { NetworkID: network } } } };
}
test('cleanup/pre-dispatch guard requires exact owned helper, pinned image and inert migration mode', () => {
  for (const kind of ['image-manifest', 'migrator']) {
    validateUpgradeContainer(owned(kind), descriptor(kind));
    const ephemeral = owned(kind); ephemeral.Mounts = [{ Type: 'tmpfs', Destination: '/tmp', Source: '' }]; ephemeral.HostConfig.Tmpfs = { '/tmp': 'rw,nosuid,size=16m' }; validateUpgradeContainer(ephemeral, descriptor(kind));
    for (const change of [v => { v.Name = '/user-postgres'; }, v => { v.Image = 'sha256:' + 'e'.repeat(64); }, v => { v.Config.Labels[upgradeLabel] = 'other'; }, v => { v.Mounts = [{ Type: 'bind', Destination: '/tmp', Source: '/host/private' }]; }, v => { v.Mounts = [{ Type: 'volume', Destination: '/data', Source: 'user' }]; }]) {
      const value = owned(kind); change(value); assert.throws(() => validateUpgradeContainer(value, descriptor(kind)));
    }
  }
  for (const change of [v => { v.Config.Cmd = ['-mode', 'migrate']; }, v => { v.Config.Entrypoint = ['/app/finops']; }, v => { v.Config.Env.push('MIGRATIONS_DIR=/customer'); }, v => { v.Config.Env.push('DATABASE_URL=postgres://postgres:fixture@postgres/finops?sslmode=disable&host=customer'); }, v => { v.Config.User = 'root'; }, v => { v.NetworkSettings.Networks.fixture_private.NetworkID = 'c'.repeat(64); }]) {
    const value = owned('migrator'); change(value); assert.throws(() => validateUpgradeContainer(value, descriptor('migrator')));
  }
  const credential = owned('image-manifest'); credential.Config.Env.push('AWS_SECRET_ACCESS_KEY=fixture-only'); assert.throws(() => validateUpgradeContainer(credential, descriptor('image-manifest')));
});

test('exact original signed stopped ownership is required both before and after DDL', () => {
  const expected = { tenantID: 'tenant-other', executionID: 'execution-one', planID: 'plan-one', resourceID: 'resource-one', payload: { id: 'plan-one', tenant_id: 'tenant-other', fixture: true, nonce: "original'nonce", operations: [{ resource_id: 'resource-one' }, {}] } };
  const proof = { tenant_id: expected.tenantID, execution_id: expected.executionID, plan_id: expected.planID, resource_id: expected.resourceID, execution_owned: true, execution_stage: 'STOPPED', resource_state: 'stopped', stop_intent: true, stop_owned: true, restored: false, provider_state: 'stopped', original_plan_matches: true, nonce_matches: true, provider_target_matches: true, signed_plan_hash: 'd'.repeat(64), signed_algorithm: 'Ed25519', has_signature: true, stop_count: 1, start_count: 0 };
  const original = assertStoppedOccurrence(proof, expected);
  assert.equal(assertStoppedOccurrence(clone(proof), expected, original), original);
  for (const [field, value] of Object.entries({ tenant_id: 'tenant-demo', execution_id: 'different', execution_owned: false, execution_stage: 'RESTORING', resource_state: 'running', stop_intent: false, stop_owned: false, restored: true, provider_state: 'running', original_plan_matches: false, nonce_matches: false, provider_target_matches: false, signed_algorithm: 'other', has_signature: false, stop_count: 2, start_count: 1, signed_plan_hash: 'e'.repeat(64) })) {
    const changed = clone(proof); changed[field] = value;
    assert.throws(() => assertStoppedOccurrence(changed, expected, original), undefined, field);
  }
  const sql = stoppedOccurrenceSQL(expected);
  assert.ok(sql.startsWith('BEGIN READ ONLY;') && sql.endsWith('COMMIT;') && sql.includes("original''nonce") && sql.includes("po.document->'state'") && sql.includes('sp.envelope::text'));
  assert.ok(!/\b(INSERT|UPDATE|DELETE|ALTER|CREATE)\b/.test(sql));
  assert.throws(() => stoppedOccurrenceSQL({ ...expected, tenantID: 'customer' }));
  assert.throws(() => stoppedOccurrenceSQL({ ...expected, payload: { ...expected.payload, fixture: false } }));
});
