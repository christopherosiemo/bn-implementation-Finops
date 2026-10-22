// Guards for an explicitly requested local fixture migration/recovery test.
// No helper performs Docker, HTTP or database actions at module import time.
import assert from 'node:assert/strict';
import path from 'node:path';

const sha = /^sha256:[a-f0-9]{64}$/;
const id = /^[a-f0-9]{64}$/;
const hash = /^[a-f0-9]{64}$/;
const loopback = new Set(['localhost', '127.0.0.1', '[::1]']);
export const upgradeLabel = 'finops.recovery-upgrade.run';
export const upgradeKindLabel = 'finops.recovery-upgrade.kind';

const environment = object => Object.fromEntries((object.Config?.Env || []).map(value => {
  const at = value.indexOf('=');
  return [value.slice(0, at), value.slice(at + 1)];
}));
function url(value, message) {
  try { return new URL(value); } catch { throw new Error(message); }
}
export function localRecoveryDockerEndpoint(value) {
  return typeof value === 'string' && (value.startsWith('unix:///') || /^npipe:\/\/\/\/\.\/pipe\/[A-Za-z0-9_.-]+$/.test(value));
}
export function recoveryDockerEndpoint(contextName, context, explicitHost) {
  assert.ok(typeof contextName === 'string' && contextName.length > 0 && context.Name === contextName, 'The selected Docker context must resolve exactly');
  assert.ok(localRecoveryDockerEndpoint(context.Endpoints?.docker?.Host), 'Remote Docker contexts are forbidden');
  if (explicitHost) assert.ok(localRecoveryDockerEndpoint(explicitHost), 'Remote Docker hosts are forbidden');
  return explicitHost || context.Endpoints.docker.Host;
}

function loopbackURL(value, expectedPath) {
  const parsed = url(value, 'The fixture endpoint URL is invalid');
  assert.ok(parsed.protocol === 'http:' && loopback.has(parsed.hostname) && !parsed.username && !parsed.password && !parsed.search && !parsed.hash && parsed.pathname === expectedPath, 'Only the exact local Compose HTTP endpoint is permitted');
  return parsed;
}
function publishedEndpoint(object, targetPort, endpoint) {
  const bindings = object.NetworkSettings?.Ports?.[targetPort + '/tcp'];
  assert.ok(Array.isArray(bindings) && bindings.length === 1, 'Exactly one loopback fixture publication is required');
  const binding = bindings[0];
  assert.ok(['127.0.0.1', '::1'].includes(binding.HostIp) && binding.HostPort === (endpoint.port || '80'), 'HTTP endpoint must match the inspected Compose loopback port');
  assert.ok(endpoint.hostname === 'localhost' || endpoint.hostname === binding.HostIp || endpoint.hostname === '[::1]' && binding.HostIp === '::1', 'HTTP endpoint address must match the inspected loopback binding');
}
function databaseBinding(object, user) {
  const parsed = url(environment(object).DATABASE_URL, 'The inspected fixture database binding is invalid');
  assert.ok(['postgres:', 'postgresql:'].includes(parsed.protocol) && parsed.hostname === 'postgres' && (!parsed.port || parsed.port === '5432') && parsed.pathname === '/finops' && decodeURIComponent(parsed.username) === user && !!parsed.password && !parsed.hash && JSON.stringify([...parsed.searchParams]) === JSON.stringify([['sslmode', 'disable']]), 'The process must use its exact role in the inspected Compose PostgreSQL database without connection overrides');
}
export function validateUpgradeFixtureSources(services, workspace, api, issuer) {
  const apiURL = loopbackURL(api, '/'), issuerURL = loopbackURL(issuer, '/realms/finops');
  let project, network;
  for (const service of ['api', 'worker', 'executor', 'temporal', 'postgres', 'keycloak']) {
    const object = services[service], labels = object?.Config?.Labels || {};
    assert.ok(object?.State?.Running === true && id.test(object.Id) && sha.test(object.Image), 'Every selected fixture service must be an inspected running container');
    assert.ok(labels['com.docker.compose.service'] === service && path.resolve(labels['com.docker.compose.project.working_dir'] || '') === path.resolve(workspace), 'Compose service must belong to this exact workspace');
    assert.ok(typeof labels['com.docker.compose.project'] === 'string' && labels['com.docker.compose.project'].length > 0, 'Compose project identity is required');
    project ||= labels['com.docker.compose.project'];
    assert.ok(project === labels['com.docker.compose.project'], 'Fixture services must share one Compose project');
    const networks = Object.values(object.NetworkSettings?.Networks || {});
    assert.ok(object.HostConfig?.NetworkMode !== 'host' && networks.length === 1 && id.test(networks[0].NetworkID), 'Fixture services must use their exact private Compose network');
    network ||= networks[0].NetworkID;
    assert.ok(network === networks[0].NetworkID, 'Fixture services must share the inspected private network');
  }
  for (const service of ['api', 'worker', 'executor']) {
    const env = environment(services[service]);
    assert.ok(env.FIXTURE_MODE === 'true' && env.DATA_MODE !== 'aws' && env.APP_ROLE === service, 'The actual API, worker and executor must be fixture processes');
    databaseBinding(services[service], 'finops_' + service);
    assert.ok(env.OIDC_ISSUER === issuer && env.OIDC_AUDIENCE === 'finops', 'Fixture process issuer/audience must match the inspected identity service');
  }
  assert.ok(environment(services.worker).TEMPORAL_ADDRESS === 'temporal:7233', 'Worker must use the inspected Compose Temporal service');
  assert.ok(environment(services.temporal).POSTGRES_SEEDS === 'postgres', 'Temporal must use the inspected Compose PostgreSQL');
  const pg = environment(services.postgres);
  assert.ok(pg.POSTGRES_DB === 'finops' && pg.POSTGRES_USER === 'postgres', 'Only the known fixture cluster database is permitted');
  publishedEndpoint(services.api, '8080', apiURL);
  publishedEndpoint(services.keycloak, '8080', issuerURL);
  const host = url(environment(services.keycloak).KC_HOSTNAME, 'The inspected identity service hostname is invalid');
  assert.ok(host.origin === issuerURL.origin && host.pathname === '/', 'OIDC issuer must belong to the inspected Keycloak service');
  for (const service of ['postgres', 'temporal', 'executor', 'worker']) {
    assert.ok(!Object.values(services[service].NetworkSettings?.Ports || {}).some(values => values?.length), 'Internal fixture services may not publish host ports');
  }
  return { project, network };
}

export function migrationManifest(files) {
  assert.ok(files && typeof files === 'object' && !Array.isArray(files), 'An immutable migration manifest is required');
  const names = Object.keys(files).sort();
  assert.ok(names.length > 0 && names.every(name => /^\d{3}_[a-z0-9_]+\.sql$/.test(name) && hash.test(files[name])), 'Only bounded immutable migration names and hashes are allowed');
  return Object.fromEntries(names.map(name => [name, files[name]]));
}
export function parseImageMigrationManifest(text) {
  const entries = {};
  for (const line of text.trim().split(/\r?\n/)) {
    const match = /^([a-f0-9]{64})  (\d{3}_[a-z0-9_]+\.sql)$/.exec(line);
    assert.ok(match && !Object.hasOwn(entries, match[2]), 'The prepared image migration manifest is invalid');
    entries[match[2]] = match[1];
  }
  return migrationManifest(entries);
}
export function validatePendingMigrations(files, applied) {
  files = migrationManifest(files);
  applied = migrationManifest(applied);
  for (const [name, value] of Object.entries(applied)) assert.ok(files[name] === value, 'Already applied migration bytes must remain unchanged');
  const pending = Object.keys(files).filter(name => !Object.hasOwn(applied, name));
  assert.ok(pending.length > 0, 'Migration recovery requires a genuinely pending additive migration');
  return pending;
}
export function assertMigrationManifest(actual, expected) {
  assert.deepEqual(migrationManifest(actual), migrationManifest(expected), 'Migration contents and exact file set must match the reviewed source');
}
export function upgradeComposeOverride(image) {
  assert.ok(sha.test(image), 'An exact locally prepared image ID is required');
  return { services: Object.fromEntries(['migrate', 'api', 'worker'].map(service => [service, { image, pull_policy: 'never' }])) };
}
export function validateUpgradeContainer(object, { runID, kind, name, image, project, network }) {
  assert.ok(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(runID) && ['image-manifest', 'migrator'].includes(kind) && name === `finops-recovery-upgrade-${kind === 'image-manifest' ? 'manifest' : 'migrate'}-${runID.replaceAll('-', '')}`, 'A fresh run-specific recovery helper identity is required');
  assert.ok(object && id.test(object.Id) && object.Name === '/' + name && object.Image === image, 'Only the exact test-owned image/container may be controlled or removed');
  assert.ok(object.Config?.Labels?.[upgradeLabel] === runID && object.Config?.Labels?.[upgradeKindLabel] === kind, 'Container ownership labels must match this recovery run');
  assert.ok((object.Mounts || []).every(mount => mount.Type === 'tmpfs' && mount.Destination === '/tmp' && !mount.Source) && Object.keys(object.HostConfig?.Tmpfs || {}).every(target => target === '/tmp'), 'Recovery helper containers may use only ephemeral /tmp, never host files or volumes');
  if (kind === 'image-manifest') {
    assert.ok(object.HostConfig?.NetworkMode === 'none' && object.HostConfig?.ReadonlyRootfs === true && object.HostConfig?.CapDrop?.includes('ALL'), 'Image inspection must remain credential-free and isolated');
    assert.ok(!object.HostConfig?.Binds?.length && (object.Config?.Env || []).every(item => item.startsWith('PATH=')), 'Image inspection may not receive runtime credentials');
  } else {
    assert.ok(kind === 'migrator' && object.Config?.Labels?.['com.docker.compose.service'] === 'migrate' && object.Config?.Labels?.['com.docker.compose.project'] === project, 'Only this project migrator may be used');
    const networks = Object.values(object.NetworkSettings?.Networks || {});
    assert.ok(networks.length === 1 && networks[0].NetworkID === network, 'Migrator must use only the inspected fixture network');
    const env = environment(object);
    assert.ok(env.FIXTURE_MODE === 'true' && env.APP_ROLE === 'migrate' && env.MIGRATIONS_DIR === '/app/migrations', 'Only the fixture migration process and pinned migration directory may run');
    assert.ok(object.Config?.User === '10001:10001' && JSON.stringify(object.Config?.Entrypoint) === JSON.stringify(['/bin/sh']) && JSON.stringify(object.Config?.Cmd) === JSON.stringify(['-c', 'sleep 180']), 'Migration preparation must be an inert bounded helper before inspection');
    databaseBinding(object, 'postgres');
  }
  return object.Id;
}

const literal = value => {
  assert.ok(typeof value === 'string' && value.length > 0 && value.length <= 65536 && !value.includes('\0'), 'The captured occurrence identity is invalid');
  return "'" + value.replaceAll("'", "''") + "'";
};
export function stoppedOccurrenceSQL({ tenantID, executionID, planID, resourceID, payload }) {
  assert.ok(tenantID === 'tenant-other' && payload?.fixture === true && payload.id === planID && payload.tenant_id === tenantID && payload.operations?.length === 2 && payload.operations[0].resource_id === resourceID, 'Only the original other-tenant fixture plan may be inspected');
  return `BEGIN READ ONLY; SELECT jsonb_build_object(
    'tenant_id',e.tenant_id,'execution_id',e.id,'plan_id',p.id,'resource_id',r.id,
    'execution_owned',e.document->'restoration_owned','execution_stage',e.document->'stage',
    'resource_state',r.document->'state','stop_intent',po.stop_intent,'stop_owned',po.stop_owned,'restored',po.restored,'provider_state',po.document->'state',
    'original_plan_matches',p.document->'payload'=${literal(JSON.stringify(payload))}::jsonb AND sp.envelope->'plan'=p.document->'payload',
    'nonce_matches',sp.nonce=p.document->'payload'->>'nonce' AND po.document->>'nonce'=sp.nonce,
    'provider_target_matches',po.resource_id=(p.document->'payload'->'operations'->0->>'account_id')||':'||(p.document->'payload'->'operations'->0->>'region')||':'||(p.document->'payload'->'operations'->0->>'provider_resource_id') AND r.document->>'provider'='AWS' AND r.document->>'account_id'=p.document->'payload'->'operations'->0->>'account_id' AND r.document->>'region'=p.document->'payload'->'operations'->0->>'region' AND r.document->>'provider_resource_id'=p.document->'payload'->'operations'->0->>'provider_resource_id',
    'signed_plan_hash',encode(sha256(convert_to(sp.envelope::text,'UTF8')),'hex'),
    'signed_algorithm',sp.envelope->>'algorithm','has_signature',length(sp.envelope->>'signature')>0,
    'stop_count',(SELECT count(*) FROM audit_events WHERE tenant_id=e.tenant_id AND action='provider.stop' AND actor='executor' AND resource=r.id AND document->'details'->>'execution_id'=e.id AND document->'details'->>'provider_resource_id'=p.document->'payload'->'operations'->0->>'provider_resource_id'),
    'start_count',(SELECT count(*) FROM audit_events WHERE tenant_id=e.tenant_id AND action='provider.start' AND document->'details'->>'execution_id'=e.id))
    FROM entities e JOIN entities p ON p.tenant_id=e.tenant_id AND p.kind='change_plans' AND p.id=e.document->>'change_plan_id'
    JOIN entities r ON r.tenant_id=e.tenant_id AND r.kind='resources' AND r.id=e.document->>'resource_id'
    JOIN provider_operations po ON po.tenant_id=e.tenant_id AND po.execution_id=e.id
    JOIN signed_plans sp ON sp.tenant_id=e.tenant_id AND sp.plan_id=p.id
    WHERE e.tenant_id=${literal(tenantID)} AND e.kind='executions' AND e.id=${literal(executionID)} AND p.id=${literal(planID)} AND r.id=${literal(resourceID)}; COMMIT;`;
}
export function assertStoppedOccurrence(proof, expected, previousHash) {
  assert.ok(proof?.tenant_id === expected.tenantID && proof.execution_id === expected.executionID && proof.plan_id === expected.planID && proof.resource_id === expected.resourceID, 'The exact original occurrence must remain present');
  assert.ok(proof.execution_owned === true && proof.execution_stage === 'STOPPED' && proof.resource_state === 'stopped' && proof.stop_intent === true && proof.stop_owned === true && proof.restored === false && proof.provider_state === 'stopped', 'The original occurrence must still own an actual stopped fixture instance');
  assert.ok(proof.original_plan_matches === true && proof.nonce_matches === true && proof.provider_target_matches === true && proof.signed_algorithm === 'Ed25519' && proof.has_signature === true && hash.test(proof.signed_plan_hash), 'Original signed plan, nonce and exact native target must remain unchanged');
  assert.ok(proof.stop_count === 1 && proof.start_count === 0, 'Migration must begin before any restoration dispatch and after exactly one stop');
  if (previousHash) assert.ok(proof.signed_plan_hash === previousHash, 'Migration may not recreate or replace the original signed envelope');
  return proof.signed_plan_hash;
}
