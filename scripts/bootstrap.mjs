import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');
const random = () => randomBytes(24).toString('hex');
if (!existsSync(envPath)) {
  const pair = generateKeyPairSync('ed25519');
  const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const seed = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  const env = {
    COMPOSE_PROJECT_NAME: 'cloud-cost-autopilot',
    POSTGRES_PASSWORD: random(), DB_API_PASSWORD: random(), DB_WORKER_PASSWORD: random(),
    DB_SIGNER_PASSWORD: random(), DB_EXECUTOR_PASSWORD: random(),
    SIGNER_TOKEN: random(), EXECUTOR_TOKEN: random(), ECONOMICS_TOKEN: random(),
    SIGNING_PRIVATE_KEY: Buffer.concat([seed, pub]).toString('base64'), SIGNING_PUBLIC_KEY: pub.toString('base64'),
    MINIO_ROOT_USER: 'autopilot-local', MINIO_ROOT_PASSWORD: random(), CLICKHOUSE_PASSWORD: random(),
    KEYCLOAK_ADMIN_PASSWORD: random(), DEMO_USERNAME: 'owner', DEMO_PASSWORD: 'local-pilot-demo',
    WEB_PORT: '3000', API_PORT: '8080', KEYCLOAK_PORT: '8081', FIXTURE_MODE: 'true',
  };
  writeFileSync(envPath, Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
}
const env = Object.fromEntries(readFileSync(envPath, 'utf8').split(/\r?\n/).filter(s => s && !s.startsWith('#')).map(s => { const i = s.indexOf('='); return [s.slice(0, i), s.slice(i + 1)]; }));
for (const [key, value] of Object.entries({ DB_INGESTER_PASSWORD: random(), DB_ACTIVITY_PASSWORD: random(), ACTIVITY_CLIENT_SECRET: random(), DB_TELEMETRY_READER_PASSWORD: random(), DB_TELEMETRY_INGRESS_PASSWORD: random(), TELEMETRY_READER_TOKEN: random(), TELEMETRY_CLIENT_SECRET: random(), DB_DEPLOYMENT_OBSERVER_PASSWORD: random(), DEPLOYMENT_OBSERVER_CLIENT_SECRET: random(), OBJECT_ACCESS_KEY: 'raw-writer', OBJECT_SECRET_KEY: random(), AUDIT_ACCESS_KEY: 'audit-writer', AUDIT_SECRET_KEY: random(), WEBHOOK_SECRET: random() })) {
  if (!env[key]) { env[key] = value; writeFileSync(envPath, `${key}=${value}\n`, { flag: 'a', mode: 0o600 }); }
}
if (!env.DB_HARDWARE_READER_PASSWORD) {
  env.DB_HARDWARE_READER_PASSWORD = random();
  writeFileSync(envPath, `DB_HARDWARE_READER_PASSWORD=${env.DB_HARDWARE_READER_PASSWORD}\n`, { flag: 'a', mode: 0o600 });
}
const roles = ['ORGANISATION_OWNER','FINOPS_ADMIN','PLATFORM_ADMIN','FINANCE','APPLICATION_OWNER','APPROVER','VIEWER','AUDITOR'];
if (['other', 'viewer', 'approver'].includes(env.DEMO_USERNAME)) throw new Error('DEMO_USERNAME collides with a reserved fixture identity');
const userProfile = {
  attributes: [
    { name: 'username', displayName: '${username}', validations: { length: { min: 3, max: 255 }, 'username-prohibited-characters': {}, 'up-username-not-idn-homograph': {} }, permissions: { view: ['admin', 'user'], edit: ['admin', 'user'] }, multivalued: false },
    { name: 'email', displayName: '${email}', validations: { email: {}, length: { max: 255 } }, required: { roles: ['user'] }, permissions: { view: ['admin', 'user'], edit: ['admin', 'user'] }, multivalued: false },
    ...['firstName', 'lastName'].map(name => ({ name, displayName: '${' + name + '}', validations: { length: { max: 255 }, 'person-name-prohibited-characters': {} }, required: { roles: ['user'] }, permissions: { view: ['admin', 'user'], edit: ['admin', 'user'] }, multivalued: false })),
    { name: 'tenant_id', displayName: 'Tenant', validations: { length: { min: 1, max: 256 }, pattern: { pattern: '^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$' } }, permissions: { view: ['admin'], edit: ['admin'] }, multivalued: false },
  ],
};
const mapper = (name, config) => ({ name, protocol: 'openid-connect', protocolMapper: name === 'tenant_id' ? 'oidc-usermodel-attribute-mapper' : 'oidc-audience-mapper', consentRequired: false, config });
const realm = {
  realm: 'finops', enabled: true, displayName: 'Cloud Cost Autopilot · local fixture',
  registrationAllowed: false, resetPasswordAllowed: false, sslRequired: 'none',
  accessTokenLifespan: 3600, roles: { realm: roles.map(name => ({ name })) },
  components: { 'org.keycloak.userprofile.UserProfileProvider': [{ name: 'declarative-user-profile', providerId: 'declarative-user-profile', config: { 'kc.user.profile.config': [JSON.stringify(userProfile)] } }] },
  clients: [{
    clientId: 'console', name: 'Autopilot console', enabled: true, protocol: 'openid-connect', publicClient: true,
    standardFlowEnabled: true, directAccessGrantsEnabled: true, serviceAccountsEnabled: false,
    redirectUris: [`http://localhost:${env.WEB_PORT}/*`, 'http://localhost:5173/*'],
    webOrigins: [`http://localhost:${env.WEB_PORT}`, 'http://localhost:5173'],
    attributes: { 'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': `http://localhost:${env.WEB_PORT}/*` },
    protocolMappers: [mapper('tenant_id', { 'user.attribute': 'tenant_id', 'claim.name': 'tenant_id', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'true' }), mapper('finops-audience', { 'included.custom.audience': 'finops', 'access.token.claim': 'true', 'id.token.claim': 'false' })],
  }, {
    clientId: 'activity-collector', name: 'Independent workload activity collector', enabled: true,
    protocol: 'openid-connect', publicClient: false, secret: env.ACTIVITY_CLIENT_SECRET,
    standardFlowEnabled: false, directAccessGrantsEnabled: false, serviceAccountsEnabled: true,
    protocolMappers: [
      mapper('activity-audience', { 'included.custom.audience': 'finops-activity', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
      { name: 'activity-tenant', protocol: 'openid-connect', protocolMapper: 'oidc-hardcoded-claim-mapper', consentRequired: false, config: { 'claim.name': 'tenant_id', 'claim.value': 'tenant-demo', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'false' } },
    ],
  }, {
    clientId: 'telemetry-collector', name: 'Independent native telemetry collector', enabled: true,
    protocol: 'openid-connect', publicClient: false, secret: env.TELEMETRY_CLIENT_SECRET,
    standardFlowEnabled: false, directAccessGrantsEnabled: false, serviceAccountsEnabled: true,
    protocolMappers: [
      mapper('telemetry-audience', { 'included.custom.audience': 'finops-telemetry', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
      { name: 'telemetry-tenant', protocol: 'openid-connect', protocolMapper: 'oidc-hardcoded-claim-mapper', consentRequired: false, config: { 'claim.name': 'tenant_id', 'claim.value': 'tenant-demo', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'false' } },
    ],
  }, {
    clientId: 'deployment-observer', name: 'Customer pipeline receipt observer (local fixture)', enabled: true,
    protocol: 'openid-connect', publicClient: false, secret: env.DEPLOYMENT_OBSERVER_CLIENT_SECRET,
    standardFlowEnabled: false, directAccessGrantsEnabled: false, serviceAccountsEnabled: true,
    protocolMappers: [
      mapper('deployment-audience', { 'included.custom.audience': 'finops-deployment-observer', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
      { name: 'deployment-tenant', protocol: 'openid-connect', protocolMapper: 'oidc-hardcoded-claim-mapper', consentRequired: false, config: { 'claim.name': 'tenant_id', 'claim.value': 'tenant-demo', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'false' } },
    ],
  }],
  users: [
    { username: env.DEMO_USERNAME, firstName: 'Pilot', lastName: 'Owner', email: 'owner@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-demo'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: roles },
    { username: 'other', firstName: 'Other', lastName: 'Tenant', email: 'other@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-other'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: roles },
    { username: 'viewer', firstName: 'Read', lastName: 'Only', email: 'viewer@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-demo'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: ['VIEWER'] },
    { username: 'approver', firstName: 'Independent', lastName: 'Approver', email: 'approver@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-demo'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: ['APPROVER'] },
  ],
};
mkdirSync(path.join(root, 'work', 'keycloak'), { recursive: true });
// This contains public development configuration and fixture credentials only.
// Keycloak runs as a different, unprivileged UID on Linux; service secrets stay in .env (0600).
const realmPath = path.join(root, 'work', 'keycloak', 'finops-realm.json');
writeFileSync(realmPath, JSON.stringify(realm, null, 2), { mode: 0o644 });
chmodSync(realmPath, 0o644);
console.log('Local configuration ready. Service secrets are in ignored .env. Fixture login: owner / local-pilot-demo (local-only realm).');
