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
for (const [key, value] of Object.entries({ DB_INGESTER_PASSWORD: random(), OBJECT_ACCESS_KEY: 'raw-writer', OBJECT_SECRET_KEY: random(), AUDIT_ACCESS_KEY: 'audit-writer', AUDIT_SECRET_KEY: random(), WEBHOOK_SECRET: random() })) {
  if (!env[key]) { env[key] = value; writeFileSync(envPath, `${key}=${value}\n`, { flag: 'a', mode: 0o600 }); }
}
const roles = ['ORGANISATION_OWNER','FINOPS_ADMIN','PLATFORM_ADMIN','FINANCE','APPLICATION_OWNER','APPROVER','VIEWER','AUDITOR'];
const mapper = (name, config) => ({ name, protocol: 'openid-connect', protocolMapper: name === 'tenant_id' ? 'oidc-usermodel-attribute-mapper' : 'oidc-audience-mapper', consentRequired: false, config });
const realm = {
  realm: 'finops', enabled: true, displayName: 'Cloud Cost Autopilot · local fixture',
  registrationAllowed: false, resetPasswordAllowed: false, sslRequired: 'none',
  accessTokenLifespan: 3600, roles: { realm: roles.map(name => ({ name })) },
  clients: [{
    clientId: 'console', name: 'Autopilot console', enabled: true, protocol: 'openid-connect', publicClient: true,
    standardFlowEnabled: true, directAccessGrantsEnabled: true, serviceAccountsEnabled: false,
    redirectUris: [`http://localhost:${env.WEB_PORT}/*`, 'http://localhost:5173/*'],
    webOrigins: [`http://localhost:${env.WEB_PORT}`, 'http://localhost:5173'],
    attributes: { 'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': `http://localhost:${env.WEB_PORT}/*` },
    protocolMappers: [mapper('tenant_id', { 'user.attribute': 'tenant_id', 'claim.name': 'tenant_id', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'true' }), mapper('finops-audience', { 'included.custom.audience': 'finops', 'access.token.claim': 'true', 'id.token.claim': 'false' })],
  }],
  users: [
    { username: env.DEMO_USERNAME, firstName: 'Pilot', lastName: 'Owner', email: 'owner@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-demo'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: roles },
    { username: 'other', firstName: 'Other', lastName: 'Tenant', email: 'other@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-other'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: roles },
    { username: 'viewer', firstName: 'Read', lastName: 'Only', email: 'viewer@fixture.invalid', emailVerified: true, enabled: true, attributes: { tenant_id: ['tenant-demo'] }, credentials: [{ type: 'password', value: env.DEMO_PASSWORD, temporary: false }], realmRoles: ['VIEWER'] },
  ],
};
mkdirSync(path.join(root, 'work', 'keycloak'), { recursive: true });
// This contains public development configuration and fixture credentials only.
// Keycloak runs as a different, unprivileged UID on Linux; service secrets stay in .env (0600).
const realmPath = path.join(root, 'work', 'keycloak', 'finops-realm.json');
writeFileSync(realmPath, JSON.stringify(realm, null, 2), { mode: 0o644 });
chmodSync(realmPath, 0o644);
console.log('Local configuration ready. Service secrets are in ignored .env. Fixture login: owner / local-pilot-demo (local-only realm).');
