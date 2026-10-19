import test from 'node:test';
import assert from 'node:assert/strict';
import { fleetHistoryEnvironment, validateFleetHistoryMinioImage, validateFleetHistoryObject, validateFleetHistorySources } from '../fleet-history-lab.mjs';

test('History runner generates isolated local service credentials without cloud or main credentials', () => {
  const env = fleetHistoryEnvironment('a'.repeat(64), 'history' + 'b'.repeat(32), 'c'.repeat(64));
  assert.ok(env.test.includes('@postgres:5432/postgres?sslmode=disable\n'));
  assert.ok(env.test.includes('TEST_FLEET_HISTORY_S3_ENDPOINT=http://minio:9000\n'));
  assert.ok(env.test.includes('AWS_EC2_METADATA_DISABLED=true\n'));
  assert.ok(!/AWS_ACCESS_KEY|AWS_SECRET|ROLE_ARN|SIGNER|EXECUTOR|OIDC/.test(env.test));
  for (const invalid of ['short', 'a'.repeat(20) + '\nsecret', 'https://external.invalid', 'a'.repeat(129)]) assert.throws(() => fleetHistoryEnvironment(invalid, 'b'.repeat(32), 'c'.repeat(32)));
});
test('History runner refuses nonfixture or foreign Compose sources and changed MinIO provenance', () => {
  assert.throws(() => validateFleetHistorySources({}, '/workspace'));
  const image = { Id: 'sha256:' + 'a'.repeat(64), Config: { Labels: { 'org.opencontainers.image.source': 'https://github.com/minio/minio', 'org.opencontainers.image.revision': '0d7408fc9969caf07de6a8c3a84f9fbb10a6739e', 'org.opencontainers.image.version': 'RELEASE.2025-04-22T22-12-26Z' } } };
  validateFleetHistoryMinioImage(image, image.Id);
  for (const key of Object.keys(image.Config.Labels)) { const changed = structuredClone(image); changed.Config.Labels[key] = 'unapproved'; assert.throws(() => validateFleetHistoryMinioImage(changed, image.Id)); }
  assert.throws(() => validateFleetHistoryMinioImage(image, 'sha256:' + 'b'.repeat(64)));
});
test('History cleanup is bound to exact owned name, image, internal network and confined containers', () => {
  const id = '12345678-1234-1234-1234-123456789abc', prefix = 'finops-history-' + id.replaceAll('-', ''), network = prefix + '-private', name = prefix + '-minio', image = 'sha256:' + 'a'.repeat(64);
  const net = { Name: network, Labels: { 'finops.local-fleet-history.run': id }, Driver: 'bridge', Internal: true, Options: {} };
  validateFleetHistoryObject(net, id, 'network', network, network);
  validateFleetHistoryObject({ ...net, Options: { 'com.docker.network.enable_ipv4': 'true', 'com.docker.network.enable_ipv6': 'false' }, EnableIPv4: true, EnableIPv6: false }, id, 'network', network, network);
  const container = { Name: '/' + name, Image: image, Config: { Labels: { 'finops.local-fleet-history.run': id } }, HostConfig: { NetworkMode: network, Privileged: false, ReadonlyRootfs: true, PortBindings: {}, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'] } };
  validateFleetHistoryObject(container, id, 'container', name, network, image);
  for (const mutate of [o => o.Name = '/postgres', o => o.Image = 'foreign', o => o.Config.Labels['finops.local-fleet-history.run'] = 'foreign', o => o.HostConfig.NetworkMode = 'host', o => o.HostConfig.Privileged = true, o => o.HostConfig.ReadonlyRootfs = false, o => o.HostConfig.PortBindings['9000/tcp'] = [], o => o.HostConfig.CapAdd = ['SYS_ADMIN'], o => o.HostConfig.SecurityOpt = []]) { const changed = structuredClone(container); mutate(changed); assert.throws(() => validateFleetHistoryObject(changed, id, 'container', name, network, image)); }
  for (const mutate of [o => o.Internal = false, o => o.Options = { 'com.docker.network.bridge.name': 'foreign' }, o => o.Options = { 'com.docker.network.enable_ipv4': 'false' }, o => o.Options = { 'com.docker.network.enable_ipv6': 'true' }, o => o.EnableIPv4 = false, o => o.EnableIPv6 = true, o => o.Labels['finops.local-fleet-history.run'] = 'foreign']) { const changed = structuredClone(net); mutate(changed); assert.throws(() => validateFleetHistoryObject(changed, id, 'network', network, network)); }
});
