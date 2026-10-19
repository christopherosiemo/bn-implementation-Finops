import test from 'node:test';
import assert from 'node:assert/strict';
import { boundaryBytes, boundaryImages, missingBoundaryResource, validateOwnedBoundaryResource } from '../nginx-body-boundary-lab.mjs';

const id = 'c1f3ef33-7777-4444-9999-0123456789ab';
const name = role => 'finops-nginx-body-' + id.replaceAll('-', '') + '-' + role;
const labels = { 'finops.nginx-body-boundary.run': id };

test('boundary lab selects only exact pinned frontend Nginx and Node images', () => {
  const source = 'ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:stable-alpine@sha256:' + 'a'.repeat(64) + '\nARG NODE_IMAGE=node:22-bookworm-slim@sha256:' + 'b'.repeat(64) + '\n';
  assert.equal(boundaryImages(source).nginx, 'nginxinc/nginx-unprivileged:stable-alpine@sha256:' + 'a'.repeat(64));
  for (const fault of [source.replace('@sha256:' + 'a'.repeat(64), ''), source.replace('nginxinc/nginx-unprivileged', 'customer/private'), source.replace('node:22-bookworm-slim', 'node:latest'), source.replace('a'.repeat(64), 'a'.repeat(63)), '']) assert.throws(() => boundaryImages(fault));
  assert.equal(boundaryBytes.api, 4194304);
  assert.equal(boundaryBytes.proxy, 5242880);
});

test('container cleanup requires the exact UUID ownership label and role name', () => {
  const object = { Name: '/' + name('proxy'), Config: { Labels: labels } };
  validateOwnedBoundaryResource(object, id, 'proxy');
  for (const fault of [{ ...object, Name: '/customer-web' }, { ...object, Config: { Labels: {} } }, { ...object, Config: { Labels: { 'finops.nginx-body-boundary.run': 'other' } } }]) assert.throws(() => validateOwnedBoundaryResource(fault, id, 'proxy'));
  assert.throws(() => validateOwnedBoundaryResource(object, id, 'upstream'));
  assert.throws(() => validateOwnedBoundaryResource(object, '../customer', 'proxy'));
});

test('network cleanup refuses public, foreign or unlabelled networks', () => {
  const object = { Name: name('network'), Labels: labels, Internal: true };
  validateOwnedBoundaryResource(object, id, 'network');
  for (const fault of [{ ...object, Internal: false }, { ...object, Name: 'finops_private' }, { ...object, Labels: {} }]) assert.throws(() => validateOwnedBoundaryResource(fault, id, 'network'));
});

test('cleanup never mistakes daemon, permission or foreign-resource errors for absence', () => {
  assert.equal(missingBoundaryResource({ stderr: 'Error response from daemon: No such object: ' + name('proxy') + '\n' }, name('proxy')), true);
  assert.equal(missingBoundaryResource({ stderr: Buffer.from('Error response from daemon: network ' + name('network') + ' not found\n') }, name('network')), true);
  for (const stderr of ['Cannot connect to the Docker daemon', 'permission denied', 'No such object: customer', 'No such image: ' + name('proxy'), 'No such object: ' + name('proxy') + '\npermission denied']) assert.equal(missingBoundaryResource({ stderr }, name('proxy')), false);
});
