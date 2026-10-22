import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { labKindPath, localDockerEndpoint } from '../kubernetes-bootstrap.mjs';

test('Kubernetes lab refuses remote Docker transports and misleading pipe names', () => {
  for (const value of ['tcp://127.0.0.1:2375', 'ssh://operator@host', 'https://docker.example.invalid', 'npipe:////remote/pipe/docker_engine', 'unix://remote/socket', undefined]) {
    assert.equal(localDockerEndpoint(value), false, String(value));
  }
  assert.equal(localDockerEndpoint('unix:///var/run/docker.sock'), true);
  assert.equal(localDockerEndpoint('npipe:////./pipe/dockerDesktopLinuxEngine'), true);
});
test('Kubernetes lab chooses only a pinned workspace helper for supported platforms', () => {
  const base = path.resolve('work', 'isolated-bootstrap-test');
  assert.equal(labKindPath(base, 'win32'), path.join(base, 'work/tools/kind.exe'));
  assert.equal(labKindPath(base, 'linux'), path.join(base, 'work/tools/kind'));
  assert.throws(() => labKindPath(base, 'darwin'));
});
