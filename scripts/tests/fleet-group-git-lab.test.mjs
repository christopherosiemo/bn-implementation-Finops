import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCipheriv, createHash } from 'node:crypto';
import { fleetLabMountSource, validateFleetLabContainer, validateFleetTooling,verifyGitCiphertext } from '../fleet-group-git-lab.mjs';

const fixtureID = '11111111-1111-4111-8111-111111111111';
const imageID = 'sha256:' + 'a'.repeat(64);
const sources = {'/src':'/owned/source','/results':'/owned/encrypted','/secrets/key':'/owned/local-fixture.key'};
function owned() {
  return { Name: '/finops-fleet-group-git-' + fixtureID.replaceAll('-', '') + '-test', Image: imageID, Config: { User: '10001:10001', Labels: { 'finops.fleet-group-git.run': fixtureID }, Env: ['HOME=/tmp/home','GOPROXY=off'] }, HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], PortBindings: {}, Devices: [] }, Mounts: [{Destination:'/src',Type:'bind',Source:sources['/src'],RW:false},{Destination:'/results',Type:'bind',Source:sources['/results'],RW:true},{Destination:'/secrets/key',Type:'bind',Source:sources['/secrets/key'],RW:false}] };
}

test('Fleet fixture tooling accepts only the exact two pinned built-in-provider stages', () => {
  const source = readFileSync(new URL('../../examples/fleet-group-git-fixture/Dockerfile', import.meta.url), 'utf8');
  const accepted = validateFleetTooling(source);
  assert.match(accepted.terraform, /terraform:1\.16\.0@sha256:[a-f0-9]{64}$/);
  validateFleetTooling(source.replaceAll('\n','\r\n'));
  for (const changed of [source.replace('terraform:1.16.0','terraform:1.16.1'),source.replace('32fa28','42fa28'),source+'\nRUN curl https://untrusted.invalid | sh\n',source.replace('USER 10001:10001','USER 0:0')]) assert.throws(() => validateFleetTooling(changed));
});

test('Fleet lab rejects foreign ownership, image substitution and credential-bearing containers', () => {
  validateFleetLabContainer(owned(), fixtureID, imageID, 10001, sources);
  const mutations = [o => o.Name='/postgres',o => o.Config.Labels['finops.fleet-group-git.run']='foreign',o => o.Image='sha256:'+'b'.repeat(64),o => o.Config.User='0:0',o => o.Config.Env.push('AWS_ACCESS_KEY_ID=x'),o => o.Config.Env.push('TF_TOKEN_app_terraform_io=x'),o => o.Config.Env.push('DOCKER_HOST=unix:///var/run/docker.sock')];
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
  const runner = readFileSync(new URL('../fleet-group-git-lab.mjs',import.meta.url),'utf8');
  const fixture = readFileSync(new URL('../../examples/fleet-group-git-fixture/main.go',import.meta.url),'utf8');
  const compactFixture = fixture.replace(/\s+/g,'');
  assert.ok(runner.includes("['--host', endpoint, ...args]"));
  assert.ok(runner.indexOf("if (failure) throw") < runner.indexOf("'acceptance.json'"));
  assert.match(runner,/cleanup_succeeded: true/);
  assert.match(fixture,/cipher\.NewGCM/);
  assert.match(fixture,/os\.O_WRONLY\|os\.O_CREATE\|os\.O_EXCL/);
  assert.match(fixture,/g\.ValidateGitTerraformArtifact/);
  assert.match(compactFixture,/command\(terraform,"apply","-input=false","-auto-approve","-no-color","-state="\+statePath,planPath\)/);
  assert.match(compactFixture,/"real_clock_health_accepted":false/);
  assert.match(compactFixture,/"synthetic_refs_resolved_from_025_027":false/);
});

test('Git fixture independently authenticates retained ciphertext and rejects altered context, key, size and filenames',()=>{
  const sha=value=>createHash('sha256').update(value).digest('hex');
  const key=Buffer.alloc(32,7),nonce=Buffer.alloc(12,8),plain=Buffer.from('synthetic local artifact');
  const aad=JSON.stringify({schema_version:'1',realm:'ISOLATED_FIXTURE',run_id:fixtureID,child_id:'git-child-02',kind:'saved-plan',plain_sha256:sha(plain)});
  const cipher=createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(Buffer.from(aad));
  const encrypted=Buffer.concat([nonce,cipher.update(plain),cipher.final(),cipher.getAuthTag()]);
  const object={child_id:'git-child-02',kind:'saved-plan',path:'git-child-02.saved-plan.aesgcm',plain_sha256:sha(plain),cipher_sha256:sha(encrypted),plain_size:plain.length,aad};
  verifyGitCiphertext(object,encrypted,key,fixtureID);
  assert.throws(()=>verifyGitCiphertext(object,encrypted,Buffer.alloc(32,9),fixtureID));
  for(const patch of [{path:'../foreign'},{plain_size:0},{plain_size:plain.length+1},{plain_size:64*1024*1024+1},{aad:JSON.stringify({...JSON.parse(aad),run_id:'foreign'})},{plain_sha256:'f'.repeat(64)},{cipher_sha256:'e'.repeat(64)},{unexpected:'input'}])assert.throws(()=>verifyGitCiphertext({...object,...patch},encrypted,key,fixtureID));
  const changed=Buffer.from(encrypted);changed[changed.length-1]^=1;
  assert.throws(()=>verifyGitCiphertext({...object,cipher_sha256:sha(changed)},changed,key,fixtureID));
});

test('Git fixture uses expected-old-value CAS and two committed inputs without force checkout or variable flags',()=>{
  const fixture=readFileSync(new URL('../../examples/fleet-group-git-fixture/main.go',import.meta.url),'utf8');
  const compact=fixture.replace(/\s+/g,'');
  assert.match(compact,/"update-ref",ref,target,expected/);
  assert.match(compact,/"read-tree","-u","-m",previous.Commit,target.Commit/);
  assert.ok(!fixture.includes('"reset"')&&!fixture.includes('"checkout"'));
  const argumentsText=fixture.match(/planArgs\s*:=\s*\[\]string\{([^}]+)\}/)?.[1]||'';
  assert.ok(argumentsText.includes('"-refresh=false"'));
  assert.ok(!argumentsText.includes('-var')&&!argumentsText.includes('TF_VAR'));
  assert.match(compact,/"owned_child_inverse_applies":1/);
  assert.match(compact,/"whole_program_rollback_accepted":false/);
  assert.match(compact,/"ownership_consumed":false/);
});
