import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCipheriv, createHash } from 'node:crypto';
import { fleetLabMountSource, validateFleetLabContainer, validateFleetTooling,verifyJournalCiphertext } from '../fleet-group-journal-lab.mjs';

const fixtureID = '11111111-1111-4111-8111-111111111111';
const imageID = 'sha256:' + 'a'.repeat(64);
const sources = {'/src':'/owned/source','/results':'/owned/encrypted','/secrets/key':'/owned/local-fixture.key'};
function owned() {
  return { Name: '/finops-fleet-group-journal-' + fixtureID.replaceAll('-', '') + '-test', Image: imageID, Config: { User: '10001:10001', Labels: { 'finops.fleet-group-journal.run': fixtureID }, Env: ['HOME=/tmp/home','GOPROXY=off'] }, HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], PortBindings: {}, Devices: [] }, Mounts: [{Destination:'/src',Type:'bind',Source:sources['/src'],RW:false},{Destination:'/results',Type:'bind',Source:sources['/results'],RW:true},{Destination:'/secrets/key',Type:'bind',Source:sources['/secrets/key'],RW:false}] };
}

test('Fleet fixture tooling accepts only the exact two pinned built-in-provider stages', () => {
  const source = readFileSync(new URL('../../examples/fleet-group-journal-fixture/Dockerfile', import.meta.url), 'utf8');
  const accepted = validateFleetTooling(source);
  assert.match(accepted.terraform, /terraform:1\.16\.0@sha256:[a-f0-9]{64}$/);
  validateFleetTooling(source.replaceAll('\n','\r\n'));
  for (const changed of [source.replace('terraform:1.16.0','terraform:1.16.1'),source.replace('32fa28','42fa28'),source+'\nRUN curl https://untrusted.invalid | sh\n',source.replace('USER 10001:10001','USER 0:0')]) assert.throws(() => validateFleetTooling(changed));
});

test('Fleet lab rejects foreign ownership, image substitution and credential-bearing containers', () => {
  validateFleetLabContainer(owned(), fixtureID, imageID, 10001, sources);
  const mutations = [o => o.Name='/postgres',o => o.Config.Labels['finops.fleet-group-journal.run']='foreign',o => o.Image='sha256:'+'b'.repeat(64),o => o.Config.User='0:0',o => o.Config.Env.push('AWS_ACCESS_KEY_ID=x'),o => o.Config.Env.push('TF_TOKEN_app_terraform_io=x'),o => o.Config.Env.push('DOCKER_HOST=unix:///var/run/docker.sock')];
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
  const runner = readFileSync(new URL('../fleet-group-journal-lab.mjs',import.meta.url),'utf8');
  const fixture = readFileSync(new URL('../../examples/fleet-group-journal-fixture/main.go',import.meta.url),'utf8');
  const flow = readFileSync(new URL('../../examples/fleet-group-journal-fixture/journal_flow.go',import.meta.url),'utf8');
  const compactFixture = (fixture+flow).replace(/\s+/g,'');
  assert.ok(runner.includes("['--host', endpoint, ...args]"));
  assert.ok(runner.indexOf("if (failure) throw") < runner.indexOf("'acceptance.json'"));
  assert.match(runner,/cleanup_succeeded: true/);
  assert.match(fixture,/cipher\.NewGCM/);
  assert.match(fixture,/os\.O_WRONLY\|os\.O_CREATE\|os\.O_EXCL/);
  assert.match(flow,/g\.ValidateJournalTerraformArtifact/);
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
  verifyJournalCiphertext(object,encrypted,key,fixtureID);
  assert.throws(()=>verifyJournalCiphertext(object,encrypted,Buffer.alloc(32,9),fixtureID));
  for(const patch of [{path:'../foreign'},{plain_size:0},{plain_size:plain.length+1},{plain_size:64*1024*1024+1},{aad:JSON.stringify({...JSON.parse(aad),run_id:'foreign'})},{plain_sha256:'f'.repeat(64)},{cipher_sha256:'e'.repeat(64)},{unexpected:'input'}])assert.throws(()=>verifyJournalCiphertext({...object,...patch},encrypted,key,fixtureID));
  const changed=Buffer.from(encrypted);changed[changed.length-1]^=1;
  assert.throws(()=>verifyJournalCiphertext({...object,cipher_sha256:sha(changed)},changed,key,fixtureID));
});

test('Journal fixture uses expected-old-value CAS, separately approved authority and three consumed LIFO effects',()=>{
  const fixture=readFileSync(new URL('../../examples/fleet-group-journal-fixture/main.go',import.meta.url),'utf8');
  const flow=readFileSync(new URL('../../examples/fleet-group-journal-fixture/journal_flow.go',import.meta.url),'utf8');
  const compact=(fixture+flow).replace(/\s+/g,'');
  assert.match(compact,/"update-ref",ref,target,expected/);
  assert.match(compact,/"read-tree","-u","-m",previous.Commit,target.Commit/);
  assert.ok(!fixture.includes('"reset"')&&!fixture.includes('"checkout"'));
  const argumentsText=flow.match(/planArgs\s*:=\s*\[\]string\{([^}]+)\}/)?.[1]||'';
  assert.ok(argumentsText.includes('"-refresh=false"'));
  assert.ok(!argumentsText.includes('-var')&&!argumentsText.includes('TF_VAR'));
  assert.match(compact,/"owned_child_inverse_applies":3/);
  assert.match(compact,/"whole_program_rollback_accepted":false/);
  assert.match(compact,/"pg_runtime_acceptance":false/);
  assert.match(compact,/"fixture_top_effects_consumed":3/);
  assert.match(compact,/g\.SignJournalAuthorization\(a,nil,parent,keys,signer/);
  assert.match(compact,/childProcess\(j,"--cas-and-crash",73\)/);
  assert.match(compact,/childProcess\(j,"--apply-and-crash",73\)/);
  assert.match(compact,/os\.Exit\(73\)/);
  assert.ok(!flow.includes('SignGitRecovery')&&!flow.includes('VerifyGitRecovery'));
});

test('File journal rejects partial/trailing histories, independent-head rollback and concurrent writers without repair',()=>{
  const source=readFileSync(new URL('../../examples/fleet-group-journal-fixture/journal_file.go',import.meta.url),'utf8');
  const compact=source.replace(/\s+/g,'');
  assert.match(compact,/syscall\.LOCK_EX\|syscall\.LOCK_NB/);
  assert.match(compact,/canonicalDecode\(line,&event\)/);
  assert.match(compact,/log\[len\(log\)-1\]!='\\n'/);
  assert.match(compact,/expected\.Head\.Ref!=v\.Head\.Head\.Ref/);
  assert.match(compact,/checkpoints:=\[\]g\.JournalHeadEnvelope\{b\.View\.Head\}/);
  assert.match(compact,/checkpoints=append\(checkpoints,event\.Head\)/);
  assert.match(compact,/g\.VerifyJournalCheckpoints\(v,checkpoints,keys,expected\.Head\.Ref,at\)/);
  assert.match(compact,/ed25519\.Sign\(ledger,message\)/);
  assert.ok(compact.indexOf('f.Sync()')<compact.indexOf('os.Rename('));
  assert.ok(!source.includes('os.Truncate')&&!source.includes('O_TRUNC'));
});

test('Private pipeline operation registry positively fences delivery and exact state is required for Git-only repair',()=>{
  const flow=readFileSync(new URL('../../examples/fleet-group-journal-fixture/journal_flow.go',import.meta.url),'utf8');
  const main=readFileSync(new URL('../../examples/fleet-group-journal-fixture/main.go',import.meta.url),'utf8');
  const compact=(flow+main).replace(/\s+/g,'');
  assert.match(compact,/ed25519\.Verify\(j\.keys\.Pipeline,operationMessage\(s\),sig\)/);
  assert.match(compact,/j\.operation\(c,"DISPATCHING",nil\)/);
  assert.ok(compact.indexOf('j.operation(c,"DISPATCHING",nil)')<compact.indexOf('command(terraform,"apply"'));
  assert.match(compact,/j\.operation\(c,"APPLIED",&terminal\)/);
  assert.ok((compact.match(/g\.Digest\(c\)==g\.Digest\(p\.Pending\.Command\)/g)||[]).length>=4);
  assert.match(compact,/requireRefused\(func\(\)\{j\.apply\(stale,false\)\},"fixturependingcommandchanged"\)/);
  assert.match(compact,/g\.ValidateJournalGitRepairCapture/);
  assert.match(compact,/nativeApplyCount\(\)==calls&&bytes\.Equal\(read\(statePath\),beforeNative\)/);
  assert.match(compact,/must\(j\.commit\(g\.JournalApplied,nil,&top\.Applied,nil\)\)/);
});

test('Native delivery, saved-plan publication and Git-only repair share the writer fence and fresh exact permits',()=>{
  const flow=readFileSync(new URL('../../examples/fleet-group-journal-fixture/journal_flow.go',import.meta.url),'utf8').replace(/\s+/g,'');
  const apply=flow.slice(flow.indexOf('func(jfixtureJournal)apply('),flow.indexOf('funcchildProcess('));
  assert.ok(apply.indexOf('j.disk.lock()')<apply.indexOf('g.AuthorizeJournalApply('));
  assert.ok(apply.indexOf('g.AuthorizeJournalApply(')<apply.indexOf('j.operation(c,"DISPATCHING",nil)'));
  assert.ok(apply.indexOf('permit.ValidUntil.After(time.Now().UTC())')<apply.indexOf('command(terraform,"apply"'));
  assert.match(apply,/j\.commitLocked\(g\.JournalApplied/);
  const finalize=flow.slice(flow.indexOf('func(jfixtureJournal)finalize('),flow.indexOf('func(jfixtureJournal)ready('));
  assert.ok(finalize.indexOf('j.disk.lock()')<finalize.indexOf('command(terraform,planArgs...)'));
  assert.match(finalize,/j\.commitLocked\(g\.JournalReserved/);
  const repair=flow.slice(flow.indexOf('func(jfixtureJournal)repair('));
  assert.ok(repair.indexOf('j.disk.lock()')<repair.indexOf('g.AuthorizeJournalGitRepair('));
  assert.ok(repair.indexOf('g.AuthorizeJournalGitRepair(')<repair.indexOf('advanceGated('));
  for(const field of ['p.CommandSHA256==g.Digest(c)','p.ArtifactSHA256==artifact','p.Head==v.Head.Head.Ref'])assert.ok(flow.includes(field));
  const advance=flow.slice(flow.indexOf('func(jfixtureJournal)advanceWithAdditionalRefusal('),flow.indexOf('func(jfixtureJournal)finalize('));
  assert.ok(advance.indexOf('j.disk.lock()')<advance.indexOf('g.AuthorizeJournalGitAdvance('));
  assert.ok(advance.indexOf('g.AuthorizeJournalGitAdvance(')<advance.indexOf('ifadditionalRefusal!=nil'));
  assert.ok(advance.indexOf('ifadditionalRefusal!=nil')<advance.indexOf('permit.ValidUntil.After(time.Now().UTC())'));
  assert.match(advance,/g\.AuthorizeJournalGitAdvance\(current,j\.keys,current\.Head\.Head\.Ref,g\.Digest\(c\),time\.Now\(\)\.UTC\(\)\)/);
});
