import assert from 'node:assert/strict';
import test from 'node:test';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {parseWorkspaceIndexExtras,readWorkspaceIndexedSource,workspacePhaseCommand} from '../group-workspace-reconstruction-lab.mjs';

const oldExtras=['scripts/group-workspace-reconstruction-lab.mjs','scripts/lib/group-workspace-retirement.mjs','migrations/033_group_native_reconstruction.sql'];
const healthExtras=['scripts/group-workspace-health-lab.mjs','scripts/lib/group-workspace-health.mjs','migrations/034_group_recovery_health.sql'];
const commonHosts=['scripts/fleet-group-connected-lab.mjs','scripts/kubernetes-bootstrap.mjs','scripts/fleet-history-lab.mjs','scripts/postgres-recovery-lab.mjs','scripts/lib/encrypted-backup.mjs','scripts/lib/fixture-go-modules.mjs','scripts/lib/group-connected-failure.mjs'];
const blob=raw=>createHash('sha1').update(Buffer.from('blob '+raw.length+'\0')).update(raw).digest('hex');

test('recovered health selects only its fixed entry and preserves the original bounded reconstruction command',()=>{
 for(const phase of ['PREPARE','RECONSTRUCT','CLEANUP']){
  assert.ok(workspacePhaseCommand(phase).at(-1).endsWith('^TestFleetGroupWorkspaceReconstructionPhases$'));
  assert.ok(workspacePhaseCommand(phase,'RECOVERY_HEALTH').at(-1).endsWith('^TestFleetGroupWorkspaceRecoveryHealthPhases$'));
 }
 assert.ok(workspacePhaseCommand('RECONSTRUCT','RECOVERY_HEALTH').includes('-test.timeout=40m'));
 for(const mode of ['','HEALTH','RECOVERY_HEALTH\nAWS_ACCESS_KEY_ID=x','../private',{},null])assert.throws(()=>workspacePhaseCommand('RECONSTRUCT',mode));
 const entry=readFileSync(new URL('../group-workspace-health-lab.mjs',import.meta.url),'utf8');
 assert.ok(entry.includes('groupWorkspaceRecoveryHealthLab()'));
 for(const value of ['process.argv.slice','process.env.','--publish','--network host','JSON.parse'])assert.equal(entry.includes(value),false);
});

test('health source extension requires its exact six bounded regular indexed blobs and no future migration',()=>{
 const paths=[...oldExtras,...healthExtras];
 const lines=paths.map(p=>'100644 blob '+blob(Buffer.from(p))+' '+p.length+'\t'+p+'\0');
 const raw=Buffer.from(lines.join(''));
 assert.equal(parseWorkspaceIndexExtras(raw,'RECOVERY_HEALTH').length,6);
 assert.throws(()=>parseWorkspaceIndexExtras(raw));
 for(const invalid of [raw.subarray(0,raw.length-1),Buffer.from(lines.slice(0,-1).join('')),Buffer.from(raw.toString().replace('100644','120000')),Buffer.from(raw.toString().replace('034_group_recovery_health','035_future')),Buffer.from(raw.toString().replace('scripts/lib/group-workspace-health.mjs','scripts/lib/../../private.key')),Buffer.concat([raw,Buffer.from(lines[0])])])assert.throws(()=>parseWorkspaceIndexExtras(invalid,'RECOVERY_HEALTH'));
});

test('actual health index capture pins034 and executed dependencies while original source capture remains capped033',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-workspace-health-index-')),repository=path.join(directory,'repo'),config=path.join(directory,'empty.config');mkdirSync(repository);writeFileSync(config,'',{mode:0o600});
 t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^finops-workspace-health-index-/);rmSync(directory,{recursive:true,force:true});});
 const env={};for(const key of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC'])if(process.env[key])env[key]=process.env[key];
 Object.assign(env,{GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:config,GIT_CONFIG_SYSTEM:config,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1'});
 const git=args=>execFileSync('git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:repository,env,encoding:'utf8',windowsHide:true,stdio:'pipe'});
 git(['-c','init.templateDir=','init','--quiet']);
 const files=new Map([['go.mod',Buffer.from('module isolated.example/healthfixture\n')],['go.sum',Buffer.alloc(0)],['internal/example/source.go',Buffer.from('package example\n')],['examples/fleet-group-connected-fixture/Dockerfile',Buffer.from('fixed synthetic toolchain\n')],...[...commonHosts,...oldExtras,...healthExtras].map(p=>[p,Buffer.from('// fixed '+p+'\n')]),...['029_fleet_fixture_proposals.sql','030_fleet_group_journal.sql','031_cross_family_admission.sql','032_group_artifacts.sql'].map(p=>['migrations/'+p,Buffer.from('-- synthetic only\n')])]);
 for(const[p,raw]of files){mkdirSync(path.dirname(path.join(repository,p)),{recursive:true});writeFileSync(path.join(repository,p),raw);}git(['add','--all']);
 const captured=readWorkspaceIndexedSource(repository,config,'RECOVERY_HEALTH');assert.equal(captured.files.size,files.size);
 for(const p of healthExtras)assert.deepEqual(captured.files.get(p),files.get(p));
 const original=readWorkspaceIndexedSource(repository,config);for(const p of healthExtras)assert.equal(original.files.has(p),false);
 writeFileSync(path.join(repository,healthExtras[2]),'UNSTAGED_SQL');writeFileSync(path.join(repository,'migrations/035_future.sql'),'-- future');git(['add','migrations/035_future.sql']);writeFileSync(path.join(repository,'internal/example/private.go'),'UNTRACKED_PRIVATE');
 const latest=readWorkspaceIndexedSource(repository,config,'RECOVERY_HEALTH');assert.deepEqual(latest.files.get(healthExtras[2]),files.get(healthExtras[2]));assert.equal(latest.files.has('migrations/035_future.sql'),false);assert.equal(latest.files.has('internal/example/private.go'),false);
 writeFileSync(path.join(repository,healthExtras[1]),'ALTERED_EXECUTED_MODULE');assert.throws(()=>readWorkspaceIndexedSource(repository,config,'RECOVERY_HEALTH'));
});

test('hosted recovered-health evidence never uploads observer authority, raw state, logs or bundles',()=>{
 const workflow=readFileSync(new URL('../../.github/workflows/ci.yaml',import.meta.url),'utf8'),job=workflow.split('  fleet-workspace-health:')[1].split('\n  kubernetes-lab:')[0],upload=job.split('name: fleet-workspace-health-acceptance')[1].split('if-no-files-found:')[0];
 assert.ok(job.includes('node scripts/group-workspace-health-lab.mjs'));
 assert.deepEqual(upload.split(/\r?\n/).map(line=>line.trim()).filter(line=>line.startsWith('work/')),['work/private/group-workspace-health/*/acceptance.json','work/private/group-workspace-health/*/failure-receipt.json']);
 for(const forbidden of ['health-private','health-activation','workspace-recovered-health.json','retirement.json','bundle','archive.key','*.log','ciphertext','/results','/source'])assert.equal(upload.includes(forbidden),false);
});
