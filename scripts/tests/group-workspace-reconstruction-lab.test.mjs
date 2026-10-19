import assert from 'node:assert/strict';
import test from 'node:test';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {parseWorkspaceIndexExtras,readWorkspaceIndexedSource,validateWorkspaceCiphertextIndex,validateWorkspaceCleanup,validateWorkspaceContainer,validateWorkspaceNetwork,validateWorkspaceReconstructed,validateWorkspaceRemoval,workspacePhaseCommand,workspaceRuntime} from '../group-workspace-reconstruction-lab.mjs';

const id='11111111-2222-3333-4444-555555555555',image='sha256:'+'a'.repeat(64),runtimeID='b'.repeat(64),name='owned-old';
const label='finops.fleet-group-workspace.run',network='owned-private';
const spec={id,name,image,network,user:'10001:10001',runtimeID,mounts:[['/src','bind','/public/source',false],['/handoff','bind','/private/handoff',true],['/compiled','volume','owned-compiled',false]],command:workspacePhaseCommand('PREPARE'),environment:['FLEET_GROUP_WORKSPACE_PHASE=PREPARE']};
function container(){return {Id:runtimeID,Name:'/'+name,Image:image,Config:{Labels:{[label]:id},User:spec.user,Cmd:spec.command,Env:['HOME=/tmp','FLEET_GROUP_WORKSPACE_PHASE=PREPARE']},HostConfig:{NetworkMode:network,ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],SecurityOpt:['no-new-privileges'],PortBindings:{},Devices:[]},Mounts:[{Destination:'/src',Type:'bind',Source:'/public/source',RW:false},{Destination:'/handoff',Type:'bind',Source:'/private/handoff',RW:true},{Destination:'/compiled',Type:'volume',Name:'owned-compiled',Source:'/var/lib/docker/volumes/owned-compiled/_data',RW:false}]};}
test('fixed phase commands and container identity refuse alternate executors, keys, mounts and ambient authority',()=>{
 for(const phase of ['PREPARE','RECONSTRUCT','CLEANUP'])assert.ok(workspacePhaseCommand(phase).at(-1).endsWith('^TestFleetGroupWorkspaceReconstructionPhases$'));
 for(const phase of ['APPLY','prepare','','PREPARE\nAWS_ACCESS_KEY_ID=x'])assert.throws(()=>workspacePhaseCommand(phase));
 validateWorkspaceContainer(container(),spec);
 for(const mutate of [x=>x.Id='c'.repeat(64),x=>x.Config.Labels[label]='foreign',x=>x.Image='sha256:'+'d'.repeat(64),x=>x.HostConfig.NetworkMode='host',x=>x.HostConfig.CapAdd=['SYS_ADMIN'],x=>x.HostConfig.PortBindings={'8080/tcp':[{}]},x=>x.Config.Env.push('CONTROLLER_PRIVATE_KEY=forbidden'),x=>x.Config.Env.push('AWS_ACCESS_KEY_ID=forbidden'),x=>x.Config.Env.push('FLEET_GROUP_WORKSPACE_PHASE=RECONSTRUCT'),x=>x.Mounts[1].Source='/private/foreign',x=>x.Mounts[1].Type='volume',x=>x.Mounts.push({Destination:'/var/run/docker.sock',Type:'bind',Source:'/var/run/docker.sock',RW:true}),x=>x.Config.Cmd=['sh','-c','alternate']]){const bad=container();mutate(bad);assert.throws(()=>validateWorkspaceContainer(bad,spec));}
});
test('dedicated network ownership and positive exact old-runtime absence are mandatory',()=>{
 const object={Name:network,Labels:{[label]:id},Internal:true,Driver:'bridge',EnableIPv4:true,EnableIPv6:false,Options:{}};validateWorkspaceNetwork(object,id,network);
 for(const mutate of [x=>x.Internal=false,x=>x.Labels[label]='foreign',x=>x.Options.extra='routing',x=>x.EnableIPv6=true]){const bad=structuredClone(object);mutate(bad);assert.throws(()=>validateWorkspaceNetwork(bad,id,network));}
 const removal=validateWorkspaceRemoval(container(),spec,['c'.repeat(64)]);assert.equal(removal.removed_runtime_id,runtimeID);assert.equal(removal.absent_after_removal,true);
 assert.throws(()=>validateWorkspaceRemoval(container(),spec,[runtimeID]));assert.throws(()=>validateWorkspaceRemoval(container(),spec,['truncated-id']));assert.throws(()=>validateWorkspaceRemoval({...container(),Id:'c'.repeat(64)},spec,[]));
});
test('runtime handoff contains only the exact installed public key and workspace identity',()=>{
 const workspace={generation:id,runtime_id:runtimeID,image_sha256:image.slice(7)};
 const runtime=workspaceRuntime(id,workspace,id,Buffer.alloc(32,3));assert.equal(Buffer.from(runtime.controller_public_key,'base64').length,32);assert.deepEqual(Object.keys(runtime),['schema_version','run_id','workspace','controller_key_id','controller_public_key']);
 for(const key of [Buffer.alloc(31),Buffer.alloc(64),'private'])assert.throws(()=>workspaceRuntime(id,workspace,id,key));
 assert.throws(()=>workspaceRuntime(id,{...workspace,controller_private_key:'forbidden'},id,Buffer.alloc(32)));
});
const old={generation:id,runtime_id:runtimeID,image_sha256:image.slice(7)},next={...old,generation:'21111111-2222-3333-4444-555555555555',runtime_id:'c'.repeat(64)};
function ready(){return {tenant_id:'fixture-tenant',chain_id:'connected-chain-'+id,command_id:'31111111-2222-3333-4444-555555555555',terminal_id:'41111111-2222-3333-4444-555555555555',terminal_sha256:'d'.repeat(64),prepared_program_sha256:'e'.repeat(64),private_bundle_sha256:'f'.repeat(64),old_workspace:old};}
function reconstructed(){return {schema_version:'1',status:'PASS',run_id:id,...ready(),new_workspace:next,reconstructed_state_sha256:'1'.repeat(64),reconstructed_outcome_sha256:'2'.repeat(64),reconstructed_without_terraform:true,reconstruction_terraform_invocation_delta:0,reconstruction_native_audit_absent:true,old_generation_refused:true,old_apply_permit_refused:true,missing_terminal_remained_unknown:true,unknown_reconciled_from_selected_positive_terminal:true,outcome_reopen_without_reapply:true,reconciled_owned_effects:1,fresh_owned_inverse_command_id:'51111111-2222-3333-4444-555555555555',inverse_terminal_id:'61111111-2222-3333-4444-555555555555',inverse_terminal_sha256:'3'.repeat(64),inverse_terminal_ref:{id:'71111111-2222-3333-4444-555555555555',bucket:'private-fixture',key:'tenant/fixture-tenant/fleet-group-fixture/proposal/generation/71111111-2222-3333-4444-555555555555.encrypted',version_id:'pinned-version',sha256:'3'.repeat(64),size_bytes:100},restored_state_sha256:'4'.repeat(64),restored_owned_effects:0,consumed_owned_effects:1,restored_original_model:true,post_reconstruction_recovery_invocations:{counts:{apply:1,plan:1,show:1},total:3,sha256:'5'.repeat(64)},reconstruction_artifact_index_sha256:'6'.repeat(64),terminal_health_pending:true,reservation_held:true,fixture:true,customer_execution_authorized:false,verified_saving:null,repeated_replacement_without_new_terminal_supported:false,full_recovery_health_accepted:false};}
test('result proof retains UNKNOWN/ownership and forbids another native dispatch or unsupported recovery credit',()=>{
 const expected={runID:id,ready:ready(),newWorkspace:next};validateWorkspaceReconstructed(reconstructed(),expected);
 for(const mutate of [x=>x.reconstruction_terraform_invocation_delta=1,x=>x.reservation_held=false,x=>x.old_generation_refused=false,x=>x.old_apply_permit_refused=false,x=>x.missing_terminal_remained_unknown=false,x=>x.unknown_reconciled_from_selected_positive_terminal=false,x=>x.reconstructed_without_terraform=false,x=>x.reconciled_owned_effects=0,x=>x.new_workspace=old,x=>x.terminal_sha256='a'.repeat(64),x=>x.customer_execution_authorized=true,x=>x.verified_saving='1',x=>x.repeated_replacement_without_new_terminal_supported=true,x=>x.full_recovery_health_accepted=true,x=>x.terminal_health_pending=false,x=>x.restored_owned_effects=1,x=>x.consumed_owned_effects=0,x=>x.post_reconstruction_recovery_invocations.counts.apply=2,x=>x.inverse_terminal_ref.sha256='a'.repeat(64),x=>x.raw_state='forbidden']){const bad=structuredClone(reconstructed());mutate(bad);assert.throws(()=>validateWorkspaceReconstructed(bad,expected));}
 const cleanup={schema_version:'1',status:'PASS',run_id:id,owned_database_dropped:true,owned_roles_dropped:3,fixture:true};validateWorkspaceCleanup(cleanup,id);
 for(const mutate of [x=>x.owned_database_dropped=false,x=>x.owned_roles_dropped=0,x=>x.run_id='foreign',x=>x.private_key='forbidden']){const bad={...cleanup};mutate(bad);assert.throws(()=>validateWorkspaceCleanup(bad,id));}
});

const extras=['scripts/group-workspace-reconstruction-lab.mjs','scripts/lib/group-workspace-retirement.mjs','migrations/033_group_native_reconstruction.sql'];
const hosts=['scripts/fleet-group-connected-lab.mjs','scripts/kubernetes-bootstrap.mjs','scripts/fleet-history-lab.mjs','scripts/postgres-recovery-lab.mjs','scripts/lib/encrypted-backup.mjs','scripts/lib/fixture-go-modules.mjs','scripts/lib/group-connected-failure.mjs'];
const blob=b=>createHash('sha1').update(Buffer.from('blob '+b.length+'\0')).update(b).digest('hex');
test('033 selector permits only three exact regular bounded indexed paths',()=>{
 const raw=Buffer.from(extras.map(p=>'100644 blob '+blob(Buffer.from(p))+' '+p.length+'\t'+p+'\0').join(''));assert.equal(parseWorkspaceIndexExtras(raw).length,3);
 for(const bad of [raw.subarray(0,raw.length-1),Buffer.from(raw.toString().replace('100644','120000')),Buffer.from(raw.toString().replace('033_group_native_reconstruction','034_future')),Buffer.from(raw.toString().replace('scripts/lib/group-workspace-retirement.mjs','scripts/lib/../private-key.mjs')),Buffer.concat([raw,raw.subarray(0,raw.indexOf(0)+1)]),Buffer.from(raw.toString().replace(' '+extras[0].length+'\t',' 262145\t'))])assert.throws(()=>parseWorkspaceIndexExtras(bad));
});
test('private ciphertext metadata pins the complete unique bounded population and preserves every previous version',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-workspace-cipher-'));t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^finops-workspace-cipher-/);rmSync(directory,{recursive:true,force:true});});
 const artifacts=Array.from({length:9},(_,n)=>{const objectID='81111111-2222-3333-4444-'+String(n).padStart(12,'0'),raw=Buffer.from('unit-only opaque ciphertext fixture '+n),file=objectID+'.ciphertext.json';writeFileSync(path.join(directory,file),raw);return {id:objectID,kind:'FIXTURE_HISTORY',plain_sha256:'a'.repeat(64),plain_size:1,cipher_sha256:createHash('sha256').update(raw).digest('hex'),cipher_size:raw.length,file,version_id:'actual-pinned-version-'+n};});
 const original={schema_version:'1',run_id:id,artifacts};assert.equal(validateWorkspaceCiphertextIndex(directory,original,id).length,9);
 for(const mutate of [x=>x.run_id='foreign',x=>x.artifacts.pop(),x=>x.artifacts.push({...x.artifacts[0]}),x=>x.artifacts[0].file='../private.key',x=>x.artifacts[0].version_id='null',x=>x.artifacts[0].kind='OPERATOR_ASSERTED_AUTHORITY',x=>x.artifacts[0].plain_size=0,x=>x.artifacts[0].cipher_size++,x=>x.artifacts[0].cipher_sha256='b'.repeat(64),x=>x.artifacts[0].raw_key='private']){const bad=structuredClone(original);mutate(bad);assert.throws(()=>validateWorkspaceCiphertextIndex(directory,bad,id));}
 const changed=structuredClone(original);changed.artifacts[0].version_id='replaced-version';assert.throws(()=>validateWorkspaceCiphertextIndex(directory,changed,id,artifacts));
 writeFileSync(path.join(directory,artifacts[0].file),'same-length altered bytes'.padEnd(artifacts[0].cipher_size,'x'));assert.throws(()=>validateWorkspaceCiphertextIndex(directory,original,id));
});
test('actual indexed extension captures033 without untracked data, future migration or executed-host drift',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-workspace-index-')),repository=path.join(directory,'repo'),config=path.join(directory,'empty.config');mkdirSync(repository);writeFileSync(config,'',{mode:0o600});
 t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^finops-workspace-index-/);rmSync(directory,{recursive:true,force:true});});
 const environment={};for(const key of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC'])if(process.env[key])environment[key]=process.env[key];Object.assign(environment,{GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:config,GIT_CONFIG_SYSTEM:config,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1'});
 const git=args=>execFileSync('git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:repository,env:environment,encoding:'utf8',windowsHide:true,stdio:'pipe'});git(['-c','init.templateDir=','init','--quiet']);
 const files=new Map([['go.mod',Buffer.from('module isolated.example/fixture\n')],['go.sum',Buffer.alloc(0)],['internal/example/source.go',Buffer.from('package example\n')],['examples/fleet-group-connected-fixture/Dockerfile',Buffer.from('fixed synthetic tooling\n')],...hosts.map(p=>[p,Buffer.from('// fixed '+p+'\n')]),...extras.map(p=>[p,Buffer.from('// fixed '+p+'\n')]),...['029_fleet_fixture_proposals.sql','030_fleet_group_journal.sql','031_cross_family_admission.sql','032_group_artifacts.sql'].map(p=>['migrations/'+p,Buffer.from('-- synthetic only\n')])]);
 for(const[p,raw]of files){mkdirSync(path.dirname(path.join(repository,p)),{recursive:true});writeFileSync(path.join(repository,p),raw);}git(['add','--all']);const before=readWorkspaceIndexedSource(repository,config);assert.deepEqual(before.files.get(extras[2]),files.get(extras[2]));assert.equal(before.files.size,files.size);
 writeFileSync(path.join(repository,extras[2]),'UNSTAGED_SQL_WIP');writeFileSync(path.join(repository,'internal/example/untracked.go'),'PRIVATE');writeFileSync(path.join(repository,'migrations/034_future.sql'),'-- future');git(['add','migrations/034_future.sql']);writeFileSync(path.join(repository,'.env'),'PRIVATE_SECRET');const after=readWorkspaceIndexedSource(repository,config);assert.deepEqual(after.files.get(extras[2]),files.get(extras[2]));assert.equal(after.files.has('migrations/034_future.sql'),false);assert.equal(after.files.has('internal/example/untracked.go'),false);assert.equal(after.files.has('.env'),false);
 writeFileSync(path.join(repository,extras[1]),'CHANGED_EXECUTED_MODULE');assert.throws(()=>readWorkspaceIndexedSource(repository,config));
});
test('host flow keeps controller key outside worker mounts and retirement between exact removal and replacement start',()=>{
 const raw=readFileSync(new URL('../group-workspace-reconstruction-lab.mjs',import.meta.url),'utf8');
 assert.ok(raw.indexOf("run(['rm','--force',oldWorkspace.runtime_id])")<raw.indexOf("const removal=validateWorkspaceRemoval"));
 assert.ok(raw.indexOf('const removal=validateWorkspaceRemoval')<raw.indexOf("worker(replacement,'RECONSTRUCT')"));
 assert.ok(raw.indexOf('controller.privateKey')<raw.indexOf("run(['start','--attach',replacement]"));
 assert.ok(raw.includes("'--tmpfs',`/workspace:rw,nosuid,nodev"));assert.ok(raw.includes("mode:0o600"));
 for(const forbidden of ['--privileged','type=bind,src=/var/run/docker.sock','controller.privateKey.export','--publish','--network\',\'host'])assert.equal(raw.includes(forbidden),false);
});
