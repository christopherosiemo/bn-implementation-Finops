import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {preparerArchivePolicy,preparerContainerArguments,preparerExecutionCommand,preparerInstallation,preparerPrivateFiles,encodePreparerPrivateTar,preparerJobEnvironment,preparerStagingCommand,preparerTmpfs,requirePreparerRunning,selectCommissionedPreparerProposal,validatePreparerContainer,preparerInertSeconds} from '../lib/group-fixture-preparer-job.mjs';
import {normalizePreparerPolicy,preparerAdminConfiguration,probePreparerAdminTools,validatePreparerAdminImage} from '../group-fixture-prepare.mjs';

const id='12345678-1234-1234-1234-123456789abc',generation='22345678-1234-1234-1234-123456789abc',source='32345678-1234-1234-1234-123456789abc',proposal='42345678-1234-1234-1234-123456789abc',image='sha256:'+'a'.repeat(64),network='b'.repeat(64);
function fixture(){
 const receipt={status:'PASS',run_id:id,source_id:source,profile_id:'fixture-profile-'+id,tooling_image_id:image,source_manifest_sha256:'c'.repeat(64),realm:'ISOLATED_FIXTURE',provider_adapter:'DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026',actual_terraform_version:'1.16.0',customer_native_authority:false,customer_execution_authorized:false,verified_saving:null,cleanup_succeeded:true};
 const side=name=>({source_id:source,target:{tenant_id:'tenant-demo',workload_id:'workload-dev',provider:'AWS',account_id:'111122223333',region:'eu-west-1',asg_arn:'arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:'+name}});
 const profile={id:receipt.profile_id,generation,realm_kind:'ISOLATED_FIXTURE',model_sha256:'d'.repeat(64),installation:{template_id:'builtin-group-fixture-v1',toolchain_image_sha256:image.slice(7),terraform_version:'1.16.0',receipt_id:id,source_sha256:receipt.source_manifest_sha256}};
 const row={id:proposal,proposal:{id:proposal,purpose:'ISOLATED_GROUP_FIXTURE_PROPOSAL',creator_id:'actual-oidc-creator',workload_id:'workload-dev',customer_execution_authorized:false,estimated_saving:null,verified_saving:null,profile,realm:{kind:'ISOLATED_FIXTURE',fixture_id:profile.id,generation,model_sha256:profile.model_sha256},binding:{old:side('old'),candidate:side('candidate')}}};
 const privateValues={database:'postgres://fixture_preparer_'+id.replaceAll('-','')+':unused-private-password@postgres:5432/finops?sslmode=disable',archiveKey:Buffer.alloc(32,3),pipelinePublic:Buffer.alloc(32,1),ledgerPublic:Buffer.alloc(32,2),access:'local-fixture-preparer-user',secret:'unused-local-fixture-secret'};
 return {row,receipt,privateValues};
}
test('server-selected proposal requires a unique exact commissioned generation/source and actual creator',()=>{
 const {row,receipt}=fixture();assert.equal(selectCommissionedPreparerProposal([row],receipt,'actual-oidc-creator'),row);
 assert.throws(()=>selectCommissionedPreparerProposal([],receipt,'actual-oidc-creator'));assert.throws(()=>selectCommissionedPreparerProposal([row,row],receipt,'actual-oidc-creator'));assert.throws(()=>selectCommissionedPreparerProposal([row],receipt,'other-subject'));
 for(const change of [r=>r.proposal.binding.candidate.source_id='foreign',r=>r.proposal.binding.old.target.resource_id='representative-ec2',r=>r.proposal.binding.old.target.tenant_id='tenant-other',r=>r.proposal.profile.installation.toolchain_image_sha256='e'.repeat(64),r=>r.proposal.customer_execution_authorized=true,r=>r.proposal.estimated_saving='0',r=>r.proposal.realm.kind='CUSTOMER_NATIVE']){const bad=structuredClone(row);change(bad);assert.throws(()=>preparerInstallation(bad,receipt));}
});
test('only public keys and fixed private credentials enter exact Linux file inputs',()=>{
 const {row,receipt,privateValues}=fixture(),files=preparerPrivateFiles(row,receipt,privateValues);assert.equal(files['pipeline-public'].length,32);assert.equal(files['ledger-public'].length,32);assert.equal(files['archive-key'].length,32);
 for(const change of [v=>v.database=v.database.replace('postgres:5432','customer:5432'),v=>v.database+='&options=-crole%3Dpostgres',v=>v.pipelinePublic=v.ledgerPublic,v=>v.archiveKey=Buffer.alloc(31),v=>v.access='AKIAreal-looking',v=>v.secret='line\nbreak']){const bad={...privateValues};change(bad);assert.throws(()=>preparerPrivateFiles(row,receipt,bad));}
 assert.ok(!Object.keys(files).some(k=>/signer|executor|private-key/.test(k)));
});
test('USTAR staging has only seven fixed regular0600 files, no links or extended names',()=>{
 const {row,receipt,privateValues}=fixture(),files=preparerPrivateFiles(row,receipt,privateValues),raw=encodePreparerPrivateTar(files);let offset=0;const names=[];
 while(raw.subarray(offset,offset+512).some(v=>v!==0)){
  const h=raw.subarray(offset,offset+512),text=(start,length)=>h.subarray(start,start+length).toString('ascii').replace(/\0.*$/s,'');const name=text(0,100),size=parseInt(text(124,12),8);names.push(name);assert.equal(parseInt(text(100,8),8),0o600);assert.equal(parseInt(text(108,8),8),10001);assert.equal(parseInt(text(116,8),8),10001);assert.equal(h[156],0x30);assert.equal(text(157,100),'');assert.equal(text(345,155),'');assert.equal(text(257,6),'ustar');assert.deepEqual(raw.subarray(offset+512,offset+512+size),files[name]);offset+=512+Math.ceil(size/512)*512;
 }
 assert.deepEqual(names,Object.keys(files).sort());assert.equal(raw.length-offset,1024);assert.ok(raw.subarray(offset).every(v=>v===0));
 assert.throws(()=>encodePreparerPrivateTar({...files,'../database':Buffer.from('no')}));assert.throws(()=>encodePreparerPrivateTar({...files,'archive-key':Buffer.alloc(31)}));assert.deepEqual(preparerExecutionCommand,['/compiled/preparer']);assert.ok(preparerStagingCommand.includes('--keep-old-files'));assert.ok(preparerStagingCommand.includes('--no-same-owner'));assert.ok(!preparerStagingCommand.includes('--no-overwrite-dir'));
});
test('new MinIO user receives versioning read and only exact immutable proposal archive prefix',()=>{
 const {row,receipt}=fixture(),policy=preparerArchivePolicy(row,receipt);assert.deepEqual(policy.Statement[0],{Effect:'Allow',Action:['s3:GetBucketVersioning'],Resource:['arn:aws:s3:::finops-raw']});assert.deepEqual(policy.Statement[1].Action,['s3:GetObject','s3:GetObjectVersion','s3:PutObject']);assert.deepEqual(policy.Statement[1].Resource,[`arn:aws:s3:::finops-raw/tenant/tenant-demo/fleet-group-fixture/${proposal}/${generation}/*`]);assert.ok(!JSON.stringify(policy).includes('Delete'));assert.ok(!JSON.stringify(policy).includes('s3:*'));
});
test('inert job has only fixed non-secret config, native workspace, stdin staging and no shell',()=>{
 const {row,receipt}=fixture(),spec=preparerContainerArguments(row,receipt,id,network),env=preparerJobEnvironment(row,receipt);assert.equal(env.GROUP_FIXTURE_PROPOSAL_ID,proposal);assert.equal(env.GROUP_FIXTURE_S3_ENDPOINT,'http://minio:9000');assert.equal(env.GROUP_FIXTURE_DATABASE_FILE,'/secrets/database');assert.equal(spec.args.at(-1),String(preparerInertSeconds));assert.ok(spec.args.includes('/usr/bin/sleep'));assert.ok(!spec.args.includes('sh'));assert.ok(!spec.args.includes('--volume'));assert.ok(!JSON.stringify(spec.args).includes('unused-private-password'));
 const o={Name:'/'+spec.name,Image:image,State:{Running:true},Config:{User:'10001:10001',Labels:{'finops.group-fixture-preparer.run':id},Entrypoint:['/usr/bin/sleep'],Cmd:[String(preparerInertSeconds)],Env:['PATH=/usr/bin',...Object.entries(env).map(([k,v])=>k+'='+v)]},HostConfig:{NetworkMode:network,ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges'],Binds:[],Devices:[],PortBindings:{},Tmpfs:{...preparerTmpfs}},Mounts:[],NetworkSettings:{Networks:{private:{NetworkID:network}}}};
 validatePreparerContainer(o,row,receipt,id,network,['PATH=/usr/bin']);
 requirePreparerRunning(o);
 for(const status of ['created','exited']){const stopped=structuredClone(o);stopped.State={Running:false,Status:status};stopped.NetworkSettings.Networks={};validatePreparerContainer(stopped,row,receipt,id,network,['PATH=/usr/bin']);assert.throws(()=>requirePreparerRunning(stopped));}
 const wrongNetwork=structuredClone(o);wrongNetwork.NetworkSettings.Networks.private.NetworkID='c'.repeat(64);assert.throws(()=>validatePreparerContainer(wrongNetwork,row,receipt,id,network,['PATH=/usr/bin']));
 for(const change of [x=>x.Config.User='root',x=>x.Config.Env.push('SIGNER_TOKEN=unused'),x=>x.Config.Entrypoint=['sh'],x=>x.HostConfig.Binds=['/host:/secrets'],x=>x.HostConfig.CapAdd=['SYS_ADMIN'],x=>x.HostConfig.NetworkMode='host',x=>x.Mounts.push({Type:'bind',Source:'/host',Destination:'/workspace'}),x=>x.HostConfig.Tmpfs['/secrets']='mode=0777']){const bad=structuredClone(o);change(bad);assert.throws(()=>validatePreparerContainer(bad,row,receipt,id,network,['PATH=/usr/bin']));}
});
test('private MinIO alias input never becomes argv secrets or permits another endpoint',()=>{
 assert.equal(preparerAdminConfiguration('fixtureuser','fixtureprivatevalue'),'MC_HOST_local=http://fixtureuser:fixtureprivatevalue@minio:9000\n');
 for(const pair of [['fixtureuser','newline\nvalue'],['fixtureuser','reserved@url'],['fixtureuser','with:colon'],['', 'value']])assert.throws(()=>preparerAdminConfiguration(...pair));
 const image={Id:'sha256:'+'a'.repeat(64),Config:{Labels:{'org.opencontainers.image.source':'https://github.com/minio/mc','org.opencontainers.image.revision':'b00526b153a31b36767991a4f5ce2cced435ee8e','org.opencontainers.image.version':'RELEASE.2025-04-16T18-13-26Z'}}};validatePreparerAdminImage(image);
 const wrong=structuredClone(image);wrong.Config.Labels['org.opencontainers.image.revision']='mutable';assert.throws(()=>validatePreparerAdminImage(wrong));
});
test('observed policy normalization cannot hide conditions, extra grants or another archive prefix',()=>{
 const {row,receipt}=fixture(),expected=preparerArchivePolicy(row,receipt),single=structuredClone(expected);single.Statement[0].Action=single.Statement[0].Action[0];single.Statement[0].Resource=single.Statement[0].Resource[0];assert.deepEqual(normalizePreparerPolicy(single),normalizePreparerPolicy(expected));
 const condition=structuredClone(expected);condition.Statement[0].Condition={anything:'not-allowed'};assert.throws(()=>normalizePreparerPolicy(condition));
 const broad=structuredClone(expected);broad.Statement[1].Action=['s3:*'];assert.notDeepEqual(normalizePreparerPolicy(broad),normalizePreparerPolicy(expected));
 const foreign=structuredClone(expected);foreign.Statement[1].Resource=['arn:aws:s3:::finops-raw/tenant/*'];assert.notDeepEqual(normalizePreparerPolicy(foreign),normalizePreparerPolicy(expected));
});

test('network-none tools probe validates created/running/exited ownership and cleans before evidence',()=>{
 const mc={Id:image,Config:{Env:['PATH=/usr/bin'],Labels:{'org.opencontainers.image.source':'https://github.com/minio/mc','org.opencontainers.image.revision':'b00526b153a31b36767991a4f5ce2cced435ee8e','org.opencontainers.image.version':'RELEASE.2025-04-16T18-13-26Z'}}};
 for(const refuse of [false,true]){let container,removed=false,daemonChecks=0;const tools=[],files=new Map();
  const run=(args,options={})=>{if(args[0]==='create'){assert.ok(args.includes('none'));assert.ok(!args.includes('--volume'));container={Name:'/finops-preparer-tools-'+id.replaceAll('-',''),Image:image,State:{Running:false,Status:'created'},Config:{User:'10001:10001',Labels:{'finops.group-fixture-preparer.run':id},Entrypoint:['/usr/bin/sleep'],Cmd:['60'],Env:mc.Config.Env},HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges'],Binds:[],PortBindings:{},Devices:[],Tmpfs:{'/secrets':'rw,nosuid,nodev,noexec,size=128k,uid=10001,gid=10001,mode=0700'}},Mounts:[]};return 'created';}
   if(args[0]==='start'){container.State={Running:true,Status:'running'};return '';}
   if(args[0]==='exec'){if(refuse){container.State={Running:false,Status:'exited'};throw new Error('Missing tool');}if(args[1]==='--interactive'){assert.equal(args[3],'/usr/bin/tar');if(files.size)throw Object.assign(new Error('Existing files'),{status:2,stderr:'Cannot open: File exists'});let offset=0;while(options.input.subarray(offset,offset+512).some(v=>v)){const h=options.input.subarray(offset,offset+512),file=h.subarray(0,100).toString().replace(/\0.*$/s,''),size=parseInt(h.subarray(124,136).toString(),8);files.set('/secrets/'+file,options.input.subarray(offset+512,offset+512+size));offset+=512+Math.ceil(size/512)*512;}return '';}
    if(args[2]==='/usr/bin/stat'){assert.ok(files.has(args.at(-1)));return 'regular file:600:10001:10001';}if(args[2]==='/usr/bin/sha256sum')return createHash('sha256').update(files.get(args.at(-1))).digest('hex')+'  '+args.at(-1);tools.push(args[2]);assert.equal(args[3],'--version');return args[2]+' (GNU coreutils) fixture';}
   if(args[0]==='ps')return container?(args.at(-1)==='{{.Names}}'?container.Name.slice(1):'owned-container'):'';
   if(args[0]==='rm'){removed=true;container=undefined;return '';}
   throw new Error('Unexpected command');};
  const act=()=>probePreparerAdminTools(run,()=>container,mc,id,()=>daemonChecks++);
  if(refuse)assert.throws(act);else{const result=act();assert.equal(result.cleanup_succeeded,true);assert.deepEqual(Object.keys(result.tools),['/usr/bin/sleep','/usr/bin/tar','/usr/bin/cat']);}
  assert.equal(removed,true);assert.equal(container,undefined);assert.equal(daemonChecks,2);assert.equal(tools.length,refuse?0:3);
 }
});
test('bridge resolves issuer subject server-side, stages stdin, replays only prepared metadata and never approves',()=>{
 const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),script=readFileSync(path.join(root,'scripts/group-fixture-prepare.mjs'),'utf8');
 assert.match(script,/protocol\/openid-connect\/userinfo/);assert.match(script,/assert\.equal\(userInfoResponse.status,200\)/);assert.match(script,/persistedFixture\(\)/);assert.match(script,/document->'fixture'='true'::jsonb/);
 assert.match(script,/encodePreparerPrivateTar\(privateFiles\)/);assert.match(script,/preparerExecutionCommand/);assert.match(script,/assert\.equal\(firstResult.existing,false\)/);assert.match(script,/assert\.equal\(replayResult.existing,true\)/);assert.match(script,/native-invocations\.jsonl/);
 assert.ok(!script.includes("method:'POST'"+",redirect:'error',headers:{Authorization"));assert.ok(!script.includes('/approvals'));assert.ok(!script.includes("['cp'"));assert.ok(!script.includes("'compose','up'"));
 assert.match(script,/info.size<=\(2<<20\)/);assert.match(script,/no_runtime_or_approval_claim:true/);assert.match(script,/native_execution_factory:false/);assert.match(script,/private_key_backup_commissioned:false/);assert.match(script,/cleanup_succeeded:true/);
});
