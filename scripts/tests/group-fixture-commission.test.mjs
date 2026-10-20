import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync,copyFileSync,mkdtempSync,rmSync,writeFileSync,unlinkSync} from 'node:fs';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {assertMigrationManifest} from '../lib/recovery-upgrade.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {commissionRegistration,commissionTitle,commissionMigrationManifest,validateCommissionTooling,validateCommissionSources,validateCommissionJob,validateCommissionSource,validateCommissionSync} from '../group-fixture-commission.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const runID='12345678-1234-1234-1234-123456789abc',image='sha256:'+'a'.repeat(64),network='b'.repeat(64),name='finops-group-commission-test',project='fixture-project';
const workspace=path.resolve('owned-fixture'),api='http://localhost:8080',issuer='http://localhost:8081/realms/finops';
const clone=x=>structuredClone(x);
function sources(){
 const values={};for(const[index,service]of ['api','worker','executor','temporal','postgres','keycloak','ingester','minio','clickhouse','economics','web'].entries()){
  const e=[];if(['api','worker','executor','ingester'].includes(service))e.push('FIXTURE_MODE=true','APP_ROLE='+service,'OIDC_ISSUER='+issuer,'OIDC_AUDIENCE=finops',`DATABASE_URL=postgres://finops_${service}:fixture-password@postgres:5432/finops?sslmode=disable`);
  if(service==='worker')e.push('TEMPORAL_ADDRESS=temporal:7233');if(service==='temporal')e.push('POSTGRES_SEEDS=postgres');if(service==='postgres')e.push('POSTGRES_DB=finops','POSTGRES_USER=postgres');if(service==='keycloak')e.push('KC_HOSTNAME=http://localhost:8081');if(service==='economics')e.push('FIXTURE_MODE=true');if(service==='web')e.push('API_UPSTREAM=api:8080');
  if(service==='ingester')for(const[k,v]of Object.entries({OBJECT_ENDPOINT:'http://minio:9000',OBJECT_BUCKET_RAW:'finops-raw',OBJECT_REGION:'eu-west-1',CLICKHOUSE_URL:'http://clickhouse:8123',CLICKHOUSE_DATABASE:'finops',CLICKHOUSE_USER:'finops',ECONOMICS_URL:'http://economics:8000',OBJECT_ACCESS_KEY:'unused-fixture-access',OBJECT_SECRET_KEY:'unused-fixture-secret',CLICKHOUSE_PASSWORD:'unused-fixture-password',ECONOMICS_TOKEN:'unused-fixture-token'}))e.push(k+'='+v);
  values[service]={Id:(index+1).toString(16).repeat(64),Image:image,State:{Running:true},Config:{Env:e,Labels:{'com.docker.compose.service':service,'com.docker.compose.project':project,'com.docker.compose.project.working_dir':workspace}},HostConfig:{NetworkMode:'fixture_private'},NetworkSettings:{Networks:{fixture_private:{NetworkID:network}},Ports:['api','keycloak','web'].includes(service)?{'8080/tcp':[{HostIp:'127.0.0.1',HostPort:service==='api'?'8080':service==='web'?'3000':'8081'}]}:{}}};
 }return values;
}
function job(){return {Name:'/'+name,Image:image,State:{Running:true},Config:{User:'10001:10001',Env:['PATH=/usr/bin','HOME=/tmp','GOMEMLIMIT=384MiB'],Labels:{'finops.group-fixture-commission.run':runID},Entrypoint:['/compiled/commission'],Cmd:[],OpenStdin:true},HostConfig:{NetworkMode:network,Privileged:false,ReadonlyRootfs:true,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges'],PortBindings:{},Devices:[],Binds:[],Tmpfs:{'/secrets':'rw,nosuid,nodev,noexec,size=128k,uid=10001,gid=10001,mode=0700','/tmp':'rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700'}},Mounts:[],NetworkSettings:{Networks:{private:{NetworkID:network}}}};}
const spec={runID,name,image,network,imageEnvironment:['PATH=/usr/bin']};

test('commissioning toolchain is a pinned credential-free two-binary source build',()=>{
 const raw=readFileSync(path.join(root,'examples/group-fixture-commission/Dockerfile'),'utf8');validateCommissionTooling(raw);
 for(const changed of [raw.replace('sharing=locked','sharing=shared'),raw.replace('USER 10001:10001','USER root'),raw+'\nCOPY .env /secrets\n',raw.replace(/@sha256:[a-f0-9]{64}/,'')])assert.throws(()=>validateCommissionTooling(changed));
});
test('only the inspected local fixture project, credentials and private stores are selected',()=>{
 assert.deepEqual(validateCommissionSources(sources(),workspace,api,issuer),{project,network});
 for(const change of [s=>s.ingester.Config.Env.push('FIXTURE_MODE=false'),s=>s.ingester.Config.Env.push('DATABASE_URL=postgres://postgres:unused@postgres:5432/finops?sslmode=disable'),s=>s.ingester.Config.Env.push('OBJECT_ENDPOINT=http://external:9000'),s=>s.ingester.Config.Env.push('AWS_ACCESS_KEY_ID=unused'),s=>s.minio.Config.Labels['com.docker.compose.project']='elsewhere',s=>s.economics.Config.Env.push('FIXTURE_MODE=false'),s=>s.clickhouse.NetworkSettings.Ports={'8123/tcp':[{HostIp:'0.0.0.0',HostPort:'8123'}]},s=>s.ingester.NetworkSettings.Networks.other={NetworkID:network}]){const bad=sources();change(bad);assert.throws(()=>validateCommissionSources(bad,workspace,api,issuer));}
});
test('stdin job container accepts no host secret mounts, privileges, alternate command or network',()=>{
 validateCommissionJob(job(),spec);
 for(const change of [o=>o.Image='sha256:'+'c'.repeat(64),o=>o.Config.User='0:0',o=>o.Config.Env.push('SIGNER_TOKEN=unused'),o=>o.Config.Cmd=['sh'],o=>o.HostConfig.Binds=['/host:/secrets'],o=>o.Mounts.push({Type:'bind',Destination:'/secrets',Source:'/host',RW:false}),o=>o.HostConfig.Privileged=true,o=>o.HostConfig.CapAdd=['SYS_ADMIN'],o=>o.HostConfig.NetworkMode='host',o=>o.NetworkSettings.Networks.private.NetworkID='c'.repeat(64),o=>o.HostConfig.Tmpfs['/secrets']='rw,mode=0777',o=>o.Config.Labels['finops.group-fixture-commission.run']='foreign']){const bad=job();change(bad);assert.throws(()=>validateCommissionJob(bad,spec));}
});
test('browser uses only inspected same-project web with fixed API upstream and loopback port',()=>{
 for(const change of [s=>s.web.Config.Env.push('API_UPSTREAM=customer:8080'),s=>s.web.NetworkSettings.Ports['8080/tcp'][0].HostIp='0.0.0.0',s=>s.web.Config.Labels['com.docker.compose.project']='foreign',s=>s.web.NetworkSettings.Networks.private={NetworkID:network}]){const bad=sources();change(bad);assert.throws(()=>validateCommissionSources(bad,workspace,api,issuer));}
 assert.throws(()=>validateCommissionSources(sources(),workspace,api,issuer,'http://customer:3000'));
 const runner=readFileSync(path.join(root,'scripts/group-fixture-commission.mjs'),'utf8');assert.match(runner,/FINOPS_WEB_URL:web/);assert.match(runner,/FINOPS_E2E_USER:'owner'/);assert.match(runner,/FINOPS_E2E_PASSWORD:privateEnv.DEMO_PASSWORD/);
});
test('fixed public source location contains no native samples, secret fields or health authority',()=>{
 const row={...commissionRegistration,id:runID,tenant_id:'tenant-demo',enabled:true};assert.equal(validateCommissionSource(row),runID);
 assert.ok(commissionRegistration.prefix.includes('DETERMINISTIC_FIXTURE'));assert.ok(commissionRegistration.read_role_binding_id.includes('DETERMINISTIC_FIXTURE'));
 for(const key of ['trusted','complete','status','raw','credentials','native_rows','role_arn'])assert.ok(!Object.hasOwn(commissionRegistration,key));
 for(const change of [o=>o.tenant_id='tenant-other',o=>o.prefix='cur/',o=>o.read_role_binding_id='customer',o=>o.region='us-east-1',o=>o.enabled=false,o=>o.revoked=true]){const bad=clone(row);change(bad);assert.throws(()=>validateCommissionSource(bad));}
});
test('normal pipeline completion requires actual recent HEALTHY metadata with explicit fixture limits',()=>{
 const now=Date.now(),result={status:'HEALTHY',mode:'SYNC_SOURCE',fixture:true,source_id:runID,provider_adapter:'DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026',config_sha256:'c'.repeat(64),last_sync_at:new Date(now-100).toISOString(),customer_execution_authorized:false,verified_saving:null};validateCommissionSync(result,runID,now);
 for(const change of [r=>r.status='SYNCING',r=>r.fixture=false,r=>r.source_id='other',r=>r.last_sync_at=new Date(now-60001).toISOString(),r=>r.last_sync_at=new Date(now+2000).toISOString(),r=>r.customer_execution_authorized=true,r=>r.verified_saving='0']){const bad=clone(result);change(bad);assert.throws(()=>validateCommissionSync(bad,runID,now));}
});
test('one exact new live case follows the other74; source loss never triggers recreation',()=>{
 const runner=readFileSync(path.join(root,'scripts/group-fixture-commission.mjs'),'utf8'),live=readFileSync(path.join(root,'frontend/tests/fleet-fixture-live.spec.ts'),'utf8');assert.ok(live.includes(commissionTitle));
 assert.match(runner,/'tests\/fleet-fixture-live\.spec\.ts'/);assert.match(runner,/FINOPS_E2E_FLEET_SOURCE_ID:sourceID/);assert.match(runner,/FINOPS_E2E_FIXTURE_PROFILE_ID:profile.id/);assert.match(runner,/cleanup_succeeded:true/);
 assert.equal((runner.match(/api\+'\/v1\/source-connections'/g)||[]).length,1);assert.ok(!runner.includes('/v1/demo/reset'));assert.ok(!runner.includes('--retries'));assert.ok(!runner.includes('--timeout'));
});


test('commissioning requires exact001–043 and the reviewed037/038/039/040/041/042/043 bytes; future or incomplete prefixes refuse',()=>{
 const migrationRoot=path.join(root,'migrations'),names=readdirSync(migrationRoot).filter(name=>/^\d{3}_[a-z0-9_]+\.sql$/.test(name)).sort();
 const expected=commissionMigrationManifest(migrationRoot);assert.equal(Object.keys(expected).length,44);assert.equal(expected['037_fleet_joint_decisions.sql'],'54a44013471e1ca3c8e6990d3f554a0f986133441a3a9762b37eabc0fb51f051');assert.equal(expected['038_fleet_decision_credential_scope.sql'],'789d53114532af2b831fc2e2c011b5d15e7df2b72affafb2068fc4a84a6ee984');assert.equal(expected['039_commitment_portfolio.sql'],'89d382c5d6b81af066774e5367aff9cd764fc53e6d79f5f49ff6359a0e8f0aaf');
 assert.equal(expected['040_commitment_decisions.sql'],'dec0a482c3cd0d0f1cdb11e1de02833817cd7a705b81c01d4f87dd2109a9b76f');
 assert.equal(expected['041_database_assessments.sql'],'305be6e59ed393e4d541334f1296c3f5ac208726bebd9b29b07fa3299b5d9380');
 assert.equal(expected['042_storage_assessments.sql'],'4167cf4ec6df2112e8d8a9233ef005e0105dfb33bd51e413310433356d1aaa30');
 assert.equal(expected['044_network_assessments.sql'],'2f98fb315df0944f6a75ec6bb1b8978c2991039257fd60d959c6d70c26b67732');
 assert.equal(expected['043_object_storage_assessments.sql'],'75fc1e107f55eb7db66233304abe4bf21056376e54a9fb729fcac71571bbc7e7');
 for(const name of names.slice(0,42))assert.equal(expected[name],createHash('sha256').update(readFileSync(path.join(migrationRoot,name))).digest('hex'));
 const folder=mkdtempSync(path.join(os.tmpdir(),'commission-reviewed040-'));try{
  for(const name of names)copyFileSync(path.join(migrationRoot,name),path.join(folder,name));assert.deepEqual(commissionMigrationManifest(folder),expected);
  for(const name of ['037_fleet_joint_decisions.sql','038_fleet_decision_credential_scope.sql','039_commitment_portfolio.sql','040_commitment_decisions.sql','041_database_assessments.sql','042_storage_assessments.sql','043_object_storage_assessments.sql','044_network_assessments.sql']){const latest=path.join(folder,name),raw=readFileSync(latest);writeFileSync(latest,Buffer.concat([raw,Buffer.from('\n-- changed release bytes\n')]));assert.throws(()=>commissionMigrationManifest(folder));writeFileSync(latest,raw);}
  writeFileSync(path.join(folder,'045_unreviewed_future.sql'),'SELECT 1;');assert.throws(()=>commissionMigrationManifest(folder));unlinkSync(path.join(folder,'045_unreviewed_future.sql'));
  const current=readFileSync(path.join(folder,'043_object_storage_assessments.sql'));unlinkSync(path.join(folder,'043_object_storage_assessments.sql'));assert.throws(()=>commissionMigrationManifest(folder));writeFileSync(path.join(folder,'043_object_storage_assessments.sql'),current);
  unlinkSync(path.join(folder,'040_commitment_decisions.sql'));assert.throws(()=>commissionMigrationManifest(folder));
  assert.throws(()=>assertMigrationManifest({...expected,'045_unreviewed_future.sql':'a'.repeat(64)},expected));
  const changed={...expected,[names[0]]:'b'.repeat(64)};assert.throws(()=>assertMigrationManifest(changed,expected));
 }finally{assert.equal(path.dirname(path.resolve(folder)),path.resolve(os.tmpdir()));assert.match(path.basename(folder),/^commission-reviewed040-/);rmSync(folder,{recursive:true,force:true});}
});
