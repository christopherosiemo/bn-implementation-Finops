// NEXT private-job building blocks only. Importing this file performs no I/O,
// Docker, SQL, S3, HTTP, preparation, signing, approval or delivery action.
import assert from 'node:assert/strict';

const digest=/^[a-f0-9]{64}$/;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const image=/^sha256:[a-f0-9]{64}$/;
const profileID=/^fixture-profile-[a-f0-9-]{36}$/;
export const preparerLabel='finops.group-fixture-preparer.run';
export const preparerFiles=Object.freeze(['archive-key','database','installation','ledger-public','object-access','object-secret','pipeline-public']);
export const preparerStagingCommand=Object.freeze(['/usr/bin/tar','--extract','--file=-','--directory=/secrets','--no-same-owner','--no-same-permissions','--keep-old-files']);
export const preparerExecutionCommand=Object.freeze(['/compiled/preparer']);
// Covers the unchanged preparer's five-minute context plus stdin staging.
export const preparerInertSeconds=360;
export const preparerTmpfs=Object.freeze({
 '/secrets':'rw,nosuid,nodev,noexec,size=128k,uid=10001,gid=10001,mode=0700',
 '/workspace':'rw,nosuid,nodev,size=128m,uid=10001,gid=10001,mode=0700',
 '/tmp':'rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700',
});

function receiptBoundary(receipt){
 assert.equal(receipt?.status,'PASS');assert.match(receipt.run_id,uuid);assert.match(receipt.source_id,uuid);assert.match(receipt.profile_id,profileID);assert.match(receipt.tooling_image_id,image);assert.match(receipt.source_manifest_sha256,digest);
 assert.equal(receipt.realm,'ISOLATED_FIXTURE');assert.equal(receipt.provider_adapter,'DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026');assert.equal(receipt.actual_terraform_version,'1.16.0');assert.equal(receipt.customer_native_authority,false);assert.equal(receipt.customer_execution_authorized,false);assert.equal(receipt.verified_saving,null);assert.equal(receipt.cleanup_succeeded,true);
}
function proposalBoundary(row,receipt){
 const p=row?.proposal;assert.ok(p);assert.match(row.id,uuid);assert.equal(p.id,row.id);assert.equal(p.purpose,'ISOLATED_GROUP_FIXTURE_PROPOSAL');assert.equal(p.workload_id,'workload-dev');assert.equal(p.customer_execution_authorized,false);assert.equal(p.estimated_saving,null);assert.equal(p.verified_saving,null);
 assert.equal(p.profile.id,receipt.profile_id);assert.match(p.profile.generation,uuid);assert.equal(p.profile.realm_kind,'ISOLATED_FIXTURE');assert.equal(p.realm.kind,'ISOLATED_FIXTURE');assert.equal(p.realm.fixture_id,p.profile.id);assert.equal(p.realm.generation,p.profile.generation);assert.equal(p.realm.model_sha256,p.profile.model_sha256);
 const installation=p.profile.installation;assert.equal(installation.template_id,'builtin-group-fixture-v1');assert.equal(installation.toolchain_image_sha256,receipt.tooling_image_id.slice(7));assert.equal(installation.terraform_version,'1.16.0');assert.equal(installation.receipt_id,receipt.run_id);assert.equal(installation.source_sha256,receipt.source_manifest_sha256);
 for(const side of ['old','candidate']){const s=p.binding[side];assert.equal(s.source_id,receipt.source_id);assert.equal(s.target.tenant_id,'tenant-demo');assert.equal(s.target.workload_id,'workload-dev');assert.equal(s.target.provider,'AWS');assert.equal(s.target.account_id,'111122223333');assert.equal(s.target.region,'eu-west-1');assert.ok(typeof s.target.asg_arn==='string'&&s.target.asg_arn.startsWith('arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:'));assert.ok(!Object.hasOwn(s.target,'resource_id'));}
 assert.notEqual(p.binding.old.target.asg_arn,p.binding.candidate.target.asg_arn);
 return p;
}

// rows must come from all authenticated, scoped API cursor pages. The opaque
// commission receipt selects one actual installed generation/source pair, not
// the most recent arbitrary proposal, an EC2 representative or caller payload.
export function selectCommissionedPreparerProposal(rows,receipt,authenticatedCreator){
 receiptBoundary(receipt);assert.ok(typeof authenticatedCreator==='string'&&authenticatedCreator.length>0&&authenticatedCreator.length<=256);assert.ok(Array.isArray(rows)&&rows.length<=10000);
 const seen=new Set();for(const row of rows){assert.match(row?.id,uuid);assert.ok(!seen.has(row.id));seen.add(row.id);}
 const matches=rows.filter(row=>row.proposal?.profile?.id===receipt.profile_id&&row.proposal?.binding?.old?.source_id===receipt.source_id&&row.proposal?.binding?.candidate?.source_id===receipt.source_id&&row.proposal?.creator_id===authenticatedCreator);
 assert.equal(matches.length,1,'Exactly one authenticated persisted selection must match the commissioning receipt');
 proposalBoundary(matches[0],receipt);return matches[0];
}

export function preparerInstallation(row,receipt){
 receiptBoundary(receipt);const p=proposalBoundary(row,receipt),i=p.profile.installation;
 return {schema_version:'1',profile_id:p.profile.id,generation:p.profile.generation,toolchain_image_sha256:i.toolchain_image_sha256,terraform_version:i.terraform_version,receipt_id:i.receipt_id,source_sha256:i.source_sha256};
}

// No key is generated or persisted here. The private installer retains the
// persistent archive master and any future fixture pipeline/ledger private
// keys outside the worker. The scoped worker receives an ephemeral archive-key
// copy needed for encryption/readback and only the two distinct PUBLIC keys.
export function preparerPrivateFiles(row,receipt,{database,archiveKey,pipelinePublic,ledgerPublic,access,secret}){
 const installation=preparerInstallation(row,receipt),u=new URL(database);
 assert.equal(u.protocol,'postgres:');assert.equal(u.host,'postgres:5432');assert.equal(u.pathname,'/finops');assert.match(u.username,/^fixture_preparer_[a-f0-9]{32}$/);assert.ok(u.password);assert.equal(u.search,'?sslmode=disable');assert.equal(u.hash,'');
 for(const b of [archiveKey,pipelinePublic,ledgerPublic])assert.ok(Buffer.isBuffer(b)&&b.length===32);assert.ok(!pipelinePublic.equals(ledgerPublic));
 for(const v of [access,secret])assert.ok(typeof v==='string'&&v.length>0&&v.length<=256&&!/[\s\0]/.test(v));assert.ok(!access.startsWith('AKIA')&&!access.startsWith('ASIA'));
 return {database:Buffer.from(database),installation:Buffer.from(JSON.stringify(installation)),'pipeline-public':Buffer.from(pipelinePublic),'ledger-public':Buffer.from(ledgerPublic),'archive-key':Buffer.from(archiveKey),'object-access':Buffer.from(access),'object-secret':Buffer.from(secret)};
}

// Deterministic USTAR, no links, dirs, extended headers or arbitrary names.
// Stream only to the inspected running container's /secrets tmpfs. Never use
// docker cp into a stopped container or stage plaintext in a host bind mount.
export function encodePreparerPrivateTar(files){
 assert.deepEqual(Object.keys(files).sort(),[...preparerFiles]);
 for(const name of preparerFiles){const body=files[name];assert.ok(Buffer.isBuffer(body)&&body.length>0&&body.length<=8192);if(['pipeline-public','ledger-public','archive-key'].includes(name))assert.equal(body.length,32);if(['object-access','object-secret'].includes(name))assert.ok(body.length<=256);if(name==='installation')assert.ok(body.length<=4096);}
 return fixedTar(files,preparerFiles);
}
export function encodePreparerAdminTar(config,policy){
 assert.ok(typeof config==='string'&&config.length>0&&Buffer.byteLength(config)<=8192);assert.ok(policy&&typeof policy==='object');
 return fixedTar({'mc.env':Buffer.from(config),'policy.json':Buffer.from(JSON.stringify(policy))},['mc.env','policy.json']);
}
function fixedTar(files,names){
 const chunks=[];
 const octal=(b,offset,length,value)=>{const text=value.toString(8).padStart(length-1,'0')+'\0';assert.equal(text.length,length);b.write(text,offset,length,'ascii');};
 for(const name of names){
  const body=files[name];assert.ok(Buffer.isBuffer(body)&&body.length>0&&body.length<=8192);
  const header=Buffer.alloc(512);header.write(name,0,100,'ascii');octal(header,100,8,0o600);octal(header,108,8,10001);octal(header,116,8,10001);octal(header,124,12,body.length);octal(header,136,12,0);header.fill(0x20,148,156);header[156]=0x30;header.write('ustar\0',257,6,'ascii');header.write('00',263,2,'ascii');const checksum=header.reduce((sum,v)=>sum+v,0);header.write(checksum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');
  chunks.push(header,Buffer.from(body),Buffer.alloc((512-body.length%512)%512));
 }
 chunks.push(Buffer.alloc(1024));const raw=Buffer.concat(chunks);assert.ok(raw.length<=65536);return raw;
}

export function preparerJobEnvironment(row,receipt){
 preparerInstallation(row,receipt);
 return {
  GROUP_FIXTURE_ENABLED:'true',GROUP_FIXTURE_MODE:'ISOLATED_FIXTURE',GROUP_FIXTURE_TENANT_ID:'tenant-demo',GROUP_FIXTURE_PROPOSAL_ID:row.id,
  GROUP_FIXTURE_DATABASE_FILE:'/secrets/database',GROUP_FIXTURE_INSTALLATION_FILE:'/secrets/installation',GROUP_FIXTURE_PIPELINE_PUBLIC_KEY_FILE:'/secrets/pipeline-public',GROUP_FIXTURE_LEDGER_PUBLIC_KEY_FILE:'/secrets/ledger-public',GROUP_FIXTURE_ARCHIVE_KEY_FILE:'/secrets/archive-key',
  GROUP_FIXTURE_S3_ENDPOINT:'http://minio:9000',GROUP_FIXTURE_S3_REGION:'eu-west-1',GROUP_FIXTURE_S3_BUCKET:'finops-raw',GROUP_FIXTURE_S3_ACCESS_KEY_FILE:'/secrets/object-access',GROUP_FIXTURE_S3_SECRET_KEY_FILE:'/secrets/object-secret',HOME:'/tmp',GOMEMLIMIT:'384MiB',
 };
}

export function preparerArchivePolicy(row,receipt){
 const installation=preparerInstallation(row,receipt);
 return {Version:'2012-10-17',Statement:[
  {Effect:'Allow',Action:['s3:GetBucketVersioning'],Resource:['arn:aws:s3:::finops-raw']},
  {Effect:'Allow',Action:['s3:GetObject','s3:GetObjectVersion','s3:PutObject'],Resource:[`arn:aws:s3:::finops-raw/tenant/tenant-demo/fleet-group-fixture/${row.id}/${installation.generation}/*`]},
 ]};
}

export function preparerContainerArguments(row,receipt,runID,network){
 assert.match(runID,uuid);assert.match(network,digest);const environment=preparerJobEnvironment(row,receipt),name='finops-group-preparer-'+runID.replaceAll('-','');
 return {name,environment,args:['create','--name',name,'--label',preparerLabel+'='+runID,'--pull','never','--network',network,'--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','512m','--cpus','1',...Object.entries(environment).flatMap(([k,v])=>['-e',k+'='+v]),...Object.entries(preparerTmpfs).flatMap(([k,v])=>['--tmpfs',k+':'+v]),'--workdir','/tmp','--entrypoint','/usr/bin/sleep',receipt.tooling_image_id,String(preparerInertSeconds)]};
}

export function validatePreparerContainer(o,row,receipt,runID,network,imageEnvironment){
 const expected=preparerContainerArguments(row,receipt,runID,network);
 assert.equal(o.Name,'/'+expected.name);assert.equal(o.Config?.Labels?.[preparerLabel],runID);assert.equal(o.Image,receipt.tooling_image_id);assert.equal(o.Config?.User,'10001:10001');assert.deepEqual(o.Config?.Entrypoint,['/usr/bin/sleep']);assert.deepEqual(o.Config?.Cmd,[String(preparerInertSeconds)]);
 assert.equal(o.HostConfig?.NetworkMode,network);const networks=Object.values(o.NetworkSettings?.Networks||{});if(o.State?.Running){assert.equal(networks.length,1);assert.equal(networks[0].NetworkID,network);}
 assert.equal(o.HostConfig?.ReadonlyRootfs,true);assert.equal(o.HostConfig?.Privileged,false);assert.deepEqual(o.HostConfig?.CapDrop,['ALL']);assert.deepEqual(o.HostConfig?.CapAdd||[],[]);assert.ok(o.HostConfig?.SecurityOpt?.includes('no-new-privileges'));assert.deepEqual(o.HostConfig?.Binds||[],[]);assert.equal((o.HostConfig?.Devices||[]).length,0);assert.equal(Object.keys(o.HostConfig?.PortBindings||{}).length,0);assert.deepEqual(o.HostConfig?.Tmpfs,preparerTmpfs);assert.ok((o.Mounts||[]).every(m=>m.Type==='tmpfs'&&Object.hasOwn(preparerTmpfs,m.Destination)&&!m.Source));
 const env=[...imageEnvironment.filter(v=>!Object.hasOwn(expected.environment,v.split('=',1)[0])),...Object.entries(expected.environment).map(([k,v])=>k+'='+v)];assert.deepEqual([...(o.Config?.Env||[])].sort(),env.sort());
}

// Ownership/configuration inspection deliberately also works before start and
// after exit. Only a freshly inspected running container can receive secrets
// or dispatch the fixed executable.
export function requirePreparerRunning(o){assert.equal(o.State?.Running,true,'Private job must be running before staging or execution');}
