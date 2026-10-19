import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';

export function validateCapacityCompose(ordinary,enabled){
 assert.match(enabled.name,/^[a-z0-9][a-z0-9_-]{0,127}$/);
 assert.equal(ordinary.name,enabled.name,'Both configurations must belong to the same local project');
 assert.deepEqual(enabled.volumes['fleet-capacity-secrets'],{name:enabled.name+'_fleet-capacity-secrets'},'The initializer can write only its own ordinary project volume');
 assert.ok(!ordinary.services['fleet-capacity'],'Optional capacity worker must be absent by default');
 assert.ok(!ordinary.services['fleet-capacity-secrets-init'],'Secret initialization must be absent by default');
 const worker=enabled.services['fleet-capacity'];assert.ok(worker);
 assert.deepEqual(worker.entrypoint,['/app/fleet-capacity-worker']);
 assert.equal(worker.read_only,true);assert.deepEqual(worker.cap_drop,['ALL']);
 assert.deepEqual(worker.security_opt,['no-new-privileges:true']);
 assert.ok(!worker.ports?.length&&!worker.privileged&&!worker.pid&&!worker.devices?.length&&!worker.secrets?.length);
 assert.deepEqual(worker.volumes.map(({type,source,target,read_only})=>({type,source,target,read_only})),[{type:'volume',source:'fleet-capacity-secrets',target:'/run/secrets',read_only:true}]);
 assert.deepEqual(Object.keys(worker.networks),['private']);
 assert.equal(Number(worker.mem_limit),512*1024*1024);assert.equal(Number(worker.cpus),1);
 assert.deepEqual(worker.tmpfs,['/tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700']);
 assert.deepEqual(worker.healthcheck.test,['CMD','/app/fleet-capacity-worker','--healthcheck']);
 const expected={FLEET_CAPACITY_ENABLED:'true',FLEET_CAPACITY_TENANT_ID:'tenant-demo',FLEET_CAPACITY_DATABASE_FILE:'/run/secrets/group-capacity-database',FLEET_CAPACITY_ARCHIVE_REGION:'eu-west-1',FLEET_CAPACITY_ARCHIVE_MODE:'LOCAL_VERSIONED_S3',FLEET_CAPACITY_ARCHIVE_ENDPOINT:'http://minio:9000',FLEET_CAPACITY_ARCHIVE_BUCKET:'finops-raw',FLEET_CAPACITY_ARCHIVE_ACCESS_KEY_FILE:'/run/secrets/group-capacity-access-key',FLEET_CAPACITY_ARCHIVE_SECRET_KEY_FILE:'/run/secrets/group-capacity-secret-key',FLEET_CAPACITY_SERVICE_MODE:'PRIVATE_SERVICES',FLEET_CAPACITY_READER_URL:'http://telemetry-reader:8095',FLEET_CAPACITY_READER_TOKEN_FILE:'/run/secrets/group-capacity-reader-token',FLEET_CAPACITY_MODEL_URL:'http://economics:8000',FLEET_CAPACITY_MODEL_TOKEN_FILE:'/run/secrets/group-capacity-model-token'};
 assert.deepEqual(worker.environment,expected,'Common signer, execution, writer or provider credentials must not reach this process');
 assert.deepEqual(Object.keys(worker.depends_on).sort(),['buckets','economics','fleet-capacity-secrets-init','migrate','telemetry-reader']);
 assert.equal(worker.depends_on['fleet-capacity-secrets-init'].condition,'service_completed_successfully');
 const initializer=enabled.services['fleet-capacity-secrets-init'];assert.ok(initializer);
 assert.equal(initializer.image,worker.image);assert.equal(initializer.user,'0:0');
 assert.deepEqual(initializer.entrypoint,['/bin/sh','-ec']);
 assert.ok(Array.isArray(initializer.command)&&initializer.command.length===1&&typeof initializer.command[0]==='string');
 assert.equal(createHash('sha256').update(initializer.command[0]).digest('hex'),'e32f59fbc5c6544fc83319611b1e1da4e6eb85f9390e609e10b0003b59a58a0b','Only the reviewed five-file initialization body may execute');
 assert.equal(initializer.network_mode,'none');assert.equal(initializer.read_only,true);
 assert.equal(Number(initializer.mem_limit),64*1024*1024);assert.equal(Number(initializer.cpus),0.1);
 assert.deepEqual(initializer.volumes.map(({type,source,target,read_only})=>({type,source,target,read_only:read_only===true})),[{type:'volume',source:'fleet-capacity-secrets',target:'/capacity-secrets',read_only:false}]);
 assert.deepEqual(initializer.cap_drop,['ALL']);assert.deepEqual(initializer.security_opt,['no-new-privileges:true']);
 assert.ok(!initializer.ports?.length&&!initializer.privileged&&!initializer.pid&&!initializer.devices?.length&&!Object.keys(initializer.environment||{}).length);
 assert.deepEqual(initializer.secrets.map(x=>x.source).sort(),['group-capacity-access-key','group-capacity-database','group-capacity-model-token','group-capacity-reader-token','group-capacity-secret-key']);
 const secretDirectory=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../work/private/fleet-capacity-secrets');
 for(const [name,file] of Object.entries({'group-capacity-database':'database','group-capacity-access-key':'access-key','group-capacity-secret-key':'secret-key','group-capacity-reader-token':'reader-token','group-capacity-model-token':'model-token'})){
  assert.equal(enabled.secrets[name].environment,undefined);
  assert.equal(enabled.secrets[name].external,undefined);
  assert.equal(path.resolve(enabled.secrets[name].file),path.join(secretDirectory,file));
 }
 for(const [name,service]of Object.entries(enabled.services))if(name!=='fleet-capacity-secrets-init')assert.ok(!(service.secrets||[]).some(x=>x.source.startsWith('group-capacity-')),'Capacity credentials cannot be mounted in another process');
 return {status:'PASS',optional_worker_default_disabled:true,isolated_identity_and_archive_reader:true,customer_mutations:false};
}

export function checkCapacityCompose(){
 assert.equal(process.argv.length,2,'No alternative deployment targets accepted');
 const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
 const read=profile=>JSON.parse(execFileSync('docker',['compose',...(profile?['--profile','fleet-capacity']:[]),'config','--format','json'],{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:4<<20,timeout:30000}));
 // The resolved configuration can contain service secrets. Keep it in memory;
 // only fixed assertions and the bounded result below may leave this process.
 return validateCapacityCompose(read(false),read(true));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{console.log(JSON.stringify(checkCapacityCompose()));}
 catch{console.error('Capacity Compose credential or deployment boundary refused. No resolved configuration was emitted.');process.exitCode=1;}
}
