import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';

export function validateAssessmentCompose(ordinary,enabled){
 assert.ok(!ordinary.services['fleet-assessment'],'Optional assessment worker must be absent by default');
 assert.ok(!ordinary.services['fleet-assessment-secrets-init'],'Secret initialization must be absent by default');
 const worker=enabled.services['fleet-assessment'];assert.ok(worker);
 assert.deepEqual(worker.entrypoint,['/app/fleet-assessment-worker']);
 assert.equal(worker.read_only,true);assert.deepEqual(worker.cap_drop,['ALL']);
 assert.deepEqual(worker.security_opt,['no-new-privileges:true']);
 assert.ok(!worker.ports?.length&&!worker.privileged&&!worker.pid&&!worker.devices?.length&&!worker.secrets?.length);
 assert.deepEqual(worker.volumes.map(({type,source,target,read_only})=>({type,source,target,read_only})),[{type:'volume',source:'fleet-assessment-secrets',target:'/run/secrets',read_only:true}]);
 assert.deepEqual(Object.keys(worker.networks),['private']);
 assert.equal(Number(worker.mem_limit),512*1024*1024);assert.equal(Number(worker.cpus),1);
 assert.deepEqual(worker.tmpfs,['/tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700']);
 assert.deepEqual(worker.healthcheck.test,['CMD','/app/fleet-assessment-worker','--healthcheck']);
 const expected={FLEET_ASSESSMENT_ENABLED:'true',FLEET_ASSESSMENT_TENANT_ID:'tenant-demo',FLEET_ASSESSMENT_DATABASE_FILE:'/run/secrets/group-assessment-database',FLEET_ASSESSMENT_ARCHIVE_REGION:'eu-west-1',FLEET_ASSESSMENT_ARCHIVE_MODE:'LOCAL_VERSIONED_S3',FLEET_ASSESSMENT_ARCHIVE_ENDPOINT:'http://minio:9000',FLEET_ASSESSMENT_ARCHIVE_BUCKET:'finops-raw',FLEET_ASSESSMENT_ARCHIVE_ACCESS_KEY_FILE:'/run/secrets/group-assessment-access-key',FLEET_ASSESSMENT_ARCHIVE_SECRET_KEY_FILE:'/run/secrets/group-assessment-secret-key'};
 assert.deepEqual(worker.environment,expected,'Common signer, execution, writer or provider credentials must not reach this process');
 assert.deepEqual(Object.keys(worker.depends_on).sort(),['buckets','fleet-assessment-secrets-init','migrate']);
 assert.equal(worker.depends_on['fleet-assessment-secrets-init'].condition,'service_completed_successfully');
 const initializer=enabled.services['fleet-assessment-secrets-init'];assert.ok(initializer);
 assert.equal(initializer.image,worker.image);assert.equal(initializer.user,'0:0');
 assert.deepEqual(initializer.entrypoint,['/bin/sh','-ec']);
 assert.equal(initializer.network_mode,'none');assert.equal(initializer.read_only,true);
 assert.equal(Number(initializer.mem_limit),64*1024*1024);assert.equal(Number(initializer.cpus),0.1);
 assert.deepEqual(initializer.volumes.map(({type,source,target,read_only})=>({type,source,target,read_only:read_only===true})),[{type:'volume',source:'fleet-assessment-secrets',target:'/assessment-secrets',read_only:false}]);
 assert.deepEqual(initializer.cap_drop,['ALL']);assert.deepEqual(initializer.security_opt,['no-new-privileges:true']);
 assert.ok(!initializer.ports?.length&&!initializer.privileged&&!initializer.pid&&!initializer.devices?.length&&!Object.keys(initializer.environment||{}).length);
 assert.deepEqual(initializer.secrets.map(x=>x.source).sort(),['group-assessment-access-key','group-assessment-database','group-assessment-secret-key']);
 const secretDirectory=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../work/private/fleet-assessment-secrets');
 for(const [name,file] of Object.entries({'group-assessment-database':'database','group-assessment-access-key':'access-key','group-assessment-secret-key':'secret-key'})){
  assert.equal(enabled.secrets[name].environment,undefined);
  assert.equal(enabled.secrets[name].external,undefined);
  assert.equal(path.resolve(enabled.secrets[name].file),path.join(secretDirectory,file));
 }
 for(const [name,service]of Object.entries(enabled.services))if(name!=='fleet-assessment-secrets-init')assert.ok(!(service.secrets||[]).some(x=>x.source.startsWith('group-assessment-')),'Assessment credentials cannot be mounted in another process');
 return {status:'PASS',optional_worker_default_disabled:true,isolated_identity_and_archive_reader:true,customer_mutations:false};
}

export function checkAssessmentCompose(){
 assert.equal(process.argv.length,2,'No alternative deployment targets accepted');
 const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
 const read=profile=>JSON.parse(execFileSync('docker',['compose',...(profile?['--profile','fleet-assessment']:[]),'config','--format','json'],{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:4<<20,timeout:30000}));
 // The resolved configuration can contain service secrets. Keep it in memory;
 // only fixed assertions and the bounded result below may leave this process.
 return validateAssessmentCompose(read(false),read(true));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{console.log(JSON.stringify(checkAssessmentCompose()));}
 catch{console.error('Assessment Compose credential or deployment boundary refused. No resolved configuration was emitted.');process.exitCode=1;}
}
