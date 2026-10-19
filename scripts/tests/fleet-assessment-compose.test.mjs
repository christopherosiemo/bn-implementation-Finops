import assert from 'node:assert/strict';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {validateAssessmentCompose} from '../fleet-assessment-compose-check.mjs';

function documents(){
 const secretFile=name=>fileURLToPath(new URL('../../work/private/fleet-assessment-secrets/'+name,import.meta.url));
 const names=['group-assessment-access-key','group-assessment-database','group-assessment-secret-key'];
 const secrets={'group-assessment-database':{file:secretFile('database')},'group-assessment-access-key':{file:secretFile('access-key')},'group-assessment-secret-key':{file:secretFile('secret-key')}};
 const worker={entrypoint:['/app/fleet-assessment-worker'],read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],networks:{private:{}},mem_limit:536870912,cpus:1,tmpfs:['/tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700'],healthcheck:{test:['CMD','/app/fleet-assessment-worker','--healthcheck']},volumes:[{type:'volume',source:'fleet-assessment-secrets',target:'/run/secrets',read_only:true}],depends_on:{migrate:{},buckets:{},'fleet-assessment-secrets-init':{condition:'service_completed_successfully'}},environment:{FLEET_ASSESSMENT_ENABLED:'true',FLEET_ASSESSMENT_TENANT_ID:'tenant-demo',FLEET_ASSESSMENT_DATABASE_FILE:'/run/secrets/group-assessment-database',FLEET_ASSESSMENT_ARCHIVE_REGION:'eu-west-1',FLEET_ASSESSMENT_ARCHIVE_MODE:'LOCAL_VERSIONED_S3',FLEET_ASSESSMENT_ARCHIVE_ENDPOINT:'http://minio:9000',FLEET_ASSESSMENT_ARCHIVE_BUCKET:'finops-raw',FLEET_ASSESSMENT_ARCHIVE_ACCESS_KEY_FILE:'/run/secrets/group-assessment-access-key',FLEET_ASSESSMENT_ARCHIVE_SECRET_KEY_FILE:'/run/secrets/group-assessment-secret-key'}};
 worker.image='cloud-cost-autopilot-go:local';
 const initializer={image:worker.image,user:'0:0',entrypoint:['/bin/sh','-ec'],mem_limit:64*1024*1024,cpus:0.1,volumes:[{type:'volume',source:'fleet-assessment-secrets',target:'/assessment-secrets'}],network_mode:'none',read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],secrets:names.map(source=>({source}))};
 return [{services:{}},{secrets,services:{'fleet-assessment':worker,'fleet-assessment-secrets-init':initializer}}];
}
test('assessment Compose boundary accepts only optional dedicated read-only process',()=>assert.equal(validateAssessmentCompose(...documents()).status,'PASS'));
test('inherited authority, host exposure, credential sharing or enabled-by-default inputs are refused',()=>{
 const mutations=[
  ([ordinary,enabled])=>{ordinary.services['fleet-assessment']=enabled.services['fleet-assessment'];},
  ([ordinary,enabled])=>{ordinary.services['fleet-assessment-secrets-init']=enabled.services['fleet-assessment-secrets-init'];},
  ([,enabled])=>{enabled.services['fleet-assessment'].environment.SIGNER_TOKEN='forged';},
  ([,enabled])=>{enabled.services['fleet-assessment'].ports=[{published:'8088'}];},
  ([,enabled])=>{enabled.services['fleet-assessment'].environment.FLEET_ASSESSMENT_ARCHIVE_MODE='AWS_IRSA';},
  ([,enabled])=>{enabled.services['fleet-assessment'].read_only=false;},
  ([,enabled])=>{enabled.services.api={secrets:[{source:'group-assessment-database'}]};},
  ([,enabled])=>{enabled.services['fleet-assessment'].tmpfs=['/tmp:rw','nosuid','nodev','noexec','size=16m','uid=10001','gid=10001','mode=0700'];},
  ([,enabled])=>{enabled.secrets['group-assessment-database']={environment:'FLEET_ASSESSMENT_DATABASE_URL'};},
  ([,enabled])=>{enabled.secrets['group-assessment-secret-key'].file='/foreign/secret';},
  ([,enabled])=>{enabled.services['fleet-assessment'].volumes[0].read_only=false;},
  ([,enabled])=>{enabled.services['fleet-assessment-secrets-init'].network_mode='host';},
  ([,enabled])=>{enabled.services['fleet-assessment-secrets-init'].environment={AWS_ACCESS_KEY_ID:'forged'};},
  ([,enabled])=>{enabled.services['fleet-assessment-secrets-init'].read_only=false;},
  ([,enabled])=>{enabled.services['fleet-assessment-secrets-init'].image='foreign';},
  ([,enabled])=>{enabled.services['fleet-assessment-secrets-init'].volumes.push({type:'bind',source:'/',target:'/foreign'});},
 ];
 for(const mutate of mutations){const pair=documents();mutate(pair);assert.throws(()=>validateAssessmentCompose(...pair));}
});
