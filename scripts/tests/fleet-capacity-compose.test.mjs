import assert from 'node:assert/strict';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import {validateCapacityCompose} from '../fleet-capacity-compose-check.mjs';

function documents(){
 const secretFile=name=>fileURLToPath(new URL('../../work/private/fleet-capacity-secrets/'+name,import.meta.url));
 const names=['group-capacity-access-key','group-capacity-database','group-capacity-model-token','group-capacity-reader-token','group-capacity-secret-key'];
 const secrets={'group-capacity-database':{file:secretFile('database')},'group-capacity-access-key':{file:secretFile('access-key')},'group-capacity-secret-key':{file:secretFile('secret-key')},'group-capacity-reader-token':{file:secretFile('reader-token')},'group-capacity-model-token':{file:secretFile('model-token')}};
 const worker={entrypoint:['/app/fleet-capacity-worker'],read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],networks:{private:{}},mem_limit:536870912,cpus:1,tmpfs:['/tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700'],healthcheck:{test:['CMD','/app/fleet-capacity-worker','--healthcheck']},volumes:[{type:'volume',source:'fleet-capacity-secrets',target:'/run/secrets',read_only:true}],depends_on:{migrate:{},buckets:{},economics:{},'telemetry-reader':{},'fleet-capacity-secrets-init':{condition:'service_completed_successfully'}},environment:{FLEET_CAPACITY_ENABLED:'true',FLEET_CAPACITY_TENANT_ID:'tenant-demo',FLEET_CAPACITY_DATABASE_FILE:'/run/secrets/group-capacity-database',FLEET_CAPACITY_ARCHIVE_REGION:'eu-west-1',FLEET_CAPACITY_ARCHIVE_MODE:'LOCAL_VERSIONED_S3',FLEET_CAPACITY_ARCHIVE_ENDPOINT:'http://minio:9000',FLEET_CAPACITY_ARCHIVE_BUCKET:'finops-raw',FLEET_CAPACITY_ARCHIVE_ACCESS_KEY_FILE:'/run/secrets/group-capacity-access-key',FLEET_CAPACITY_ARCHIVE_SECRET_KEY_FILE:'/run/secrets/group-capacity-secret-key',FLEET_CAPACITY_SERVICE_MODE:'PRIVATE_SERVICES',FLEET_CAPACITY_READER_URL:'http://telemetry-reader:8095',FLEET_CAPACITY_READER_TOKEN_FILE:'/run/secrets/group-capacity-reader-token',FLEET_CAPACITY_MODEL_URL:'http://economics:8000',FLEET_CAPACITY_MODEL_TOKEN_FILE:'/run/secrets/group-capacity-model-token'}};
 worker.image='cloud-cost-autopilot-go:local';
 const yaml=readFileSync(new URL('../../compose.yaml',import.meta.url),'utf8'),body=yaml.match(/  fleet-capacity-secrets-init:\r?\n[\s\S]*?    command:\r?\n      - \|\r?\n([\s\S]*?)    user:/)?.[1];assert.ok(body);
 // Compose's canonical config retains escaped dollars; substitution occurs
 // only when that inspected definition creates the initializer container.
 const command=body.replaceAll('\r\n','\n').split('\n').map(line=>line.slice(8)).join('\n');
 const initializer={image:worker.image,user:'0:0',entrypoint:['/bin/sh','-ec'],command:[command],mem_limit:64*1024*1024,cpus:0.1,volumes:[{type:'volume',source:'fleet-capacity-secrets',target:'/capacity-secrets'}],network_mode:'none',read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],secrets:names.map(source=>({source}))};
 return [{name:'cloud-cost-autopilot',services:{}},{name:'cloud-cost-autopilot',volumes:{'fleet-capacity-secrets':{name:'cloud-cost-autopilot_fleet-capacity-secrets'}},secrets,services:{'fleet-capacity':worker,'fleet-capacity-secrets-init':initializer}}];
}
test('capacity Compose boundary accepts only optional dedicated read-only process',()=>assert.equal(validateCapacityCompose(...documents()).status,'PASS'));
test('inherited authority, host exposure, credential sharing or enabled-by-default inputs are refused',()=>{
 const mutations=[
  ([,enabled])=>{enabled.services['fleet-capacity-secrets-init'].command=['cat /run/secrets/group-capacity-database'];},
  ([,enabled])=>{enabled.volumes['fleet-capacity-secrets'].external=true;},
  ([,enabled])=>{enabled.volumes['fleet-capacity-secrets'].name='foreign-owned-volume';},
  ([,enabled])=>{enabled.volumes['fleet-capacity-secrets'].driver_opts={type:'none',device:'/',o:'bind'};},
  ([ordinary,enabled])=>{ordinary.services['fleet-capacity']=enabled.services['fleet-capacity'];},
  ([ordinary,enabled])=>{ordinary.services['fleet-capacity-secrets-init']=enabled.services['fleet-capacity-secrets-init'];},
  ([,enabled])=>{enabled.services['fleet-capacity'].environment.SIGNER_TOKEN='forged';},
  ([,enabled])=>{enabled.services['fleet-capacity'].ports=[{published:'8088'}];},
  ([,enabled])=>{enabled.services['fleet-capacity'].environment.FLEET_CAPACITY_ARCHIVE_MODE='AWS_IRSA';},
  ([,enabled])=>{enabled.services['fleet-capacity'].read_only=false;},
  ([,enabled])=>{enabled.services.api={secrets:[{source:'group-capacity-database'}]};},
  ([,enabled])=>{enabled.services['fleet-capacity'].tmpfs=['/tmp:rw','nosuid','nodev','noexec','size=16m','uid=10001','gid=10001','mode=0700'];},
  ([,enabled])=>{enabled.secrets['group-capacity-database']={environment:'FLEET_CAPACITY_DATABASE_URL'};},
  ([,enabled])=>{enabled.secrets['group-capacity-secret-key'].file='/foreign/secret';},
  ([,enabled])=>{enabled.services['fleet-capacity'].volumes[0].read_only=false;},
  ([,enabled])=>{enabled.services['fleet-capacity-secrets-init'].network_mode='host';},
  ([,enabled])=>{enabled.services['fleet-capacity-secrets-init'].environment={AWS_ACCESS_KEY_ID:'forged'};},
  ([,enabled])=>{enabled.services['fleet-capacity-secrets-init'].read_only=false;},
  ([,enabled])=>{enabled.services['fleet-capacity-secrets-init'].image='foreign';},
  ([,enabled])=>{enabled.services['fleet-capacity-secrets-init'].volumes.push({type:'bind',source:'/',target:'/foreign'});},
 ];
 for(const mutate of mutations){const pair=documents();mutate(pair);assert.throws(()=>validateCapacityCompose(...pair));}
});
