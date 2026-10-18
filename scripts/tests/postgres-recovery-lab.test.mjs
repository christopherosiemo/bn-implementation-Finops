import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { validateRecoverySources, validateOwnedRecoveryObject } from '../postgres-recovery-lab.mjs';

const workspace=path.resolve('fixture-workspace');
function source(service){return {Image:'sha256:'+'a'.repeat(64),State:{Running:true},Config:{Env:service==='api'?['FIXTURE_MODE=true']:[],Labels:{'com.docker.compose.service':service,'com.docker.compose.project':'local-project','com.docker.compose.project.working_dir':workspace}}};}
test('recovery source guard accepts only the explicit running workspace fixture services',()=>{
  validateRecoverySources(source('api'),source('postgres'),workspace);
  for(const mode of ['live','stopped','different-workspace','different-project','wrong-service','cloud-credentials']){
    const api=source('api'),postgres=source('postgres');
    if(mode==='live')api.Config.Env=['FIXTURE_MODE=false'];
    if(mode==='stopped')postgres.State.Running=false;
    if(mode==='different-workspace')postgres.Config.Labels['com.docker.compose.project.working_dir']=path.resolve('another-workspace');
    if(mode==='different-project')postgres.Config.Labels['com.docker.compose.project']='another-project';
    if(mode==='wrong-service')postgres.Config.Labels['com.docker.compose.service']='customer-postgres';
    if(mode==='cloud-credentials')postgres.Config.Env=['AWS_ACCESS_KEY_ID=unusable-test-value'];
    assert.throws(()=>validateRecoverySources(api,postgres,workspace),undefined,mode);
  }
});
test('cleanup refuses every volume/container without the exact test run and source labels',()=>{
  const owned={Name:'finops-pg-recovery-test',Labels:{'finops.local-recovery.run':'run-a','finops.local-recovery.source':'source-a'}};
  validateOwnedRecoveryObject(owned,'run-a','source-a');
  for(const object of [{...owned,Name:'user-postgres'}, {...owned,Labels:{}}, {...owned,Labels:{...owned.Labels,'finops.local-recovery.run':'other'}}, {...owned,Labels:{...owned.Labels,'finops.local-recovery.source':'other'}}])assert.throws(()=>validateOwnedRecoveryObject(object,'run-a','source-a'));
});
