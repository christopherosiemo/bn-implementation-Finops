import assert from 'node:assert/strict';
import test from 'node:test';
import {generateKeyPairSync,verify} from 'node:crypto';
import {mkdtempSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {signObservedWorkspaceRetirement,validateWorkspaceReady,readPrivateReconstructionJSON} from '../lib/group-workspace-retirement.mjs';

const run='11111111-2222-3333-4444-555555555555',chain='connected-chain-21111111-2222-3333-4444-555555555555';
const old={generation:'31111111-2222-3333-4444-555555555555',runtime_id:'a'.repeat(64),image_sha256:'b'.repeat(64)},next={...old,generation:'41111111-2222-3333-4444-555555555555',runtime_id:'c'.repeat(64)};
const keys=generateKeyPairSync('ed25519');
function input(){return {tenantID:'fixture-tenant',chainID:chain,programSHA256:'d'.repeat(64),oldWorkspace:{...old},newWorkspace:{...next},observedAt:new Date('2026-10-19T06:00:00.120Z'),removal:{run_id:run,removed_runtime_id:old.runtime_id,image_sha256:old.image_sha256,absent_after_removal:true}};}

test('retirement signature uses the native domain, exact runtime identities and canonical UTC fractions',()=>{
 const signed=signObservedWorkspaceRetirement(input(),keys.privateKey);
 assert.equal(signed.retirement.observed_at,'2026-10-19T06:00:00.12Z');
 const message=Buffer.concat([Buffer.from('finops/group-fixture/workspace-retirement/v1\0'),Buffer.from(JSON.stringify(signed.retirement))]);
 assert.equal(verify(null,message,keys.publicKey,Buffer.from(signed.signature,'base64')),true);
 for(const field of ['tenant_id','chain_id','program_sha256','observed_at']){
  const modified={...signed.retirement,[field]:'altered'};
  assert.equal(verify(null,Buffer.concat([Buffer.from('finops/group-fixture/workspace-retirement/v1\0'),Buffer.from(JSON.stringify(modified))]),keys.publicKey,Buffer.from(signed.signature,'base64')),false);
 }
 assert.equal(verify(null,Buffer.from(JSON.stringify(signed.retirement)),keys.publicKey,Buffer.from(signed.signature,'base64')),false);
});
test('retirement cannot be inferred from a lease, another image or a reused runtime',()=>{
 for(const mutate of [x=>x.removal.absent_after_removal=false,x=>x.removal.removed_runtime_id='e'.repeat(64),x=>x.removal.image_sha256='f'.repeat(64),x=>x.removal.lease_expired=true,x=>x.newWorkspace.runtime_id=x.oldWorkspace.runtime_id,x=>x.newWorkspace.generation=x.oldWorkspace.generation,x=>x.newWorkspace.image_sha256='e'.repeat(64),x=>x.oldWorkspace.extra='field']){
  const value=input();mutate(value);assert.throws(()=>signObservedWorkspaceRetirement(value,keys.privateKey));
 }
 assert.throws(()=>signObservedWorkspaceRetirement(input(),keys.publicKey));
});
function ready(){return {schema_version:'1',status:'READY_TO_RETIRE',run_id:run,tenant_id:'fixture-tenant',chain_id:chain,command_id:'51111111-2222-3333-4444-555555555555',terminal_id:'61111111-2222-3333-4444-555555555555',old_workspace:{...old},terminal_sha256:'d'.repeat(64),prepared_program_sha256:'e'.repeat(64),private_bundle_sha256:'f'.repeat(64),terraform_apply_attempts:3,fixture:true,customer_execution_authorized:false};}
test('ready-to-retire receipt pins the actual old runtime, handoff hash and exactly three prior applies',()=>{
 const expected={runID:run,oldWorkspace:old,privateBundleSHA256:'f'.repeat(64)};
 validateWorkspaceReady(ready(),expected);
 for(const mutate of [x=>x.old_workspace.runtime_id='f'.repeat(64),x=>x.run_id=chain,x=>x.private_bundle_sha256='a'.repeat(64),x=>x.customer_execution_authorized=true,x=>x.terraform_apply_attempts=0,x=>x.terraform_apply_attempts=2,x=>x.terraform_apply_attempts=4,x=>x.terraform_apply_attempts='3',x=>x.credentials='private',x=>x.status='PASS']){const value=ready();mutate(value);assert.throws(()=>validateWorkspaceReady(value,expected));}
});
test('private handoff reader refuses duplicate fields, trailing data and oversized bytes',()=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-workspace-'));
 try{const file=path.join(directory,'ready.json');writeFileSync(file,JSON.stringify(ready()));assert.equal(readPrivateReconstructionJSON(file,4096).value.run_id,run);
  for(const raw of ['{"a":1,"a":2}','{} {}','[]','x'.repeat(4097)]){writeFileSync(file,raw);assert.throws(()=>readPrivateReconstructionJSON(file,4096));}
 }finally{assert.equal(path.dirname(directory),tmpdir());rmSync(directory,{recursive:true,force:true});}
});
test('private handoff reader refuses symlinks before reading their targets',{skip:process.platform==='win32'},()=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-workspace-'));
 try{writeFileSync(path.join(directory,'target'),'{}');symlinkSync(path.join(directory,'target'),path.join(directory,'link'));assert.throws(()=>readPrivateReconstructionJSON(path.join(directory,'link'),4096));}
 finally{assert.equal(path.dirname(directory),tmpdir());rmSync(directory,{recursive:true,force:true});}
});
