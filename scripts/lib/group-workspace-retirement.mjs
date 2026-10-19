// Private local rehearsal controller. The native workers never receive this
// controller's private key or the Docker socket. Container removal must be
// independently observed by the fixed host orchestrator before it signs.
import assert from 'node:assert/strict';
import {createPublicKey,randomUUID,sign,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const chain=/^connected-chain-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const domain=Buffer.from('finops/group-fixture/workspace-retirement/v1\0');
const algorithm='Ed25519/group-fixture-native/v1';

export function validateReconstructionWorkspace(value){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['generation','image_sha256','runtime_id']);
 assert.match(value.generation,uuid);assert.match(value.runtime_id,sha);assert.match(value.image_sha256,sha);
 return {generation:value.generation,runtime_id:value.runtime_id,image_sha256:value.image_sha256};
}
export function readPrivateReconstructionJSON(file,maximumBytes){
 assert.ok(Number.isSafeInteger(maximumBytes)&&maximumBytes>0&&maximumBytes<=32*1024*1024);
 const info=lstatSync(file);assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.size>0&&info.size<=maximumBytes);
 const raw=readFileSync(file);assert.equal(raw.length,info.size);
 const value=JSON.parse(raw.toString('utf8'));
 // Exact canonical bytes refuse duplicate keys and alternate spellings. The
 // Go phase writer uses encoding/json without pretty-printing or trailing data.
 assert.ok(raw.equals(Buffer.from(JSON.stringify(value)))||raw.equals(Buffer.from(JSON.stringify(value)+'\n')));
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));return {raw,value};
}
function nativeTime(value){
 assert.ok(value instanceof Date&&Number.isFinite(value.getTime()));
 return value.toISOString().replace(/\.(\d+)Z$/,(_,fraction)=>{const part=fraction.replace(/0+$/,'');return part?'.'+part+'Z':'Z';});
}
export function signObservedWorkspaceRetirement({tenantID,chainID,programSHA256,oldWorkspace,newWorkspace,observedAt,removal},privateKey){
 assert.ok(typeof tenantID==='string'&&tenantID.length>0&&tenantID.length<=256&&!/[\0\r\n]/.test(tenantID));
 assert.match(chainID,chain);assert.match(programSHA256,sha);
 const old=validateReconstructionWorkspace(oldWorkspace),next=validateReconstructionWorkspace(newWorkspace);
 assert.notEqual(old.generation,next.generation);assert.notEqual(old.runtime_id,next.runtime_id);assert.equal(old.image_sha256,next.image_sha256);
 assert.deepEqual(Object.keys(removal).sort(),['absent_after_removal','image_sha256','removed_runtime_id','run_id']);
 assert.match(removal.run_id,uuid);assert.equal(removal.removed_runtime_id,old.runtime_id);assert.equal(removal.image_sha256,old.image_sha256);assert.equal(removal.absent_after_removal,true);
 assert.equal(privateKey?.type,'private');assert.equal(privateKey.asymmetricKeyType,'ed25519');
 // Property order and fractional seconds match the versioned Go signing DTO.
 const retirement={schema_version:'1',id:randomUUID(),tenant_id:tenantID,chain_id:chainID,program_sha256:programSHA256,method:'OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED',old,new:next,observed_at:nativeTime(observedAt)};
 const message=Buffer.concat([domain,Buffer.from(JSON.stringify(retirement))]);
 const signature=sign(null,message,privateKey);
 assert.ok(verify(null,message,createPublicKey(privateKey),signature));
 return {retirement,algorithm,signature:signature.toString('base64')};
}
export function validateWorkspaceReady(value,{runID,oldWorkspace,privateBundleSHA256}){
 assert.match(runID,uuid);assert.match(privateBundleSHA256,sha);
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['chain_id','command_id','customer_execution_authorized','fixture','old_workspace','prepared_program_sha256','private_bundle_sha256','run_id','schema_version','status','tenant_id','terminal_id','terminal_sha256','terraform_apply_attempts']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'READY_TO_RETIRE');assert.equal(value.run_id,runID);
 assert.match(value.chain_id,chain);for(const name of ['command_id','terminal_id'])assert.match(value[name],uuid);
 for(const name of ['terminal_sha256','prepared_program_sha256'])assert.match(value[name],sha);
 assert.ok(typeof value.tenant_id==='string'&&value.tenant_id.length>0&&value.tenant_id.length<=256&&!/[\0\r\n]/.test(value.tenant_id));
 assert.deepEqual(validateReconstructionWorkspace(value.old_workspace),validateReconstructionWorkspace(oldWorkspace));
 assert.equal(value.private_bundle_sha256,privateBundleSHA256);assert.equal(value.terraform_apply_attempts,3);
 assert.equal(value.fixture,true);assert.equal(value.customer_execution_authorized,false);return value;
}
