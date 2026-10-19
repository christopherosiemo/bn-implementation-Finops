// Independent host checks for the private replacement-workspace rehearsal.
// The pre-loss activation is an externally resolved input, never a key supplied
// by a result. These checks complement the restricted PostgreSQL release gate;
// they cannot turn fixture observations into customer deployment authority.
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {validateReconstructionWorkspace} from './group-workspace-retirement.mjs';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const chain=/^connected-chain-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const algorithm='Ed25519/group-recovery-health/v1';
const outcomeDomain=Buffer.from('finops/group-fixture/recovery-health-outcome/v1\0');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const nsPerSecond=1_000_000_000n;
function shape(value,keys){assert.ok(value&&typeof value==='object'&&!Array.isArray(value));assert.deepEqual(Object.keys(value).sort(),[...keys].sort());}
function text(value,max=256){assert.ok(typeof value==='string'&&value.length>0&&value.length<=max&&!/[\0\r\n]/.test(value));return value;}
function integer(value,min=0,max=Number.MAX_SAFE_INTEGER){assert.ok(Number.isSafeInteger(value)&&value>=min&&value<=max);return value;}
function ids(values,pattern=uuid,maximum=4096){assert.ok(Array.isArray(values)&&values.length>0&&values.length<=maximum);for(const value of values)assert.match(value,pattern);assert.equal(new Set(values).size,values.length);return values;}
function canonical(value){return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));}
function strictJSON(raw,maximum){text(raw,maximum);assert.equal(Buffer.from(raw).toString('utf8'),raw);assert.ok(Buffer.byteLength(raw)<=maximum);const value=JSON.parse(raw);assert.equal(canonical(value),raw);return value;}
function base64(value,length){assert.ok(typeof value==='string'&&value.length<=128);const bytes=Buffer.from(value,'base64');assert.equal(bytes.length,length);assert.equal(bytes.toString('base64'),value);return bytes;}

// Date's millisecond truncation must not admit an observation one nanosecond
// short of a full window. Parse the fractional part independently as BigInt.
function instant(value){
 assert.ok(typeof value==='string');
 const m=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);assert.ok(m);
 const millis=Date.parse(m[1]+'Z');assert.ok(Number.isSafeInteger(millis));assert.equal(new Date(millis).toISOString(),m[1]+'.000Z');
 assert.ok(!m[2]||!m[2].endsWith('0'),'Go canonical time omits trailing fractional zeroes');
 return BigInt(millis)*1_000_000n+BigInt((m[2]??'').padEnd(9,'0'));
}
function reference(value,tenantID,namespace){
 shape(value,['id','bucket','key','version_id','sha256','size_bytes']);assert.match(value.id,uuid);assert.match(value.sha256,sha);integer(value.size_bytes,1,24<<20);
 assert.match(value.bucket,/^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/);text(value.version_id,1024);assert.notEqual(value.version_id,'null');text(value.key,2048);
 assert.ok(value.key.startsWith('tenant/'+tenantID+'/fleet-group-fixture/')&&value.key.endsWith('/'+value.id+'.encrypted'));
 const parts=value.key.split('/');assert.equal(parts.length,6);assert.ok(!parts.some(part=>part==='.'||part==='..'||part===''));assert.ok(!value.key.includes('\\'));if(namespace!==undefined)assert.equal(value.key.slice(0,value.key.lastIndexOf('/')+1),namespace);
 return value;
}
function healthBinding(value,tenantID,programSHA256){
 shape(value,['binding','realm','program_sha256','command_id','operation_id','fence']);assert.equal(value.program_sha256,programSHA256);text(value.command_id);text(value.operation_id);integer(value.fence,1);
 shape(value.binding,['old','candidate']);
 for(const selection of [value.binding.old,value.binding.candidate]){
  shape(selection,['target','registration','declaration','scope','source_id','source_registration_version','source_config_sha256']);
  shape(selection.target,['tenant_id','workload_id','provider','account_id','region','fleet_id','asg_arn']);
  assert.equal(selection.target.tenant_id,tenantID);assert.equal(selection.target.provider,'AWS');assert.equal(selection.target.region,'eu-west-1');assert.match(selection.target.account_id,/^\d{12}$/);
  for(const key of ['workload_id','fleet_id','asg_arn','source_id'])text(key==='source_id'?selection[key]:selection.target[key],2048);
  for(const key of ['registration','declaration']){shape(selection[key],['id','version','sha256']);assert.match(selection[key].id,uuid);integer(selection[key].version,1);assert.match(selection[key].sha256,sha);}
  shape(selection.scope,['id','sha256']);assert.match(selection.scope.id,uuid);assert.match(selection.scope.sha256,sha);integer(selection.source_registration_version,1);assert.match(selection.source_config_sha256,sha);
 }
 assert.equal(value.binding.old.target.workload_id,value.binding.candidate.target.workload_id);assert.equal(value.binding.old.target.account_id,value.binding.candidate.target.account_id);assert.notEqual(value.binding.old.target.asg_arn,value.binding.candidate.target.asg_arn);
 shape(value.realm,['kind','fixture_id','generation','model_sha256']);assert.equal(value.realm.kind,'ISOLATED_FIXTURE');text(value.realm.fixture_id);text(value.realm.generation);assert.match(value.realm.model_sha256,sha);
 return value;
}
function limits(value){
 shape(value,['minimum_samples','max_p95_ns','max_p99_ns','max_error_rate_ppm','min_availability_ppm','max_inflight','max_backlog']);integer(value.minimum_samples,30,1_000_000);integer(value.max_p95_ns,1);integer(value.max_p99_ns,value.max_p95_ns);integer(value.max_error_rate_ppm,0,1_000_000);integer(value.min_availability_ppm,0,1_000_000);integer(value.max_inflight,1);integer(value.max_backlog);
}
function head(value){shape(value,['version','record_count','last_record_sha256']);integer(value.version,1);integer(value.record_count,1,512);assert.match(value.last_record_sha256,sha);return value;}

export function validateRecoveryHealthActivation(value,{runID,ready,activationSHA256,activationRaw}){
 assert.match(runID,uuid);assert.match(activationSHA256,sha);
 // The host hashes/caches the original Go bytes before destroying the old
 // runtime. An optional raw input additionally checks that exact file here.
 if(activationRaw!==undefined){const raw=Buffer.from(activationRaw);assert.ok(raw.length>0&&raw.length<=16<<10);assert.equal(hash(raw),activationSHA256);assert.deepEqual(strictJSON(raw.toString('utf8'),16<<10),value);}
 assert.ok(Buffer.byteLength(canonical(value))<=16<<10);
 shape(value,['schema_version','run_id','tenant_id','chain_id','program_sha256','old_workspace','observer','baseline','baseline_receipt_refs']);
 assert.equal(value.schema_version,'1');assert.equal(value.run_id,runID);assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.chain_id,ready.chain_id);assert.match(value.chain_id,chain);assert.equal(value.program_sha256,ready.prepared_program_sha256);
 assert.deepEqual(validateReconstructionWorkspace(value.old_workspace),validateReconstructionWorkspace(ready.old_workspace));
 const o=value.observer;shape(o,['id','tenant_id','chain_id','database_login','identity','public_key','limits']);assert.match(o.id,uuid);assert.equal(o.tenant_id,value.tenant_id);assert.equal(o.chain_id,value.chain_id);text(o.database_login,63);assert.match(o.database_login,/^[a-z_][a-z0-9_]*$/);base64(o.public_key,32);limits(o.limits);
 shape(o.identity,['source_id','issuer','subject','audience']);for(const key of Object.keys(o.identity))text(o.identity[key],2048);
 const b=value.baseline;shape(b,['schema_version','id','tenant_id','chain_id','anchor','anchor_reference','observation_ids']);assert.equal(b.schema_version,'1');assert.match(b.id,uuid);assert.equal(b.tenant_id,value.tenant_id);assert.equal(b.chain_id,value.chain_id);ids(b.observation_ids);
 reference(b.anchor_reference,value.tenant_id);shape(b.anchor,['anchor','algorithm','signature']);assert.equal(b.anchor.algorithm,'Ed25519/group-fixture-activated-health/v1');base64(b.anchor.signature,64);
 const a=b.anchor.anchor;shape(a,['schema_version','program_sha256','authorization_sha256','observer','measurement_revision','activation_record_sha256','activation_record_sequence','activated_at','receipt_sha256s','artifacts','issued_at']);
 assert.equal(a.schema_version,'1');assert.equal(a.program_sha256,value.program_sha256);assert.match(a.authorization_sha256,sha);assert.match(a.activation_record_sha256,sha);integer(a.activation_record_sequence,1,512);healthBinding(a.observer,value.tenant_id,value.program_sha256);assert.equal(a.measurement_revision,'GO_MONOTONIC_HTTP_V2');assert.ok(instant(a.issued_at)>=instant(a.activated_at));ids(a.receipt_sha256s,sha);
 assert.equal(b.anchor_reference.sha256,hash(canonical(b.anchor)));assert.equal(b.anchor_reference.size_bytes,Buffer.byteLength(canonical(b.anchor)));
 assert.ok(Array.isArray(value.baseline_receipt_refs));assert.equal(value.baseline_receipt_refs.length,b.observation_ids.length);assert.equal(value.baseline_receipt_refs.length,a.receipt_sha256s.length);assert.equal(a.artifacts.length,value.baseline_receipt_refs.length);
 assert.equal(b.anchor_reference.key.split('/')[4],a.observer.realm.generation);const namespace=b.anchor_reference.key.slice(0,b.anchor_reference.key.lastIndexOf('/')+1);
 const seen=new Set([b.anchor_reference.id]);for(let i=0;i<value.baseline_receipt_refs.length;i++){
  const ref=reference(value.baseline_receipt_refs[i],value.tenant_id,namespace);assert.ok(!seen.has(ref.id));seen.add(ref.id);shape(a.artifacts[i],['reference','issued_at']);assert.deepEqual(a.artifacts[i].reference,ref);assert.ok(instant(a.artifacts[i].issued_at)<=instant(a.activated_at));
 }
 return value;
}

function window(value,activation,positive){
 const keys=['status','reason_codes','binding','start','required_end','observed_through','receipt_sha256s','baseline_receipt_sha256s','sample_count','p95_ns','p99_ns','baseline_p95_ns','baseline_p99_ns','error_rate_ppm','availability_ppm','accepted','completed','rejected','failed','backlog','inflight','definition','availability_basis','customer_execution_authorized','measurement_revision','monotonic_duration_ns','baseline_monotonic_duration_ns'];
 shape(value,keys);assert.ok(['OBSERVED','BREACH','BLOCKED'].includes(value.status));assert.ok(Array.isArray(value.reason_codes)&&value.reason_codes.length<=32);for(const reason of value.reason_codes)assert.match(reason,/^[A-Z][A-Z0-9_]{0,127}$/);
 healthBinding(value.binding,activation.tenant_id,activation.program_sha256);assert.deepEqual(value.binding,activation.baseline.anchor.anchor.observer);
 assert.equal(instant(value.required_end)-instant(value.start),900n*nsPerSecond);assert.ok(instant(value.observed_through)>=instant(value.start));
 ids(value.receipt_sha256s,sha);assert.deepEqual(value.baseline_receipt_sha256s,activation.baseline.anchor.anchor.receipt_sha256s);integer(value.sample_count);
 for(const key of ['p95_ns','p99_ns','baseline_p95_ns','baseline_p99_ns','error_rate_ppm','availability_ppm','accepted','completed','rejected','failed','backlog','inflight','monotonic_duration_ns','baseline_monotonic_duration_ns'])if(value[key]!==null)integer(value[key]);
 assert.equal(value.definition,'ISOLATED_HTTP_COMPLETED_OPERATION');assert.equal(value.availability_basis,'OBSERVED_HTTP_REQUEST_SUCCESS');assert.equal(value.measurement_revision,'GO_MONOTONIC_HTTP_V2');assert.equal(value.customer_execution_authorized,false);
 if(positive){
  const l=activation.observer.limits;assert.equal(value.status,'OBSERVED');assert.deepEqual(value.reason_codes,[]);assert.ok(instant(value.observed_through)>=instant(value.required_end));integer(value.monotonic_duration_ns,900e9);integer(value.baseline_monotonic_duration_ns,120e9);integer(value.sample_count,l.minimum_samples);
  for(const key of ['p95_ns','p99_ns','baseline_p95_ns','baseline_p99_ns'])integer(value[key],1);
  assert.ok(value.p95_ns<=l.max_p95_ns&&value.p99_ns<=l.max_p99_ns&&value.p95_ns<=value.p99_ns&&value.baseline_p95_ns<=value.baseline_p99_ns);
  assert.ok(BigInt(value.p95_ns)*100n<=BigInt(value.baseline_p95_ns)*115n&&BigInt(value.p99_ns)*100n<=BigInt(value.baseline_p99_ns)*115n);
  integer(value.error_rate_ppm,0,l.max_error_rate_ppm);integer(value.availability_ppm,l.min_availability_ppm,1_000_000);assert.ok(value.error_rate_ppm+value.availability_ppm>=999999&&value.error_rate_ppm+value.availability_ppm<=1_000_000);integer(value.backlog,0,l.max_backlog);integer(value.inflight,0,l.max_inflight);integer(value.accepted,1);integer(value.completed,1);integer(value.rejected);integer(value.failed);
  // All measured snapshot boundaries are idle. The reported saturation fields
  // are interval peaks, so they must not be added to the final counters.
  assert.equal(BigInt(value.accepted),BigInt(value.completed)+BigInt(value.failed));
 }
 return value;
}

function abandonedWindow(value,activation){
 // A definitive observer-abandonment receipt is not a measured positive
 // window. The versioned Go DTO intentionally emits its remaining zero values.
 const zero=value=>typeof value==='string'?'':typeof value==='number'?0:Object.fromEntries(Object.entries(value).map(([key,item])=>[key,zero(item)]));
 assert.deepEqual(value,{status:'BLOCKED',reason_codes:['RECOVERY_OBSERVER_ATTEMPT_ABANDONED'],binding:zero(activation.baseline.anchor.anchor.observer),start:'0001-01-01T00:00:00Z',required_end:'0001-01-01T00:00:00Z',observed_through:'0001-01-01T00:00:00Z',receipt_sha256s:null,baseline_receipt_sha256s:null,sample_count:0,p95_ns:null,p99_ns:null,baseline_p95_ns:null,baseline_p99_ns:null,error_rate_ppm:null,availability_ppm:null,accepted:null,completed:null,rejected:null,failed:null,backlog:null,inflight:null,definition:'',availability_basis:'',customer_execution_authorized:false});
}

// Signature validity alone is not an issued outcome or permission to release.
// The caller below additionally checks typed scope, attempts and actual refs.
export function verifyRecoveryHealthOutcomeSignature(raw,{algorithm:actualAlgorithm,signature,publicKey}){
 assert.equal(actualAlgorithm,algorithm);const outcome=strictJSON(raw,16<<10),key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),base64(publicKey,32)]),format:'der',type:'spki'});
 assert.equal(verify(null,Buffer.concat([outcomeDomain,Buffer.from(raw)]),key,base64(signature,64)),true);return outcome;
}
function signedOutcome(value,activation){
 shape(value,['outcome_canonical_json','algorithm','signature','reference']);const raw=Buffer.from(value.outcome_canonical_json??''),outcome=verifyRecoveryHealthOutcomeSignature(value.outcome_canonical_json,{algorithm:value.algorithm,signature:value.signature,publicKey:activation.observer.public_key});
 shape(outcome,['schema_version','id','tenant_id','chain_id','attempt_id','observer_id','status','observation_ids','window','signed_at']);assert.equal(outcome.schema_version,'1');assert.match(outcome.id,uuid);assert.match(outcome.attempt_id,uuid);assert.equal(outcome.tenant_id,activation.tenant_id);assert.equal(outcome.chain_id,activation.chain_id);assert.equal(outcome.observer_id,activation.observer.id);assert.ok(['OBSERVED','BREACH','INVALID','ABANDONED'].includes(outcome.status));ids(outcome.observation_ids);instant(outcome.signed_at);
 const namespace=activation.baseline.anchor_reference.key.slice(0,activation.baseline.anchor_reference.key.lastIndexOf('/')+1),ref=reference(value.reference,activation.tenant_id,namespace),envelope={outcome,algorithm:value.algorithm,signature:value.signature};assert.equal(ref.sha256,hash(canonical(envelope)));assert.equal(ref.size_bytes,Buffer.byteLength(canonical(envelope)));
 if(outcome.status==='ABANDONED')abandonedWindow(outcome.window,activation);else {window(outcome.window,activation,outcome.status==='OBSERVED');assert.equal(outcome.window.status,outcome.status==='INVALID'?'BLOCKED':outcome.status);assert.ok(instant(outcome.signed_at)>=instant(outcome.window.observed_through));}
 return {outcome,reference:ref,body_sha256:hash(raw)};
}

export function validateWorkspaceRecoveredHealth(value,{runID,ready,newWorkspace,reconstructed,reconstructedSHA256,activation,activationSHA256,activationRaw}){
 assert.ok(activationRaw!==undefined,'the cached pre-loss activation bytes are required');
 validateRecoveryHealthActivation(activation,{runID,ready,activationSHA256,activationRaw});assert.match(reconstructedSHA256,sha);
 assert.ok(Buffer.byteLength(canonical(value))<=64<<10);
 shape(value,['schema_version','status','run_id','tenant_id','chain_id','prepared_program_sha256','original_reconstruction_sha256','health_activation_sha256','new_workspace','baseline_id','observer_id','attempts','selected_outcome_id','selected_outcome_sha256','final_head','restored_state_sha256','restored_owned_effects','consumed_owned_effects','pending','reservation_released','terminal_health_pending','full_recovery_health_accepted','financial_disqualified_forever','recovery_health_artifact_index_sha256','fixture','customer_execution_authorized','verified_saving','observer_restart_confirmed','failed_attempt_elapsed_reused']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'PASS');assert.equal(value.run_id,runID);
 for(const key of ['tenant_id','chain_id','prepared_program_sha256'])assert.equal(value[key],ready[key]);
 assert.equal(value.original_reconstruction_sha256,reconstructedSHA256);assert.equal(value.health_activation_sha256,activationSHA256);assert.equal(value.baseline_id,activation.baseline.id);assert.equal(value.observer_id,activation.observer.id);
 assert.deepEqual(validateReconstructionWorkspace(value.new_workspace),validateReconstructionWorkspace(newWorkspace));assert.deepEqual(value.new_workspace,reconstructed.new_workspace);assert.notEqual(value.new_workspace.generation,activation.old_workspace.generation);assert.notEqual(value.new_workspace.runtime_id,activation.old_workspace.runtime_id);
 assert.equal(reconstructed.run_id,runID);assert.equal(reconstructed.status,'PASS');assert.equal(reconstructed.reservation_held,true);assert.equal(reconstructed.terminal_health_pending,true);assert.equal(reconstructed.full_recovery_health_accepted,false);
 for(const key of ['tenant_id','chain_id','prepared_program_sha256'])assert.equal(reconstructed[key],ready[key]);
 assert.match(value.restored_state_sha256,sha);assert.equal(value.restored_state_sha256,reconstructed.restored_state_sha256);head(value.final_head);assert.match(value.recovery_health_artifact_index_sha256,sha);
 for(const key of ['reservation_released','full_recovery_health_accepted','financial_disqualified_forever','fixture','observer_restart_confirmed'])assert.equal(value[key],true);
 for(const key of ['pending','terminal_health_pending','customer_execution_authorized','failed_attempt_elapsed_reused'])assert.equal(value[key],false);
 assert.equal(value.verified_saving,null);assert.equal(value.restored_owned_effects,0);assert.equal(value.consumed_owned_effects,reconstructed.consumed_owned_effects);assert.equal(value.consumed_owned_effects,1);
 assert.ok(Array.isArray(value.attempts)&&value.attempts.length>=2&&value.attempts.length<=8);
 const seenIDs=new Set([...activation.baseline.observation_ids]),seenRefs=new Set([activation.baseline.anchor_reference.id,...activation.baseline_receipt_refs.map(r=>r.id)]),seenHashes=new Set(activation.baseline_receipt_refs.map(r=>r.sha256)),artifactReferences=[{kind:'HEALTH_VERDICT',ref:activation.baseline.anchor_reference},...activation.baseline_receipt_refs.map(ref=>({kind:'HEALTH_BASELINE',ref}))],attemptIDs=new Set(),outcomeIDs=new Set();
 let previousOutcome='',previousEnd=null,last;
 for(let index=0;index<value.attempts.length;index++){
  const row=value.attempts[index];shape(row,['attempt','outcome_canonical_json','algorithm','signature','outcome_reference','observation_references']);
  const a=row.attempt;shape(a,['schema_version','id','tenant_id','chain_id','observer_id','baseline_id','previous_outcome_id','workspace','command_id','operation_id','fence','terminal_id','state_sha256','head','started_at']);
  assert.equal(a.schema_version,'1');assert.match(a.id,uuid);assert.ok(!attemptIDs.has(a.id));attemptIDs.add(a.id);assert.equal(a.tenant_id,activation.tenant_id);assert.equal(a.chain_id,activation.chain_id);assert.equal(a.observer_id,activation.observer.id);assert.equal(a.baseline_id,activation.baseline.id);assert.equal(a.previous_outcome_id,previousOutcome);
  assert.deepEqual(validateReconstructionWorkspace(a.workspace),value.new_workspace);assert.equal(a.command_id,reconstructed.fresh_owned_inverse_command_id);assert.match(a.operation_id,uuid);integer(a.fence,1);assert.equal(a.terminal_id,reconstructed.inverse_terminal_id);assert.equal(a.state_sha256,value.restored_state_sha256);assert.deepEqual(head(a.head),value.final_head);
  const began=instant(a.started_at);if(previousEnd!==null)assert.ok(began>=previousEnd);
  const checked=signedOutcome({outcome_canonical_json:row.outcome_canonical_json,algorithm:row.algorithm,signature:row.signature,reference:row.outcome_reference},activation),o=checked.outcome;
  assert.equal(o.attempt_id,a.id);assert.ok(!outcomeIDs.has(o.id));outcomeIDs.add(o.id);assert.ok(instant(o.signed_at)>=began);if(o.status!=='ABANDONED')assert.ok(instant(o.window.start)>=began);
  if(index===value.attempts.length-1)assert.equal(o.status,'OBSERVED');else assert.ok(['BREACH','INVALID','ABANDONED'].includes(o.status));
  assert.ok(Array.isArray(row.observation_references));assert.equal(row.observation_references.length,o.observation_ids.length);if(o.status!=='ABANDONED')assert.equal(row.observation_references.length,o.window.receipt_sha256s.length);
  for(let i=0;i<row.observation_references.length;i++){
   // receipt_sha256s hash a receipt with its own SHA field cleared; ref.sha256
   // hashes the complete archived JSON. They cannot be equated. The034 gate
   // resolves each signed observation ID, rederives the content hash and binds
   // its exact issued032 ref/readback. Here the host checks those ref metadata
   // against its ciphertext index; it does not recompute raw measurements.
   const anchorKey=activation.baseline.anchor_reference.key,ref=reference(row.observation_references[i],activation.tenant_id,anchorKey.slice(0,anchorKey.lastIndexOf('/')+1)),observationID=o.observation_ids[i];assert.ok(!seenIDs.has(observationID));seenIDs.add(observationID);assert.ok(!seenRefs.has(ref.id));seenRefs.add(ref.id);assert.ok(!seenHashes.has(ref.sha256));seenHashes.add(ref.sha256);artifactReferences.push({kind:'HEALTH_RECEIPT',ref});
  }
  assert.ok(!seenRefs.has(checked.reference.id));seenRefs.add(checked.reference.id);artifactReferences.push({kind:'HEALTH_VERDICT',ref:checked.reference});previousOutcome=o.id;previousEnd=instant(o.signed_at);last=checked;
 }
 assert.equal(value.selected_outcome_id,last.outcome.id);assert.equal(value.selected_outcome_sha256,last.body_sha256);
 return {artifactReferences,selectedOutcome:last.outcome,selectedOutcomeReference:last.reference,activationSHA256,originalReconstructionSHA256:reconstructedSHA256};
}
