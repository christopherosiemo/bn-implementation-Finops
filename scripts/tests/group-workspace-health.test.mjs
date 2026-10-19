import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {validateRecoveryHealthActivation,validateWorkspaceRecoveredHealth,verifyRecoveryHealthOutcomeSignature} from '../lib/group-workspace-health.mjs';

// Synthetic signature/DTO tests only. These contain no raw HTTP measurements,
// PostgreSQL publication, elapsed-time or native reconstruction acceptance.
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const json=value=>JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
const id=n=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');
const hash=n=>sha('test-only-'+n);
const keys=generateKeyPairSync('ed25519');
const runID=id(1),tenant='fixture-tenant',chainID='connected-chain-'+id(2),program=hash('program');
const old={generation:id(3),runtime_id:hash('old-runtime'),image_sha256:hash('image')},next={...old,generation:id(4),runtime_id:hash('new-runtime')};
function ref(n,body){return {id:id(n),bucket:'fixture-artifacts',key:'tenant/'+tenant+'/fleet-group-fixture/'+id(5)+'/'+id(6)+'/'+id(n)+'.encrypted',version_id:'version-'+n,sha256:sha(body??('raw-artifact-'+n)),size_bytes:Buffer.byteLength(body??('raw-artifact-'+n))};}
function selection(n){return {target:{tenant_id:tenant,workload_id:'workload',provider:'AWS',account_id:'111122223333',region:'eu-west-1',fleet_id:'fleet-'+n,asg_arn:'arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:'+id(n)+':autoScalingGroupName/group-'+n},registration:{id:id(n+1),version:1,sha256:hash(n+1)},declaration:{id:id(n+2),version:1,sha256:hash(n+2)},scope:{id:id(n+3),sha256:hash(n+3)},source_id:id(7),source_registration_version:1,source_config_sha256:hash('source')};}
function binding(){return {binding:{old:selection(10),candidate:selection(20)},realm:{kind:'ISOLATED_FIXTURE',fixture_id:'fixture-profile',generation:id(6),model_sha256:hash('model')},program_sha256:program,command_id:id(8),operation_id:id(9),fence:1};}
function activation(){
 const baselineRefs=[ref(30),ref(31)],anchor={schema_version:'1',program_sha256:program,authorization_sha256:hash('authorization'),observer:binding(),measurement_revision:'GO_MONOTONIC_HTTP_V2',activation_record_sha256:hash('activation-record'),activation_record_sequence:8,activated_at:'2026-10-19T06:00:00Z',receipt_sha256s:[hash('baseline-content-1'),hash('baseline-content-2')],artifacts:baselineRefs.map(reference=>({reference,issued_at:'2026-10-19T05:59:59.123456789Z'})),issued_at:'2026-10-19T06:00:00.123456789Z'};
 const envelope={anchor,algorithm:'Ed25519/group-fixture-activated-health/v1',signature:Buffer.alloc(64,9).toString('base64')};
 return {schema_version:'1',run_id:runID,tenant_id:tenant,chain_id:chainID,program_sha256:program,old_workspace:{...old},observer:{id:id(32),tenant_id:tenant,chain_id:chainID,database_login:'fixture_health_observer',identity:{source_id:'fixture-http',issuer:'https://fixture.invalid',subject:'instrumented-observer',audience:'fixture-health'},public_key:keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),limits:{minimum_samples:30,max_p95_ns:2_000_000_000,max_p99_ns:3_000_000_000,max_error_rate_ppm:10000,min_availability_ppm:990000,max_inflight:2,max_backlog:0}},baseline:{schema_version:'1',id:id(33),tenant_id:tenant,chain_id:chainID,anchor:envelope,anchor_reference:ref(34,json(envelope)),observation_ids:[id(35),id(36)]},baseline_receipt_refs:baselineRefs};
}
function healthWindow(){return {status:'OBSERVED',reason_codes:[],binding:binding(),start:'2026-10-19T08:00:00.123456789Z',required_end:'2026-10-19T08:15:00.123456789Z',observed_through:'2026-10-19T08:15:00.123456789Z',receipt_sha256s:[hash('current-content-1'),hash('current-content-2')],baseline_receipt_sha256s:[hash('baseline-content-1'),hash('baseline-content-2')],sample_count:80,p95_ns:1_000_000_000,p99_ns:1_100_000_000,baseline_p95_ns:1_000_000_000,baseline_p99_ns:1_100_000_000,error_rate_ppm:0,availability_ppm:1000000,accepted:80,completed:80,rejected:0,failed:0,backlog:0,inflight:0,definition:'ISOLATED_HTTP_COMPLETED_OPERATION',availability_basis:'OBSERVED_HTTP_REQUEST_SUCCESS',customer_execution_authorized:false,measurement_revision:'GO_MONOTONIC_HTTP_V2',monotonic_duration_ns:900_000_000_000,baseline_monotonic_duration_ns:120_000_000_000};}
function abandonedWindow(){
 const zero=value=>typeof value==='string'?'':typeof value==='number'?0:Object.fromEntries(Object.entries(value).map(([key,item])=>[key,zero(item)]));
 return {status:'BLOCKED',reason_codes:['RECOVERY_OBSERVER_ATTEMPT_ABANDONED'],binding:zero(binding()),start:'0001-01-01T00:00:00Z',required_end:'0001-01-01T00:00:00Z',observed_through:'0001-01-01T00:00:00Z',receipt_sha256s:null,baseline_receipt_sha256s:null,sample_count:0,p95_ns:null,p99_ns:null,baseline_p95_ns:null,baseline_p99_ns:null,error_rate_ppm:null,availability_ppm:null,accepted:null,completed:null,rejected:null,failed:null,backlog:null,inflight:null,definition:'',availability_basis:'',customer_execution_authorized:false};
}
function makeAttempt(n,previousOutcomeID,abandoned=false){
 const attempt={schema_version:'1',id:id(n),tenant_id:tenant,chain_id:chainID,observer_id:id(32),baseline_id:id(33),previous_outcome_id:previousOutcomeID,workspace:{...next},command_id:id(40),operation_id:id(41),fence:2,terminal_id:id(42),state_sha256:hash('restored'),head:{version:24,record_count:24,last_record_sha256:hash('head')},started_at:abandoned?'2026-10-19T07:30:00Z':'2026-10-19T07:59:59Z'};
 const outcome={schema_version:'1',id:id(n+1),tenant_id:tenant,chain_id:chainID,attempt_id:attempt.id,observer_id:id(32),status:abandoned?'ABANDONED':'OBSERVED',observation_ids:abandoned?[id(n+2)]:[id(n+2),id(n+3)],window:abandoned?abandonedWindow():healthWindow(),signed_at:abandoned?'2026-10-19T07:30:40Z':'2026-10-19T08:15:01Z'};
 const row={attempt,outcome_canonical_json:'',algorithm:'Ed25519/group-recovery-health/v1',signature:'',outcome_reference:ref(n+4),observation_references:outcome.observation_ids.map((_,index)=>ref(n+5+index))};resign(row,outcome);return row;
}
function resign(row,outcome,privateKey=keys.privateKey){
 row.outcome_canonical_json=json(outcome);row.signature=sign(null,Buffer.concat([Buffer.from('finops/group-fixture/recovery-health-outcome/v1\0'),Buffer.from(row.outcome_canonical_json)]),privateKey).toString('base64');
 const envelope=json({outcome,algorithm:row.algorithm,signature:row.signature});row.outcome_reference.sha256=sha(envelope);row.outcome_reference.size_bytes=Buffer.byteLength(envelope);
}
function fixture(){
 const a=activation(),activationRaw=Buffer.from(json(a)),first=makeAttempt(50,'',true),last=makeAttempt(60,id(51));
 const reconstructed={schema_version:'1',status:'PASS',run_id:runID,tenant_id:tenant,chain_id:chainID,prepared_program_sha256:program,new_workspace:{...next},reservation_held:true,terminal_health_pending:true,full_recovery_health_accepted:false,fresh_owned_inverse_command_id:id(40),inverse_terminal_id:id(42),restored_state_sha256:hash('restored'),consumed_owned_effects:1};
 const ready={tenant_id:tenant,chain_id:chainID,prepared_program_sha256:program,old_workspace:{...old}};
 const context={runID,ready,newWorkspace:next,reconstructed,reconstructedSHA256:sha(json(reconstructed)),activation:a,activationSHA256:sha(activationRaw),activationRaw};
 const result={schema_version:'1',status:'PASS',run_id:runID,tenant_id:tenant,chain_id:chainID,prepared_program_sha256:program,original_reconstruction_sha256:context.reconstructedSHA256,health_activation_sha256:context.activationSHA256,new_workspace:{...next},baseline_id:a.baseline.id,observer_id:a.observer.id,attempts:[first,last],selected_outcome_id:id(61),selected_outcome_sha256:sha(last.outcome_canonical_json),final_head:{...last.attempt.head},restored_state_sha256:hash('restored'),restored_owned_effects:0,consumed_owned_effects:1,pending:false,reservation_released:true,terminal_health_pending:false,full_recovery_health_accepted:true,financial_disqualified_forever:true,recovery_health_artifact_index_sha256:hash('final-index'),fixture:true,customer_execution_authorized:false,verified_saving:null,observer_restart_confirmed:true,failed_attempt_elapsed_reused:false};
 return {result,context};
}
function mutateOutcome(f,index,mutate){const row=f.result.attempts[index],o=JSON.parse(row.outcome_canonical_json);mutate(o);resign(row,o);if(index===f.result.attempts.length-1)f.result.selected_outcome_sha256=sha(row.outcome_canonical_json);}
const check=f=>validateWorkspaceRecoveredHealth(f.result,f.context);

test('independent Go signing vector preserves nanoseconds, Go HTML escaping and exact domain bytes',()=>{
 // Generated by store.SignGroupRecoveryHealthOutcome with a synthetic unit
 // key. Only public bytes are retained here; the invalid unit scope cannot
 // pass the complete result validator or represent an issued observation.
 const window=abandonedWindow();window.reason_codes=['UNIT_<CLOCK>&'];
 const body={schema_version:'1',id:'unit-outcome',tenant_id:'unit-tenant',chain_id:'unit-chain',attempt_id:'unit-attempt',observer_id:'unit-observer',status:'ABANDONED',observation_ids:[],window,signed_at:'2026-10-19T10:20:30.123456789Z'},raw=json(body);
 const pins={algorithm:'Ed25519/group-recovery-health/v1',publicKey:'n0lDnp2wlbxBEe0l01eV2DG8VaBH9LHX9q7jd3u0EiA=',signature:'MER7W0oNdSI8bYdpQoARXCdwH/J/sq5b6mnrXSnC74XIdvk7zul6jG7/0Wk8w0hbrAQWEGHahwgvNihm7EmxDw=='};
 assert.equal(sha(raw),'03867b7a5bb20048dd61108798d39183f31cd0c50a9cac87a5759ddd2f0f2e16');assert.deepEqual(verifyRecoveryHealthOutcomeSignature(raw,pins),body);
 for(const changed of [raw.replace('123456789Z','123456788Z'),raw.replace('\\u003c','<'),raw.replace('UNIT_','OTHER_')])assert.throws(()=>verifyRecoveryHealthOutcomeSignature(changed,pins));
 assert.throws(()=>verifyRecoveryHealthOutcomeSignature(raw,{...pins,algorithm:'Ed25519'}));
});

test('fresh signed recovery result binds pre-loss public configuration and returns exact artifact kinds',()=>{
 const f=fixture(),before=json(f.result),contextBefore=json(f.context),v=check(f);
 assert.equal(v.selectedOutcome.status,'OBSERVED');assert.deepEqual(v.artifactReferences.map(x=>x.kind),['HEALTH_VERDICT','HEALTH_BASELINE','HEALTH_BASELINE','HEALTH_RECEIPT','HEALTH_VERDICT','HEALTH_RECEIPT','HEALTH_RECEIPT','HEALTH_VERDICT']);
 assert.equal(new Set(v.artifactReferences.map(x=>x.ref.id)).size,8);assert.equal(json(f.result),before);assert.equal(json(f.context),contextBefore);
 assert.notEqual(f.context.activation.baseline_receipt_refs[0].sha256,f.context.activation.baseline.anchor.anchor.receipt_sha256s[0]);assert.notEqual(f.result.attempts[1].observation_references[0].sha256,v.selectedOutcome.window.receipt_sha256s[0]);
});
test('activation binds raw canonical Go bytes and independently supplied pre-loss image and scope',()=>{
 for(const mutate of [f=>delete f.context.activationRaw,f=>f.context.activationRaw=Buffer.from(json(f.context.activation)+'\n'),f=>f.context.activation.observer.public_key=generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),f=>f.context.activationSHA256=hash('other'),f=>f.context.activation.old_workspace.runtime_id=next.runtime_id,f=>f.context.activation.observer.tenant_id='foreign',f=>f.context.activation.baseline.anchor.anchor.observer.realm.kind='CUSTOMER_NATIVE']){const f=fixture();mutate(f);assert.throws(()=>check(f));}
});
test('raw activation public sidecar refuses unknown fields, malformed keys and changed baseline refs',()=>{
 for(const mutate of [a=>a.observer.private_key='secret',a=>a.observer.public_key+='=',a=>a.observer.limits.minimum_samples=29,a=>a.baseline.anchor_reference.version_id='null',a=>a.baseline_receipt_refs[0].key=a.baseline_receipt_refs[0].key.replace(id(6),id(90)),a=>a.baseline.observation_ids.push(a.baseline.observation_ids[0])]){
  const f=fixture();mutate(f.context.activation);f.context.activationRaw=Buffer.from(json(f.context.activation));f.context.activationSHA256=sha(f.context.activationRaw);assert.throws(()=>validateRecoveryHealthActivation(f.context.activation,f.context));
 }
});
test('outcomes use the external observer key, exact domain, algorithm and canonical body',()=>{
 for(const mutate of [f=>f.result.attempts[1].algorithm='Ed25519',f=>f.result.attempts[1].signature+='=',f=>f.result.attempts[1].signature=Buffer.alloc(64).toString('base64'),f=>{const row=f.result.attempts[1];resign(row,JSON.parse(row.outcome_canonical_json),generateKeyPairSync('ed25519').privateKey);},f=>f.result.attempts[1].outcome_canonical_json+='\n',f=>f.result.attempts[1].outcome_canonical_json=f.result.attempts[1].outcome_canonical_json.replace('"schema_version":"1"','"schema_version":"1","schema_version":"1"')]){const f=fixture();mutate(f);assert.throws(()=>check(f));}
});
test('validly signed cross-tenant, program, observer and business-work substitutions still fail',()=>{
 for(const mutate of [o=>o.tenant_id='foreign',o=>o.chain_id='connected-chain-'+id(99),o=>o.observer_id=id(99),o=>o.window.binding.program_sha256=hash('foreign'),o=>o.window.binding.realm.generation=id(99),o=>o.window.definition='CUSTOMER_COMPLETED_ORDERS',o=>o.window.customer_execution_authorized=true]){const f=fixture();mutateOutcome(f,1,mutate);assert.throws(()=>check(f));}
});
test('a full recovery requires900seconds of independent UTC and monotonic evidence at nanosecond precision',()=>{
 for(const mutate of [w=>w.required_end='2026-10-19T08:15:00.123456788Z',w=>w.observed_through='2026-10-19T08:15:00.123456788Z',w=>w.monotonic_duration_ns=899_999_999_999,w=>w.baseline_monotonic_duration_ns=119_999_999_999,w=>w.monotonic_duration_ns=null,w=>w.required_end='2026-02-30T08:15:00Z',w=>w.start='2026-10-19T08:00:00.1234567890Z',w=>w.start='2026-10-19T09:00:00.123456789+01:00']){const f=fixture();mutateOutcome(f,1,o=>mutate(o.window));assert.throws(()=>check(f));}
});
test('original baseline content and stable observer operation cannot be replaced after loss',()=>{
 for(const mutate of [w=>w.baseline_receipt_sha256s=[hash('new-baseline')],w=>w.binding.command_id=id(99),w=>w.binding.operation_id=id(99),w=>w.binding.fence=2,w=>w.measurement_revision='GO_WALL_CLOCK',w=>w.availability_basis='BUSINESS_WORK_PRESERVED']){const f=fixture();mutateOutcome(f,1,o=>mutate(o.window));assert.throws(()=>check(f));}
});
test('positive window independently enforces fixed hard limits,15percent regression and explicit counters',()=>{
 for(const mutate of [w=>w.p95_ns=1_150_000_001,w=>w.p99_ns=1_265_000_001,w=>w.p95_ns=2_000_000_001,w=>w.sample_count=29,w=>w.error_rate_ppm=10001,w=>w.availability_ppm=989999,w=>w.backlog=1,w=>w.inflight=3,w=>w.completed=null,w=>w.accepted=81,w=>w.completed=Number.MAX_SAFE_INTEGER+1,w=>w.status='BREACH',w=>w.reason_codes=['HEALTH_COVERAGE_UNKNOWN']]){const f=fixture();mutateOutcome(f,1,o=>mutate(o.window));assert.throws(()=>check(f));}
 const boundary=fixture();mutateOutcome(boundary,1,o=>{o.window.p95_ns=1_150_000_000;o.window.p99_ns=1_265_000_000;});assert.doesNotThrow(()=>check(boundary));
});
test('interval saturation peaks and independently floored PPM rates preserve valid measured semantics',()=>{
 const f=fixture();mutateOutcome(f,1,o=>{o.window.inflight=1;o.window.error_rate_ppm=3333;o.window.availability_ppm=996666;o.window.accepted=300;o.window.completed=299;o.window.failed=1;});assert.doesNotThrow(()=>check(f));
});
test('signed envelope hash, length and exact namespace are checked, with explicit object versions required',()=>{
 for(const mutate of [r=>r.sha256=hash('wrong'),r=>r.size_bytes++,r=>r.version_id='null',r=>r.key=r.key.replace(tenant,'foreign'),r=>r.key=r.key.replace(id(6),id(90)),r=>r.key=r.key.replace('/'+r.id+'.encrypted','/../'+r.id+'.encrypted'),r=>r.key+='?version=other',r=>r.raw_body='private']){const f=fixture();mutate(f.result.attempts[1].outcome_reference);assert.throws(()=>check(f));}
});
test('failed observer attempt remains signed and cannot lend its elapsed time or receipt identities to retry',()=>{
 for(const mutate of [f=>f.result.attempts=f.result.attempts.slice(1),f=>f.result.attempts[1].attempt.previous_outcome_id='',f=>f.result.attempts[1].attempt.started_at='2026-10-19T07:30:39Z',f=>f.result.attempts[1].attempt.started_at='2026-10-19T08:00:01Z',f=>f.result.attempts[1].observation_references[0]=f.result.attempts[0].observation_references[0],f=>f.result.attempts[1].observation_references[0]=f.context.activation.baseline_receipt_refs[0],f=>f.result.failed_attempt_elapsed_reused=true]){const f=fixture();mutate(f);assert.throws(()=>check(f));}
 const reusedID=fixture();mutateOutcome(reusedID,1,o=>o.observation_ids[0]=id(52));assert.throws(()=>check(reusedID));
});
test('abandonment accepts only the precise nonpositive Go zero-window form and actual issued references',()=>{
 for(const mutate of [o=>o.window.monotonic_duration_ns=900_000_000_000,o=>o.window.status='OBSERVED',o=>o.window.reason_codes=[],o=>o.window.definition='ISOLATED_HTTP_COMPLETED_OPERATION',o=>o.observation_ids=[]]){const f=fixture();mutateOutcome(f,0,mutate);assert.throws(()=>check(f));}
 const noRefs=fixture();noRefs.result.attempts[0].observation_references=[];assert.throws(()=>check(noRefs));
});
test('attempt binds the current replacement, inverse effect, state and logical journal head',()=>{
 for(const mutate of [a=>a.workspace={...old},a=>a.command_id=id(90),a=>a.terminal_id=id(91),a=>a.state_sha256=hash('old'),a=>a.head.version++,a=>a.fence=0,a=>a.observer_id=id(92),a=>a.baseline_id=id(93),a=>a.tenant_id='foreign']){const f=fixture();mutate(f.result.attempts[1].attempt);assert.throws(()=>check(f));}
});
test('final release cannot hide pending work, erase disqualification or claim customer savings',()=>{
 for(const mutate of [v=>v.pending=true,v=>v.reservation_released=false,v=>v.terminal_health_pending=true,v=>v.full_recovery_health_accepted=false,v=>v.financial_disqualified_forever=false,v=>v.observer_restart_confirmed=false,v=>v.restored_owned_effects=1,v=>v.consumed_owned_effects=0,v=>v.customer_execution_authorized=true,v=>v.verified_saving=0,v=>v.fixture=false,v=>v.credentials='secret',v=>v.selected_outcome_id=id(51),v=>v.selected_outcome_sha256=hash('wrong')]){const f=fixture();mutate(f.result);assert.throws(()=>check(f));}
});
test('the unchanged pending-health result and activation hashes remain bound to this exact run',()=>{
 for(const mutate of [f=>f.result.original_reconstruction_sha256=hash('other'),f=>f.result.health_activation_sha256=hash('other'),f=>f.result.new_workspace.runtime_id=hash('other'),f=>f.context.reconstructed.reservation_held=false,f=>f.context.reconstructed.full_recovery_health_accepted=true,f=>f.result.run_id=id(99),f=>f.result.chain_id='connected-chain-'+id(99)]){const f=fixture();mutate(f);assert.throws(()=>check(f));}
});
