import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {jointBrowserFailure,jointCapacityProgress,jointBrowserRealm,jointFinanceSubject,jointFinanceUsername,jointBodySHA,jointCanonicalJSON,jointWorkerEnvironment,validateJointWorkerReady,validateJointInputs,validateJointBrowserResult} from '../lib/fleet-joint-browser.mjs';
import {capacityBrowserSubject} from '../lib/fleet-capacity-browser.mjs';

const id=n=>`${String(n).padStart(8,'0')}-1111-4111-8111-111111111111`,sha=n=>String(n).repeat(64);
const ready={schema_version:'1',run_id:id(1),tenant_id:'fixture-http-'+id(2),workload_id:'fixture-workload',operator_subject:capacityBrowserSubject,username:'capacity-owner',old_proposal_id:id(3),candidate_proposal_id:id(4),safety_profile_version:3,first_batch_id:id(5),memory_instance_id:'i-aaaaaaaaaaaaaaaaa',candidate_template_version:'18446744073709551615',fixture:true,customer_execution_authorized:false};
const readySHA256=sha(1),inputs={schema_version:'1',run_id:ready.run_id,ready_sha256:readySHA256,workload_id:ready.workload_id,assessment_request_id:id(6),capacity_batch_request_id:id(7),input_refs:[{id:'assessment-issued',sha256:sha(2)},{id:'scope-issued',sha256:sha(3)},{id:'batch-issued',sha256:sha(4)}],expected_scenario_status:'OBSERVED_CONDITIONAL',fixture:true,customer_execution_authorized:false},inputsSHA256=sha(5);
const proof={schema_version:'1',status:'PASS',run_id:ready.run_id,ready_sha256:readySHA256,joint_inputs_sha256:inputsSHA256,tenant_id:ready.tenant_id,workload_id:ready.workload_id,creator_id:jointFinanceSubject,request_id:id(8),decision_id:'group-joint-decision-'+sha(6),decision_sha256:sha(6),assessment_request_id:inputs.assessment_request_id,capacity_batch_request_id:inputs.capacity_batch_request_id,physical_status:'FAIL',member_count:3,scenario_status:'OBSERVED_CONDITIONAL',oidc_pkce:true,oidc_authorization_code:true,ui_ids_only_request:true,actual_joint_worker:true,all_five_dimensions:true,unknown_member_preserved:true,persisted_reload:true,fixture_labels_visible:true,fixture:true,group_capacity_authorized:false,customer_execution_authorized:false,contracted_avoidable_cost:null,estimated_saving:null,verified_saving:null};
test('separate finance identity retains public S256 and basic subject scope without widening owner',()=>{
 const r=jointBrowserRealm(ready,sha(7),sha(8));assert.deepEqual(r.roles.realm.map(x=>x.name),['APPLICATION_OWNER','FINANCE']);assert.deepEqual(r.users[0].realmRoles,['APPLICATION_OWNER']);assert.deepEqual(r.users[1].realmRoles,['FINANCE']);assert.equal(r.users[1].id,jointFinanceSubject);assert.equal(r.users[1].username,jointFinanceUsername);assert.notEqual(r.users[0].id,r.users[1].id);assert.equal(r.clients.length,1);assert.equal(r.clients[0].publicClient,true);assert.equal(r.clients[0].directAccessGrantsEnabled,false);assert.equal(r.clients[0].serviceAccountsEnabled,false);assert.equal(r.clients[0].attributes['pkce.code.challenge.method'],'S256');assert.ok(r.clients[0].defaultClientScopes.includes('basic'));assert.throws(()=>jointBrowserRealm(ready,sha(7),sha(7)));
});
test('configuration is one-purpose one-database file without native or authority credentials',()=>{
 const env=jointWorkerEnvironment(ready);assert.deepEqual(Object.keys(env).sort(),['FLEET_DECISION_DATABASE_FILE','FLEET_DECISION_DATABASE_MODE','FLEET_DECISION_ENABLED','FLEET_DECISION_TENANT_ID']);const v={schema_version:'1',run_id:ready.run_id,tenant_id:ready.tenant_id,purpose:'group-decision-reader',database_file_sha256:sha(9),database_file_size:256,configuration_sha256:jointBodySHA(env)};validateJointWorkerReady(v,{ready});for(const d of [{...v,tenant_id:'other'},{...v,purpose:'executor'},{...v,configuration_sha256:sha(2)},{...v,database_file_size:8193},{...v,secret:'forbidden'}])assert.throws(()=>validateJointWorkerReady(d,{ready}));
});
test('issued input references are exactly scoped and do not carry amounts or authority',()=>{
 validateJointInputs(inputs,{ready,readySHA256,capacityRequestID:id(7)});for(const mutate of [d=>d.run_id=id(9),d=>d.workload_id='other',d=>d.capacity_batch_request_id=id(9),d=>d.input_refs.push({...d.input_refs[0]}),d=>d.expected_scenario_status='READY',d=>d.price='0.12',d=>d.fixture=false,d=>d.customer_execution_authorized=true]){const d=structuredClone(inputs);mutate(d);assert.throws(()=>validateJointInputs(d,{ready,readySHA256,capacityRequestID:id(7)}));}
});
test('signed-in result preserves unknown member, exact inputs and unavailable financial authority',()=>{
 validateJointBrowserResult(proof,{ready,readySHA256,inputs,inputsSHA256});for(const mutate of [d=>d.creator_id=ready.operator_subject,d=>d.joint_inputs_sha256=sha(1),d=>d.member_count=2,d=>d.physical_status='PASS',d=>d.unknown_member_preserved=false,d=>d.all_five_dimensions=false,d=>d.persisted_reload=false,d=>d.scenario_status='UNAVAILABLE',d=>d.verified_saving='0',d=>d.group_capacity_authorized=true,d=>d.customer_execution_authorized=true,d=>d.extra='authority']){const d=structuredClone(proof);mutate(d);assert.throws(()=>validateJointBrowserResult(d,{ready,readySHA256,inputs,inputsSHA256}));}
});
test('canonical decision hash matches Go map ordering/HTML escapes and refuses unsafe numeric precision',()=>{
 assert.equal(jointCanonicalJSON({z:'<>&\u2028\u2029',a:[{y:2,x:'0.00'}]}),'{"a":[{"x":"0.00","y":2}],"z":"\\u003c\\u003e\\u0026\\u2028\\u2029"}');assert.equal(jointBodySHA({a:1,b:2}),jointBodySHA({b:2,a:1}));assert.throws(()=>jointCanonicalJSON({n:9007199254740992}));assert.throws(()=>jointCanonicalJSON({n:NaN}));
});
test('capacity deadline has its exact own code and bounded last API progress, without copying raw bodies',()=>{
 const record={status:'QUEUED',scope:{request_id:id(7),scope:{snapshot_sha256:sha(4),current_member_ids:['i-aaaaaaaaaaaaaaaaa','i-bbbbbbbbbbbbbbbbb']}},batch:null,secret:'Bearer fixture-sensitive-output',observations:[{value:95}]};
 const progress={record,requestID:id(7),apiStatus:200};
 const value=jointBrowserFailure(Error('actual capacity worker did not publish'),{phase:'ACTUAL_DAEMON_RESULT',capacityProgress:progress});
 assert.equal(value.code,'CAPACITY_RESULT_DEADLINE_EXCEEDED');
 assert.equal(value.error.raw_message_sha256,'93445935fdeda11e02c969126b5634abf01af1e14343bfb2a909124335b5dbc4');
 assert.deepEqual(value.capacity_result,{request_id:id(7),api_status:200,last_record_status:'QUEUED',scope_request_id:id(7),scope_sha256:sha(4),roster_count:2,member_count:null});
 assert.match(value.error.message,/fixed 60-second/);
 assert.doesNotMatch(JSON.stringify(value),/fixture-sensitive-output|observations|"value"|i-aaaaaaaa/);
 const empty=jointCapacityProgress({status:'ASSESSED',scope:{scope:{current_member_ids:[]}},batch:{members:[]}},{requestID:id(7),apiStatus:200});
 assert.equal(empty.roster_count,0);assert.equal(empty.member_count,0);
 const unknown=jointCapacityProgress({status:'secret-status',scope:{request_id:'https://secret.invalid/?token=secret',scope:{snapshot_sha256:'Bearer secret',current_member_ids:Array(257)}},batch:{members:Array(257)}},{requestID:'private-secret',apiStatus:999});
 assert.deepEqual(unknown,{request_id:null,api_status:null,last_record_status:null,scope_request_id:null,scope_sha256:null,roster_count:null,member_count:null});
});
test('page exceptions remain distinct and win over subsequent assertions; unknown errors disclose only hashes',()=>{
 const raw='https://private.invalid/?token=fixture-secret Bearer fixture-secret <html>secret</html>';
 const generic=jointBrowserFailure(Error(raw),{phase:'ACTUAL_DAEMON_RESULT'});
 assert.equal(generic.code,'BROWSER_CHECK_FAILED');assert.doesNotMatch(JSON.stringify(generic),/private.invalid|fixture-secret|<html>/);
 const wrongPhase=jointBrowserFailure(Error('actual capacity worker did not publish'),{phase:'REAL_PKCE_SIGN_IN'});
 assert.equal(wrongPhase.code,'BROWSER_CHECK_FAILED');
 const page=jointBrowserFailure(Error('actual capacity worker did not publish'),{phase:'ACTUAL_DAEMON_RESULT',pageError:new TypeError("Cannot read properties of null (reading 'map')")});
 assert.equal(page.code,'PAGE_EXECUTION_ERROR');assert.equal(page.page_error.error_class,'TypeError');assert.equal(page.page_error.message,"Cannot read properties of null (reading 'map')");assert.equal(page.capacity_result,undefined);
});
test('real browser keeps accepted owner flow, fixed budgets, fresh finance and actual IDs-only queue',()=>{
 const base=new URL('../../examples/fleet-joint-browser/',import.meta.url),main=readFileSync(new URL('main.mjs',base),'utf8'),joint=readFileSync(new URL('joint.mjs',base),'utf8');assert.match(main,/finance_password,password,run_id/);assert.match(main,/write\('joint-input-request\.json'/);assert.match(main,/jointBrowserPhase/);assert.match(main,/actual capacity worker did not publish',60000/);assert.match(main,/jointBrowserFailure\(error,\{phase,pageError,capacityProgress\}\)/);assert.match(main,/apiStatus:response\.status\(\),record:capacityProgress\?\.record\?\?null/);assert.match(main,/capacityProgress\.record=value/);assert.match(main,/pageError=error;void page\.close\(\)/);assert.match(joint,/actual replacement joint worker did not publish',60000/);assert.match(joint,/setDefaultTimeout\(15000\)/);assert.match(joint,/setDefaultNavigationTimeout\(30000\)/);assert.match(joint,/joint-decision-request\.json/);assert.match(joint,/response\.status\(\),202/);assert.match(joint,/headers\(\)\['if-match'\]/);assert.match(joint,/headers\(\)\['idempotency-key'\]/);assert.match(joint,/newContext/);assert.match(joint,/jointFinanceUsername/);assert.doesNotMatch(main+joint,/route\.fulfill|test\.skip|\.fixme\(|retries\s*:/);assert.match(joint,/browser-joint-desktop\.png/);assert.match(joint,/browser-joint-mobile\.png/);assert.match(joint,/capacityBrowserPageError\(error\)/);assert.doesNotMatch(joint,/console\.log\(|error\.stack/);
});
