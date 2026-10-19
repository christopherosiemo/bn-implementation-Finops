// Private candidate acceptance metadata. None of these files grants authority.
import assert from 'node:assert/strict';
import {capacityBrowserRealm,capacityBrowserSHA,capacityBrowserPageError,validateCapacityBrowserReady} from './fleet-capacity-browser.mjs';
export const jointFinanceSubject='15b833b1-3c50-4b20-921f-a8a72d88f1f2';
export const jointFinanceUsername='joint-finance';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
// Failure evidence is a bounded API progress projection, never response bodies
// or observations. Missing counts stay null rather than becoming observed zero.
export function jointCapacityProgress(record,{requestID,apiStatus}={}){
 const batch=record?.batch,scope=record?.scope;
 const boundedCount=value=>Array.isArray(value)&&value.length<=256?value.length:null;
 return {
  request_id:typeof requestID==='string'&&UUID.test(requestID)?requestID:null,
  api_status:Number.isInteger(apiStatus)&&apiStatus>=100&&apiStatus<=599?apiStatus:null,
  last_record_status:['QUEUED','ASSESSED'].includes(record?.status)?record.status:null,
  scope_request_id:typeof scope?.request_id==='string'&&UUID.test(scope.request_id)?scope.request_id:null,
  scope_sha256:typeof scope?.scope?.snapshot_sha256==='string'&&SHA.test(scope.scope.snapshot_sha256)?scope.scope.snapshot_sha256:null,
  roster_count:boundedCount(scope?.scope?.current_member_ids),
  member_count:boundedCount(batch?.members),
 };
}
export function jointBrowserFailure(error,{phase,pageError,capacityProgress}={}){
 // A real page exception takes precedence over a later closed-page assertion.
 if(pageError)return {phase,code:'PAGE_EXECUTION_ERROR',page_error:capacityBrowserPageError(pageError)};
 const capacityDeadline=phase==='ACTUAL_DAEMON_RESULT'&&error?.message==='actual capacity worker did not publish';
 const detail={phase,code:capacityDeadline?'CAPACITY_RESULT_DEADLINE_EXCEEDED':'BROWSER_CHECK_FAILED',error:capacityBrowserPageError(error)};
 detail.error.message=capacityDeadline?'Capacity result was not ASSESSED within the fixed 60-second browser wait.':'Browser check failed; unrestricted details withheld.';
 if(phase==='ACTUAL_DAEMON_RESULT'&&capacityProgress)detail.capacity_result=jointCapacityProgress(capacityProgress.record,capacityProgress);
 return detail;
}
const keys=(value,names)=>assert.deepEqual(Object.keys(value).sort(),[...names].sort());
export function jointCanonicalJSON(value){
 const ordered=v=>{
  if(typeof v==='number')assert.ok(Number.isSafeInteger(v),'Joint fixture metadata requires exact integer numbers');
  return Array.isArray(v)?v.map(ordered):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(key=>[key,ordered(v[key])])):v;
 };
 return JSON.stringify(ordered(value)).replace(/[<>&\u2028\u2029]/g,char=>'\\u'+char.charCodeAt(0).toString(16).padStart(4,'0'));
}
export const jointBodySHA=value=>capacityBrowserSHA(jointCanonicalJSON(value));
export function jointBrowserRealm(ready,ownerPassword,financePassword){
 assert.match(financePassword,/^[a-f0-9]{64}$/);assert.notEqual(ownerPassword,financePassword);
 const realm=capacityBrowserRealm(ready,ownerPassword);
 realm.roles.realm.push({name:'FINANCE'});
 realm.users.push({id:jointFinanceSubject,username:jointFinanceUsername,firstName:'Joint',lastName:'Fixture finance',email:'joint-finance@fixture.invalid',emailVerified:true,enabled:true,requiredActions:[],credentials:[{type:'password',value:financePassword,temporary:false}],realmRoles:['FINANCE']});
 return realm;
}
export function validateJointWorkerReady(value,{ready}={}){
 validateCapacityBrowserReady(ready);keys(value,['schema_version','run_id','tenant_id','purpose','database_file_sha256','database_file_size','configuration_sha256']);
 assert.equal(value.schema_version,'1');assert.equal(value.run_id,ready.run_id);assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.purpose,'group-decision-reader');
 assert.match(value.database_file_sha256,SHA);assert.ok(Number.isSafeInteger(value.database_file_size)&&value.database_file_size>0&&value.database_file_size<=8192);
 assert.equal(value.configuration_sha256,jointBodySHA(jointWorkerEnvironment(ready)));return value;
}
export function jointWorkerEnvironment(ready){validateCapacityBrowserReady(ready);return Object.freeze({FLEET_DECISION_ENABLED:'true',FLEET_DECISION_TENANT_ID:ready.tenant_id,FLEET_DECISION_DATABASE_FILE:'/run/secrets/group-decision-database',FLEET_DECISION_DATABASE_MODE:'LOCAL_PRIVATE'});}
export function validateJointInputs(value,{ready,readySHA256,capacityRequestID}={}){
 validateCapacityBrowserReady(ready);keys(value,['schema_version','run_id','ready_sha256','workload_id','assessment_request_id','capacity_batch_request_id','input_refs','expected_scenario_status','fixture','customer_execution_authorized']);
 assert.equal(value.schema_version,'1');assert.equal(value.run_id,ready.run_id);assert.equal(value.ready_sha256,readySHA256);assert.match(readySHA256,SHA);assert.equal(value.workload_id,ready.workload_id);
 assert.match(value.assessment_request_id,UUID);assert.match(value.capacity_batch_request_id,UUID);if(capacityRequestID!==undefined)assert.equal(value.capacity_batch_request_id,capacityRequestID);
 assert.equal(value.input_refs.length,3);assert.equal(new Set(value.input_refs.map(ref=>ref.id)).size,3);for(const ref of value.input_refs){keys(ref,['id','sha256']);assert.ok(typeof ref.id==='string'&&ref.id.length>0&&ref.id.length<=256);assert.match(ref.sha256,SHA);}
 assert.ok(['UNAVAILABLE','OBSERVED_CONDITIONAL'].includes(value.expected_scenario_status));assert.equal(value.fixture,true);assert.equal(value.customer_execution_authorized,false);return value;
}
export function validateJointBrowserResult(value,{ready,readySHA256,inputs,inputsSHA256}={}){
 validateJointInputs(inputs,{ready,readySHA256});assert.match(inputsSHA256,SHA);
 keys(value,['schema_version','status','run_id','ready_sha256','joint_inputs_sha256','tenant_id','workload_id','creator_id','request_id','decision_id','decision_sha256','assessment_request_id','capacity_batch_request_id','physical_status','member_count','scenario_status','oidc_pkce','oidc_authorization_code','ui_ids_only_request','actual_joint_worker','all_five_dimensions','unknown_member_preserved','persisted_reload','fixture_labels_visible','fixture','group_capacity_authorized','customer_execution_authorized','contracted_avoidable_cost','estimated_saving','verified_saving']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'PASS');assert.equal(value.run_id,ready.run_id);assert.equal(value.ready_sha256,readySHA256);assert.equal(value.joint_inputs_sha256,inputsSHA256);
 assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.workload_id,ready.workload_id);assert.equal(value.creator_id,jointFinanceSubject);assert.match(value.request_id,UUID);assert.match(value.decision_id,/^group-joint-decision-[a-f0-9]{64}$/);assert.match(value.decision_sha256,SHA);
 assert.equal(value.assessment_request_id,inputs.assessment_request_id);assert.equal(value.capacity_batch_request_id,inputs.capacity_batch_request_id);assert.equal(value.physical_status,'FAIL');assert.equal(value.member_count,3);assert.equal(value.scenario_status,inputs.expected_scenario_status);
 for(const key of ['oidc_pkce','oidc_authorization_code','ui_ids_only_request','actual_joint_worker','all_five_dimensions','unknown_member_preserved','persisted_reload','fixture_labels_visible','fixture'])assert.equal(value[key],true);
 for(const key of ['group_capacity_authorized','customer_execution_authorized'])assert.equal(value[key],false);
 for(const key of ['contracted_avoidable_cost','estimated_saving','verified_saving'])assert.equal(value[key],null);return value;
}
