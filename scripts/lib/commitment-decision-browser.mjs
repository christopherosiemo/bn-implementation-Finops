// Isolated fixture selectors and bounded proofs; never public evidence input.
import assert from 'node:assert/strict';
import {portfolioBrowserRealm,validatePortfolioBrowserReady} from './commitment-portfolio-browser.mjs';
import {jointBodySHA,jointFinanceSubject} from './fleet-joint-browser.mjs';

export const decisionFinanceReviewerSubject='e66a8a4c-1e42-4b97-8c31-85a9ef27b847';
export const decisionFinanceReviewerUsername='decision-finance-reviewer';
const sha=/^[a-f0-9]{64}$/,uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const keys=(v,names)=>{assert.ok(v&&typeof v==='object'&&!Array.isArray(v));assert.deepEqual(Object.keys(v).sort(),[...names].sort());};
const id=value=>assert.match(value,/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/);

export function decisionBrowserRealm(ready,password,reviewerPassword){
 assert.match(reviewerPassword,sha);assert.notEqual(password,reviewerPassword);
 const realm=portfolioBrowserRealm(ready,password);
 realm.users.push({id:decisionFinanceReviewerSubject,username:decisionFinanceReviewerUsername,firstName:'Decision',lastName:'Independent fixture finance',email:'decision-reviewer@fixture.invalid',emailVerified:true,enabled:true,requiredActions:[],credentials:[{type:'password',value:reviewerPassword,temporary:false}],realmRoles:['FINANCE']});
 return realm;
}

export function validateDecisionBrowserInputs(value,{ready,readySHA256}){
 validatePortfolioBrowserReady(ready);assert.match(readySHA256,sha);
 keys(value,['schema_version','run_id','tenant_id','ready_sha256','workload_id','cases']);
 assert.equal(value.schema_version,'1');assert.equal(value.run_id,ready.run_id);assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.ready_sha256,readySHA256);id(value.workload_id);
 assert.ok(Array.isArray(value.cases)&&value.cases.length===2);assert.deepEqual(value.cases.map(row=>row.case),['POSITIVE','DNP']);
 for(const row of value.cases){keys(row,['case','portfolio_analysis_request_id','offer_receipt_id']);assert.match(row.portfolio_analysis_request_id,uuid);id(row.offer_receipt_id);}
 assert.notEqual(jointBodySHA(value.cases[0]),jointBodySHA(value.cases[1]));return value;
}

export function decisionBrowserSignal({ready,readySHA256,inputs}){
 validateDecisionBrowserInputs(inputs,{ready,readySHA256});
 return {schema_version:'1',run_id:ready.run_id,ready_sha256:readySHA256,inputs_sha256:jointBodySHA(inputs)};
}
export function validateDecisionNativeCurrent(value,context){
 keys(value,['schema_version','run_id','ready_sha256','inputs_sha256']);assert.deepEqual(value,decisionBrowserSignal(context));return value;
}
export function validateDecisionNativeRenewal(value,context){
 keys(value,['schema_version','run_id','ready_sha256','inputs_sha256','minimum_interval_seconds','ordinary_source_sync','quote_refresh_checked','controller_refresh_checked']);
 for(const[key,expected]of Object.entries(decisionBrowserSignal(context)))assert.equal(value[key],expected);
 assert.equal(value.minimum_interval_seconds,60);for(const key of ['ordinary_source_sync','quote_refresh_checked','controller_refresh_checked'])assert.equal(value[key],true);return value;
}

export function validateDecisionBrowserResult(value,{ready,readySHA256,inputs}){
 validateDecisionBrowserInputs(inputs,{ready,readySHA256});
 keys(value,['schema_version','status','run_id','tenant_id','ready_sha256','inputs_sha256','workload_id','cases','approval_id','reviewer_id','requester_id','oidc_pkce','oidc_authorization_code','ui_ids_only_requests','actual_analyst','persisted_reload','routine_native_renewal_before_finance','independent_finance','exact_review_version','idempotent_review_replay','fixture','purchase_authorized','execution_authorized','verified_saving']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'PASS');assert.equal(value.run_id,ready.run_id);assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.ready_sha256,readySHA256);assert.equal(value.inputs_sha256,jointBodySHA(inputs));assert.equal(value.workload_id,inputs.workload_id);
 assert.equal(value.requester_id,jointFinanceSubject);assert.equal(value.reviewer_id,decisionFinanceReviewerSubject);assert.notEqual(value.requester_id,value.reviewer_id);id(value.approval_id);
 assert.ok(Array.isArray(value.cases)&&value.cases.length===2);
 for(let i=0;i<2;i++){const row=value.cases[i];keys(row,['case','preparation_request_id','request_id','decision_id','decision_sha256','input_sha256','outcome']);assert.equal(row.case,inputs.cases[i].case);assert.match(row.preparation_request_id,uuid);assert.match(row.request_id,uuid);assert.match(row.decision_id,sha);assert.match(row.decision_sha256,sha);assert.match(row.input_sha256,sha);assert.equal(row.outcome,i===0?'RECOMMEND_PURCHASE_PENDING_FINANCE':'DO_NOT_PURCHASE');}
 assert.notEqual(value.cases[0].request_id,value.cases[1].request_id);
 for(const key of ['oidc_pkce','oidc_authorization_code','ui_ids_only_requests','actual_analyst','persisted_reload','routine_native_renewal_before_finance','independent_finance','exact_review_version','idempotent_review_replay','fixture'])assert.equal(value[key],true);
 assert.equal(value.purchase_authorized,false);assert.equal(value.execution_authorized,false);assert.equal(value.verified_saving,null);return value;
}
