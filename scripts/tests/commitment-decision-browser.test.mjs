import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {jointBodySHA,jointFinanceSubject,jointFinanceUsername} from '../lib/fleet-joint-browser.mjs';
import {decisionBrowserRealm,decisionFinanceReviewerSubject,decisionFinanceReviewerUsername,validateDecisionBrowserInputs,validateDecisionBrowserResult,decisionBrowserSignal,validateDecisionNativeCurrent,validateDecisionNativeRenewal} from '../lib/commitment-decision-browser.mjs';

const run='b3cd15c0-f946-4135-91f7-c21b078d0d57',hash='a'.repeat(64),other='b'.repeat(64);
const ready={schema_version:'1',run_id:run,tenant_id:'fixture-http-'+run,selection:{source_id:'assessment-native',commitment_receipt_id:'inventory',billing_receipt_ids:['cur-receipt'],period:{start:'2026-10-18T00:00:00Z',end:'2026-10-19T00:00:00Z'}},fixture:true,customer_execution_authorized:false};
const inputs=()=>({schema_version:'1',run_id:run,tenant_id:ready.tenant_id,ready_sha256:hash,workload_id:'workload-native',cases:[{case:'POSITIVE',portfolio_analysis_request_id:run,offer_receipt_id:'offering-one'},{case:'DNP',portfolio_analysis_request_id:run,offer_receipt_id:'offering-two'}]});
const proof=()=>({schema_version:'1',status:'PASS',run_id:run,tenant_id:ready.tenant_id,ready_sha256:hash,inputs_sha256:jointBodySHA(inputs()),workload_id:'workload-native',cases:inputs().cases.map((value,i)=>({case:value.case,preparation_request_id:run,request_id:i?'e7f33a41-3aa3-4d53-93c2-05f2ed337113':run,decision_id:hash,decision_sha256:other,input_sha256:hash,outcome:i?'DO_NOT_PURCHASE':'RECOMMEND_PURCHASE_PENDING_FINANCE'})),approval_id:'actual-review',reviewer_id:decisionFinanceReviewerSubject,requester_id:jointFinanceSubject,oidc_pkce:true,oidc_authorization_code:true,ui_ids_only_requests:true,actual_analyst:true,persisted_reload:true,routine_native_renewal_before_finance:true,independent_finance:true,exact_review_version:true,idempotent_review_replay:true,fixture:true,purchase_authorized:false,execution_authorized:false,verified_saving:null});

test('native decision selectors remain two issued IDs without monetary/status authority',()=>{
 validateDecisionBrowserInputs(inputs(),{ready,readySHA256:hash});
 for(const change of [v=>v.ready_sha256=other,v=>v.tenant_id='tenant-demo',v=>v.cases[0].price='0.2',v=>v.cases[0].forecast_id='already-manufactured',v=>v.cases[1].case='POSITIVE',v=>v.cases.push(v.cases[0]),v=>v.cases[0].portfolio_analysis_request_id='unissued']){const value=inputs();change(value);assert.throws(()=>validateDecisionBrowserInputs(value,{ready,readySHA256:hash}));}
});

test('real realm has two independent FINANCE identities and public S256 only',()=>{
 const realm=decisionBrowserRealm(ready,hash,other),client=realm.clients[0];
 assert.deepEqual(realm.roles.realm,[{name:'FINANCE'}]);assert.equal(realm.users.length,2);assert.equal(realm.users[0].id,jointFinanceSubject);assert.equal(realm.users[0].username,jointFinanceUsername);assert.equal(realm.users[1].id,decisionFinanceReviewerSubject);assert.equal(realm.users[1].username,decisionFinanceReviewerUsername);assert.notEqual(realm.users[0].id,realm.users[1].id);assert.notEqual(realm.users[0].credentials[0].value,realm.users[1].credentials[0].value);
 for(const user of realm.users)assert.deepEqual(user.realmRoles,['FINANCE']);
 assert.equal(client.publicClient,true);assert.equal(client.standardFlowEnabled,true);assert.equal(client.directAccessGrantsEnabled,false);assert.equal(client.serviceAccountsEnabled,false);assert.equal(client.attributes['pkce.code.challenge.method'],'S256');assert.ok(client.defaultClientScopes.includes('basic'));assert.deepEqual(client.redirectUris,['http://localhost:8080/*']);
 assert.throws(()=>decisionBrowserRealm(ready,hash,hash));
});

test('bounded proof requires actual positive and DNP plus independent exact Finance replay',()=>{
 validateDecisionBrowserResult(proof(),{ready,readySHA256:hash,inputs:inputs()});
 for(const change of [v=>v.reviewer_id=jointFinanceSubject,v=>v.inputs_sha256=other,v=>v.cases[1].outcome='BLOCKED',v=>v.cases[1].request_id=v.cases[0].request_id,v=>v.idempotent_review_replay=false,v=>v.actual_analyst=false,v=>v.purchase_authorized=true,v=>v.verified_saving='0',v=>v.cases[0].expected_savings='1']){const value=proof();change(value);assert.throws(()=>validateDecisionBrowserResult(value,{ready,readySHA256:hash,inputs:inputs()}));}
});

test('source refresh and routine renewal are exact run and input bound handshakes',()=>{
 const context={ready,readySHA256:hash,inputs:inputs()},signal=decisionBrowserSignal(context);
 validateDecisionNativeCurrent(signal,context);
 const renewal={...signal,minimum_interval_seconds:60,ordinary_source_sync:true,quote_refresh_checked:true,controller_refresh_checked:true};validateDecisionNativeRenewal(renewal,context);
 for(const change of [v=>v.inputs_sha256=other,v=>v.minimum_interval_seconds=59,v=>v.ordinary_source_sync=false,v=>v.controller_refresh_checked=false,v=>v.price='0.2']){const value=structuredClone(renewal);change(value);assert.throws(()=>validateDecisionNativeRenewal(value,context));}
 assert.throws(()=>validateDecisionNativeCurrent({...signal,inputs_sha256:other},context));
});

test('copied browser extension keeps existing budgets and real network-only UI',()=>{
 const phase=readFileSync(new URL('../../examples/commitment-portfolio-browser/decision.mjs',import.meta.url),'utf8'),host=readFileSync(new URL('../lib/commitment-portfolio-browser-host.mjs',import.meta.url),'utf8'),main=readFileSync(new URL('../../examples/commitment-portfolio-browser/main.mjs',import.meta.url),'utf8');
 assert.ok(phase.includes('Date.now()+60000'));assert.ok(phase.includes('page.setDefaultTimeout(15000)'));assert.ok(phase.includes('page.setDefaultNavigationTimeout(30000)'));assert.ok(host.includes('const end=Date.now()+180000;while(check(browser).State.Running)'));
 assert.ok(!/\.fulfill\s*\(|\.unroute\s*\(|addInitScript|page\.clock|setSystemTime/.test(phase));
 assert.ok(host.includes('const wait=async(name,max=8192,setupMS=180000)'));assert.ok(host.includes("wait('portfolio-browser-ready.json',8192,900000)"));assert.equal((host.match(/900000/g)||[]).length,1);
 assert.ok(main.indexOf('await portfolioBrowserPhase(')<main.indexOf('await portfolioDecisionBrowserPhase('));assert.ok(host.indexOf('validateDecisionBrowserResult(JSON.parse(regular')<host.indexOf("remove(daemon);marker('portfolio-worker-complete.json'"));
 assert.ok(host.indexOf("start(discovery,true,185000)")<host.indexOf("marker('decision-native-refresh-request.json'"));assert.ok(host.indexOf('validateDecisionNativeCurrent(JSON.parse(await wait')<host.indexOf("daemon=create('analyst'"));assert.ok(phase.indexOf("phase='DECISION_ROUTINE_NATIVE_RENEWAL'")<phase.indexOf("phase='DECISION_INDEPENDENT_FINANCE_PKCE'"));
 assert.ok(phase.includes("context.request.post('http://localhost:8080/v1/approvals'"));assert.ok(phase.includes("'If-Match':requestHeaders['if-match']"));assert.ok(phase.includes("'Idempotency-Key':requestHeaders['idempotency-key']"));
});
