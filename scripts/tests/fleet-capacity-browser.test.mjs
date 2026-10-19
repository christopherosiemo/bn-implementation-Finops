import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {capacityBrowserRealm,capacityBrowserSubject,capacityBrowserPageError,capacityBrowserSHA,validateCapacityBrowserNamespace,validateCapacityBrowserReady,validateCapacityBrowserResult} from '../lib/fleet-capacity-browser.mjs';

const run='11111111-2222-4333-8444-555555555555',hash='a'.repeat(64);
const ready={schema_version:'1',run_id:run,tenant_id:'fixture-http-'+run,workload_id:'fixture-workload',operator_subject:capacityBrowserSubject,username:'capacity-owner',old_proposal_id:'00000000-0000-4000-8000-000000000001',candidate_proposal_id:'00000000-0000-4000-8000-000000000002',safety_profile_version:3,first_batch_id:'00000000-0000-4000-8000-000000000003',memory_instance_id:'i-0123456789abcdef0',candidate_template_version:'9007199254740993',fixture:true,customer_execution_authorized:false};
const clone=v=>structuredClone(v);
test('fresh realm has only scoped application owner and actual S256 authorization-code client',()=>{
 const r=capacityBrowserRealm(ready,'1'.repeat(64));assert.equal(r.users.length,1);assert.equal(r.users[0].id,ready.operator_subject);assert.deepEqual(r.users[0].realmRoles,['APPLICATION_OWNER']);assert.deepEqual(r.roles.realm,[{name:'APPLICATION_OWNER'}]);assert.equal(r.clients[0].publicClient,true);assert.equal(r.clients[0].directAccessGrantsEnabled,false);assert.equal(r.clients[0].serviceAccountsEnabled,false);assert.deepEqual(r.clients[0].defaultClientScopes,['basic','profile','email','roles','web-origins']);assert.equal(new Set(r.clients[0].defaultClientScopes).size,r.clients[0].defaultClientScopes.length);assert.equal(r.clients[0].attributes['pkce.code.challenge.method'],'S256');assert.equal(r.clients[0].protocolMappers[0].config['claim.value'],ready.tenant_id);assert.deepEqual(r.clients[0].redirectUris,['http://localhost:8080/*']);assert.equal(JSON.stringify(r).includes('ORGANISATION_OWNER'),false);
});
test('public handshake refuses arbitrary tenant, target, authority, identity and rounded native version',()=>{
 validateCapacityBrowserReady(ready,{runID:run});
 for(const change of [r=>r.tenant_id='tenant-demo',r=>r.workload_id='workload-dev',r=>r.operator_subject='caller',r=>r.candidate_proposal_id=r.old_proposal_id,r=>r.candidate_template_version=9007199254740993,r=>r.customer_execution_authorized=true,r=>r.api='http://arbitrary:8080',r=>r.observations=[]]){const r=clone(ready);change(r);assert.throws(()=>validateCapacityBrowserReady(r,{runID:run}));}
 assert.throws(()=>capacityBrowserRealm(ready,'caller-password'));assert.throws(()=>validateCapacityBrowserReady(ready,{runID:'different'}));
});
function result(){return {schema_version:'1',status:'PASS',run_id:run,ready_sha256:hash,tenant_id:ready.tenant_id,workload_id:ready.workload_id,request_id:'00000000-0000-4000-8000-000000000004',member_id:'fleet-capacity-member-'+hash,member_sha256:hash,scope_sha256:hash,candidate_template_version:ready.candidate_template_version,model_version:'capacity-weekday-block-v2',browser_version:'140.0.7339.16',oidc_pkce:true,oidc_authorization_code:true,ui_ids_only_request:true,actual_worker_result:true,memory95_rejected:true,lazy_member_detail:true,persisted_reload:true,fixture_labels_visible:true,fixture:true,customer_execution_authorized:false,verified_saving:null};}
test('result pins exact ready/scope/native version and refuses invented authority or missing actual browser steps',()=>{
 validateCapacityBrowserResult(result(),{ready,readySHA256:hash});
 for(const change of [r=>r.request_id=ready.first_batch_id,r=>r.ready_sha256='b'.repeat(64),r=>r.model_version='fixture',r=>r.candidate_template_version='9007199254740992',r=>r.persisted_reload=false,r=>r.actual_worker_result=false,r=>r.oidc_authorization_code=false,r=>r.oidc_pkce=false,r=>r.customer_execution_authorized=true,r=>r.verified_saving='0',r=>r.token='secret']){const r=result();change(r);assert.throws(()=>validateCapacityBrowserResult(r,{ready,readySHA256:hash}));}
});
function container(mode){return {Id:'a'.repeat(64),HostConfig:{NetworkMode:mode,ReadonlyRootfs:true,Privileged:false,PortBindings:{},PublishAllPorts:false,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges'],PidMode:'',IpcMode:'private'}};}
test('namespace pins exact owned edge and refuses published/main/host namespaces',()=>{
 const options={role:'keycloak',webRuntimeID:'a'.repeat(64),privateNetwork:'owned-private'};validateCapacityBrowserNamespace(container('container:'+'a'.repeat(64)),options);
 for(const change of [c=>c.HostConfig.NetworkMode='host',c=>c.HostConfig.NetworkMode='container:'+'b'.repeat(64),c=>c.HostConfig.PortBindings={'8080/tcp':[{HostIp:'127.0.0.1',HostPort:'3000'}]},c=>c.HostConfig.PublishAllPorts=true,c=>c.HostConfig.ReadonlyRootfs=false,c=>c.HostConfig.PidMode='host',c=>c.HostConfig.IpcMode='host']){const c=container('container:'+'a'.repeat(64));change(c);assert.throws(()=>validateCapacityBrowserNamespace(c,options));}
 validateCapacityBrowserNamespace(container('owned-private'),{...options,role:'web'});
});
test('browser executes real App/auth/API without injected responses, tokens or relaxed existing deadlines',()=>{
 const script=readFileSync(new URL('../../examples/fleet-capacity-browser/main.mjs',import.meta.url),'utf8');assert.doesNotMatch(script,/route\.fulfill|addInitScript|storageState|request\.post\(|page\.request\.post\(|grant_type.?[:=].?['"]password/);assert.match(script,/code_challenge_method/);assert.match(script,/code_verifier/);assert.match(script,/dialog\.getByRole\('button',\{name:'Request fleet member evaluation'/);assert.match(script,/context\.clearCookies\(\)/);assert.match(script,/setDefaultTimeout\(15000\)/);assert.match(script,/setDefaultNavigationTimeout\(30000\)/);assert.match(script,/readFileSync\('\/run\/secrets\/browser.json'/);assert.match(script,/Browser|browser/);
});
test('identity setup and the actual journey have separate fixed clocks with an exact startup binding',()=>{
 const raw=readFileSync(new URL('../../internal/service/fleet_capacity_browser_fixture_test.go',import.meta.url),'utf8');
 const phase=raw.slice(raw.indexOf('func fleetCapacityPositiveBrowserPhase('));
 assert.match(phase,/setupCtx, cancelSetup := context.WithTimeout\(ctx, 180\*time.Second\)/);
 assert.match(phase,/fleetCapacityBrowserWait\(setupCtx, "browser-start.json", &started\)/);
 assert.match(phase,/setupCtx.Err\(\) != nil/);
 assert.ok(phase.indexOf('fleetCapacityBrowserJourneyContext(ctx, started, signal)')>phase.indexOf('fleetCapacityBrowserWait(setupCtx, "browser-start.json", &started)'));
 assert.ok(phase.indexOf('fleetCapacityBrowserJourneyContext(ctx, started, signal)')<phase.indexOf('refreshNative(journeyCtx)'));
 assert.ok(phase.indexOf('refreshNative(journeyCtx)')<phase.indexOf('fleetCapacityBrowserWrite("/results/browser-api-ready.json"'));
 assert.match(raw,/started != expected/);assert.match(raw,/context.WithTimeout\(parent, 180\*time.Second\)/);
 assert.match(phase,/oidc.ClientContext\(ctx, &http.Client\{Timeout: 30 \* time.Second\}\)/);
 for(const name of ['browser-result.json','browser-worker-complete.json'])assert.ok(phase.includes('fleetCapacityBrowserWait(journeyCtx, "'+name+'"'));
 assert.doesNotMatch(phase,/phaseCtx/);
});
test('actual dashboard authorization refusal is checked before credentials or data are consumed',()=>{
 const raw=readFileSync(new URL('../../examples/fleet-capacity-browser/main.mjs',import.meta.url),'utf8');
 const signIn=raw.slice(raw.indexOf('async function signIn()'),raw.indexOf("phase='REAL_PKCE_SIGN_IN'"));
 assert.match(signIn,/pathname==='\/v1\/dashboard'&&r.request\(\).method\(\)==='GET'\)/);
 assert.doesNotMatch(signIn,/r\.ok\(\)/);
 const authorized=signIn.indexOf("assert.equal(response.status(),200,'actual dashboard response must be authorized')");
 assert.ok(authorized>signIn.indexOf('const response=await dashboard'));
 assert.ok(authorized<signIn.indexOf('apiToken=response.request().headers().authorization'));
 assert.ok(authorized<signIn.indexOf('const data=await response.json()'));
});
test('the first page error fails the real action and retains only bounded structural diagnostics',()=>{
 const raw="Cannot read properties of null (reading 'length')",known=capacityBrowserPageError(new TypeError(raw));
 assert.deepEqual(known,{error_class:'TypeError',message:raw,raw_message_sha256:capacityBrowserSHA(raw)});
 for(const text of ['https://private.invalid/callback?code=secret','Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.private','<html><input value="private-password"></html>',"Cannot read properties of null (reading 'private_password')",'a'.repeat(65536)]){
  const safe=capacityBrowserPageError({name:'private-value',message:text});assert.equal(safe.error_class,'PageError');assert.equal(safe.message,'Page execution failed; unrestricted details withheld.');assert.equal(safe.raw_message_sha256,capacityBrowserSHA(text));assert.ok(Buffer.byteLength(safe.message)<=256);assert.equal(safe.message.includes(text),false);
 }
 const script=readFileSync(new URL('../../examples/fleet-capacity-browser/main.mjs',import.meta.url),'utf8');
 assert.match(script,/page\.once\('pageerror',error=>\{pageError=capacityBrowserPageError\(error\);void page\.close\(\)/);
 assert.match(script,/const detail=pageError\?JSON\.stringify\(\{phase,page_error:pageError\}\)/);
 assert.ok(script.indexOf("page.once('pageerror'")<script.indexOf("phase='WAIT_REAL_IDP'"));
});
