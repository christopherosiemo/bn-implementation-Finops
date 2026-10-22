// Private fixture coordination only. No public evidence or authority upload.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

export const capacityBrowserSubject='52a55d35-21b6-4a32-9dcb-fda96b34552e';
export const capacityBrowserUsername='capacity-owner';
export const capacityBrowserOrigins=Object.freeze(['http://localhost:8080','http://localhost:8081']);
export const capacityBrowserIssuer='http://localhost:8081/realms/finops';
export const capacityBrowserImages=Object.freeze({
 keycloak:'quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244',
 browser:'mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27',
 node:'node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392',
 nginx:'nginxinc/nginx-unprivileged@sha256:782bb89768cc87b7f95c18b95baa1af250e5d451f26794f59363540161147c01',
});
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
export const capacityBrowserSHA=raw=>createHash('sha256').update(raw).digest('hex');
const keys=(o,names)=>{assert.ok(o&&typeof o==='object'&&!Array.isArray(o));assert.deepEqual(Object.keys(o).sort(),[...names].sort());};

// A browser exception may contain credentials, URLs or rendered HTML. Retain
// only a known structural error and its public field name; hash other details
// in memory rather than copying arbitrary page content into diagnostics.
export function capacityBrowserPageError(error){
 const raw=typeof error?.message==='string'?error.message:'',allowedNames=new Set(['TypeError','ReferenceError','SyntaxError','RangeError','URIError','EvalError','Error']);
 const error_class=allowedNames.has(error?.name)?error.name:'PageError';
 const fields=new Set(['length','map','binding','registration','maintenance','recurring_blackouts','blackouts','demand_events','scope','status','id','version','name','reason_codes','capacity_suitable']);
 const known=raw.length<=256?/^Cannot read properties of (null|undefined) \(reading '([A-Za-z_][A-Za-z0-9_]{0,63})'\)$/.exec(raw):null;
 const message=known&&fields.has(known[2])?raw:'Page execution failed; unrestricted details withheld.';
 return {error_class,message:message.slice(0,256),raw_message_sha256:capacityBrowserSHA(raw)};
}

export function validateCapacityBrowserReady(value,{runID}={}){
 keys(value,['schema_version','run_id','tenant_id','workload_id','operator_subject','username','old_proposal_id','candidate_proposal_id','safety_profile_version','first_batch_id','memory_instance_id','candidate_template_version','fixture','customer_execution_authorized']);
 assert.equal(value.schema_version,'1');assert.match(value.run_id,uuid);if(runID!==undefined)assert.equal(value.run_id,runID);
 assert.match(value.tenant_id,/^fixture-http-[a-f0-9-]{36}$/);assert.match(value.tenant_id.slice(13),uuid);
 assert.equal(value.workload_id,'fixture-workload');assert.equal(value.operator_subject,capacityBrowserSubject);assert.equal(value.username,capacityBrowserUsername);
 for(const k of ['old_proposal_id','candidate_proposal_id','first_batch_id'])assert.match(value[k],uuid);
 assert.notEqual(value.old_proposal_id,value.candidate_proposal_id);
 assert.ok(Number.isSafeInteger(value.safety_profile_version)&&value.safety_profile_version>0);
 assert.match(value.memory_instance_id,/^i-[a-f0-9]{17}$/);assert.match(value.candidate_template_version,/^[1-9][0-9]{0,19}$/);
 assert.equal(value.fixture,true);assert.equal(value.customer_execution_authorized,false);return value;
}

export function capacityBrowserRealm(ready,password){
 validateCapacityBrowserReady(ready);assert.match(password,/^[a-f0-9]{64}$/);
 return {realm:'finops',enabled:true,displayName:'Native capacity · isolated synthetic fixture',registrationAllowed:false,resetPasswordAllowed:false,sslRequired:'none',accessTokenLifespan:600,
  roles:{realm:[{name:'APPLICATION_OWNER'}]},
  // Keycloak's basic scope supplies access-token sub; the production API
  // requires that actual subject in addition to the separately pinned tenant.
  clients:[{clientId:'console',enabled:true,protocol:'openid-connect',publicClient:true,standardFlowEnabled:true,directAccessGrantsEnabled:false,serviceAccountsEnabled:false,defaultClientScopes:['basic','profile','email','roles','web-origins'],redirectUris:['http://localhost:8080/*'],webOrigins:['http://localhost:8080'],attributes:{'pkce.code.challenge.method':'S256','post.logout.redirect.uris':'http://localhost:8080/*'},protocolMappers:[
   {name:'isolated-fixture-tenant',protocol:'openid-connect',protocolMapper:'oidc-hardcoded-claim-mapper',consentRequired:false,config:{'claim.name':'tenant_id','claim.value':ready.tenant_id,'jsonType.label':'String','access.token.claim':'true','id.token.claim':'true'}},
   {name:'finops-audience',protocol:'openid-connect',protocolMapper:'oidc-audience-mapper',consentRequired:false,config:{'included.custom.audience':'finops','access.token.claim':'true','id.token.claim':'false'}}]}],
  users:[{id:capacityBrowserSubject,username:capacityBrowserUsername,firstName:'Capacity',lastName:'Fixture owner',email:'capacity-owner@fixture.invalid',emailVerified:true,enabled:true,requiredActions:[],credentials:[{type:'password',value:password,temporary:false}],realmRoles:['APPLICATION_OWNER']}]};
}

// Called in addition to the host's full image/mount/env/ownership validation.
// Sharing one exact owned edge's namespace makes localhost a secure browser
// origin without exposing a port or connecting to the retained main stack.
export function validateCapacityBrowserNamespace(object,{role,webRuntimeID,privateNetwork}){
 assert.ok(['web','keycloak','browser'].includes(role));assert.match(webRuntimeID,/^[a-f0-9]{64}$/);
 assert.equal(object.HostConfig?.NetworkMode,role==='web'?privateNetwork:'container:'+webRuntimeID);
 if(role==='web')assert.equal(object.Id,webRuntimeID);
 assert.equal(Object.keys(object.HostConfig?.PortBindings||{}).length,0);assert.equal(object.HostConfig?.PublishAllPorts,false);
 assert.equal(object.HostConfig?.Privileged,false);assert.equal(object.HostConfig?.PidMode||'','');assert.equal(object.HostConfig?.IpcMode==='host',false);
 assert.equal(object.HostConfig?.ReadonlyRootfs,true);assert.deepEqual(object.HostConfig?.CapDrop,['ALL']);assert.deepEqual(object.HostConfig?.CapAdd||[],[]);
 assert.ok(object.HostConfig?.SecurityOpt?.includes('no-new-privileges'));return object;
}

export function validateCapacityBrowserResult(value,{ready,readySHA256}){
 validateCapacityBrowserReady(ready);assert.match(readySHA256,sha);
 keys(value,['schema_version','status','run_id','ready_sha256','tenant_id','workload_id','request_id','member_id','member_sha256','scope_sha256','candidate_template_version','model_version','browser_version','oidc_pkce','oidc_authorization_code','ui_ids_only_request','actual_worker_result','memory95_rejected','lazy_member_detail','persisted_reload','fixture_labels_visible','fixture','customer_execution_authorized','verified_saving']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'PASS');assert.equal(value.run_id,ready.run_id);assert.equal(value.ready_sha256,readySHA256);
 assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.workload_id,ready.workload_id);assert.match(value.request_id,uuid);assert.notEqual(value.request_id,ready.first_batch_id);
 assert.match(value.member_id,/^fleet-capacity-member-[a-f0-9]{64}$/);assert.match(value.member_sha256,sha);assert.match(value.scope_sha256,sha);
 assert.equal(value.candidate_template_version,ready.candidate_template_version);assert.equal(value.model_version,'capacity-weekday-block-v2');assert.match(value.browser_version,/^[0-9]+(?:\.[0-9]+){1,3}$/);
 for(const key of ['oidc_pkce','oidc_authorization_code','ui_ids_only_request','actual_worker_result','memory95_rejected','lazy_member_detail','persisted_reload','fixture_labels_visible','fixture'])assert.equal(value[key],true);
 assert.equal(value.customer_execution_authorized,false);assert.equal(value.verified_saving,null);return value;
}
