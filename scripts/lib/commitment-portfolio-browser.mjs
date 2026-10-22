// Public metadata for an isolated provider-shaped fixture, never authority input.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {jointFinanceSubject,jointFinanceUsername,jointBodySHA} from './fleet-joint-browser.mjs';
export {jointFinanceSubject,jointFinanceUsername};
export const portfolioBrowserSHA=bytes=>createHash('sha256').update(bytes).digest('hex');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const keys=(o,n)=>{assert.ok(o&&typeof o==='object'&&!Array.isArray(o));assert.deepEqual(Object.keys(o).sort(),[...n].sort());};
const id=value=>assert.ok(typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(value));
export function validatePortfolioBrowserReady(value,runID){
 keys(value,['schema_version','run_id','tenant_id','selection','fixture','customer_execution_authorized']);assert.equal(value.schema_version,'1');assert.match(value.run_id,uuid);if(runID!==undefined)assert.equal(value.run_id,runID);
 assert.match(value.tenant_id,/^fixture-http-[a-f0-9-]{36}$/);assert.match(value.tenant_id.slice(13),uuid);assert.equal(value.fixture,true);assert.equal(value.customer_execution_authorized,false);
 const s=value.selection;keys(s,['source_id','commitment_receipt_id','billing_receipt_ids','period']);id(s.source_id);id(s.commitment_receipt_id);assert.ok(Array.isArray(s.billing_receipt_ids)&&s.billing_receipt_ids.length>=1&&s.billing_receipt_ids.length<=24);s.billing_receipt_ids.forEach(id);assert.equal(new Set(s.billing_receipt_ids).size,s.billing_receipt_ids.length);
 keys(s.period,['start','end']);for(const t of Object.values(s.period))assert.match(t,/^\d{4}-\d{2}-\d{2}T00:00:00Z$/);const start=Date.parse(s.period.start),end=Date.parse(s.period.end);assert.ok(Number.isFinite(start)&&end>start&&end-start<=31*86400000);return value;
}
export function portfolioBrowserRealm(ready,password){
 validatePortfolioBrowserReady(ready);assert.match(password,/^[a-f0-9]{64}$/);
 return {realm:'finops',enabled:true,displayName:'Commitment portfolio · isolated synthetic fixture',registrationAllowed:false,resetPasswordAllowed:false,sslRequired:'none',accessTokenLifespan:600,
  roles:{realm:[{name:'FINANCE'}]},clients:[{clientId:'console',enabled:true,protocol:'openid-connect',publicClient:true,standardFlowEnabled:true,directAccessGrantsEnabled:false,serviceAccountsEnabled:false,defaultClientScopes:['basic','profile','email','roles','web-origins'],redirectUris:['http://localhost:8080/*'],webOrigins:['http://localhost:8080'],attributes:{'pkce.code.challenge.method':'S256','post.logout.redirect.uris':'http://localhost:8080/*'},protocolMappers:[
   {name:'isolated-fixture-tenant',protocol:'openid-connect',protocolMapper:'oidc-hardcoded-claim-mapper',consentRequired:false,config:{'claim.name':'tenant_id','claim.value':ready.tenant_id,'jsonType.label':'String','access.token.claim':'true','id.token.claim':'true'}},
   {name:'finops-audience',protocol:'openid-connect',protocolMapper:'oidc-audience-mapper',consentRequired:false,config:{'included.custom.audience':'finops','access.token.claim':'true','id.token.claim':'false'}}]}],
  users:[{id:jointFinanceSubject,username:jointFinanceUsername,firstName:'Portfolio',lastName:'Fixture finance',email:'portfolio-finance@fixture.invalid',emailVerified:true,enabled:true,requiredActions:[],credentials:[{type:'password',value:password,temporary:false}],realmRoles:['FINANCE']}]};
}
export function portfolioWorkerEnvironment(tenant){
 assert.match(tenant,/^fixture-http-[a-f0-9-]{36}$/);
 return {COMMITMENT_PORTFOLIO_ENABLED:'true',COMMITMENT_PORTFOLIO_TENANT_ID:tenant,COMMITMENT_PORTFOLIO_DATABASE_FILE:'/run/secrets/commitment-portfolio-database',COMMITMENT_PORTFOLIO_DATABASE_MODE:'LOCAL_PRIVATE',COMMITMENT_PORTFOLIO_MODEL_URL:'http://commitment-portfolio-model:8000',COMMITMENT_PORTFOLIO_MODEL_TOKEN_FILE:'/run/secrets/commitment-portfolio-model-token'};
}
export function validatePortfolioWorkerReady(value,ready){
 validatePortfolioBrowserReady(ready);keys(value,['schema_version','run_id','tenant_id','purpose','configuration_sha256','files']);assert.equal(value.schema_version,'1');assert.equal(value.run_id,ready.run_id);assert.equal(value.tenant_id,ready.tenant_id);assert.equal(value.purpose,'commitment-portfolio-reader');assert.equal(value.configuration_sha256,jointBodySHA(portfolioWorkerEnvironment(ready.tenant_id)));
 keys(value.files,['database','model_token']);for(const [kind,max]of [['database',8192],['model_token',4097]]){const f=value.files[kind];keys(f,['sha256','size']);assert.match(f.sha256,sha);assert.ok(Number.isSafeInteger(f.size)&&f.size>=2&&f.size<=max);}assert.notEqual(value.files.database.sha256,value.files.model_token.sha256);return value;
}
export function validatePortfolioWorkerFiles(value,ready){
 keys(value,['directory_mode','files','binary_sha256']);assert.equal(value.directory_mode,448);assert.match(value.binary_sha256,sha);keys(value.files,['commitment-portfolio-database','commitment-portfolio-model-token']);
 for(const[name,key]of [['commitment-portfolio-database','database'],['commitment-portfolio-model-token','model_token']]){const f=value.files[name];keys(f,['sha256','size','mode','nlink','is_file','is_symbolic_link']);assert.equal(f.sha256,ready.files[key].sha256);assert.equal(f.size,ready.files[key].size);assert.equal(f.mode,384);assert.equal(f.nlink,1);assert.equal(f.is_file,true);assert.equal(f.is_symbolic_link,false);}return value;
}
export function validatePortfolioBrowserResult(value,{ready}){
 validatePortfolioBrowserReady(ready);keys(value,['schema_version','status','run_id','tenant_id','request_id','analysis_id','analysis_sha256','selection_sha256','creator_id','position_count','unmatched_billing_count','oidc_pkce','oidc_authorization_code','ui_ids_only_request','actual_portfolio_worker','observed_utilization','observed_unused_commitment','sparse_ri_unknown','native_concentration','persisted_reload','fixture','recommendation_authorized','purchase_authorized','customer_execution_authorized','expected_savings','estimated_saving','verified_saving']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'PASS');assert.equal(value.run_id,ready.run_id);assert.equal(value.tenant_id,ready.tenant_id);assert.match(value.request_id,uuid);assert.match(value.analysis_id,sha);assert.match(value.analysis_sha256,sha);assert.equal(value.selection_sha256,jointBodySHA(ready.selection));assert.equal(value.creator_id,jointFinanceSubject);assert.ok(Number.isSafeInteger(value.position_count)&&value.position_count>=1&&value.position_count<=2000);assert.ok(Number.isSafeInteger(value.unmatched_billing_count)&&value.unmatched_billing_count>=1&&value.unmatched_billing_count<=100000);
 for(const k of ['oidc_pkce','oidc_authorization_code','ui_ids_only_request','actual_portfolio_worker','observed_utilization','observed_unused_commitment','sparse_ri_unknown','native_concentration','persisted_reload','fixture'])assert.equal(value[k],true);for(const k of ['recommendation_authorized','purchase_authorized','customer_execution_authorized'])assert.equal(value[k],false);for(const k of ['expected_savings','estimated_saving','verified_saving'])assert.equal(value[k],null);return value;
}
export function validatePortfolioDist(files){
 assert.ok(Array.isArray(files)&&files.length>=2&&files.length<=512);let total=0;const names=[];for(const f of files){keys(f,['path','size','sha256']);assert.match(f.path,/^(?:[A-Za-z0-9_-]+\.[A-Za-z0-9]+|assets\/[A-Za-z0-9_.-]+)$/);assert.ok(Number.isSafeInteger(f.size)&&f.size>0&&f.size<=16*1024*1024);assert.match(f.sha256,sha);total+=f.size;names.push(f.path);}assert.ok(total<=64*1024*1024);assert.equal(new Set(names).size,names.length);assert.ok(names.includes('index.html'));return files;
}
