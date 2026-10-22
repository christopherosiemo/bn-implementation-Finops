import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const env = Object.fromEntries(readFileSync(path.join(root,'.env'),'utf8').split(/\r?\n/).filter(s=>s && !s.startsWith('#')).map(s=>{const i=s.indexOf('=');return [s.slice(0,i),s.slice(i+1)];}));
const api = process.env.API_URL || `http://localhost:${env.API_PORT || 8080}`;
const issuer = process.env.OIDC_ISSUER || `http://localhost:${env.KEYCLOAK_PORT || 8081}/realms/finops`;
const delay = ms => new Promise(resolve => setTimeout(resolve,ms));
async function waitFor(fn, label, timeout=180000) {
  const deadline=Date.now()+timeout; let last;
  while(Date.now()<deadline){try{const result=await fn();if(result)return result;}catch(e){last=e;}await delay(1000);}
  throw new Error(`${label} timed out${last ? ': '+last.message : ''}`);
}
async function login(username) {
  const response=await fetch(`${issuer}/protocol/openid-connect/token`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'password',client_id:'console',username,password:env.DEMO_PASSWORD})});
  assert.equal(response.status,200,`fixture OIDC login ${username}`);
  const {access_token}=await response.json(); assert.ok(access_token); return access_token;
}
async function request(token,method,url,body,options={}) {
  const headers={ ...(token ? {Authorization:`Bearer ${token}`} : {}) };
  if(method==='POST'){headers['Content-Type']='application/json';headers['Idempotency-Key']=options.key || randomUUID();}
  if(options.version!==undefined)headers['If-Match']=`"${options.version}"`;
  const response=await fetch(api+url,{method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
  const text=await response.text();let data;try{data=JSON.parse(text);}catch{data={message:text.slice(0,200)};}
  if(options.status!==undefined)assert.equal(response.status,options.status,`${method} ${url}: ${JSON.stringify(data)}`);
  else assert.ok(response.ok,`${method} ${url}: ${response.status} ${JSON.stringify(data)}`);
  return {data,status:response.status};
}
const checks=[];
function passed(name){checks.push(name);console.log(`PASS ${name}`);}

await waitFor(async()=> (await fetch(api+'/healthz')).ok,'API readiness');
await waitFor(async()=> (await fetch(issuer+'/.well-known/openid-configuration')).ok,'OIDC readiness');
const token=await login(env.DEMO_USERNAME || 'owner');
const other=await login('other');const viewer=await login('viewer');
await request(null,'GET','/v1/dashboard',undefined,{status:401});passed('OIDC required');
await request(viewer,'POST','/v1/recommendations',{}, {status:403});passed('viewer cannot mutate');

let dashboard=(await request(token,'GET','/v1/dashboard')).data;
assert.equal(dashboard.fixture,true,'smoke never runs mutations in live AWS mode');
assert.equal(dashboard.org.residency,'EU');
for(const key of ['cloud_accounts','resources','workloads','recommendations','schedules','executions','savings','audit'])assert.ok(Array.isArray(dashboard[key]),key);
passed('tenant-scoped fixture discovery and evidence views');

assert.ok(!dashboard.executions.some(x=>x.restoration_owned),'finish owned fixture restoration before resetting');
await request(token,'POST','/v1/demo/reset',{});
await request(token,'POST','/v1/demo/scenario',{scenario:'healthy'});
dashboard=(await request(token,'GET','/v1/dashboard')).data;
const workload=dashboard.workloads.find(x=>x.id==='workload-dev');assert.ok(workload);
const signals=await request(token,'POST',`/v1/workloads/${workload.id}/signals`,{incident:'CLEAR',deployment:'CLEAR',job:'CLEAR'},{version:workload.version});
assert.equal(signals.data.job,'CLEAR');

const connected=await request(token,'POST','/v1/cloud-accounts',{provider:'AWS',name:'Smoke read-only AWS fixture',account_id:'111122223333',region:'eu-west-1'});
assert.equal(connected.data.provider,'AWS');passed('read-only account onboarding');

const generated=await waitFor(async()=>{
  const value=(await request(token,'POST','/v1/recommendations',{workload_id:'workload-dev'})).data;
  return value.recommendations.some(x=>x.pre_execution_ready===true)?value:false;
},'persisted source-backed execution readiness');
assert.ok(generated.recommendations.some(x=>x.status==='VALIDATED'&&x.pre_execution_ready===true));
assert.ok(generated.recommendations.some(x=>x.status==='BLOCKED'));passed('eligibility separates actionable and protected resources');
const rec=generated.recommendations.find(x=>x.status==='VALIDATED'&&x.pre_execution_ready===true);
const readiness=(await request(token,'GET',`/v1/resources/${rec.resource_id}/readiness`)).data;
assert.equal(readiness.pre_execution_ready,true);
assert.equal(readiness.verification_status,'MEASURING');
assert.ok(readiness.baseline_id&&readiness.measurement_id);
passed('baseline readiness permits execution before financial verification');
const ack={recommendation_id:rec.id,schedule_id:'schedule-dev',memory_state_acknowledged:true,public_ip_change_acknowledged:true};
const key=randomUUID();const plan=(await request(token,'POST','/v1/change-plans',ack,{key})).data;
assert.equal(plan.payload.schema_version,'2');
assert.equal(plan.payload.baseline_id,readiness.baseline_id);
assert.equal(plan.payload.measurement_id,readiness.measurement_id);
const replay=(await request(token,'POST','/v1/change-plans',ack,{key})).data;
assert.equal(plan.id,replay.id);passed('idempotent immutable plan creation');
await request(token,'POST','/v1/change-plans',{...ack,public_ip_change_acknowledged:false},{key,status:409});
await request(other,'GET',`/v1/change-plans/${plan.id}`,undefined,{status:404});passed('cross-tenant plan access denied');
await request(token,'POST','/v1/approvals',{change_plan_id:plan.id},{version:plan.version+1,status:409});passed('stale ETag rejected');
const approved=(await request(token,'POST','/v1/approvals',{change_plan_id:plan.id},{version:plan.version})).data;
const executionKey=randomUUID();
const execution=(await request(token,'POST','/v1/executions',{change_plan_id:plan.id},{key:executionKey,version:approved.change_plan.version})).data;
const repeated=(await request(token,'POST','/v1/executions',{change_plan_id:plan.id},{key:executionKey,version:approved.change_plan.version})).data;
assert.equal(execution.id,repeated.id);passed('duplicate execution submission creates one occurrence');

await waitFor(async()=>{
  const x=(await request(token,'GET',`/v1/executions/${execution.id}`)).data;
  if(x.status==='FAILED'||x.status==='SKIPPED')throw new Error(`execution ${x.status}: ${x.error||x.reason_code||''}`);
  return x.restoration_owned||x.stage==='STOPPED'||x.status==='RESTORING' ? x : false;
},'schedule owns stop',90000);
dashboard=(await request(token,'GET','/v1/dashboard')).data;
await request(token,'POST','/v1/control/pause',{paused:true},{version:dashboard.org.version});
passed('emergency pause during an owned occurrence');
const completed=await waitFor(async()=>{
  const x=(await request(token,'GET',`/v1/executions/${execution.id}`)).data;
  return x.status==='COMPLETED'?x:false;
},'restoration continues through pause',90000);
assert.equal(completed.restoration_owned,false);passed('durable stop/start, application health and restoration under pause');

const verified=await waitFor(async()=>{
  const value=(await request(token,'POST','/v1/savings/verify',{execution_id:execution.id})).data;
  return value.savings?.some(x=>x.status==='VERIFIED')?value:false;
},'complete persisted fixture measurement and owned-interval verification');
assert.ok(verified.savings.length>=1);
assert.equal(verified.savings[0].status,'VERIFIED');
assert.equal(typeof verified.savings[0].verified_saving,'string');
assert.equal(verified.savings[0].verified_saving,'5.160000000000');
assert.ok(verified.savings[0].claim_key);passed('invoice-backed exact savings claim');
const before=(await request(token,'GET','/v1/dashboard')).data;
await request(token,'POST','/v1/savings/verify',{execution_id:execution.id});
const after=(await request(token,'GET','/v1/dashboard')).data;
assert.equal(before.savings.length,after.savings.length);passed('repeat verification does not duplicate ledger claim');
assert.equal(after.savings.filter(x=>x.status==='VERIFIED'&&x.is_current===true&&x.claim_key===verified.savings[0].claim_key).length,1);
passed('preserved financial history has one current verified claim per period');
assert.ok(after.audit.some(x=>x.action==='provider.stop'));
assert.ok(after.audit.some(x=>x.action==='provider.start'));passed('immutable execution audit trail');
await request(token,'POST','/v1/control/pause',{paused:false},{version:after.org.version});
await request(token,'POST','/v1/demo/scenario',{scenario:'incident'});
await request(token,'POST','/v1/change-plans',ack,{status:422});passed('active incident blocks new stop');
await request(token,'POST','/v1/demo/scenario',{scenario:'healthy'});

console.log(`\n${checks.length} operating-loop checks passed. Fixture only; no live AWS action was performed.`);
