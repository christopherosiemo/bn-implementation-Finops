// Opt-in live acceptance. Default is inspection only; never prints a bearer token.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const names=['FINOPS_API_URL','FINOPS_API_TOKEN','FINOPS_SANDBOX_TENANT_ID','FINOPS_SANDBOX_ACCOUNT_ID','FINOPS_SANDBOX_INSTANCE_ID'];
for(const name of names)assert.ok(process.env[name],`${name} is required`);
const base=new URL(process.env.FINOPS_API_URL);
assert.ok(base.protocol==='https:'||['localhost','127.0.0.1'].includes(base.hostname),'Use HTTPS or a local authenticated port-forward');
const token=process.env.FINOPS_API_TOKEN;
async function call(path,body,version){
 const headers={Authorization:`Bearer ${token}`};
 if(body){headers['Content-Type']='application/json';headers['Idempotency-Key']=createHash('sha256').update(path+JSON.stringify(body)).digest('hex');}
 if(version!==undefined)headers['If-Match']=`"${version}"`;
 const response=await fetch(new URL(path,base),{method:body?'POST':'GET',headers,body:body?JSON.stringify(body):undefined});
 const result=await response.json();assert.ok(response.ok,`${path}: ${response.status} ${result.error||''}`);return result;
}
const dashboard=await call('/v1/dashboard');
assert.equal(dashboard.fixture,false,'This gate is only for a deliberately configured live sandbox');
assert.equal(dashboard.org.id,process.env.FINOPS_SANDBOX_TENANT_ID,'Unexpected tenant');
const resource=dashboard.resources.find(r=>r.provider_resource_id===process.env.FINOPS_SANDBOX_INSTANCE_ID&&r.account_id===process.env.FINOPS_SANDBOX_ACCOUNT_ID);
assert.ok(resource,'Explicit allowlisted sandbox resource was not discovered');
const workload=dashboard.workloads.find(w=>w.id===resource.workload_id);
assert.equal(resource.environment,'NON_PRODUCTION');assert.equal(workload?.environment,'NON_PRODUCTION');
assert.equal(resource.runtime_stop_start_delegated,true);assert.equal(resource.commitment_known,true);assert.equal(resource.uncovered_on_demand,true);
console.log('Live sandbox identity and non-production target inspected. No mutation has occurred.');
if(!process.argv.includes('--execute'))process.exit(0);
assert.equal(process.env.FINOPS_LIVE_ACK,'STOP_AND_RESTORE_THIS_SANDBOX_INSTANCE','Explicit FINOPS_LIVE_ACK is required');
assert.ok(process.env.FINOPS_APPROVED_PLAN_ID,'Review and approve a concrete ChangePlan in the console first');
const plan=await call('/v1/change-plans/'+encodeURIComponent(process.env.FINOPS_APPROVED_PLAN_ID));
assert.equal(plan.status,'APPROVED');assert.equal(plan.resource_id,resource.id);assert.equal(plan.fixture,false);
for(const op of plan.payload.operations){assert.equal(op.provider_resource_id,resource.provider_resource_id);assert.equal(op.account_id,resource.account_id);assert.equal(op.region,resource.region);}
const stopAt=Date.parse(plan.payload.stop_at||plan.stop_at);
assert.ok(Number.isFinite(stopAt)&&Math.abs(stopAt-Date.now())<15*60*1000,'The approved stop window must be within 15 minutes');
const execution=await call('/v1/executions',{change_plan_id:plan.id},plan.version);
console.log(`Created approved sandbox execution ${execution.id}. Waiting for stop ownership before immediate restoration.`);
const deadline=Date.now()+30*60*1000;let restored=false,requested=false;
while(Date.now()<deadline){
 const current=await call('/v1/executions/'+execution.id);
 if(current.status==='FAILED'||current.status==='SKIPPED')throw new Error(`Execution did not stop: ${current.error||current.status}`);
 if(!requested&&(current.stage==='STOPPED'||current.restoration_owned)){
  await call('/v1/executions/'+execution.id+'/start-now',{},current.version);requested=true;
 }
 if(current.status==='COMPLETED'){restored=true;break;}
 await new Promise(resolve=>setTimeout(resolve,5000));
}
assert.ok(restored,'Acceptance timeout: use the restoration runbook; the durable executor retains its recovery obligation');
console.log('Live stop/restoration and mandatory health checks completed. Savings remain provisional until real observation windows and invoice finality.');
