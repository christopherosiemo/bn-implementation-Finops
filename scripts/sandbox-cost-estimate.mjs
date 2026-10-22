// Offline commissioning arithmetic only: no credentials, network or deployment.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export const snapshot=JSON.parse(readFileSync(new URL('../docs/sandbox-cost-estimate.json',import.meta.url),'utf8'));
const scale=10n**12n;
const gcd=(a,b)=>{while(b){[a,b]=[b,a%b];}return a;};
const rational=(n,d=1n)=>{assert.ok(d>0n);const g=gcd(n,d);return{n:n/g,d:d/g};};
function decimal(v){assert.ok(typeof v==='string'&&/^(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$/.test(v),'Exact nonnegative decimal string required');const [a,b='']=v.split('.');return rational(BigInt(a)*scale+BigInt(b.padEnd(12,'0')),scale);}
const mul=(a,b)=>rational(a.n*b.n,a.d*b.d);
const div=(a,b)=>{assert.ok(b.n>0n);return rational(a.n*b.d,a.d*b.n);};
const add=(a,b)=>rational(a.n*b.d+b.n*a.d,a.d*b.d);
const atMost=(a,b)=>a.n*b.d<=b.n*a.d;
function formatted(v,digits=6){const f=10n**BigInt(digits);const rounded=(v.n*f*2n+v.d)/(2n*v.d);const text=rounded.toString().padStart(digits+1,'0');return digits?text.slice(0,-digits)+'.'+text.slice(-digits):text;}
function exact(v){return{numerator:v.n.toString(),denominator:v.d.toString()};}
function overrides(base,input){assert.ok(input&&typeof input==='object'&&!Array.isArray(input));for(const k of Object.keys(input))assert.ok(Object.hasOwn(base,k),'Unknown quantity: '+k);return{...base,...input};}

export function estimate({quantities={},volumes={},supportTier='STANDARD',eksVersion=snapshot.eks_support.default_version,asOf=snapshot.checked_at}={}){
 assert.equal(snapshot.region,'eu-west-1');assert.equal(snapshot.currency,'USD');
 assert.equal(snapshot.price_basis,'PUBLIC_ON_DEMAND_PLANNING_SNAPSHOT');
 assert.ok(supportTier==='STANDARD'||supportTier==='EXTENDED');
 const ends=supportTier==='STANDARD'?snapshot.eks_support.standard_support_end_utc:snapshot.eks_support.extended_support_end_utc;
 const end=ends[eksVersion];
 assert.ok(end&&Number.isFinite(Date.parse(asOf)),'Known reviewed EKS version and instant required');
 const q=overrides(snapshot.default_quantities,quantities),v=overrides(snapshot.volume_quantities,volumes);
 for(const value of Object.values(q))decimal(value);
 for(const value of Object.values(v))if(value!==null)decimal(value);
 const start=rational(BigInt(Date.parse(asOf))),finish=add(start,mul(decimal(q.hours),decimal('3600000')));
 assert.ok(Date.parse(asOf)<Date.parse(end)&&atMost(finish,rational(BigInt(Date.parse(end)))),'EKS_SUPPORT_TIER_REVIEW_REQUIRED');
 const rate=id=>decimal(snapshot.rates[id].usd);
 const product=(...values)=>values.reduce(mul,decimal('1'));
 const monthFraction=div(decimal(q.hours),decimal('730'));
 const items=[];
 const item=(id,tariff,...factors)=>{const value=product(rate(tariff),...factors);items.push({id,rate_id:tariff,usd:formatted(value),exact_usd:exact(value)});return value;};
 const fixed=[
  item('eks',supportTier==='STANDARD'?'eks_standard':'eks_extended',decimal(q.hours),decimal(q.eks_clusters)),
  item('nodes','node',decimal(q.hours),decimal(q.nodes)),
  item('node_root_volumes','ebs_gp3',decimal(q.nodes),decimal(q.node_root_gb),monthFraction),
  item('clickhouse_volume','ebs_gp3',decimal(q.clickhouse_gb),monthFraction),
  item('rds_primary_and_standby','rds_instance',decimal(q.hours)),
  item('rds_storage_primary_and_standby','rds_gp3',decimal(q.database_gb),monthFraction),
  item('nat_gateway','nat_hour',decimal(q.hours),decimal(q.nat_gateways)),
  item('public_ipv4','ipv4',decimal(q.hours),decimal(q.public_ipv4)),
  item('kms_billable_key_units','kms_key',decimal(q.kms_billable_key_units),monthFraction),
  item('secrets','secret',decimal(q.secrets),monthFraction),
  item('optional_alb','alb_hour',decimal(q.hours),decimal(q.albs)),
  item('optional_alb_capacity','alb_lcu',decimal(q.hours),decimal(q.albs),decimal(q.average_lcus_per_alb))
 ];
 const subtotal=fixed.reduce(add,rational(0n));
 const meters={s3_stored_gb_months:'s3_standard',s3_put_list_requests:'s3_put_list',s3_get_requests:'s3_get',kms_billable_requests:'kms_request',secret_requests:'secret_request',nat_processed_gb:'nat_data',logs_ingested_gb:'logs_ingest',logs_stored_gb_months:'logs_store',rds_excess_backup_gb_months:'rds_excess_backup',rds_surplus_vcpu_hours:'rds_surplus_cpu'};
 const volumeItems=Object.entries(meters).map(([quantity,tariff])=>{
  if(v[quantity]===null)return{quantity,rate_id:tariff,usd:null};
  // The caller supplies only the GB-months apportioned to the first tier;
  // account-wide tier aggregation and other tiers require a separate review.
  if(quantity==='s3_stored_gb_months')assert.ok(atMost(decimal(v[quantity]),decimal(snapshot.rates[tariff].tier_limit_gb)),'S3_TIER_REVIEW_REQUIRED');
  const value=mul(rate(tariff),decimal(v[quantity]));return{quantity,rate_id:tariff,usd:formatted(value),exact_usd:exact(value)};
 });
 return{currency:'USD',region:'eu-west-1',hours:q.hours,support_tier:supportTier,eks_version:eksVersion,reference_subtotal_usd:formatted(subtotal),reference_subtotal_exact_usd:exact(subtotal),reference_subtotal_display_usd:formatted(subtotal,2),items,volume_items:volumeItems,full_estimate_usd:null,unpriced_or_external:snapshot.unpriced_or_external,deployment_authorized:false,budget_approved:false,contracted_cost:null};
}

// Uniform continuous uploads during a bounded pilot, then deletion exactly at
// each version's minimum retention date. This is a lower-bound storage scenario;
// the actual Terraform has NO automatic expiration and may retain indefinitely.
export function retentionExample({days='30',rawGBPerDay='1',auditGBPerDay='0.1'}={}){
 const d=decimal(days),raw=decimal(rawGBPerDay),audit=decimal(auditGBPerDay);
 assert.ok(d.n>0n);
 assert.ok(atMost(d,decimal(snapshot.retention.raw_minimum_days)),'PILOT_RETENTION_REVIEW_REQUIRED');
 const daysPerMonth=div(decimal('730'),decimal('24'));
 const bytesAtEnd=mul(add(raw,audit),d);
 assert.ok(atMost(bytesAtEnd,decimal(snapshot.rates.s3_standard.tier_limit_gb)),'S3_TIER_REVIEW_REQUIRED');
 const firstPeriodGBMonths=div(div(mul(add(raw,audit),mul(d,d)),decimal('2')),daysPerMonth);
 const minimumGBDays=mul(d,add(mul(raw,decimal(snapshot.retention.raw_minimum_days)),mul(audit,decimal(snapshot.retention.audit_minimum_days))));
 const minimumGBMonths=div(minimumGBDays,daysPerMonth);
 const price=decimal(snapshot.rates.s3_standard.usd);
 return{scenario_only:true,days,raw_gb_per_day:rawGBPerDay,audit_gb_per_day:auditGBPerDay,gb_at_pilot_end:formatted(bytesAtEnd),first_period_storage_usd:formatted(mul(firstPeriodGBMonths,price)),subsequent_730h_storage_usd_without_deletion:formatted(mul(bytesAtEnd,price)),minimum_lifetime_storage_usd_with_exact_expiry_deletion:formatted(mul(minimumGBMonths,price)),minimum_lifetime_storage_exact_usd:exact(mul(minimumGBMonths,price)),automatic_expiration_configured:false,kms_requests_and_keys_included:false,full_cost_usd:null};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){assert.equal(process.argv.length,2,'This offline reference has no deployment or credential arguments');console.log(JSON.stringify({estimate:estimate(),retention_example:retentionExample()},null,2));}
