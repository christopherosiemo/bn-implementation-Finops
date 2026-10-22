import test from 'node:test';
import assert from 'node:assert/strict';
import {estimate,retentionExample,snapshot} from '../sandbox-cost-estimate.mjs';

test('Ireland reference includes both RDS copies once, six keys, node roots, CH and NAT IPv4',()=>{
 const result=estimate();assert.equal(result.reference_subtotal_display_usd,'394.11');
 const line=id=>result.items.find(x=>x.id===id).usd;
 assert.equal(line('rds_primary_and_standby'),'100.740000');assert.equal(line('rds_storage_primary_and_standby'),'7.620000');
 assert.equal(line('nodes'),'156.220000');assert.equal(line('node_root_volumes'),'8.800000');assert.equal(line('clickhouse_volume'),'2.640000');assert.equal(line('public_ipv4'),'3.650000');
 assert.equal(result.full_estimate_usd,null);assert.equal(result.budget_approved,false);assert.equal(result.contracted_cost,null);
 assert.ok(result.volume_items.every(x=>x.usd===null));
});
test('Quantity and optional private ALB sensitivities preserve exact native USD math',()=>{
 assert.equal(estimate({quantities:{nodes:'4'}}).reference_subtotal_display_usd,'559.13');
 assert.equal(estimate({quantities:{albs:'1',average_lcus_per_alb:'1'}}).reference_subtotal_usd,'418.346000');
 assert.equal(estimate({quantities:{database_gb:'100'}}).reference_subtotal_display_usd,'411.89');
 assert.equal(estimate({quantities:{hours:'365'}}).reference_subtotal_usd,'197.055000');
});
test('Expired standard-support assumption is refused rather than hiding EKS extended charges',()=>{
 assert.throws(()=>estimate({asOf:'2027-03-27T00:00:00Z'}),/EKS_SUPPORT_TIER_REVIEW_REQUIRED/);
 assert.throws(()=>estimate({eksVersion:'1.34',asOf:'2026-12-02T00:00:00Z'}),/EKS_SUPPORT_TIER_REVIEW_REQUIRED/);
 assert.throws(()=>estimate({asOf:'2027-03-26T00:00:00Z'}),/EKS_SUPPORT_TIER_REVIEW_REQUIRED/);
 assert.doesNotThrow(()=>estimate({asOf:'2027-03-26T00:00:00Z',quantities:{hours:'24'}}));
 assert.throws(()=>estimate({asOf:'2027-03-26T00:00:00Z',quantities:{hours:'24.000000001'}}),/EKS_SUPPORT_TIER_REVIEW_REQUIRED/);
 assert.equal(estimate({supportTier:'EXTENDED',asOf:'2027-03-27T00:00:00Z'}).reference_subtotal_display_usd,'759.11');
 assert.throws(()=>estimate({supportTier:'EXTENDED',asOf:'2029-01-01T00:00:00Z'}),/EKS_SUPPORT_TIER_REVIEW_REQUIRED/);
 assert.throws(()=>estimate({supportTier:'EXTENDED',asOf:'2028-03-26T00:00:00Z'}),/EKS_SUPPORT_TIER_REVIEW_REQUIRED/);
});
test('Unknown volume differs from observed zero; surplus CPU and requests use explicit meters',()=>{
 const result=estimate({volumes:{rds_surplus_vcpu_hours:'10',nat_processed_gb:'0',s3_put_list_requests:'1000',s3_get_requests:'10000'}});
 const line=id=>result.volume_items.find(x=>x.quantity===id).usd;
 assert.equal(line('rds_surplus_vcpu_hours'),'0.750000');assert.equal(line('nat_processed_gb'),'0.000000');assert.equal(line('logs_ingested_gb'),null);
 assert.equal(line('s3_put_list_requests'),'0.005000');assert.equal(line('s3_get_requests'),'0.004000');assert.equal(result.full_estimate_usd,null);
 assert.equal(estimate({quantities:{kms_billable_key_units:'18'}}).reference_subtotal_display_usd,'406.11');
 for(const value of [1,-1,'-1','NaN','1e3','0.0000000000001'])assert.throws(()=>estimate({volumes:{logs_ingested_gb:value}}));
 assert.throws(()=>estimate({volumes:{s3_stored_gb_months:'51201'}}),/S3_TIER_REVIEW_REQUIRED/);
});
test('Compliance-retention example includes all new versions beyond the pilot and never assumes expiry cleanup',()=>{
 const r=retentionExample();assert.equal(r.gb_at_pilot_end,'33.000000');assert.equal(r.first_period_storage_usd,'0.374301');
 assert.equal(r.subsequent_730h_storage_usd_without_deletion,'0.759000');assert.equal(r.minimum_lifetime_storage_usd_with_exact_expiry_deletion,'2.869644');
 assert.equal(r.automatic_expiration_configured,false);assert.equal(r.kms_requests_and_keys_included,false);assert.equal(r.full_cost_usd,null);
 assert.ok(Number(retentionExample({rawGBPerDay:'2'}).minimum_lifetime_storage_usd_with_exact_expiry_deletion)>Number(r.minimum_lifetime_storage_usd_with_exact_expiry_deletion));
 assert.throws(()=>retentionExample({days:'91'}),/PILOT_RETENTION_REVIEW_REQUIRED/);
 assert.throws(()=>retentionExample({rawGBPerDay:'2000'}),/S3_TIER_REVIEW_REQUIRED/);
});
test('Every rate has an official source and immutable regional snapshots remain Ireland/USD only',()=>{
 for(const rate of Object.values(snapshot.rates)){const source=snapshot.sources[rate.source];assert.match(source.url,/^https:\/\/(pricing\.us-east-1\.amazonaws\.com|aws\.amazon\.com)\//);}
 for(const source of Object.values(snapshot.sources))if(source.version){assert.ok(source.url.includes('/'+source.version+'/eu-west-1/'));assert.ok(source.published_at);}
 assert.equal(snapshot.region,'eu-west-1');assert.equal(snapshot.currency,'USD');assert.equal(snapshot.retention.automatic_expiration_configured,false);
});
