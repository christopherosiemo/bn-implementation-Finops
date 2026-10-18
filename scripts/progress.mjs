import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ledger = JSON.parse(readFileSync(path.join(root, 'docs/progress-ledger.json'), 'utf8'));
const weights = { billing_inventory_telemetry: 18, workload_graph_demand_slo: 12, optimisation_forecast_commitments: 18, execution_iac_gitops: 18, reconciliation_verified_savings: 10, identity_tenancy_policy_audit: 10, console_api_enterprise: 6, production_operations: 8 };
const stages = new Set([0, 20, 40, 70, 90, 100]);
assert.equal(ledger.schema_version, '1');
assert.deepEqual(new Set(ledger.domains.map(domain => domain.id)), new Set(Object.keys(weights)));
let total = 0;
for (const domain of ledger.domains) {
  assert.equal(domain.weight_percent, weights[domain.id], `Fixed scope weight changed for ${domain.id}`);
  let scope = 0, credit = 0;
  for (const capability of domain.packages) {
    assert.ok(stages.has(capability.accepted_maturity), `Unsupported acceptance stage ${capability.id}`);
    assert.ok(capability.scope_weight_percent > 0 && capability.evidence.length && capability.remaining);
    scope += capability.scope_weight_percent;
    credit += capability.scope_weight_percent * capability.accepted_maturity / 100;
  }
  assert.ok(Math.abs(scope - domain.weight_percent) < 1e-9, `Package scope does not sum for ${domain.id}`);
  assert.ok(Math.abs(credit - domain.contribution_points) < 1e-9, `Package credit does not sum for ${domain.id}`);
  total += credit;
}
assert.ok(Math.abs(total - ledger.current_weighted_percent) < 1e-9, 'Current progress disagrees with accepted capability credit');
if (total >= 100) assert.ok(ledger.live_aws_validated && ledger.customer_verified_savings && ledger.commercial_ga_accepted, 'Incomplete delivery cannot be called 100%');
const displayed = total < 100 ? Math.min(99, Math.round(total)) : 100;
console.log(`Fixed scope weights and capability credit reconcile: approximately ${displayed}% of the complete product.`);
