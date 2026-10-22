import test from 'node:test';
import assert from 'node:assert/strict';
import { checkRolloutPlan, parsePlanArguments } from '../check-rollout-plan.mjs';
const options = { expectedAccount: '111122223333', region: 'eu-west-1', stack: 'customer', mode: 'read-only' };
function fixture() {
  return { format_version: '1.2', variables: { expected_account_id: { value: options.expectedAccount }, region: { value: options.region }, enable_execution: { value: false } },
    configuration: { provider_config: { aws: { name: 'aws', expressions: { region: { references: ['var.region'] }, allowed_account_ids: { references: ['var.expected_account_id'] } } } } },
    planned_values: { root_module: { resources: [{ type: 'aws_caller_identity', mode: 'data', values: { account_id: options.expectedAccount } }, { address: 'aws_iam_role.customer["read"]', type: 'aws_iam_role', mode: 'managed', values: {} }] } },
    resource_changes: [{ address: 'aws_iam_role.customer["read"]', change: { actions: ['create'] } }] };
}
test('accepts guarded fresh read-only creation without executing anything', () => assert.equal(checkRolloutPlan(fixture(), options).changes, 1));
for (const actions of [['delete'], ['delete', 'create'], ['create', 'delete'], ['forget']]) {
  test(`rejects destructive or unknown actions ${actions}`, () => { const p = fixture(); p.resource_changes[0].change.actions = actions; assert.throws(() => checkRolloutPlan(p, options), /Deletion or replacement/); });
}
for (const [name, mutate] of [
  ['wrong account', p => { p.variables.expected_account_id.value = '999988887777'; }],
  ['wrong caller', p => { p.planned_values.root_module.resources[0].values.account_id = '999988887777'; }],
  ['missing caller evidence', p => { p.planned_values.root_module.resources.shift(); }],
  ['wrong region', p => { p.variables.region.value = 'us-east-1'; }],
  ['unguarded provider', p => { delete p.configuration.provider_config.aws.expressions.allowed_account_ids; }],
  ['unguarded alias', p => { p.configuration.provider_config['aws.other'] = { name: 'aws', expressions: {} }; }],
  ['incomplete plan', p => { p.complete = false; }],
  ['deferred changes', p => { p.deferred_changes = [{}]; }],
  ['unreviewed drift', p => { p.resource_drift = [{ address: 'drift', change: { actions: ['update'] } }]; }],
  ['execution enabled', p => { p.variables.enable_execution.value = true; }],
  ['execution trust', p => { p.variables.customer_execution_role_arns = { value: ['arn:aws:iam::111122223333:role/executor'] }; }],
  ['execution role', p => { p.planned_values.root_module.resources.push({ type: 'aws_iam_role', address: 'aws_iam_role.customer["execution"]' }); }],
  ['nested execution role', p => { p.planned_values.root_module.child_modules = [{ resources: [{ type: 'aws_iam_role', address: 'module.customer.aws_iam_role.customer["execution"]' }] }]; }],
  ['wrong resource account', p => { p.planned_values.root_module.resources[1].values.arn = 'arn:aws:iam::999988887777:role/read'; }]
]) test(`rejects ${name}`, () => { const p = fixture(); mutate(p); assert.throws(() => checkRolloutPlan(p, options)); });
for (const action of ['ec2:StopInstances', 'ec2:Start*', 'ec2:*', '*']) test(`rejects hidden mutation permission ${action}`, () => {
  const p = fixture(); p.planned_values.root_module.resources.push({ type: 'aws_iam_role_policy', address: 'hidden', values: { policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Action: action }] }) } });
  assert.throws(() => checkRolloutPlan(p, options), /permits EC2/);
});
test('execution requires explicit allowlist and principal', () => {
  const p = fixture(); p.variables.enable_execution.value = true;
  assert.throws(() => checkRolloutPlan(p, { ...options, mode: 'execution' }), /allowlist/);
  p.variables.instance_ids = { value: ['i-0123456789abcdef0'] }; p.variables.execution_principal_arn = { value: 'arn:aws:iam::111122223333:role/executor' };
  assert.equal(checkRolloutPlan(p, { ...options, mode: 'execution' }).mode, 'execution');
});
test('read-only rejects broad Allow NotAction policy', () => {
  const p = fixture(); p.planned_values.root_module.resources.push({ type: 'aws_iam_policy', address: 'hidden', values: { policy: JSON.stringify({ Statement: [{ Effect: 'Allow', NotAction: 'ec2:TerminateInstances' }] }) } });
  assert.throws(() => checkRolloutPlan(p, options), /permits EC2/);
});
test('rejects missing or ambiguous CLI targets', () => {
  assert.throws(() => parsePlanArguments(['--apply']));
  assert.throws(() => parsePlanArguments(['--plan', 'x', '--plan', 'y']));
  assert.equal(parsePlanArguments(['--plan', 'x']).file, 'x');
});
