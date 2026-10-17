// Offline review of `terraform show -json PLAN`. Never runs Terraform or applies a plan.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function insist(condition, message) { if (!condition) throw new Error(message); }
function resources(module) {
  return [...(module?.resources || []), ...(module?.child_modules || []).flatMap(resources)];
}
function expressionMatches(expression, variable, constant) {
  return expression?.references?.includes(`var.${variable}`) ||
    JSON.stringify(expression?.constant_value) === JSON.stringify(constant);
}
function permitsComputeMutation(policy) {
  if (typeof policy === 'string') {
    try { policy = JSON.parse(policy); } catch { throw new Error('Malformed IAM policy in plan'); }
  }
  const statements = Array.isArray(policy?.Statement) ? policy.Statement : [policy?.Statement];
  return statements.filter(Boolean).some(statement => statement.Effect === 'Allow' && (statement.NotAction !== undefined ||
    (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).some(action =>
      typeof action === 'string' && ['ec2:StartInstances', 'ec2:StopInstances'].some(target => {
        const pattern = action.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
        return new RegExp(`^${pattern}$`, 'i').test(target);
      }))));
}

export function checkRolloutPlan(plan, { expectedAccount, region, stack, mode }) {
  insist(/^[0-9]{12}$/.test(expectedAccount || ''), 'Exact expected account is required');
  insist(region === 'eu-west-1', 'Pilot region must be eu-west-1');
  insist(['platform', 'customer'].includes(stack), 'Stack must be platform or customer');
  insist(['read-only', 'execution'].includes(mode), 'Mode must be read-only or execution');
  insist(typeof plan?.format_version === 'string' && plan.format_version.startsWith('1.'), 'Unsupported Terraform plan JSON format');
  insist(plan.errored !== true && plan.complete !== false && !plan.deferred_changes?.length, 'Errored, incomplete or deferred plans are rejected');
  insist(plan.variables?.expected_account_id?.value === expectedAccount, 'Plan expected_account_id differs from the operator target');
  insist(plan.variables?.region?.value === region, 'Plan region differs from the operator target');
  const providers = Object.values(plan.configuration?.provider_config || {}).filter(provider => provider.full_name === 'registry.terraform.io/hashicorp/aws' || provider.name === 'aws');
  insist(providers.length > 0, 'AWS provider configuration is missing');
  for (const provider of providers) {
    insist(expressionMatches(provider.expressions?.region, 'region', region), 'Every AWS provider must bind the expected region');
    insist(expressionMatches(provider.expressions?.allowed_account_ids, 'expected_account_id', [expectedAccount]), 'Every AWS provider must enforce allowed_account_ids');
  }
  const planned = resources(plan.planned_values?.root_module);
  const callers = planned.filter(resource => resource.type === 'aws_caller_identity');
  insist(callers.length > 0 && callers.every(resource => resource.values?.account_id === expectedAccount), 'Concrete caller account evidence is absent or mismatches');
  insist(Array.isArray(plan.resource_changes), 'Plan resource_changes is missing');
  for (const change of [...plan.resource_changes, ...(plan.resource_drift || [])]) {
    const actions = change.change?.actions;
    insist(Array.isArray(actions) && actions.length > 0 && actions.every(action => ['no-op', 'read', 'create', 'update'].includes(action)), `Deletion or replacement rejected: ${change.address}`);
    if (plan.resource_drift?.includes(change)) insist(actions.every(action => action === 'no-op'), `Unreviewed drift rejected: ${change.address}`);
  }
  for (const resource of planned.filter(resource => resource.mode !== 'data' && resource.type?.startsWith('aws_'))) {
    const values = resource.values || {};
    if (typeof values.region === 'string') insist(values.region === region, `Resource outside expected region: ${resource.address}`);
    for (const field of ['account_id', 'owner_id']) {
      if (/^[0-9]{12}$/.test(values[field] || '')) insist(values[field] === expectedAccount, `Resource account mismatch: ${resource.address}`);
    }
    const arnAccount = /^arn:aws:[^:]+:[^:]*:([0-9]{12}):/.exec(values.arn || '')?.[1];
    if (arnAccount) insist(arnAccount === expectedAccount, `Resource ARN account mismatch: ${resource.address}`);
  }
  if (mode === 'read-only') {
    insist(!(plan.variables?.customer_execution_role_arns?.value || []).length, 'Read-only platform must not trust customer execution roles');
    insist(plan.variables?.enable_execution?.value !== true, 'Read-only customer stack must disable execution');
    for (const resource of planned) {
      insist(!/(?:^|\.)aws_iam_role\.customer\["execution"\]$/.test(resource.address || '') && !/(?:^|\.)aws_iam_role_policy\.execution(?:\[|$)/.test(resource.address || ''), 'Read-only customer plan contains an execution identity/policy');
      if (resource.type?.startsWith('aws_iam_') && resource.values?.policy) {
        insist(!permitsComputeMutation(resource.values.policy), `Read-only plan permits EC2 start/stop: ${resource.address}`);
      }
    }
  } else if (stack === 'customer') {
    insist(plan.variables?.enable_execution?.value === true, 'Execution customer plan must explicitly enable execution');
    insist((plan.variables?.instance_ids?.value || []).length > 0 && plan.variables?.execution_principal_arn?.value, 'Execution requires a trusted principal and explicit instance allowlist');
  }
  return { stack, mode, account: expectedAccount, region, changes: plan.resource_changes.filter(change => !change.change.actions.every(action => ['no-op', 'read'].includes(action))).length };
}

export function parsePlanArguments(args) {
  const names = { '--plan': 'file', '--expected-account': 'expectedAccount', '--region': 'region', '--stack': 'stack', '--mode': 'mode' };
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = names[args[index]];
    insist(name && args[index + 1] && !args[index + 1].startsWith('--') && !(name in options), `Invalid or duplicate option: ${args[index]}`);
    options[name] = args[index + 1];
  }
  insist(options.file, '--plan PATH is required');
  return options;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = parsePlanArguments(process.argv.slice(2));
    let plan;
    try { plan = JSON.parse(readFileSync(options.file, 'utf8')); } catch { throw new Error('Plan file could not be read as valid JSON'); }
    const result = checkRolloutPlan(plan, options);
    console.log(`PASS ${result.stack} ${result.mode}: ${result.account}/${result.region}, ${result.changes} non-destructive changes. Offline checks only; nothing applied.`);
  } catch (error) { console.error(`Rollout plan rejected: ${error.message}`); process.exitCode = 1; }
}
