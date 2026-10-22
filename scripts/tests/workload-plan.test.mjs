import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { parseWorkloadPlanArguments, workloadPlanCommand, runWorkloadPlan, verifyWorkloadPlanArtifacts } from '../check-workload-plan.mjs';

function artifactTree(t) {
  const parent = realpathSync(tmpdir());
  const root = mkdtempSync(path.join(parent, 'finops-offline-artifacts-'));
  mkdirSync(path.join(root, 'internal/fleet'), { recursive: true });
  mkdirSync(path.join(root, 'work'));
  writeFileSync(path.join(root, 'go.mod'), 'module fixture.invalid\n');
  const options = parseWorkloadPlanArguments(argumentsFor());
  for (const name of ['parent', 'child', 'plan-json', 'saved-plan', 'provenance', 'public-key']) writeFileSync(path.join(root, options[name]), 'fixture-artifact');
  t.after(() => {
    const actual = realpathSync(root);
    assert.equal(path.dirname(actual), parent);
    assert.ok(path.basename(actual).startsWith('finops-offline-artifacts-'));
    rmSync(actual, { recursive: true, force: true });
  });
  return { root, options };
}

function argumentsFor() {
  return Object.entries({ parent: 'work/parent.json', child: 'work/child.json', 'plan-json': 'work/show.json', 'saved-plan': 'work/saved.tfplan', provenance: 'work/provenance.json', 'public-key': 'work/public.key', tenant: 'tenant', workload: 'workload', resource: 'fleet', 'provider-resource': 'asg-blue', account: '111122223333', region: 'eu-west-1' }).flatMap(([name, value]) => [`--${name}`, value]);
}
test('offline workload wrapper requires exact identity and every signed artifact', () => {
  const args = argumentsFor();
  assert.equal(parseWorkloadPlanArguments(args).account, '111122223333');
  assert.throws(() => parseWorkloadPlanArguments(args.slice(2)), /required/);
  assert.throws(() => parseWorkloadPlanArguments([...args, '--account', '999988887777']), /duplicate/);
  assert.throws(() => parseWorkloadPlanArguments([...args, '--apply', 'true']), /Invalid/);
  assert.throws(() => parseWorkloadPlanArguments(args.map(value => value === 'eu-west-1' ? 'us-east-1' : value)), /eu-west-1/);
});
test('offline workload wrapper mounts artifacts read-only with no network or cloud credentials', () => {
  const command = workloadPlanCommand(parseWorkloadPlanArguments(argumentsFor()), '/workspace/repo', 'linux');
  assert.equal(command.command, 'docker');
  assert.ok(command.args.includes('--read-only'));
  assert.equal(command.args[command.args.indexOf('--network') + 1], 'none');
  assert.ok(command.args.includes('type=bind,source=/workspace/repo/go.mod,target=/src/go.mod,readonly'));
  assert.ok(command.args.includes('type=bind,source=/workspace/repo/internal/fleet,target=/src/internal/fleet,readonly'));
  assert.ok(command.args.includes('type=bind,source=/workspace/repo/work/parent.json,target=/inputs/parent,readonly'));
  assert.ok(!command.args.includes('type=bind,source=/workspace/repo,target=/src,readonly'));
  assert.ok(command.args.includes('./internal/fleet/cmd/check-workload-plan'));
  assert.ok(!command.args.some(value => /AWS_|\.aws|docker\.sock|--env-file|terraform.*apply/.test(value)));
});
test('offline wrapper rejects repository escapes before invoking a helper', () => {
  const options = parseWorkloadPlanArguments(argumentsFor());
  options.parent = '../outside-parent.json';
  assert.throws(() => workloadPlanCommand(options, '/workspace/repo', 'linux'), /repository/);
});
test('offline wrapper propagates validator rejection and never uses a shell', t => {
  const { root } = artifactTree(t);
  let invocation;
  const status = runWorkloadPlan(argumentsFor(), { root, run: (...args) => { invocation = args; return { status: 1 }; } });
  assert.equal(status, 1);
  assert.equal(invocation[2].shell, false);
  assert.ok(!('AWS_SECRET_ACCESS_KEY' in invocation[2].env));
  assert.throws(() => runWorkloadPlan(argumentsFor(), { root, run: () => ({ signal: 'SIGTERM' }) }), /could not complete/);
});
test('offline mounts cannot escape through repository links or mount delimiters', t => {
  const { root, options } = artifactTree(t);
  const outside = artifactTree(t);
  // A Windows directory junction does not require an elevated symlink privilege.
  symlinkSync(path.join(outside.root, 'work'), path.join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => verifyWorkloadPlanArtifacts({ ...options, parent: 'escape/parent.json' }, root), /within the repository/);
  assert.throws(() => workloadPlanCommand({ ...options, parent: 'work/parent,source=outside.json' }, root), /delimiters/);
  assert.throws(() => workloadPlanCommand(options, '/workspace/repo,source=outside', 'linux'), /delimiters/);
  assert.throws(() => verifyWorkloadPlanArtifacts({ ...options, parent: 'work' }, root), /regular file/);
  writeFileSync(path.join(root, options.parent), '');
  assert.throws(() => verifyWorkloadPlanArtifacts(options, root), /regular file/);
});
