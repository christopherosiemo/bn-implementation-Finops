// Offline wrapper around the single Go workload-plan validator. This deliberately
// does not duplicate safety logic or invoke terraform/apply/cloud credentials.
import { spawnSync } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve, dirname, posix, win32 } from 'node:path';

const required = ['parent', 'child', 'plan-json', 'saved-plan', 'provenance', 'public-key', 'tenant', 'workload', 'resource', 'provider-resource', 'account', 'region'];
const fileOptions = new Set(required.slice(0, 6));
export function parseWorkloadPlanArguments(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i]?.startsWith('--') ? args[i].slice(2) : '';
    if (!required.includes(name) || name in options || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Invalid, missing, or duplicate workload-plan option');
    options[name] = args[i + 1];
  }
  for (const name of required) if (!options[name]) throw new Error(`--${name} is required`);
  if (!/^\d{12}$/.test(options.account) || options.region !== 'eu-west-1') throw new Error('Exact AWS workload account and eu-west-1 are required');
  return options;
}
export function workloadPlanCommand(options, root, platform = process.platform) {
  // Inputs are explicit artifacts in this checkout, mounted read-only. No .env,
  // AWS configuration, Docker socket or host credential directory is mounted.
  const args = [];
  const paths = platform === 'win32' ? win32 : posix;
  if (/[\r\n\0,]/.test(root)) throw new Error('Repository path cannot contain Docker mount delimiters');
  const mounts = ['--mount', `type=bind,source=${paths.resolve(root, 'go.mod')},target=/src/go.mod,readonly`, '--mount', `type=bind,source=${paths.resolve(root, 'internal/fleet')},target=/src/internal/fleet,readonly`];
  for (const name of required) {
    let value = options[name];
    if (fileOptions.has(name)) {
      if (/[\r\n\0,]/.test(value)) throw new Error('Artifact path cannot contain Docker mount delimiters');
      const suffix = paths.relative(root, paths.resolve(root, value));
      if (!suffix || suffix === '..' || suffix.startsWith(`..${platform === 'win32' ? '\\' : '/'}`) || paths.isAbsolute(suffix) || suffix.split(/[\\/]/).includes('..')) throw new Error('Artifact paths must remain within the repository');
      mounts.push('--mount', `type=bind,source=${paths.resolve(root, value)},target=/inputs/${name},readonly`);
      value = `/inputs/${name}`;
    }
    args.push(`--${name}`, value);
  }
  return { command: 'docker', args: ['run', '--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=512m', '--env', 'GOTOOLCHAIN=local', '--env', 'GOCACHE=/tmp/go-build', ...mounts, '--workdir', '/src', 'golang:1.27.3-bookworm@sha256:32fa283222e2905d9fee971f60c842e5c815fdc036cf7ea599bf36bd7ca8f67f', 'go', 'run', './internal/fleet/cmd/check-workload-plan', ...args] };
}
export function verifyWorkloadPlanArtifacts(options, root) {
  const repository = realpathSync(root);
  const inside = candidate => {
    const actual = realpathSync(candidate);
    const suffix = (process.platform === 'win32' ? win32 : posix).relative(repository, actual);
    if (!suffix || suffix === '..' || suffix.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || (process.platform === 'win32' ? win32 : posix).isAbsolute(suffix) || /[\r\n\0,]/.test(actual)) throw new Error('Resolved artifact must remain within the repository');
    return actual;
  };
  const checked = { ...options };
  for (const name of fileOptions) {
    const file = inside(resolve(repository, options[name]));
    const information = statSync(file);
    const maximum = name === 'saved-plan' ? 256 << 20 : name === 'plan-json' ? 64 << 20 : 2 << 20;
    if (!information.isFile() || information.size < 1 || information.size > maximum) throw new Error('Artifact must be a bounded regular file');
    checked[name] = file;
  }
  if (!statSync(inside(resolve(repository, 'go.mod'))).isFile() || !statSync(inside(resolve(repository, 'internal/fleet'))).isDirectory()) throw new Error('Workload validator sources must remain inside this repository');
  return { options: checked, root: repository };
}
export function runWorkloadPlan(args, { run = spawnSync, root = resolve(dirname(fileURLToPath(import.meta.url)), '..') } = {}) {
  const options = parseWorkloadPlanArguments(args);
  // Resolve before Docker sees the mounts: lexical containment alone does not
  // constrain repository symlinks or Docker's comma-separated mount grammar.
  workloadPlanCommand(options, root);
  const checked = verifyWorkloadPlanArtifacts(options, root);
  const invocation = workloadPlanCommand(checked.options, checked.root);
  const result = run(invocation.command, invocation.args, { stdio: 'inherit', shell: false, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, DOCKER_CONFIG: process.env.DOCKER_CONFIG } });
  if (result.error || result.signal) throw new Error('Offline workload validator could not complete');
  return result.status ?? 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.exitCode = runWorkloadPlan(process.argv.slice(2)); }
  catch (error) { console.error(`Workload plan rejected: ${error.message}`); process.exitCode = 1; }
}
