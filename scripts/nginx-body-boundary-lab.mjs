// Local, credential-free HTTP boundary acceptance. No Compose services, host
// ports, cloud calls or application databases are used by this lab.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { localDockerEndpoint } from './kubernetes-bootstrap.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const label = 'finops.nginx-body-boundary.run';
const prefix = 'finops-nginx-body-';
export const boundaryBytes = Object.freeze({ api: 4 * 1024 * 1024, proxy: 5 * 1024 * 1024 });

export function boundaryImages(dockerfile) {
  const images = {};
  for (const [argument, name, image] of [
    ['NGINX_IMAGE', 'nginx', 'nginxinc/nginx-unprivileged:stable-alpine'],
    ['NODE_IMAGE', 'node', 'node:22-bookworm-slim'],
  ]) {
    const line = dockerfile.split(/\r?\n/).find(value => value.startsWith('ARG ' + argument + '='));
    const value = line?.slice(('ARG ' + argument + '=').length);
    assert.match(value || '', new RegExp('^' + image.replaceAll('/', '\\/').replaceAll('.', '\\.') + '@sha256:[a-f0-9]{64}$'), 'Only the frontend pinned public base images are accepted');
    images[name] = value;
  }
  return images;
}

export function validateOwnedBoundaryResource(object, runID, role) {
  assert.match(runID, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
  assert.ok(['network', 'upstream', 'proxy', 'client'].includes(role));
  const expected = prefix + runID.replaceAll('-', '') + '-' + role;
  assert.equal((object.Name || '').replace(/^\//, ''), expected, 'Exact lab resource name required');
  const labels = role === 'network' ? object.Labels : object.Config?.Labels;
  assert.equal(labels?.[label], runID, 'Exact lab ownership label required');
  if (role === 'network') assert.equal(object.Internal, true, 'Only the owned internal network may be removed');
}

export function missingBoundaryResource(error, name) {
  const stderr = Buffer.isBuffer(error?.stderr) ? error.stderr.toString('utf8') : String(error?.stderr || '');
  const message = stderr.trim().replace(/^Error response from daemon: /, '');
  return ['No such object: ' + name, 'No such container: ' + name, 'No such network: ' + name, 'network ' + name + ' not found'].includes(message);
}

const upstreamSource = String.raw`
import http from 'node:http';
import { createHash } from 'node:crypto';
const records = [];
const boundary = 4 * 1024 * 1024;
const failure = {error:'BODY_TOO_LARGE',message:'request body exceeds 4 MiB'};
http.createServer((req,res) => {
  const reply = (status,body) => {res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-body-boundary-upstream':'reached'});res.end(JSON.stringify(body));};
  if (req.url === '/healthz') return reply(200,{status:'ok'});
  if (req.url === '/inspect') return reply(200,{records});
  const record = {path:req.url,bytes:0,authenticated:req.headers.authorization === 'Bearer fixture-only-auth'};
  records.push(record);
  // Model only the HTTP precedence; the actual Go/JWT/restricted-PG boundary
  // is tested independently by TestMutationBodyLimitRejectsEntireOversizedRequestBeforeReplayOrSQL.
  if (!record.authenticated) {req.resume();return reply(401,{error:'UNAUTHORIZED',message:'fixture authentication required'});}
  const hash = createHash('sha256');
  req.on('data',chunk => {record.bytes += chunk.length;hash.update(chunk);});
  req.on('end',() => {
    record.sha256 = hash.digest('hex');
    if (req.url === '/v1/upstream-rejection') return reply(413,{error:'UPSTREAM_SENTINEL',message:'upstream rejection preserved'});
    if (record.bytes > boundary) return reply(413,failure);
    reply(200,{bytes:record.bytes,sha256:record.sha256});
  });
}).listen(8088,'0.0.0.0');
`;

const clientSource = String.raw`
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
const API = 4 * 1024 * 1024, EDGE = 5 * 1024 * 1024;
const failure = {error:'BODY_TOO_LARGE',message:'request body exceeds 4 MiB'};
const body = count => Buffer.from('{}'.padEnd(count,' '));
function request(host,path,raw,framing='known',authenticated=true) {
  return new Promise((resolve,reject) => {
    const headers = raw == null ? {} : {'content-type':'application/json','idempotency-key':'fixture-boundary-key'};
    if (authenticated) headers.authorization = 'Bearer fixture-only-auth';
    if (raw != null && framing === 'known') headers['content-length'] = String(raw.length);
    const req = http.request({host,port:host === 'proxy' ? 8080 : 8088,path,method:raw == null ? 'GET' : 'POST',headers},res => {
      const chunks = [];let length = 0;
      res.on('data',chunk => {length += chunk.length;if(length>65536){res.destroy(new Error('Unbounded lab response'));return;}chunks.push(chunk);});
      res.on('error',reject);
      res.on('end',() => {try{const raw=Buffer.concat(chunks).toString('utf8');resolve({status:res.statusCode,headers:res.headers,body:res.headers['content-type']?.startsWith('application/json') ? JSON.parse(raw) : raw});}catch(error){reject(error);}});
    });
    req.setTimeout(10000,() => req.destroy(new Error('Local boundary request timed out')));
    req.on('error',reject);
    if(raw != null){if(framing === 'chunked'){for(let offset=0;offset<raw.length;offset+=65536)req.write(raw.subarray(offset,offset+65536));}else req.write(raw);}
    req.end();
  });
}
for(let attempt=0;;attempt++) {
  try {assert.equal((await request('proxy','/healthz')).status,200);assert.equal((await request('upstream','/healthz')).status,200);break;}
  catch(error){if(attempt>=29)throw error;await new Promise(resolve=>setTimeout(resolve,1000));}
}
const records = async () => (await request('upstream','/inspect')).body.records;
const cases = [];
for(const framing of ['known','chunked']) {
  for(const size of [API,API+1,EDGE]) {
    const raw=body(size),before=(await records()).length;
    const reply=await request('proxy','/v1/probe',raw,framing);
    assert.equal(reply.status,size===API ? 200 : 413);
    assert.equal(reply.headers['x-body-boundary-upstream'],'reached','API boundary must remain reachable through the proxy');
    if(size===API)assert.deepEqual(reply.body,{bytes:size,sha256:createHash('sha256').update(raw).digest('hex')});else assert.deepEqual(reply.body,failure);
    const after=await records();assert.equal(after.length,before+1);assert.equal(after.at(-1).bytes,size);
    cases.push({framing,bytes:size,status:reply.status,authority:'UPSTREAM_REACHED'});
  }
  // This crosses the edge boundary after a valid JSON prefix and whitespace.
  const hidden=Buffer.concat([body(EDGE),Buffer.from(' {"hidden":true}')]);
  for(const [raw,authenticated] of [[body(EDGE+1),true],[hidden,true],[body(EDGE+1),false]]) {
    const before=(await records()).length;
    const reply=await request('proxy','/v1/probe',raw,framing,authenticated);
    assert.equal(reply.status,413);assert.deepEqual(reply.body,failure);
    assert.match(reply.headers['content-type'],/^application\/json/);
    assert.equal(reply.headers['cache-control'],'no-store');
    assert.equal(reply.headers['x-content-type-options'],'nosniff');
    assert.equal(reply.headers['x-frame-options'],'DENY');
    assert.equal(reply.headers['referrer-policy'],'strict-origin-when-cross-origin');
    assert.equal(reply.headers['x-body-boundary-upstream'],undefined);
    assert.equal((await records()).length,before,'Edge-rejected content must never be forwarded, including valid-prefix bodies');
    cases.push({framing,bytes:raw.length,status:413,authenticated,authority:'PROXY_PREAUTH_REJECTION_NO_FORWARD'});
  }
  const before=(await records()).length;
  const unauthenticated=await request('proxy','/v1/probe',body(API+1),framing,false);
  assert.equal(unauthenticated.status,401);assert.equal(unauthenticated.body.error,'UNAUTHORIZED');
  const after=await records();assert.equal(after.length,before+1);assert.equal(after.at(-1).authenticated,false);assert.equal(after.at(-1).bytes,0);
  cases.push({framing,bytes:API+1,status:401,authority:'UPSTREAM_AUTH_FIRST'});
}
const sentinel=await request('proxy','/v1/upstream-rejection',Buffer.from('{}'));
assert.equal(sentinel.status,413);assert.equal(sentinel.headers['x-body-boundary-upstream'],'reached');
assert.deepEqual(sentinel.body,{error:'UPSTREAM_SENTINEL',message:'upstream rejection preserved'});
cases.push({bytes:2,status:413,authority:'UPSTREAM_413_UNCHANGED'});
console.log(JSON.stringify({status:'PASS',cases,forwarded_requests:(await records()).length}));
`;

export async function nginxBodyBoundaryLab() {
  assert.equal(process.argv.length, 2, 'No alternate image, upstream, network or cloud arguments accepted');
  if (process.env.DOCKER_HOST) assert.ok(localDockerEndpoint(process.env.DOCKER_HOST), 'Remote Docker endpoints refused');
  const invoke = (args, options = {}) => execFileSync('docker', args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 4 << 20, stdio: ['pipe', 'pipe', 'pipe'], ...options }).trim();
  const contextName = invoke(['context', 'show']);
  const context = JSON.parse(invoke(['context', 'inspect', contextName]))[0];
  const endpoint = process.env.DOCKER_HOST || context.Endpoints?.docker?.Host;
  assert.ok(localDockerEndpoint(endpoint), 'Only an explicitly local Docker daemon is permitted');
  // Freeze the validated endpoint rather than resolving mutable current context
  // on subsequent calls. No host environment is passed into any container.
  const env = { ...process.env };
  for (const name of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[name];
  const run = (args, options = {}) => invoke(['--host', endpoint, ...args], { env, ...options });
  const images = boundaryImages(readFileSync(path.join(root, 'frontend', 'Dockerfile'), 'utf8'));
  const imageIDs = {};
  for (const [name, image] of Object.entries(images)) {
    let object;
    try { object = JSON.parse(run(['image', 'inspect', image]))[0]; }
    catch { run(['pull', image], { timeout: 180000 }); object = JSON.parse(run(['image', 'inspect', image]))[0]; }
    assert.match(object.Id, /^sha256:[a-f0-9]{64}$/);
    imageIDs[name] = object.Id;
  }
  const runID = randomUUID();
  const daemonID = run(['info', '--format', '{{.ID}}']);
  assert.match(daemonID, /^[A-Za-z0-9:._-]{1,200}$/, 'Exact local Docker daemon identity required');
  const names = Object.fromEntries(['network', 'upstream', 'proxy', 'client'].map(role => [role, prefix + runID.replaceAll('-', '') + '-' + role]));
  const directory = path.join(root, 'work', 'nginx-body-boundary', runID);
  mkdirSync(directory, { recursive: true, mode: 0o755 });
  const relative = path.relative(realpathSync(root), realpathSync(directory));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  const sourceHashes = {
    'scripts/nginx-body-boundary-lab.mjs': createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex'),
  };
  for (const file of ['nginx.conf', 'nginx-root.conf']) {
    const source = path.join(root, 'frontend', file);
    assert.ok(lstatSync(source).isFile() && !lstatSync(source).isSymbolicLink());
    const bytes = readFileSync(source);
    sourceHashes['frontend/' + file] = createHash('sha256').update(bytes).digest('hex');
    const target = path.join(directory, file === 'nginx.conf' ? 'default.conf.template' : file);
    writeFileSync(target, bytes, { flag: 'wx', mode: 0o444 });chmodSync(target, 0o444);
  }
  for (const [file, source] of [['upstream.mjs', upstreamSource], ['client.mjs', clientSource]]) {
    sourceHashes['fixtures/' + file] = createHash('sha256').update(source).digest('hex');
    const target = path.join(directory, file);writeFileSync(target, source, { flag: 'wx', mode: 0o444 });chmodSync(target, 0o444);
  }
  const containerArguments = role => ['--name', names[role], '--label', label + '=' + runID, '--pull', 'never', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '256m', '--cpus', '1', '--network', names.network];
  const started = Date.now();
  let acceptance;
  try {
    run(['network', 'create', '--internal', '--label', label + '=' + runID, names.network]);
    run(['run', '-d', ...containerArguments('upstream'), '--user', '1000:1000', '--network-alias', 'upstream', '--mount', 'type=bind,src=' + path.join(directory, 'upstream.mjs') + ',dst=/lab/upstream.mjs,readonly', imageIDs.node, 'node', '/lab/upstream.mjs']);
    run(['run', '-d', ...containerArguments('proxy'), '--user', '101:101', '--network-alias', 'proxy', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m', '-e', 'API_UPSTREAM=upstream:8088', '-e', 'NGINX_ENVSUBST_OUTPUT_DIR=/tmp', '-e', 'NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1', '--mount', 'type=bind,src=' + path.join(directory, 'default.conf.template') + ',dst=/etc/nginx/templates/default.conf.template,readonly', '--mount', 'type=bind,src=' + path.join(directory, 'nginx-root.conf') + ',dst=/etc/nginx/nginx.conf,readonly', imageIDs.nginx]);
    run(['exec', names.proxy, 'nginx', '-t']);
    const nginxVersion = run(['exec', names.proxy, 'sh', '-c', 'nginx -v 2>&1']);
    const output = run(['run', ...containerArguments('client'), '--user', '1000:1000', '--mount', 'type=bind,src=' + path.join(directory, 'client.mjs') + ',dst=/lab/client.mjs,readonly', imageIDs.node, 'node', '/lab/client.mjs'], { timeout: 120000 });
    const result = JSON.parse(output);
    assert.equal(result.status, 'PASS');assert.equal(result.cases.length, 15);
    acceptance = { ...result, schema_version: '1', run_id: runID, daemon_id: daemonID, nginx_version: nginxVersion, images, image_ids: imageIDs, source_sha256: sourceHashes, network: 'OWNED_INTERNAL_NO_PUBLISHED_PORTS', upstream: 'INSPECTABLE_HTTP_FIXTURE_NOT_GO_AUTHORITY', main_stack_modified: false };
  } catch (error) {
    const text = value => typeof value === 'string' ? value : Buffer.isBuffer(value) ? value.toString('utf8') : '';
    let diagnostic = String(error.message) + '\n' + text(error.stdout) + '\n' + text(error.stderr);
    try { diagnostic += '\nNGINX\n' + run(['logs', names.proxy]); } catch {}
    writeFileSync(path.join(directory, 'failure.log'), diagnostic, { mode: 0o644 });
    throw new Error('Local Nginx boundary acceptance failed; public fixture diagnostics are in work/nginx-body-boundary/' + runID);
  } finally {
    try {
      // Refuse destructive cleanup if the validated local endpoint was replaced.
      // A functional result is never persisted as PASS until cleanup completes.
      assert.equal(run(['info', '--format', '{{.ID}}']), daemonID, 'Docker daemon identity changed; no cleanup attempted');
      for (const role of ['client', 'proxy', 'upstream']) {
        let object;
        try { object = JSON.parse(run(['inspect', '--type', 'container', names[role]]))[0]; }
        catch (error) { if (!missingBoundaryResource(error, names[role])) throw error;continue; }
        validateOwnedBoundaryResource(object, runID, role);
        run(['rm', '-f', object.Id]);
      }
      let network;
      try { network = JSON.parse(run(['network', 'inspect', names.network]))[0]; }
      catch (error) { if (!missingBoundaryResource(error, names.network)) throw error; }
      if (network) { validateOwnedBoundaryResource(network, runID, 'network');assert.equal(Object.keys(network.Containers || {}).length, 0, 'Unknown network attachments must prevent cleanup');run(['network', 'rm', network.Id]); }
    } catch (error) {
      writeFileSync(path.join(directory, 'failure.log'), '\nOwned cleanup failed: ' + String(error.message) + '\n', { flag: 'a', mode: 0o644 });
      throw error;
    }
  }
  assert.ok(acceptance, 'No Nginx body-boundary acceptance recorded');
  writeFileSync(path.join(directory, 'acceptance.json'), JSON.stringify({ ...acceptance, cleanup_succeeded: true, duration_seconds: (Date.now() - started) / 1000 }, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  console.log('Nginx body boundary lab PASS: 15 actual-Nginx known/chunked cases; exact API boundary reachable, edge JSON413 rejects before forwarding, upstream413 preserved; owned cleanup complete.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) nginxBodyBoundaryLab().catch(error => { console.error(error.message);process.exitCode = 1; });
