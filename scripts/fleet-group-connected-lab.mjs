// Actual private preparation acceptance. Only inspected image IDs are reused;
// all databases, object stores, networks, keys and caches belong to this run.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {chmodSync,chownSync,lstatSync,mkdirSync,readFileSync,readdirSync,realpathSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {localDockerEndpoint} from './kubernetes-bootstrap.mjs';
import {validateFleetHistorySources,validateFleetHistoryMinioImage} from './fleet-history-lab.mjs';
import {createFixtureGoCache,prepareFixtureGoModules,removeFixtureGoCache} from './lib/fixture-go-modules.mjs';
import {connectedFailureReceipt,readConnectedDriverDiagnostic} from './lib/group-connected-failure.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const label='finops.fleet-group-connected.run';
const fixture='examples/fleet-group-connected-fixture';
const testName='TestFleetGroupConnectedNativePreparationAndIndependentApproval';
const runnerPath='scripts/fleet-group-connected-lab.mjs';
const harnessDependencies=Object.freeze(['scripts/kubernetes-bootstrap.mjs','scripts/fleet-history-lab.mjs','scripts/postgres-recovery-lab.mjs','scripts/lib/encrypted-backup.mjs','scripts/lib/fixture-go-modules.mjs','scripts/lib/group-connected-failure.mjs']);
const indexedHostFiles=Object.freeze([runnerPath,...harnessDependencies]);
const hash=x=>createHash('sha256').update(x).digest('hex');
const images={terraform:'hashicorp/terraform:1.16.0@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e',go:'golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61'};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

export function validateConnectedTooling(raw){
 const lines=String(raw).replaceAll('\r\n','\n').split('\n').map(x=>x.trim()).filter(x=>x&&!x.startsWith('#'));
 assert.deepEqual(lines,['FROM '+images.terraform+' AS terraform','FROM '+images.go,'COPY --from=terraform /bin/terraform /usr/local/bin/terraform','USER 10001:10001']);
}
export function connectedMountSource(raw,platform=process.platform){
 assert.ok(typeof raw==='string'&&raw&&!/[\0\r\n]/.test(raw));let p=raw.replaceAll('\\','/');
 if(platform==='win32'){const m=/^([a-zA-Z]):\/(.+)$/.exec(p);if(m)p='/run/desktop/mnt/host/'+m[1].toLowerCase()+'/'+m[2];}
 assert.ok(p.startsWith('/')&&!p.split('/').includes('..'));return p.replace(/\/$/,'');
}
export function connectedEnvironment(password,user,secret,imageSHA,sourceSHA){
 for(const x of [password,user,secret])assert.match(x,/^[a-zA-Z0-9]{20,128}$/);
 for(const x of [imageSHA,sourceSHA])assert.match(x,/^[a-f0-9]{64}$/);
 return {postgres:`POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=${password}\nPOSTGRES_DB=postgres\nPGDATA=/var/lib/postgresql/data\n`,minio:`MINIO_ROOT_USER=${user}\nMINIO_ROOT_PASSWORD=${secret}\nHOME=/tmp\n`,test:`TEST_DATABASE_URL=postgres://postgres:${password}@postgres:5432/postgres?sslmode=disable\nFLEET_CONNECTED_FIXTURE=ISOLATED_FIXTURE\nFLEET_CONNECTED_NATIVE_RUNTIME=1\nFLEET_CONNECTED_S3_ENDPOINT=http://minio:9000\nFLEET_CONNECTED_S3_USER=${user}\nFLEET_CONNECTED_S3_SECRET=${secret}\nFLEET_CONNECTED_IMAGE_SHA256=${imageSHA}\nFLEET_CONNECTED_SOURCE_SHA256=${sourceSHA}\n`};
}
export function validateConnectedOperatingLoop(result){
 assert.equal(result.native_journal_runtime_accepted,true);const loop=result.native_operating_loop;
 assert.equal(loop?.status,'PASS');assert.equal(loop.fixture_only,true);assert.equal(loop.native_saved_plan_exact_applies,5);assert.equal(loop.owned_effects,2);assert.equal(loop.fresh_lifo_inverse_commits,2);assert.equal(loop.actual_subprocess_terminal_exit_unknown_reconciled,true);assert.equal(loop.repeat_capture_and_apply_no_extra_terraform,true);assert.ok(loop.baseline_actual_duration_seconds>=120);assert.equal(loop.baseline_measurement_revision,'GO_MONOTONIC_HTTP_V2');assert.ok(Number.isSafeInteger(loop.baseline_monotonic_duration_ns)&&loop.baseline_monotonic_duration_ns>=120e9);assert.equal(loop.customer_execution_authorized,false);assert.equal(loop.verified_saving,null);
 assert.equal(loop.healthy_fixture_work_ns,1e9);assert.match(loop.baseline_anchor_sha256,/^[a-f0-9]{64}$/);assert.match(loop.baseline_anchor_ref?.id,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);assert.equal(loop.baseline_anchor_ref.sha256,loop.baseline_anchor_sha256);assert.equal(typeof loop.baseline_anchor_ref.version_id,'string');assert.ok(loop.baseline_anchor_ref.version_id&&loop.baseline_anchor_ref.version_id!=='null');assert.equal(loop.permanent_forward_disqualification,true);assert.equal(loop.financial_disqualified_forever,true);assert.ok(Array.isArray(loop.health_incident_refs)&&loop.health_incident_refs.length>=1&&loop.health_incident_refs.length<=4096);assert.equal(loop.recovery_alert_delivery,'UNAVAILABLE_NO_COMMISSIONED_ADAPTER');assert.equal(loop.production_durable_retry_accepted,false);
 assert.ok(Array.isArray(result.artifacts));const healthIDs=new Set();for(const ref of [loop.baseline_anchor_ref,...loop.health_incident_refs]){assert.match(ref?.id,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);assert.match(ref.sha256,/^[a-f0-9]{64}$/);assert.equal(typeof ref.version_id,'string');assert.ok(ref.version_id&&ref.version_id!=='null');assert.ok(!healthIDs.has(ref.id));healthIDs.add(ref.id);const issued=result.artifacts.filter(a=>a.id===ref.id);assert.equal(issued.length,1);assert.equal(issued[0].kind,'HEALTH_VERDICT');assert.equal(issued[0].plain_sha256,ref.sha256);assert.equal(issued[0].version_id,ref.version_id);}
 for(const [key,seconds,status]of [['warmup',120,'OBSERVED'],['canary_breach',3600,'BREACH'],['terminal',900,'OBSERVED']]){const v=loop[key]?.verdict;assert.equal(v?.Status??v?.status,status);assert.equal(v.measurement_revision,'GO_MONOTONIC_HTTP_V2');assert.ok(Number.isSafeInteger(v.monotonic_duration_ns)&&v.monotonic_duration_ns>0);assert.ok(Number.isSafeInteger(v.baseline_monotonic_duration_ns)&&v.baseline_monotonic_duration_ns>=120e9);const start=Date.parse(v.start),end=Date.parse(v.required_end),through=Date.parse(v.observed_through);assert.ok(Number.isFinite(start)&&Number.isFinite(end)&&Number.isFinite(through));assert.equal(end-start,seconds*1000);if(status==='OBSERVED'){assert.ok(through>=end);assert.ok(v.monotonic_duration_ns>=seconds*1e9);}else{assert.ok(through<end);assert.ok(v.reason_codes.includes('LATENCY_REGRESSION_ABOVE_15_PERCENT'));assert.ok(BigInt(v.p95_ns)*100n>BigInt(v.baseline_p95_ns)*115n);}}
 assert.equal(loop.terraform_invocations?.counts?.apply,6);
}
export function validateConnectedNetwork(o,id,name){
 assert.equal(o.Name,name);assert.equal(o.Labels?.[label],id);assert.equal(o.Internal,true);assert.equal(o.Driver,'bridge');
 if(Object.hasOwn(o,'EnableIPv4'))assert.equal(o.EnableIPv4,true);if(Object.hasOwn(o,'EnableIPv6'))assert.equal(o.EnableIPv6,false);
 for(const[k,v]of Object.entries(o.Options||{}))assert.ok(k==='com.docker.network.enable_ipv4'&&v==='true'||k==='com.docker.network.enable_ipv6'&&v==='false');
}
export function validateConnectedContainer(o,{id,name,image,network,user,mounts,command,postgresImageEnvironment=[]}){
 assert.equal(o.Name,'/'+name);assert.equal(o.Config?.Labels?.[label],id);assert.equal(o.Image,image);assert.equal(o.Config?.User,user);
 assert.equal(o.HostConfig?.NetworkMode,network);assert.equal(o.HostConfig?.ReadonlyRootfs,true);assert.equal(o.HostConfig?.Privileged,false);
 assert.deepEqual(o.HostConfig?.CapDrop,['ALL']);assert.deepEqual(o.HostConfig?.CapAdd||[],[]);assert.ok(o.HostConfig?.SecurityOpt?.includes('no-new-privileges'));
 assert.equal(Object.keys(o.HostConfig?.PortBindings||{}).length,0);assert.equal(Object.keys(o.HostConfig?.Devices||{}).length,0);
 assert.deepEqual(o.Config?.Cmd,command);
 const actual=(o.Mounts||[]).filter(m=>m.Type!=='tmpfs').map(m=>[m.Destination,m.Type,m.Type==='bind'?connectedMountSource(m.Source):m.Name,m.RW]).sort((a,b)=>a[0].localeCompare(b[0]));
 assert.deepEqual(actual,[...mounts].sort((a,b)=>a[0].localeCompare(b[0])));
 // Alpine's reviewed PostgreSQL image includes its build dependency list.
 // It is accepted only byte-for-byte from that exact immutable image, and
 // never turns into a general Docker client/configuration environment bypass.
 assert.ok(postgresImageEnvironment.every(v=>typeof v==='string'&&v.startsWith('DOCKER_PG_LLVM_DEPS=')));
 const env=o.Config?.Env||[];assert.ok(!env.some(v=>/^(AWS_|AZURE_|ARM_|GOOGLE_|GCP_|DOCKER_|TF_VAR_|TF_CLI_ARGS|TF_TOKEN_|GIT_CONFIG_COUNT=)/.test(v)&&!postgresImageEnvironment.includes(v)));
}
function privateDirectory(id){
 const p=path.join(root,'work','private','fleet-group-connected',id);mkdirSync(p,{recursive:true,mode:0o700});const resolved=realpathSync(p),suffix=path.relative(realpathSync(root),resolved);assert.ok(suffix&&!suffix.startsWith('..')&&!path.isAbsolute(suffix));chmodSync(resolved,0o700);
 if(process.platform==='win32'){const account=execFileSync('whoami.exe',[],{encoding:'utf8',windowsHide:true}).trim();assert.match(account,/^[^\r\n]+\\[^\r\n]+$/);execFileSync('icacls.exe',[resolved,'/inheritance:r','/grant:r',account+':(OI)(CI)F'],{windowsHide:true,stdio:'pipe'});}return resolved;
}
function indexedSourcePath(p){
 if(p==='go.mod'||p==='go.sum'||p===fixture+'/Dockerfile')return true;
 if(p.startsWith('internal/')&&p.endsWith('.go')){assert.match(p,/^internal\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_]+\.go$/);return true;}
 const m=/^migrations\/(\d{3})_[a-z0-9_]+\.sql$/.exec(p);return !!m&&Number(m[1])<=32;
}
export function parseConnectedIndexListing(raw){
 assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=(2<<20)&&raw.at(-1)===0);
 const entries=[],seen=new Set();let total=0;const records=raw.toString('utf8').split('\0');records.pop();assert.ok(records.length<=4096);
 for(const line of records){
  const m=/^([0-7]{6}) (blob|commit) ([a-f0-9]{40}|[a-f0-9]{64}) +([0-9]+|-)\t([^\0]+)$/.exec(line);assert.ok(m,'Malformed indexed source listing');const p=m[5];
  assert.ok(!seen.has(p));seen.add(p);const scoped=p==='go.mod'||p==='go.sum'||p.startsWith('internal/')||p.startsWith('migrations/')||p===fixture+'/Dockerfile'||indexedHostFiles.includes(p);assert.ok(scoped,'Unexpected indexed source scope');
  assert.equal(m[1],'100644','Only regular indexed source blobs accepted');assert.equal(m[2],'blob');assert.ok(!p.split('/').some(x=>!x||x==='.'||x==='..'));
  if(!indexedSourcePath(p)&&!indexedHostFiles.includes(p))continue;
  const size=Number(m[4]);assert.ok(Number.isSafeInteger(size)&&size>=0&&size<=(2<<20));total+=size;assert.ok(total<=(32<<20));entries.push({path:p,oid:m[3],size});assert.ok(entries.length<=2048);
 }
 for(const p of ['go.mod','go.sum',fixture+'/Dockerfile',...indexedHostFiles,'migrations/029_fleet_fixture_proposals.sql','migrations/030_fleet_group_journal.sql','migrations/031_cross_family_admission.sql','migrations/032_group_artifacts.sql'])assert.ok(entries.some(e=>e.path===p),'Required indexed source absent');
 assert.ok(entries.some(e=>e.path.startsWith('internal/')&&e.path.endsWith('.go')));return entries;
}
export function parseConnectedIndexObjects(raw,entries){
 assert.ok(Buffer.isBuffer(raw)&&raw.length<=(34<<20));const files=new Map();let at=0;
 for(const entry of entries){const end=raw.indexOf(10,at);assert.ok(end>at&&end-at<160);const header=raw.subarray(at,end).toString('ascii').split(' ');assert.deepEqual(header,[entry.oid,'blob',String(entry.size)]);at=end+1;assert.ok(at+entry.size<raw.length);const body=Buffer.from(raw.subarray(at,at+entry.size));at+=entry.size;assert.equal(raw[at++],10);const oid=createHash(entry.oid.length===40?'sha1':'sha256').update(Buffer.from('blob '+body.length+'\0')).update(body).digest('hex');assert.equal(oid,entry.oid,'Indexed blob bytes differ from object identity');files.set(entry.path,body);}
 assert.equal(at,raw.length);return files;
}
// Fixed raw-object commands bypass filters, attributes, export-subst and worktree
// files. The caller cannot choose a ref, directory, Git option or source path.
export function readConnectedIndexedSource(repositoryRoot,emptyConfig){
 const config=lstatSync(emptyConfig);assert.ok(config.isFile()&&!config.isSymbolicLink()&&config.size===0);
 const environment={};for(const key of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC'])if(process.env[key])environment[key]=process.env[key];
 Object.assign(environment,{LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_SYSTEM:emptyConfig,GIT_CONFIG_GLOBAL:emptyConfig,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0'});
 const git=(args,input)=>execFileSync('git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:repositoryRoot,env:environment,windowsHide:true,encoding:null,stdio:['pipe','pipe','pipe'],input,maxBuffer:(34<<20),timeout:30000});
 const tree=git(['write-tree']).toString('ascii').trim();assert.match(tree,/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
 const entries=parseConnectedIndexListing(git(['ls-tree','-r','-z','--long','--full-tree',tree,'--','go.mod','go.sum','internal','migrations',fixture+'/Dockerfile',...indexedHostFiles]));
 const files=parseConnectedIndexObjects(git(['cat-file','--batch'],Buffer.from(entries.map(e=>e.oid+'\n').join(''))),entries);
 const hostHashes={};for(const p of indexedHostFiles){const actual=path.join(repositoryRoot,p),info=lstatSync(actual);assert.ok(info.isFile()&&!info.isSymbolicLink());const relative=path.relative(realpathSync(repositoryRoot),realpathSync(actual));assert.ok(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative));assert.ok(readFileSync(actual).equals(files.get(p)),'Executed host source differs from Git index');hostHashes[p]=hash(files.get(p));}
 assert.equal(git(['write-tree']).toString('ascii').trim(),tree,'Git index changed while capturing source');return {tree,files,hostHashes};
}
function snapshot(directory,runnerSHA,harnessHashes){
 const config=path.join(directory,'git-empty.config');writeFileSync(config,'',{flag:'wx',mode:0o600});const indexed=readConnectedIndexedSource(root,config);assert.equal(indexed.hostHashes[runnerPath],runnerSHA);for(const p of harnessDependencies)assert.equal(indexed.hostHashes[p],harnessHashes[p]);
 const source=path.join(directory,'source');mkdirSync(source,{mode:0o755});const manifest={},directories=new Set([source]);
 for(const [relative,raw]of indexed.files){if(!indexedSourcePath(relative))continue;const target=path.join(source,relative);let directory=path.dirname(target);mkdirSync(directory,{recursive:true,mode:0o755});while(directory!==source){directories.add(directory);directory=path.dirname(directory);}writeFileSync(target,raw,{flag:'wx',mode:0o444});chmodSync(target,0o444);manifest[relative]=hash(raw);}
 validateConnectedTooling(readFileSync(path.join(source,fixture,'Dockerfile'),'utf8'));for(const directory of [...directories].sort((a,b)=>b.length-a.length))chmodSync(directory,0o555);return {source,manifest,sourceTree:indexed.tree};
}
export async function fleetGroupConnectedLab(){
 assert.equal(process.argv.length,2,'No alternate endpoints, targets, images, credentials or commands accepted');assert.ok(!process.env.BUILDKIT_HOST&&!process.env.BUILDX_BUILDER);
 const startedAt=new Date().toISOString();
 const runnerSHA=hash(readFileSync(fileURLToPath(import.meta.url)));
 const harnessHashes=Object.fromEntries(harnessDependencies.map(p=>[p,hash(readFileSync(path.join(root,p)))]));
 const invoke=(args,options={})=>execFileSync('docker',args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:120000,maxBuffer:8<<20,stdio:['pipe','pipe','pipe'],...options}).trim();
 if(process.env.DOCKER_HOST)assert.ok(localDockerEndpoint(process.env.DOCKER_HOST));const context=JSON.parse(invoke(['context','inspect',invoke(['context','show'])]))[0],endpoint=context.Endpoints?.docker?.Host;assert.ok(localDockerEndpoint(endpoint));
 const run=(args,options)=>invoke(['--host',endpoint,...args],options),inspect=(kind,name)=>JSON.parse(run(['inspect','--type',kind,name]))[0];const daemon=run(['info','--format','{{.ID}}']);assert.ok(daemon);
 const builder=run(['buildx','inspect','default']);assert.match(builder,/^Driver:\s+docker\s*$/m);const points=[...builder.matchAll(/^Endpoint:\s+([^\r\n]+)\s*$/gm)].map(m=>m[1].trim());assert.equal(points.length,1);
 const builderEndpoint=localDockerEndpoint(points[0])?points[0]:JSON.parse(invoke(['context','inspect',points[0]]))[0].Endpoints?.docker?.Host;assert.ok(localDockerEndpoint(builderEndpoint));assert.equal(invoke(['--host',builderEndpoint,'info','--format','{{.ID}}']),daemon);
 const sources={};for(const service of ['api','postgres','minio']){const key=run(['compose','ps','-q',service]);assert.match(key,/^[a-f0-9]{64}$/);sources[service]=inspect('container',key);}validateFleetHistorySources(sources,root);validateFleetHistoryMinioImage(inspect('image',sources.minio.Image),sources.minio.Image);
 const pguid=run(['exec',sources.postgres.Id,'id','-u','postgres']),pggid=run(['exec',sources.postgres.Id,'id','-g','postgres']);for(const x of [pguid,pggid])assert.match(x,/^[1-9][0-9]{0,4}$/);
 const id=randomUUID(),prefix='finops-connected-'+id.replaceAll('-',''),directory=privateDirectory(id),uid=process.getuid?.()>0?process.getuid():10001;let captured;
 try{captured=snapshot(directory,runnerSHA,harnessHashes);}catch{const receipt=connectedFailureReceipt({runID:id,startedAt,observedAt:new Date().toISOString(),phase:'INDEX_SNAPSHOT',cleanupSucceeded:true});writeFileSync(path.join(directory,'failure-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});throw new Error('Git index source snapshot refused before owned resources');}
 const {source,manifest,sourceTree}=captured;
 const results=path.join(directory,'encrypted');mkdirSync(results,{mode:0o700});const archiveKey=path.join(directory,'archive.key');writeFileSync(archiveKey,randomBytes(32),{flag:'wx',mode:0o600});
 if(process.platform!=='win32'&&process.getuid?.()===0){chownSync(results,uid,uid);chownSync(archiveKey,uid,uid);}
 const network=prefix+'-private',tag=prefix+':tooling',modules=prefix+'-gomod',cache=prefix+'-gobuild',compiled=prefix+'-compiled';let imageID,result,failure,phase='BUILD_IMAGE',failurePhase,cleanupSucceeded=false;const owned=[],volumes=[],envFiles={};
 const check=(name,spec)=>validateConnectedContainer(inspect('container',name),{id,name,...spec});
 const create=(name,spec,args)=>{owned.push({name,spec});run(['create','--name',name,'--label',label+'='+id,'--pull','never','--network',spec.network,'--user',spec.user,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256',...args,spec.image,...spec.command]);check(name,spec);return name;};
 try{
  run(['build','--builder','default','--network','none','--pull=false','--label',label+'='+id,'--tag',tag,'--file',path.join(source,fixture,'Dockerfile'),source],{timeout:300000});const image=inspect('image',tag);assert.equal(image.Config?.Labels?.[label],id);assert.match(image.Id,/^sha256:[a-f0-9]{64}$/);imageID=image.Id;
  phase='PREPARE_MODULES';
  for(const name of [modules,cache,compiled]){volumes.push(name);createFixtureGoCache(run,name,label,id);}
  // The public lockfile-only downloader uses the pinned base Go image's root
  // owner for its newly created cache. Native acceptance remains nonroot.
  const moduleImage=inspect('image',images.go);assert.match(moduleImage.Id,/^sha256:[a-f0-9]{64}$/);
  prepareFixtureGoModules(run,{imageID:moduleImage.Id,sourceDirectory:source,privateDirectory:directory,moduleVolume:modules,labelKey:label,runID:id,containerName:prefix+'-modules'});
  phase='OFFLINE_COMPILE';
  const buildName=prefix+'-compile',buildSpec={image:imageID,network:'none',user:'0:0',mounts:[['/src','bind',connectedMountSource(source),false],['/go/pkg/mod','volume',modules,true],['/root/.cache/go-build','volume',cache,true],['/compiled','volume',compiled,true]],command:['sh','-ec','go test -p 1 -c -o /compiled/connected.test ./internal/service && chmod 0555 /compiled/connected.test && go vet -p 1 ./internal/service ./internal/groupfixtureproducer']};
  create(buildName,buildSpec,['--memory','1024m','--cpus','1','-e','GOTOOLCHAIN=local','-e','GOPROXY=off','-e','GOSUMDB=off','-e','GOMAXPROCS=1','-e','GOMEMLIMIT=768MiB','--mount','type=bind,src='+source+',dst=/src,readonly','--mount','type=volume,src='+modules+',dst=/go/pkg/mod','--mount','type=volume,src='+cache+',dst=/root/.cache/go-build','--mount','type=volume,src='+compiled+',dst=/compiled','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=512m','--workdir','/src']);
  run(['start','--attach',buildName],{timeout:600000});check(buildName,buildSpec);assert.equal(inspect('container',buildName).State?.ExitCode,0,'Offline source compilation failed');
  phase='START_SERVICES';
  const env=connectedEnvironment(randomBytes(32).toString('hex'),'connected'+randomBytes(16).toString('hex'),randomBytes(32).toString('hex'),imageID.slice(7),hash(JSON.stringify(manifest)));
  for(const [kind,raw]of Object.entries(env)){const file=path.join(directory,kind+'.env');writeFileSync(file,raw,{flag:'wx',mode:0o600});envFiles[kind]=file;}
  run(['network','create','--internal','--driver','bridge','--label',label+'='+id,network]);validateConnectedNetwork(inspect('network',network),id,network);
  const postgres=prefix+'-postgres',pgSpec={image:sources.postgres.Image,network,user:pguid+':'+pggid,mounts:[],command:sources.postgres.Config.Cmd,postgresImageEnvironment:(inspect('image',sources.postgres.Image).Config?.Env||[]).filter(v=>v.startsWith('DOCKER_PG_LLVM_DEPS='))};
  create(postgres,pgSpec,['--network-alias','postgres','--env-file',envFiles.postgres,'--memory','384m','--cpus','1','--tmpfs',`/var/lib/postgresql/data:rw,nosuid,nodev,size=768m,uid=${pguid},gid=${pggid},mode=0700`,'--tmpfs',`/var/run/postgresql:rw,nosuid,nodev,size=16m,uid=${pguid},gid=${pggid},mode=0700`,'--tmpfs',`/tmp:rw,nosuid,nodev,size=32m,uid=${pguid},gid=${pggid}`]);run(['start',postgres]);
  const minio=prefix+'-minio',minioSpec={image:sources.minio.Image,network,user:'10001:10001',mounts:[],command:['server','/data','--console-address',':9001']};
  create(minio,minioSpec,['--network-alias','minio','--env-file',envFiles.minio,'--memory','384m','--cpus','1','--tmpfs','/data:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700','--tmpfs','/tmp:rw,nosuid,nodev,size=32m,uid=10001,gid=10001']);run(['start',minio]);
  // initdb's temporary server accepts Unix sockets before the final TCP server.
  // The worker connects over TCP, so local socket readiness cannot admit it.
  let ready=false;for(let n=0;n<60;n++){try{run(['exec',postgres,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres','-d','postgres']);ready=true;break;}catch{assert.equal(inspect('container',postgres).State?.Running,true);await sleep(500);}}assert.ok(ready);
  const test=prefix+'-test',testSpec={image:imageID,network,user:uid+':'+uid,mounts:[['/src','bind',connectedMountSource(source),false],['/results','bind',connectedMountSource(results),true],['/secrets/archive.key','bind',connectedMountSource(archiveKey),false],['/compiled','volume',compiled,false]],command:['/compiled/connected.test','-test.v','-test.count=1','-test.timeout=30m','-test.run=^'+testName+'$']};
  create(test,testSpec,['--env-file',envFiles.test,'--memory','768m','--cpus','1','-e','HOME=/tmp/empty-home','-e','GOMAXPROCS=1','-e','GOMEMLIMIT=512MiB','--mount','type=bind,src='+source+',dst=/src,readonly','--mount','type=bind,src='+results+',dst=/results','--mount','type=bind,src='+archiveKey+',dst=/secrets/archive.key,readonly','--mount','type=volume,src='+compiled+',dst=/compiled,readonly','--tmpfs',`/workspace:rw,nosuid,nodev,size=192m,uid=${uid},gid=${uid},mode=0700`,'--tmpfs',`/tmp:rw,exec,nosuid,nodev,size=192m,uid=${uid},gid=${uid},mode=0700`,'--workdir','/src/internal/service']);
  phase='NATIVE_TEST';const logs=run(['start','--attach',test],{timeout:31*60*1000});check(test,testSpec);assert.equal(inspect('container',test).State?.ExitCode,0,'Native connected fixture failed');assert.ok(logs.includes('--- PASS: '+testName+' '));assert.ok(!logs.includes('--- SKIP:'));writeFileSync(path.join(directory,'acceptance.log'),logs+'\n',{mode:0o600});
  phase='VALIDATE_RESULT_SIZE';const resultPath=path.join(results,'result.json'),resultInfo=lstatSync(resultPath);assert.ok(resultInfo.isFile()&&!resultInfo.isSymbolicLink()&&resultInfo.size>0&&resultInfo.size<128*1024);
  phase='VALIDATE_RESULT';result=JSON.parse(readFileSync(resultPath,'utf8'));validateConnectedOperatingLoop(result);assert.equal(result.status,'PASS');assert.equal(result.actual_git_manifest_entries,26);assert.equal(result.independent_jwt_approval_persisted,true);assert.equal(result.independent_journal_and_continuation_http_approvals_persisted,true);assert.equal(result.commissioned_distinct_key_registry,true);assert.equal(result.durable_zero_command_bootstrap,true);assert.equal(result.customer_execution_authorized,false);assert.equal(result.native_journal_runtime_accepted,true);assert.equal(result.native_operating_loop?.native_saved_plan_exact_applies,5);assert.equal(result.native_operating_loop?.owned_effects,2);assert.equal(result.native_operating_loop?.fresh_lifo_inverse_commits,2);assert.equal(result.native_operating_loop?.actual_subprocess_terminal_exit_unknown_reconciled,true);assert.ok(result.native_operating_loop?.baseline_actual_duration_seconds>=120);assert.equal(result.customer_history_status,'BLOCKED');assert.equal(result.verified_saving,null);assert.ok(result.artifacts.length>9&&result.artifacts.length<=4096);
  phase='VALIDATE_CIPHERTEXT';const files=new Set(['result.json']);const driver=readConnectedDriverDiagnostic(path.join(results,'driver-phase.json'));assert.notEqual(driver.status,'INVALID','Invalid bounded driver diagnostic');if(driver.status==='VALID')files.add('driver-phase.json');for(const object of result.artifacts){assert.match(object.id,/^[a-f0-9-]{36}$/);assert.equal(object.file,object.id+'.ciphertext.json');assert.ok(!files.has(object.file),'Duplicate immutable artifact ID');assert.match(object.cipher_sha256,/^[a-f0-9]{64}$/);assert.ok(object.cipher_size>0&&object.cipher_size<=24*1024*1024);const file=path.join(results,object.file),info=lstatSync(file);assert.ok(info.isFile()&&!info.isSymbolicLink());assert.equal(info.size,object.cipher_size);assert.equal(hash(readFileSync(file)),object.cipher_sha256);files.add(object.file);}assert.deepEqual(readdirSync(results).sort(),[...files].sort());
 }catch(error){failure=error;failurePhase=phase;const diagnostic=String(error.stdout||'')+'\n'+String(error.stderr||'');writeFileSync(path.join(directory,'failure.log'),diagnostic,{mode:0o600});writeFileSync(path.join(directory,'failure.json'),JSON.stringify({status:'FAIL',error_name:error.name,error_code:error.code,last_owned_container:owned.at(-1)?.name||null})+'\n',{mode:0o600});}
 finally{
  phase='OWNED_CLEANUP';const errors=[];
  try{
  assert.equal(run(['info','--format','{{.ID}}']),daemon,'Daemon changed before cleanup');
  for(const {name,spec}of owned.reverse()){try{const present=run(['ps','--all','--filter','name=^/'+name+'$','--format','{{.Names}}']).split('\n');if(!present.includes(name))continue;check(name,spec);run(['rm','--force',name]);}catch{errors.push('container');}}
  try{if(run(['network','ls','--filter','name=^'+network+'$','--format','{{.Name}}']).split('\n').includes(network)){const o=inspect('network',network);validateConnectedNetwork(o,id,network);assert.equal(Object.keys(o.Containers||{}).length,0);run(['network','rm',network]);}}catch{errors.push('network');}
  for(const volume of volumes.reverse())try{removeFixtureGoCache(run,volume,label,id);}catch{errors.push('volume');}
  try{if(run(['image','ls','--filter','reference='+tag,'--format','{{.Repository}}:{{.Tag}}']).split('\n').includes(tag)){const o=inspect('image',tag);if(imageID)assert.equal(o.Id,imageID);assert.equal(o.Config?.Labels?.[label],id);run(['image','rm',tag]);}}catch{errors.push('image');}
  assert.equal(errors.length,0,'Exact owned cleanup failed; private diagnostics retained');
  phase='FINAL_OWNERSHIP_CHECK';for(const kind of ['container','network','volume'])assert.equal(run(kind==='container'?['ps','--all','--filter','label='+label+'='+id,'--format','{{.ID}}']:[kind,'ls','--filter','label='+label+'='+id,'--format',kind==='volume'?'{{.Name}}':'{{.ID}}']),'');
  }catch{errors.push('owned_cleanup_or_final_check');}
  cleanupSucceeded=errors.length===0;
  if(!cleanupSucceeded){failure||=new Error('Exact owned cleanup failed');failurePhase=phase==='FINAL_OWNERSHIP_CHECK'?'FINAL_OWNERSHIP_CHECK':'OWNED_CLEANUP';}
 }
 if(failure){const receipt=connectedFailureReceipt({runID:id,startedAt,observedAt:new Date().toISOString(),phase:failurePhase,cleanupSucceeded,driver:readConnectedDriverDiagnostic(path.join(results,'driver-phase.json'))});writeFileSync(path.join(directory,'failure-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});throw new Error('Connected preparation failed; bounded failure receipt retained, no acceptance published.');}
 const acceptance={schema_version:'1',status:'PASS',run_id:id,observed_at:new Date().toISOString(),source_snapshot_kind:'GIT_INDEX_BLOBS',source_tree:sourceTree,tooling_image_id:imageID,tooling_bases:images,postgres_image_id:sources.postgres.Image,minio_image_id:sources.minio.Image,source_sha256:manifest,source_manifest_sha256:hash(JSON.stringify(manifest)),runner_sha256:runnerSHA,harness_dependencies_sha256:harnessHashes,result_sha256:hash(readFileSync(path.join(results,'result.json'))),actual_git_manifest_entries:26,authenticated_encrypted_artifacts:result.artifacts.length,independent_jwt_approval_persisted:true,realm:'ISOLATED_FIXTURE',main_schema_modified:false,customer_execution_authorized:false,verified_saving:null,native_journal_runtime_accepted:true,operating_loop_fixture_only:true,native_saved_plan_exact_applies:5,owned_lifo_inverse_commits:2,cleanup_succeeded:true};
 writeFileSync(path.join(directory,'acceptance.json'),JSON.stringify(acceptance,null,2)+'\n',{mode:0o600});console.log('Connected fixture operating loop PASS: native saved-plan applies, measured canary abort, owned LIFO restoration, real observation windows and restart reconciliation; customer history and execution remain blocked.');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)fleetGroupConnectedLab().catch(()=>{console.error('Connected fixture failed; credentials, keys, source state and plans are not printed.');process.exitCode=1;});
