// Actual private PostgreSQL/versioned MinIO acceptance. AWS responses are
// visibly provider-shaped fixtures; no customer credentials or cloud calls.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {chmodSync,chownSync,lstatSync,mkdirSync,readFileSync,readdirSync,realpathSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {localDockerEndpoint} from './kubernetes-bootstrap.mjs';
import {validateFleetHistorySources,validateFleetHistoryMinioImage} from './fleet-history-lab.mjs';
import {connectedMountSource,parseConnectedIndexObjects,readConnectedIndexedSource,validateConnectedContainer,validateConnectedNetwork} from './fleet-group-connected-lab.mjs';
import {createFixtureGoCache,prepareFixtureGoModules,removeFixtureGoCache} from './lib/fixture-go-modules.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const runnerPath='scripts/fleet-native-assessment-lab.mjs',policyPath='config/minio/group-assessor-policy.json';
const extraPaths=Object.freeze([runnerPath,policyPath,'migrations/033_group_native_reconstruction.sql','migrations/034_group_recovery_health.sql','migrations/035_group_native_assessments.sql']);
const label='finops.native-assessment.run',sharedLabel='finops.fleet-group-connected.run';
const goImage='golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61';
const testName='TestFleetNativeAssessmentActualVersionedRawIngestionAPIAndWorker';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

export function parseNativeAssessmentIndexExtras(raw){
 assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=16384&&raw.at(-1)===0);
 const rows=raw.toString('utf8').split('\0');rows.pop();assert.equal(rows.length,extraPaths.length);const seen=new Set();
 return rows.map(row=>{const m=/^100644 blob ([a-f0-9]{40}|[a-f0-9]{64}) +([0-9]+)\t([^\0]+)$/.exec(row);assert.ok(m&&extraPaths.includes(m[3])&&!seen.has(m[3]));seen.add(m[3]);const size=Number(m[2]);assert.ok(Number.isSafeInteger(size)&&size>0&&size<=(256<<10));return {path:m[3],oid:m[1],size};});
}
// Fixed <=035 extension; the accepted connected lab keeps its <=032 boundary.
export function readNativeAssessmentIndexedSource(repositoryRoot,emptyConfig){
 const captured=readConnectedIndexedSource(repositoryRoot,emptyConfig),env={};
 for(const key of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC'])if(process.env[key])env[key]=process.env[key];
 Object.assign(env,{LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_SYSTEM:emptyConfig,GIT_CONFIG_GLOBAL:emptyConfig,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0'});
 const git=(args,input)=>execFileSync('git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:repositoryRoot,env,encoding:null,windowsHide:true,input,maxBuffer:(2<<20),timeout:30000});
 assert.equal(git(['write-tree']).toString('ascii').trim(),captured.tree);
 const entries=parseNativeAssessmentIndexExtras(git(['ls-tree','-r','-z','--long','--full-tree',captured.tree,'--',...extraPaths]));
 const extras=parseConnectedIndexObjects(git(['cat-file','--batch'],Buffer.from(entries.map(e=>e.oid+'\n').join(''))),entries);
 const actual=path.join(repositoryRoot,runnerPath),stat=lstatSync(actual);assert.ok(stat.isFile()&&!stat.isSymbolicLink());
 const relative=path.relative(realpathSync(repositoryRoot),realpathSync(actual));assert.ok(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative));
 assert.ok(readFileSync(actual).equals(extras.get(runnerPath)),'Executed assessment runner differs from Git index');captured.hostHashes[runnerPath]=hash(extras.get(runnerPath));
 for(const[p,raw]of extras)captured.files.set(p,raw);assert.ok([...captured.files.values()].reduce((n,b)=>n+b.length,0)<=(32<<20));
 assert.equal(git(['write-tree']).toString('ascii').trim(),captured.tree,'Git index changed during assessment snapshot');return captured;
}
export function nativeAssessmentReaderPolicy(raw){
 assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=4096);const parsed=JSON.parse(raw);
 assert.equal(parsed.Version,'2012-10-17');assert.equal(parsed.Statement.length,3);
 const expected=[{Effect:'Deny',Action:['s3:GetObject','s3:GetObjectVersion'],Resource:['arn:aws:s3:::finops-raw/tenant/tenant-demo/*'],Condition:{Null:{'s3:versionid':'true'}}},{Effect:'Deny',Action:['s3:GetObject','s3:GetObjectVersion'],Resource:['arn:aws:s3:::finops-raw/tenant/tenant-demo/*'],Condition:{StringEquals:{'s3:versionid':['','null']}}},{Effect:'Allow',Action:['s3:GetObjectVersion'],Resource:['arn:aws:s3:::finops-raw/tenant/tenant-demo/*']}];
 assert.deepEqual(parsed.Statement,expected);
 // Only this new empty object store is affected. Its generated test tenant and
 // bucket remain bounded by these fixture-only resource names.
 for(const statement of parsed.Statement)statement.Resource=['arn:aws:s3:::native-assessment-*/tenant/*'];return Buffer.from(JSON.stringify(parsed));
}
export function validateNativeAssessmentContainer(object,spec){
 assert.equal(object.Config?.Labels?.[label],spec.id);assert.equal(object.Id,spec.runtimeID);
 validateConnectedContainer({...object,Config:{...object.Config,Labels:{...object.Config.Labels,[sharedLabel]:spec.id}}},spec);
 assert.deepEqual(object.Config?.Entrypoint||[],spec.entrypoint||[]);
}
export function validateNativeAssessmentNetwork(object,id,name){assert.equal(object.Labels?.[label],id);validateConnectedNetwork({...object,Labels:{...object.Labels,[sharedLabel]:id}},id,name);}
export function validateNativeAssessmentResult(value){
 assert.deepEqual(Object.keys(value).sort(),['archived_readbacks','candidate_hourly_compute','capacity_status','contracted_avoidable_cost','currency','customer_execution_authorized','fixture','hourly_compute_difference','immutable_replay','member_count','old_hourly_compute','raw_transport','schema_version','sql_guard_negatives','status','verified_saving']);
 assert.equal(value.schema_version,'1');assert.equal(value.status,'PASS');assert.equal(value.raw_transport,'PROVIDER_SHAPED_FIXTURE');
 assert.equal(value.old_hourly_compute,'0.4');assert.equal(value.candidate_hourly_compute,'0.24');assert.equal(value.hourly_compute_difference,'0.16');assert.equal(value.currency,'USD');assert.equal(value.member_count,2);
 assert.ok(Number.isSafeInteger(value.archived_readbacks)&&value.archived_readbacks>=10&&value.archived_readbacks<=256);assert.equal(value.sql_guard_negatives,6);assert.equal(value.capacity_status,'UNAVAILABLE');assert.equal(value.immutable_replay,true);assert.equal(value.fixture,true);assert.equal(value.customer_execution_authorized,false);assert.equal(value.verified_saving,null);assert.equal(value.contracted_avoidable_cost,null);
}
function privateDirectory(id){
 const directory=path.join(root,'work/private/fleet-native-assessment',id);mkdirSync(directory,{recursive:true,mode:0o700});const actual=realpathSync(directory),relative=path.relative(realpathSync(root),actual);assert.ok(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative));chmodSync(actual,0o700);
 if(process.platform==='win32'){const account=execFileSync('whoami.exe',[],{encoding:'utf8',windowsHide:true}).trim();assert.match(account,/^[^\r\n]+\\[^\r\n]+$/);execFileSync('icacls.exe',[actual,'/inheritance:r','/grant:r',account+':(OI)(CI)F'],{windowsHide:true,stdio:'pipe'});}return actual;
}
function materialize(directory,captured){
 const source=path.join(directory,'source'),directories=new Set([source]),manifest={};mkdirSync(source,{mode:0o755});
 for(const[p,raw]of captured.files){if(p.startsWith('scripts/'))continue;const file=path.join(source,p);mkdirSync(path.dirname(file),{recursive:true,mode:0o755});let parent=path.dirname(file);while(parent!==source){directories.add(parent);parent=path.dirname(parent);}writeFileSync(file,raw,{flag:'wx',mode:0o444});chmodSync(file,0o444);manifest[p]=hash(raw);}
 for(const p of [...directories].sort((a,b)=>b.length-a.length))chmodSync(p,0o555);return {source,manifest};
}
export async function fleetNativeAssessmentLab(){
 assert.equal(process.argv.length,2,'No target, clock, image, source or credential arguments accepted');assert.equal(path.resolve(process.argv[1]),path.join(root,runnerPath));
 const id=randomUUID(),startedAt=new Date().toISOString(),prefix='finops-native-assessment-'+id.replaceAll('-',''),directory=privateDirectory(id),network=prefix+'-private';
 const invoke=(args,options={})=>execFileSync('docker',args,{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:(4<<20),timeout:120000,stdio:['pipe','pipe','pipe'],...options}).trim();
 if(process.env.DOCKER_HOST)assert.ok(localDockerEndpoint(process.env.DOCKER_HOST));const context=JSON.parse(invoke(['context','inspect',invoke(['context','show'])]))[0],endpoint=context.Endpoints?.docker?.Host;assert.ok(localDockerEndpoint(endpoint));
 const run=(args,options)=>invoke(['--host',endpoint,...args],options),inspect=(kind,name)=>JSON.parse(run(['inspect','--type',kind,name]))[0],daemon=run(['info','--format','{{.ID}}']);assert.ok(daemon);
 const sources={};for(const service of ['api','postgres','minio']){const cid=run(['compose','ps','-q',service]);assert.match(cid,/^[a-f0-9]{64}$/);sources[service]=inspect('container',cid);}validateFleetHistorySources(sources,root);validateFleetHistoryMinioImage(inspect('image',sources.minio.Image),sources.minio.Image);
 const pguid=run(['exec',sources.postgres.Id,'id','-u','postgres']),pggid=run(['exec',sources.postgres.Id,'id','-g','postgres']);for(const n of [pguid,pggid])assert.match(n,/^[1-9][0-9]{0,4}$/);
 const go=inspect('image',goImage),mc=inspect('image','cloud-cost-autopilot-mc:local');assert.match(go.Id,/^sha256:[a-f0-9]{64}$/);assert.match(mc.Id,/^sha256:[a-f0-9]{64}$/);assert.equal(mc.Config?.Labels?.['org.opencontainers.image.source'],'https://github.com/minio/mc');assert.equal(mc.Config?.Labels?.['org.opencontainers.image.revision'],'b00526b153a31b36767991a4f5ce2cced435ee8e');assert.equal(mc.Config?.Labels?.['org.opencontainers.image.version'],'RELEASE.2025-04-16T18-13-26Z');
 const empty=path.join(directory,'git-empty.config');writeFileSync(empty,'',{flag:'wx',mode:0o600});const captured=readNativeAssessmentIndexedSource(root,empty),{source,manifest}=materialize(directory,captured),policy=nativeAssessmentReaderPolicy(captured.files.get(policyPath));
 const write=(name,body,mode=0o600)=>{const p=path.join(directory,name);writeFileSync(p,body,{flag:'wx',mode});chmodSync(p,mode);return p;};const policyFile=write('fixture-reader-policy.json',policy,0o444),results=path.join(directory,'results');mkdirSync(results,{mode:0o700});
 const uid=process.getuid?.()>0?process.getuid():10001;if(process.platform!=='win32'&&process.getuid?.()===0)chownSync(results,uid,uid);
 const owned=[],volumes=[],modules=prefix+'-modules',buildCache=prefix+'-build',compiled=prefix+'-compiled';let phase='PREPARE_MODULES',failed=false,cleanupSucceeded=false,result,networkCreated=false;
 const check=entry=>validateNativeAssessmentContainer(inspect('container',entry.name),{id,name:entry.name,...entry.spec});
 const create=(suffix,spec,args)=>{const name=prefix+'-'+suffix,entry={name,spec};owned.push(entry);const cid=run(['create','--name',name,'--label',label+'='+id,'--pull','never','--network',spec.network,'--user',spec.user,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256',...args,spec.image,...spec.command]);assert.match(cid,/^[a-f0-9]{64}$/);spec.runtimeID=cid;check(entry);return entry;};
 const logs=entry=>{try{write(entry.name+'.log',run(['logs','--tail','1000',entry.spec.runtimeID],{maxBuffer:(4<<20)}));}catch{}};
 try{
  // Fresh owned caches. No credentials, broad source mount or native network
  // enter the outbound lockfile-only module preparation process.
  for(const name of [modules,buildCache,compiled]){volumes.push(name);createFixtureGoCache(run,name,label,id);}prepareFixtureGoModules(run,{imageID:go.Id,sourceDirectory:source,privateDirectory:directory,moduleVolume:modules,labelKey:label,runID:id,containerName:prefix+'-modules-prepare'});
  phase='OFFLINE_COMPILE';const compile=create('compile',{image:go.Id,network:'none',user:'0:0',entrypoint:go.Config.Entrypoint||[],mounts:[['/src','bind',connectedMountSource(source),false],['/go/pkg/mod','volume',modules,false],['/cache','volume',buildCache,true],['/compiled','volume',compiled,true]],command:['sh','-ec','mkdir -p /cache/tmp && go test -p 1 -c -o /compiled/assessment.test ./internal/service && chmod 0555 /compiled/assessment.test && go vet -p 1 ./internal/service ./internal/fleetassessmentworker']},['--memory','512m','--cpus','1','-e','GOTOOLCHAIN=local','-e','GOPROXY=off','-e','GOSUMDB=off','-e','GOMAXPROCS=1','-e','GOMEMLIMIT=384MiB','-e','GOCACHE=/cache','-e','GOTMPDIR=/cache/tmp','--mount','type=bind,src='+source+',dst=/src,readonly','--mount','type=volume,src='+modules+',dst=/go/pkg/mod,readonly','--mount','type=volume,src='+buildCache+',dst=/cache','--mount','type=volume,src='+compiled+',dst=/compiled','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=384m','--workdir','/src']);run(['start','--attach',compile.spec.runtimeID],{timeout:15*60*1000});check(compile);assert.equal(inspect('container',compile.name).State.ExitCode,0);
  phase='START_SERVICES';const password=randomBytes(32).toString('hex'),rootUser='root'+randomBytes(12).toString('hex'),rootSecret=randomBytes(32).toString('hex'),readerUser='reader'+randomBytes(12).toString('hex'),readerSecret=randomBytes(32).toString('hex');
  const pgEnv=write('postgres.env',`POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=${password}\nPOSTGRES_DB=postgres\nPGDATA=/var/lib/postgresql/data\n`),minioEnv=write('minio.env',`MINIO_ROOT_USER=${rootUser}\nMINIO_ROOT_PASSWORD=${rootSecret}\nHOME=/tmp\n`),adminEnv=write('admin.env',`MC_HOST_root=http://${rootUser}:${rootSecret}@minio:9000\nHOME=/tmp\n`);
  run(['network','create','--internal','--driver','bridge','--label',label+'='+id,network]);networkCreated=true;validateNativeAssessmentNetwork(inspect('network',network),id,network);
  const pgImage=inspect('image',sources.postgres.Image),postgres=create('postgres',{image:pgImage.Id,network,user:pguid+':'+pggid,entrypoint:pgImage.Config.Entrypoint||[],mounts:[],command:['postgres','-c','shared_buffers=32MB','-c','max_connections=40'],postgresImageEnvironment:(pgImage.Config.Env||[]).filter(x=>x.startsWith('DOCKER_PG_LLVM_DEPS='))},['--network-alias','postgres','--env-file',pgEnv,'--memory','256m','--cpus','0.5','--tmpfs',`/var/lib/postgresql/data:rw,nosuid,nodev,size=384m,uid=${pguid},gid=${pggid},mode=0700`,'--tmpfs',`/var/run/postgresql:rw,nosuid,nodev,size=16m,uid=${pguid},gid=${pggid},mode=0700`,'--tmpfs',`/tmp:rw,nosuid,nodev,size=16m,uid=${pguid},gid=${pggid}`]);run(['start',postgres.spec.runtimeID]);
  const minio=create('minio',{image:sources.minio.Image,network,user:'10001:10001',entrypoint:['/usr/local/bin/minio'],mounts:[],command:['server','/data']},['--network-alias','minio','--env-file',minioEnv,'--entrypoint','/usr/local/bin/minio','--memory','256m','--cpus','0.5','--tmpfs','/data:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700','--tmpfs','/tmp:rw,nosuid,nodev,size=16m,uid=10001,gid=10001']);run(['start',minio.spec.runtimeID]);
  let ready=false;for(let i=0;i<60;i++){try{run(['exec',postgres.spec.runtimeID,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres','-d','postgres']);ready=true;break;}catch{assert.equal(inspect('container',postgres.name).State.Running,true);await sleep(500);}}assert.ok(ready,'Private PostgreSQL TCP startup refused');
  phase='COMMISSION_READER';const admin=create('admin',{image:mc.Id,network,user:'10001:10001',entrypoint:['/bin/sh'],mounts:[['/policy.json','bind',connectedMountSource(policyFile),false]],command:['-c','sleep 600']},['--entrypoint','/bin/sh','--env-file',adminEnv,'--memory','128m','--cpus','0.5','--tmpfs','/tmp:rw,nosuid,nodev,size=16m,uid=10001,gid=10001','--mount','type=bind,src='+policyFile+',dst=/policy.json,readonly']);run(['start',admin.spec.runtimeID]);
  const mcRun=(args,input)=>run(['exec','-i',admin.spec.runtimeID,'/usr/local/bin/mc','--config-dir','/tmp/mc','--json',...args],{input,timeout:30000});ready=false;for(let i=0;i<30;i++){try{mcRun(['ready','root']);ready=true;break;}catch{await sleep(500);}}assert.ok(ready,'Private MinIO startup refused');mcRun(['admin','policy','create','root','fixture-version-reader','/policy.json']);const created=JSON.parse(mcRun(['admin','user','add','root'],readerUser+'\n'+readerSecret+'\n'));assert.ok(created.accessKey===readerUser&&created.secretKey===readerSecret,'Private reader identity mismatch');mcRun(['admin','policy','attach','root','fixture-version-reader','--user',readerUser]);
  phase='ACTUAL_NATIVE_PIPELINE_AND_WORKER';const testEnv=write('test.env',`TEST_DATABASE_URL=postgres://postgres:${password}@postgres:5432/postgres?sslmode=disable\nFLEET_NATIVE_ASSESSMENT_LAB=ISOLATED_VERSIONED_MINIO\nFLEET_NATIVE_ASSESSMENT_WRITE_RESULT=1\nTEST_FLEET_HISTORY_S3_ENDPOINT=http://minio:9000\nTEST_FLEET_HISTORY_S3_ACCESS_KEY=${rootUser}\nTEST_FLEET_HISTORY_S3_SECRET_KEY=${rootSecret}\nTEST_FLEET_ASSESSMENT_READ_ACCESS_KEY=${readerUser}\nTEST_FLEET_ASSESSMENT_READ_SECRET_KEY=${readerSecret}\nGOMAXPROCS=1\nGOMEMLIMIT=384MiB\nHOME=/tmp\n`);
  const test=create('test',{image:go.Id,network,user:uid+':'+uid,entrypoint:go.Config.Entrypoint||[],mounts:[['/src','bind',connectedMountSource(source),false],['/results','bind',connectedMountSource(results),true],['/compiled','volume',compiled,false]],command:['/compiled/assessment.test','-test.v','-test.count=1','-test.timeout=6m','-test.run=^'+testName+'$']},['--env-file',testEnv,'--memory','512m','--cpus','1','--mount','type=bind,src='+source+',dst=/src,readonly','--mount','type=bind,src='+results+',dst=/results','--mount','type=volume,src='+compiled+',dst=/compiled,readonly','--tmpfs',`/tmp:rw,exec,nosuid,nodev,size=192m,uid=${uid},gid=${uid},mode=0700`,'--workdir','/src/internal/service']);run(['start','--attach',test.spec.runtimeID],{timeout:7*60*1000});check(test);assert.equal(inspect('container',test.name).State.ExitCode,0);
  phase='VALIDATE_RESULT';assert.deepEqual(readdirSync(results),['result.json']);const resultFile=path.join(results,'result.json'),stat=lstatSync(resultFile);assert.ok(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=4096);result=JSON.parse(readFileSync(resultFile));validateNativeAssessmentResult(result);
 }catch(error){failed=true;write('failure.log',Buffer.from(String(error.stdout||'')+'\n'+String(error.stderr||'')).subarray(0,1<<20));}
 finally{
  const errors=[];try{assert.equal(run(['info','--format','{{.ID}}']),daemon);for(const entry of [...owned].reverse())try{const present=run(['ps','--all','--filter','name=^/'+entry.name+'$','--format','{{.Names}}']).split('\n');if(!present.includes(entry.name))continue;check(entry);logs(entry);run(['rm','--force',entry.spec.runtimeID]);}catch{errors.push('container');}
   if(networkCreated||run(['network','ls','--filter','name=^'+network+'$','--format','{{.Name}}']).split('\n').includes(network))try{const object=inspect('network',network);validateNativeAssessmentNetwork(object,id,network);assert.equal(Object.keys(object.Containers||{}).length,0);run(['network','rm',object.Id]);}catch{errors.push('network');}
   for(const volume of [...volumes].reverse())try{removeFixtureGoCache(run,volume,label,id);}catch{errors.push('volume');}
   for(const kind of ['container','network','volume'])assert.equal(run(kind==='container'?['ps','--all','--filter','label='+label+'='+id,'--format','{{.ID}}']:[kind,'ls','--filter','label='+label+'='+id,'--format',kind==='volume'?'{{.Name}}':'{{.ID}}']),'');
  }catch{errors.push('cleanup');}cleanupSucceeded=errors.length===0;if(!cleanupSucceeded){failed=true;phase='OWNED_CLEANUP';}
 }
 const receipt={schema_version:'1',status:failed?'FAIL':'PASS',run_id:id,started_at:startedAt,observed_at:new Date().toISOString(),source_snapshot_kind:'GIT_INDEX_BLOBS',source_tree:captured.tree,source_sha256:manifest,host_sha256:captured.hostHashes,source_manifest_sha256:hash(JSON.stringify(manifest)),go_image_id:go.Id,postgres_image_id:sources.postgres.Image,minio_image_id:sources.minio.Image,mc_image_id:mc.Id,policy_sha256:hash(captured.files.get(policyPath)),fixture_policy_sha256:hash(policy),phase,cleanup_succeeded:cleanupSucceeded,published_ports:0,main_resources_modified:false,cloud_credentials_used:false,fixture:true,customer_execution_authorized:false,verified_saving:null,...(!failed?{result_sha256:hash(readFileSync(path.join(results,'result.json'))),native_transport:'PROVIDER_SHAPED_FIXTURE',immutable_worker_replay:true,capacity_status:'UNAVAILABLE'}:{})};
 const receiptRaw=JSON.stringify(receipt,null,2)+'\n';assert.ok(Buffer.byteLength(receiptRaw)<=(128<<10));write(failed?'failure-receipt.json':'acceptance.json',receiptRaw);if(failed)throw new Error('Private native assessment fixture failed; bounded receipt retained.');console.log('Native assessment fixture PASS; actual versioned raw ingestion, restricted worker publication and cleanup completed.');
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)await fleetNativeAssessmentLab();
