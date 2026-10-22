// Explicit local-fixture acceptance. No Azure/GCP tokens, queries, cloud CLI or
// customer calls. Provider responses are HTTP transport doubles in Go tests.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmodSync, copyFileSync, lstatSync, mkdirSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { localDockerEndpoint } from './kubernetes-bootstrap.mjs';
import { validateRecoverySources } from './postgres-recovery-lab.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const goImage='golang:1.27.3-bookworm@sha256:32fa283222e2905d9fee971f60c842e5c815fdc036cf7ea599bf36bd7ca8f67f';
const roleTests=['TestPublicationPostgresIsolationRestartAndAuthorityBoundary','TestPublicationPostgresNativeOrderingOutOfOrderCompletionAndRevival','TestPublicationRealPostgresVersionedMinIOAndClickHouse'];
const environment=o=>Object.fromEntries((o.Config?.Env||[]).map(line=>{const at=line.indexOf('=');return[line.slice(0,at),line.slice(at+1)];}));
export function validatePublicationSources(sources,workspace){
  const {api,postgres,minio,clickhouse}=sources;
  validateRecoverySources(api,postgres,workspace);
  for(const [object,service] of [[minio,'minio'],[clickhouse,'clickhouse']]){
    assert.equal(object.State?.Running,true,'Only explicit running local fixture storage is permitted');
    assert.equal(object.Config?.Labels?.['com.docker.compose.service'],service);
    assert.equal(path.resolve(object.Config?.Labels?.['com.docker.compose.project.working_dir']||''),path.resolve(workspace));
    assert.equal(object.Config?.Labels?.['com.docker.compose.project'],api.Config.Labels['com.docker.compose.project']);
    assert.ok(!Object.keys(environment(object)).some(key=>/^(AWS_|AZURE_|GOOGLE_|GCP_|ARM_)/.test(key)),'Local fixture storage may not carry cloud credentials');
  }
  const project=api.Config.Labels['com.docker.compose.project'];
  const common=Object.keys(postgres.NetworkSettings?.Networks||{}).filter(name=>name===project+'_private'&&[api,minio,clickhouse].every(o=>Object.hasOwn(o.NetworkSettings?.Networks||{},name)));
  assert.equal(common.length,1,'Exact shared Compose private network required');
  return common[0];
}
export function privatePublicationEnvironment(sources){
  const pg=environment(sources.postgres),s3=environment(sources.minio),ch=environment(sources.clickhouse);
  for(const value of [pg.POSTGRES_PASSWORD,s3.MINIO_ROOT_USER,s3.MINIO_ROOT_PASSWORD,ch.CLICKHOUSE_USER,ch.CLICKHOUSE_PASSWORD])assert.ok(value&&value.length<4096&&!/[\r\n\0]/.test(value),'Explicit private fixture credentials required');
  assert.equal(pg.POSTGRES_USER||'postgres','postgres','Only this local fixture administration identity is accepted');
  return [
    'TEST_MULTICLOUD_ADMIN_URL=postgres://postgres:'+encodeURIComponent(pg.POSTGRES_PASSWORD)+'@postgres:5432/postgres?sslmode=disable',
    'TEST_MULTICLOUD_STORAGE=true',
    'TEST_MULTICLOUD_S3_ENDPOINT=http://minio:9000',
    'TEST_MULTICLOUD_S3_ACCESS_KEY='+s3.MINIO_ROOT_USER,
    'TEST_MULTICLOUD_S3_SECRET_KEY='+s3.MINIO_ROOT_PASSWORD,
    'TEST_MULTICLOUD_CH_ENDPOINT=http://clickhouse:8123',
    'TEST_MULTICLOUD_CH_USER='+ch.CLICKHOUSE_USER,
    'TEST_MULTICLOUD_CH_PASSWORD='+ch.CLICKHOUSE_PASSWORD,
  ].join('\n')+'\n';
}
function privateDirectory(runID){
  const directory=path.join(root,'work','private','multicloud-publication',runID);mkdirSync(directory,{recursive:true,mode:0o700});
  const resolved=realpathSync(directory),suffix=path.relative(realpathSync(root),resolved);assert.ok(suffix&&!suffix.startsWith('..')&&!path.isAbsolute(suffix));chmodSync(resolved,0o700);
  if(process.platform==='win32'){const account=execFileSync('whoami.exe',[],{encoding:'utf8',windowsHide:true}).trim();assert.match(account,/^[^\r\n]+\\[^\r\n]+$/);execFileSync('icacls.exe',[resolved,'/inheritance:r','/grant:r',account+':(OI)(CI)F'],{windowsHide:true,stdio:'pipe'});}
  return resolved;
}
export function validateOwnedPublicationContainer(object,runID){assert.equal(object.Config?.Labels?.['finops.local-publication.run'],runID);assert.equal(object.Name?.replace(/^\//,''),'finops-multicloud-publication-'+runID.replaceAll('-',''));}
export function publicationSourceNames(names){return names.filter(name=>/^[a-z][a-z0-9_]*\.go$/.test(name)).sort();}
export function publicationSourceSnapshot(directory){
  const snapshot=path.join(directory,'source');mkdirSync(path.join(snapshot,'internal','multicloud'),{recursive:true,mode:0o700});mkdirSync(path.join(snapshot,'migrations'),{mode:0o700});
  const copy=relative=>{const source=path.join(root,relative),suffix=path.relative(realpathSync(root),realpathSync(source));assert.ok(suffix&&!suffix.startsWith('..')&&!path.isAbsolute(suffix)&&lstatSync(source).isFile()&&!lstatSync(source).isSymbolicLink(),'Only ordinary workspace source files may be staged');copyFileSync(source,path.join(snapshot,relative));};
  for(const file of ['go.mod','go.sum','migrations/001_control_plane.sql','migrations/019_multicloud_observations.sql'])copy(file);
  for(const file of publicationSourceNames(readdirSync(path.join(root,'internal','multicloud'))))copy(path.join('internal','multicloud',file));
  // This allowlisted snapshot contains public source only. On Linux the host
  // runner owns it, whereas the test runs as container root with ALL capabilities
  // dropped. UID0 then has no DAC_OVERRIDE and cannot read host-owned0700 dirs.
  // Keep the enclosing private run/credentials0700/0600, and make only source
  // readable/searchable without granting writes or adding a capability.
  const readonly=directory=>{for(const entry of readdirSync(directory,{withFileTypes:true})){const name=path.join(directory,entry.name);assert.ok(!entry.isSymbolicLink(),'Source snapshot cannot contain symbolic links');if(entry.isDirectory())readonly(name);else{assert.ok(entry.isFile(),'Source snapshot must contain ordinary files only');chmodSync(name,0o444);}}chmodSync(directory,0o555);};
  readonly(snapshot);
  return snapshot;
}
export async function publicationLab(){
  assert.equal(process.argv.length,2,'No alternate source, endpoint, credentials, context or remote arguments accepted');
  const invoke=(args,options={})=>execFileSync('docker',args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:120_000,maxBuffer:8<<20,stdio:['pipe','pipe','pipe'],...options}).trim();
  if(process.env.DOCKER_HOST)assert.ok(localDockerEndpoint(process.env.DOCKER_HOST),'Remote Docker endpoints refused');
  const contextName=invoke(['context','show']);const context=JSON.parse(invoke(['context','inspect',contextName]))[0];assert.ok(localDockerEndpoint(context.Endpoints?.docker?.Host),'Remote Docker context refused');
  // Pin the inspected context so a later global context change cannot redirect
  // credentials or fixture mutations to another daemon.
  const run=(args,options)=>invoke(['--context',contextName,...args],options);
  const sources={};for(const service of ['api','postgres','minio','clickhouse']){const id=run(['compose','ps','-q',service]);assert.match(id,/^[a-f0-9]{64}$/);sources[service]=JSON.parse(run(['inspect','--type','container',id]))[0];}
  const network=validatePublicationSources(sources,root);const runID=randomUUID();const directory=privateDirectory(runID);const stagedSource=publicationSourceSnapshot(directory);const envFile=path.join(directory,'acceptance.env');writeFileSync(envFile,privatePublicationEnvironment(sources),{flag:'wx',mode:0o600});chmodSync(envFile,0o600);
  let image;try{image=JSON.parse(run(['image','inspect',goImage]))[0];}catch{run(['pull',goImage],{timeout:180_000});image=JSON.parse(run(['image','inspect',goImage]))[0];}assert.match(image.Id,/^sha256:[a-f0-9]{64}$/);
  const container='finops-multicloud-publication-'+runID.replaceAll('-','');const started=Date.now();let passed=false;
  try{
    const command='go test ./internal/multicloud -count=1 -v -run "^('+roleTests.join('|')+')$" && go vet ./internal/multicloud';
    const output=run(['run','--rm','--name',container,'--label','finops.local-publication.run='+runID,'--pull','never','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--memory','1536m','--cpus','2','--network',network,'--env-file',envFile,'-e','AWS_EC2_METADATA_DISABLED=true','--mount','type=bind,src='+stagedSource+',dst=/src,readonly','--mount','type=volume,src=finops-go-mod,dst=/go/pkg/mod','--mount','type=volume,src=finops-go-build,dst=/root/.cache/go-build','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=512m','-w','/src',image.Id,'sh','-c',command],{timeout:300_000});
    writeFileSync(path.join(directory,'acceptance.log'),output+'\n',{flag:'wx',mode:0o600});
    for(const name of roleTests)assert.ok(output.includes('--- PASS: '+name+' '),'Required actual local publication test did not pass: '+name);
    assert.ok(!output.includes('--- SKIP:'),'Actual publication acceptance may not silently skip');passed=true;
    writeFileSync(path.join(directory,'acceptance.json'),JSON.stringify({schema_version:'1',status:'PASS',run_id:runID,tests:roleTests,duration_seconds:(Date.now()-started)/1000,provider_calls:'HTTP_TRANSPORT_DOUBLES_ONLY',stores:'ACTUAL_LOCAL_POSTGRESQL_VERSIONED_MINIO_CLICKHOUSE',authority:'PROVISIONAL_OBSERVATIONS_ONLY',main_schema_modified:false},null,2)+'\n',{flag:'wx',mode:0o600});
    console.log('Multicloud publication lab PASS: 3 actual local PostgreSQL/MinIO/ClickHouse acceptance tests; native provider transport doubles; no cloud query or execution authority.');
  }catch(error){const printable=value=>typeof value==='string'?value:Buffer.isBuffer(value)?value.toString('utf8'):'';const diagnostic=printable(error.stdout)+'\n'+printable(error.stderr);if(diagnostic.trim())writeFileSync(path.join(directory,'failure.log'),diagnostic,{mode:0o600});throw new Error('Local multicloud publication acceptance failed; diagnostics remain in its private workspace run directory.');}
  finally{
    let object;try{object=JSON.parse(run(['inspect','--type','container',container]))[0];}catch{/* --rm already removed the exact test process. */}
    if(object){validateOwnedPublicationContainer(object,runID);run(['rm','-f',container]);}
    if(!passed)console.error('No publication acceptance recorded. Inspect private diagnostics and exact test ownership tags before cleaning interrupted fixtures.');
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)publicationLab().catch(()=>{console.error('Multicloud publication lab failed; no credentials or native billing payloads are logged.');process.exitCode=1;});
