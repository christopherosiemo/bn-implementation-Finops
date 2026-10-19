// Explicit local commissioning, followed by exactly one real OIDC browser case.
// Run ordinary browser cases first: operating-loop resets the fixture tenant.
// The reader below is a labelled deterministic September test double. Its normal
// pipeline receipts do not establish customer-native or historical authority.
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {chmodSync,copyFileSync,lstatSync,mkdirSync,readFileSync,readdirSync,realpathSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {recoveryDockerEndpoint,localRecoveryDockerEndpoint,validateUpgradeFixtureSources,assertMigrationManifest} from './lib/recovery-upgrade.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const label='finops.group-fixture-commission.run';
const fixture='examples/group-fixture-commission';
const sha=x=>createHash('sha256').update(x).digest('hex');
const digest=/^[a-f0-9]{64}$/;
const imageDigest=/^sha256:[a-f0-9]{64}$/;
export const commissionTitle='real OIDC two registered groups produce a persisted isolated fixture selection while unknown-program approval and runtime remain refused';
export const commissionRegistration=Object.freeze({kind:'AWS_CUR2',payer_account_id:'111122223333',usage_account_ids:['111122223333'],region:'eu-west-1',export_arn:'arn:aws:bcm-data-exports:us-east-1:111122223333:export/fixture-export',bucket:'finops-fixture-cur2',bucket_owner:'111122223333',prefix:'DETERMINISTIC_FIXTURE_GROUP/cur/',read_role_binding_id:'DETERMINISTIC_FIXTURE_GROUP_COMMISSION'});
export const commissionBases={terraform:'hashicorp/terraform:1.16.0@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e',go:'golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61'};
const environment=o=>Object.fromEntries((o.Config?.Env||[]).map(v=>{const at=v.indexOf('=');return [v.slice(0,at),v.slice(at+1)];}));

export function validateCommissionTooling(raw){
 const lines=String(raw).replaceAll('\r\n','\n').split('\n').map(x=>x.trim()).filter(x=>x&&!x.startsWith('#'));
 assert.deepEqual(lines,[
  'FROM '+commissionBases.terraform+' AS terraform','FROM '+commissionBases.go,'WORKDIR /src','ENV GOTOOLCHAIN=local GOMAXPROCS=1','COPY go.mod go.sum ./',
  'RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download','COPY internal ./internal','COPY cmd/group-fixture-commission ./cmd/group-fixture-commission','COPY cmd/group-fixture-preparer ./cmd/group-fixture-preparer',
  'RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build,sharing=locked CGO_ENABLED=0 go build -p 1 -trimpath -ldflags="-s -w" -o /compiled/commission ./cmd/group-fixture-commission && CGO_ENABLED=0 go build -p 1 -trimpath -ldflags="-s -w" -o /compiled/preparer ./cmd/group-fixture-preparer',
  'COPY --from=terraform /bin/terraform /usr/local/bin/terraform','USER 10001:10001','WORKDIR /tmp','CMD []']);
}

export function validateCommissionSources(sources,workspace,api,issuer,web='http://localhost:3000'){
 const identity=validateUpgradeFixtureSources(sources,workspace,api,issuer);
 for(const service of ['ingester','minio','clickhouse','economics']){
  const o=sources[service],labels=o?.Config?.Labels||{},networks=Object.values(o?.NetworkSettings?.Networks||{});
  assert.equal(o?.State?.Running,true);assert.match(o.Id,digest);assert.match(o.Image,imageDigest);
  assert.equal(labels['com.docker.compose.service'],service);assert.equal(labels['com.docker.compose.project'],identity.project);assert.equal(path.resolve(labels['com.docker.compose.project.working_dir']||''),path.resolve(workspace));
  assert.equal(networks.length,1);assert.equal(networks[0].NetworkID,identity.network);assert.notEqual(o.HostConfig?.NetworkMode,'host');
  assert.ok(!Object.values(o.NetworkSettings?.Ports||{}).some(v=>v?.length),'Private stores and ingester cannot publish ports');
 }
 const e=environment(sources.ingester),database=new URL(e.DATABASE_URL);
 assert.equal(e.FIXTURE_MODE,'true');assert.equal(e.APP_ROLE,'ingester');assert.notEqual(e.DATA_MODE,'aws');
 assert.equal(database.protocol,'postgres:');assert.equal(database.hostname,'postgres');assert.equal(database.port,'5432');assert.equal(database.pathname,'/finops');assert.equal(database.username,'finops_ingester');assert.ok(database.password);assert.equal(database.search,'?sslmode=disable');assert.equal(database.hash,'');
 for(const[k,v]of Object.entries({OBJECT_ENDPOINT:'http://minio:9000',OBJECT_BUCKET_RAW:'finops-raw',OBJECT_REGION:'eu-west-1',CLICKHOUSE_URL:'http://clickhouse:8123',CLICKHOUSE_DATABASE:'finops',CLICKHOUSE_USER:'finops',ECONOMICS_URL:'http://economics:8000'}))assert.equal(e[k],v);
 for(const k of ['OBJECT_ACCESS_KEY','OBJECT_SECRET_KEY','CLICKHOUSE_PASSWORD','ECONOMICS_TOKEN'])assert.ok(typeof e[k]==='string'&&e[k].length>0&&e[k].length<=8192&&!/[\0\r\n]/.test(e[k]));
 assert.equal(environment(sources.economics).FIXTURE_MODE,'true');
 const w=sources.web,labels=w?.Config?.Labels||{},networks=Object.values(w?.NetworkSettings?.Networks||{}),webURL=new URL(web);
 assert.equal(w?.State?.Running,true);assert.match(w.Id,digest);assert.match(w.Image,imageDigest);assert.equal(labels['com.docker.compose.service'],'web');assert.equal(labels['com.docker.compose.project'],identity.project);assert.equal(path.resolve(labels['com.docker.compose.project.working_dir']||''),path.resolve(workspace));
 assert.equal(networks.length,1);assert.equal(networks[0].NetworkID,identity.network);assert.notEqual(w.HostConfig?.NetworkMode,'host');assert.equal(environment(w).API_UPSTREAM,'api:8080');
 assert.equal(webURL.protocol,'http:');assert.equal(webURL.hostname,'localhost');assert.equal(webURL.pathname,'/');assert.equal(webURL.username+webURL.password+webURL.search+webURL.hash,'');
 assert.deepEqual(w.NetworkSettings?.Ports?.['8080/tcp'],[{HostIp:'127.0.0.1',HostPort:webURL.port}]);assert.equal(Object.values(w.NetworkSettings?.Ports||{}).filter(x=>x?.length).length,1);
 for(const[k,v]of Object.entries(e))assert.ok(!/^(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ROLE_ARN|AWS_WEB_IDENTITY_TOKEN_FILE|AZURE_|GOOGLE_|GCP_|ARM_)/.test(k)||!v,'Ambient customer provider authority refused');
 return identity;
}

export function validateCommissionJob(o,{runID,name,image,network,imageEnvironment}){
 assert.match(runID,/^[a-f0-9-]{36}$/);assert.match(image,imageDigest);assert.match(network,digest);
 assert.equal(o.Name,'/'+name);assert.equal(o.Config?.Labels?.[label],runID);assert.equal(o.Image,image);assert.equal(o.Config?.User,'10001:10001');
 assert.equal(o.HostConfig?.NetworkMode,network);assert.equal(o.HostConfig?.Privileged,false);assert.equal(o.HostConfig?.ReadonlyRootfs,true);assert.deepEqual(o.HostConfig?.CapDrop,['ALL']);assert.deepEqual(o.HostConfig?.CapAdd||[],[]);
 assert.ok(o.HostConfig?.SecurityOpt?.includes('no-new-privileges'));assert.equal(Object.keys(o.HostConfig?.PortBindings||{}).length,0);assert.equal((o.HostConfig?.Devices||[]).length,0);assert.deepEqual(o.HostConfig?.Binds||[],[]);
 assert.deepEqual(o.Config?.Entrypoint,['/compiled/commission']);assert.deepEqual(o.Config?.Cmd||[],[]);assert.equal(o.Config?.OpenStdin,true);
 const tmpfs=o.HostConfig?.Tmpfs||{};assert.deepEqual(Object.keys(tmpfs).sort(),['/secrets','/tmp']);
 assert.equal(tmpfs['/secrets'],'rw,nosuid,nodev,noexec,size=128k,uid=10001,gid=10001,mode=0700');assert.equal(tmpfs['/tmp'],'rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700');
 assert.ok((o.Mounts||[]).every(m=>m.Type==='tmpfs'&&['/secrets','/tmp'].includes(m.Destination)&&!m.Source));
 assert.deepEqual([...(o.Config?.Env||[])].sort(),[...imageEnvironment,'HOME=/tmp','GOMEMLIMIT=384MiB'].sort());
 const networks=Object.values(o.NetworkSettings?.Networks||{});if(o.State?.Running){assert.equal(networks.length,1);assert.equal(networks[0].NetworkID,network);}
}

export function validateCommissionSource(row){
 assert.match(row?.id,/^[a-f0-9-]{36}$/);assert.equal(row.tenant_id,'tenant-demo');assert.equal(row.enabled,true);assert.notEqual(row.revoked,true);
 for(const[k,v]of Object.entries(commissionRegistration))assert.deepEqual(row[k],v,'Only exact deterministic fixture registration is allowed');
 return row.id;
}
export function validateCommissionSync(result,sourceID,now=Date.now()){
 assert.equal(result?.status,'HEALTHY');assert.equal(result.mode,'SYNC_SOURCE');assert.equal(result.fixture,true);assert.equal(result.source_id,sourceID);assert.equal(result.provider_adapter,'DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026');assert.equal(result.customer_execution_authorized,false);assert.equal(result.verified_saving,null);assert.match(result.config_sha256,digest);
 const time=Date.parse(result.last_sync_at);assert.ok(Number.isFinite(time)&&time<=now+1000&&time>=now-60000);return result;
}

function privateDirectory(id){
 const directory=path.join(root,'work','private','group-fixture-commission',id);mkdirSync(directory,{recursive:true,mode:0o700});const actual=realpathSync(directory),relative=path.relative(realpathSync(root),actual);assert.ok(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative));chmodSync(actual,0o700);
 if(process.platform==='win32'){const account=execFileSync('whoami.exe',[],{encoding:'utf8',windowsHide:true}).trim();assert.match(account,/^[^\r\n]+\\[^\r\n]+$/);execFileSync('icacls.exe',[actual,'/inheritance:r','/grant:r',account+':(OI)(CI)F'],{windowsHide:true,stdio:'pipe'});}return actual;
}
// Match the reviewed release schema exactly. A fresh Compose bootstrap applies
// every migration, so accepting only an older prefix rejects an additive upgrade.
// A future runtime migration still fails assertMigrationManifest below.
export function commissionMigrationManifest(directory){
 const names=readdirSync(directory).filter(x=>/^\d{3}_[a-z0-9_]+\.sql$/.test(x)).sort();
 assert.equal(names.length,38);
 assert.deepEqual(names.map(x=>Number(x.slice(0,3))),Array.from({length:38},(_,n)=>n+1));
 assert.equal(names.at(-1),'038_fleet_decision_credential_scope.sql');
 const manifest=Object.fromEntries(names.map(name=>{const file=path.join(directory,name),info=lstatSync(file);assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.size>0&&info.size<=(2<<20));return[name,sha(readFileSync(file))];}));
 assert.equal(manifest['037_fleet_joint_decisions.sql'],'54a44013471e1ca3c8e6990d3f554a0f986133441a3a9762b37eabc0fb51f051','Migration037 must equal the independently reviewed release bytes');
 assert.equal(manifest['038_fleet_decision_credential_scope.sql'],'789d53114532af2b831fc2e2c011b5d15e7df2b72affafb2068fc4a84a6ee984','Migration038 must equal the independently reviewed credential scope bytes');
 return manifest;
}

function snapshot(directory){
 const source=path.join(directory,'source');mkdirSync(source,{mode:0o755});const hashes={};
 const copy=relative=>{const input=path.join(root,relative),info=lstatSync(input),within=path.relative(realpathSync(root),realpathSync(input));assert.ok(within&&!within.startsWith('..')&&!path.isAbsolute(within)&&!info.isSymbolicLink());
  if(info.isDirectory()){mkdirSync(path.join(source,relative),{recursive:true,mode:0o755});for(const name of readdirSync(input).sort())if((!name.startsWith('.')&&lstatSync(path.join(input,name)).isDirectory())||/^[A-Za-z0-9_]+\.go$/.test(name))copy(path.join(relative,name));}
  else{assert.ok(info.isFile());mkdirSync(path.dirname(path.join(source,relative)),{recursive:true,mode:0o755});copyFileSync(input,path.join(source,relative));chmodSync(path.join(source,relative),0o444);hashes[relative.replaceAll('\\','/')]=sha(readFileSync(path.join(source,relative)));}};
 for(const p of ['go.mod','go.sum','internal','cmd/group-fixture-commission','cmd/group-fixture-preparer',fixture+'/Dockerfile'])copy(p);
 validateCommissionTooling(readFileSync(path.join(source,fixture,'Dockerfile'),'utf8'));return {source,hashes};
}
function fileEnvironment(){return Object.fromEntries(readFileSync(path.join(root,'.env'),'utf8').split(/\r?\n/).filter(x=>x&&!x.startsWith('#')).map(x=>{const at=x.indexOf('=');return [x.slice(0,at),x.slice(at+1)];}));}
const sqlLiteral=value=>{assert.ok(typeof value==='string'&&!value.includes('\0'));return "'"+value.replaceAll("'","''")+"'";};

export async function groupFixtureCommission(){
 assert.equal(process.argv.length,2,'No alternate endpoints, credentials, target source, images or commands are accepted');
 assert.ok(!process.env.BUILDKIT_HOST&&!process.env.BUILDX_BUILDER&&!process.env.NODE_OPTIONS);
 const runID=randomUUID(),prefix='finops-group-commission-'+runID.replaceAll('-',''),directory=privateDirectory(runID);
 const privateEnv=fileEnvironment(),api='http://localhost:'+(privateEnv.API_PORT||8080),issuer='http://localhost:'+(privateEnv.KEYCLOAK_PORT||8081)+'/realms/finops',web='http://localhost:'+(privateEnv.WEB_PORT||3000);
 const dockerEnvironment={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnvironment[key];
 const raw=(args,options={})=>execFileSync('docker',args,{cwd:root,encoding:'utf8',windowsHide:true,env:dockerEnvironment,timeout:120000,maxBuffer:8<<20,stdio:['pipe','pipe','pipe'],...options}).trim();
 const contextName=raw(['context','show']),context=JSON.parse(raw(['context','inspect',contextName]))[0],endpoint=recoveryDockerEndpoint(contextName,context,process.env.DOCKER_HOST);
 const run=(args,options)=>raw(['--host',endpoint,...args],options),inspect=(kind,name)=>JSON.parse(run(['inspect','--type',kind,name]))[0],daemon=run(['info','--format','{{.ID}}']);assert.ok(daemon);
 const sources={};for(const service of ['api','worker','executor','temporal','postgres','keycloak','ingester','minio','clickhouse','economics','web']){const id=run(['compose','ps','-q',service]);assert.match(id,digest);sources[service]=inspect('container',id);}
 const identity=validateCommissionSources(sources,root,api,issuer,web),ingester=environment(sources.ingester);
 const network=JSON.parse(run(['network','inspect',identity.network]))[0];assert.equal(network.Driver,'bridge');assert.equal(network.Labels?.['com.docker.compose.project'],identity.project);assert.equal(network.Labels?.['com.docker.compose.network'],'private');
 const builder=run(['buildx','inspect','default']);assert.match(builder,/^Driver:\s+docker\s*$/m);const points=[...builder.matchAll(/^Endpoint:\s+([^\r\n]+)\s*$/gm)].map(x=>x[1].trim());assert.equal(points.length,1);
 const builderContext=localRecoveryDockerEndpoint(points[0])?null:points[0]===contextName?context:JSON.parse(raw(['context','inspect',points[0]]))[0];const builderEndpoint=builderContext?recoveryDockerEndpoint(builderContext.Name,builderContext):points[0];assert.equal(raw(['--host',builderEndpoint,'info','--format','{{.ID}}']),daemon);
 const psql=sql=>run(['exec','--interactive',sources.postgres.Id,'psql','-X','-w','-v','ON_ERROR_STOP=1','-U','postgres','-d','finops','-Atq'],{input:sql});
 let expected;
 try{
  expected=commissionMigrationManifest(path.join(root,'migrations'));
  assertMigrationManifest(JSON.parse(psql('SELECT jsonb_object_agg(filename,sha256)::text FROM public.schema_migrations;')),expected);
 }catch{
  writeFileSync(path.join(directory,'failure-receipt.json'),JSON.stringify({schema_version:'1',status:'FAIL',run_id:runID,phase:'MIGRATION_PREFLIGHT',reason_code:'REVIEWED_SCHEMA_NOT_CONFIRMED',cleanup_succeeded:true,resources_created:false,fixture:true,customer_execution_authorized:false,verified_saving:null})+'\n',{flag:'wx',mode:0o600});
  throw new Error('Reviewed fixture schema not confirmed; no commissioning resources created.');
 }
 const {source,hashes}=snapshot(directory),sourceSHA=sha(JSON.stringify(hashes)),runnerSHA=sha(readFileSync(fileURLToPath(import.meta.url))),dependencySHA=sha(readFileSync(path.join(root,'scripts/lib/recovery-upgrade.mjs')));
 const tag=prefix+':tooling',login='fixture_commission_'+runID.replaceAll('-',''),password=randomBytes(32).toString('hex'),marker='group-fixture-commission:'+runID;
 const owned=new Map();let image,profile,sourceID,roleCreated=false,retainImage=false,browser,step='BUILD',failure,stopping=false,syncs=[],browserExit,installation;
 const verifyDaemon=()=>assert.equal(run(['info','--format','{{.ID}}']),daemon);
 const checkJob=(name)=>{const spec=owned.get(name);assert.ok(spec);return validateCommissionJob(inspect('container',name),spec);};
 const removeJob=name=>{verifyDaemon();if(!run(['ps','--all','--filter','name=^/'+name+'$','--format','{{.Names}}']).split('\n').includes(name))return;checkJob(name);run(['rm','--force',name]);owned.delete(name);};
 function job(config,files){
  const name=prefix+'-job-'+randomUUID().replaceAll('-','');const spec={runID,name,image:image.Id,network:identity.network,imageEnvironment:image.Config.Env||[]};owned.set(name,spec);
  run(['create','--interactive','--name',name,'--label',label+'='+runID,'--pull','never','--network',identity.network,'--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','512m','--cpus','1','-e','HOME=/tmp','-e','GOMEMLIMIT=384MiB','--tmpfs','/secrets:rw,nosuid,nodev,noexec,size=128k,uid=10001,gid=10001,mode=0700','--tmpfs','/tmp:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700','--entrypoint','/compiled/commission',image.Id]);checkJob(name);
  const input=JSON.stringify({job:config,files:Object.fromEntries(Object.entries(files).map(([k,v])=>[k,Buffer.from(v).toString('base64')]))});assert.ok(Buffer.byteLength(input)<=65536);
  try{const output=run(['start','--attach','--interactive',name],{input,timeout:130000});checkJob(name);assert.equal(inspect('container',name).State?.ExitCode,0);assert.ok(output.length<=65536);return JSON.parse(output);}finally{removeJob(name);}
 }
 const config=mode=>({schema_version:'1',mode,fixture:true,tenant_id:'tenant-demo',database_file:'/secrets/database'});
 const sync=()=>{const result=job({...config('SYNC_SOURCE'),source_id:sourceID,storage:{object_access_file:'/secrets/object-access',object_secret_file:'/secrets/object-secret',clickhouse_password_file:'/secrets/clickhouse-password',economics_token_file:'/secrets/economics-token'}},{database:ingester.DATABASE_URL,'object-access':ingester.OBJECT_ACCESS_KEY,'object-secret':ingester.OBJECT_SECRET_KEY,'clickhouse-password':ingester.CLICKHOUSE_PASSWORD,'economics-token':ingester.ECONOMICS_TOKEN});syncs.push(validateCommissionSync(result,sourceID));assert.ok(syncs.length<=40);};
 const roleState=()=>JSON.parse(psql(`SELECT jsonb_build_object('name',r.rolname,'login',r.rolcanlogin,'super',r.rolsuper,'replication',r.rolreplication,'bypass',r.rolbypassrls,'createdb',r.rolcreatedb,'createrole',r.rolcreaterole,'comment',shobj_description(r.oid,'pg_authid'),'parents',(SELECT jsonb_agg(p.rolname ORDER BY p.rolname) FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid WHERE m.member=r.oid)) FROM pg_roles r WHERE r.rolname=${sqlLiteral(login)};`));
 const validateRole=()=>{const r=roleState();assert.deepEqual(r,{name:login,login:true,super:false,replication:false,bypass:false,createdb:false,createrole:false,comment:marker,parents:['finops_group_fixture']});};
 try{
  run(['build','--builder','default','--pull=false','--label',label+'='+runID,'--tag',tag,'--file',path.join(source,fixture,'Dockerfile'),source],{timeout:600000});image=inspect('image',tag);assert.equal(image.Config?.Labels?.[label],runID);assert.equal(image.Config?.User,'10001:10001');assert.match(image.Id,imageDigest);
  step='INSTALL';psql(`BEGIN; CREATE ROLE ${login} LOGIN PASSWORD ${sqlLiteral(password)} IN ROLE finops_group_fixture; COMMENT ON ROLE ${login} IS ${sqlLiteral(marker)}; COMMIT;`);roleCreated=true;validateRole();
  const database=`postgres://${login}:${password}@postgres:5432/finops?sslmode=disable`;retainImage=true;
  installation=job({...config('INSTALL_PROFILE'),image_sha256:image.Id.slice(7),source_sha256:sourceSHA,receipt_id:runID},{database});assert.equal(installation.status,'INSTALLED');assert.equal(installation.fixture,true);assert.equal(installation.customer_execution_authorized,false);assert.equal(installation.verified_saving,null);assert.equal(installation.image_sha256,image.Id.slice(7));assert.equal(installation.source_sha256,sourceSHA);assert.equal(installation.receipt_id,runID);assert.equal(installation.actual_terraform_version,'1.16.0');assert.match(installation.actual_git_version,/^git version \d+\.\d+\.\d+$/);assert.match(installation.actual_platform,/^linux_(amd64|arm64)$/);profile=installation.profile;assert.match(profile?.id,/^fixture-profile-[a-f0-9-]{36}$/);assert.equal(profile.installation?.toolchain_image_sha256,image.Id.slice(7));
  step='REGISTER';const tokenReply=await fetch(issuer+'/protocol/openid-connect/token',{method:'POST',redirect:'error',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'password',client_id:'console',username:'owner',password:privateEnv.DEMO_PASSWORD}),signal:AbortSignal.timeout(15000)});assert.equal(tokenReply.status,200);const {access_token}=await tokenReply.json();assert.ok(access_token);
  const dashboardReply=await fetch(api+'/v1/dashboard',{redirect:'error',headers:{Authorization:'Bearer '+access_token},signal:AbortSignal.timeout(15000)});assert.equal(dashboardReply.status,200);assert.equal((await dashboardReply.json()).fixture,true);
  const registration=await fetch(api+'/v1/source-connections',{method:'POST',redirect:'error',headers:{Authorization:'Bearer '+access_token,'Content-Type':'application/json','Idempotency-Key':runID},body:JSON.stringify(commissionRegistration),signal:AbortSignal.timeout(30000)});assert.equal(registration.status,201);sourceID=validateCommissionSource(await registration.json());
  step='SYNC';sync();writeFileSync(path.join(directory,'commissioned.json'),JSON.stringify({schema_version:'1',status:'COMMISSIONED_FIXTURE_ONLY',run_id:runID,source_id:sourceID,profile_id:profile.id,tooling_image_id:image.Id,installation,source_manifest_sha256:sourceSHA,source_sha256:hashes,runner_sha256:runnerSHA,harness_dependency_sha256:dependencySHA,realm:'ISOLATED_FIXTURE',provider_adapter:'DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026',customer_native_authority:false,customer_execution_authorized:false,verified_saving:null},null,2)+'\n',{mode:0o600});
  console.log(JSON.stringify({status:'COMMISSIONED_FIXTURE_ONLY',run_id:runID,source_id:sourceID,profile_id:profile.id,repeat_sync_seconds:20,customer_execution_authorized:false}));
  step='BROWSER';const playwright=path.join(root,'frontend/node_modules/@playwright/test/cli.js'),output=path.join(directory,'browser');mkdirSync(output,{mode:0o700});const log=path.join(output,'run.log');let browserFailure;
  browser=spawn(process.execPath,[playwright,'test','tests/fleet-fixture-live.spec.ts','--output',path.join(output,'results')],{cwd:path.join(root,'frontend'),windowsHide:true,env:{...process.env,FINOPS_WEB_URL:web,FINOPS_E2E_USER:'owner',FINOPS_E2E_PASSWORD:privateEnv.DEMO_PASSWORD,FINOPS_E2E_FLEET_SOURCE_ID:sourceID,FINOPS_E2E_FIXTURE_PROFILE_ID:profile.id,PLAYWRIGHT_HTML_OUTPUT_DIR:path.join(output,'html')},stdio:['ignore','pipe','pipe']});
  const exited=new Promise(resolve=>{browser.once('error',()=>{browserFailure=true;resolve(-1);});browser.once('close',code=>resolve(code));});
  browser.stdout.on('data',chunk=>{writeFileSync(log,chunk,{flag:'a',mode:0o600});process.stdout.write(chunk);});browser.stderr.on('data',chunk=>writeFileSync(log,chunk,{flag:'a',mode:0o600}));
  const deadline=Date.now()+180000;let next=Date.now()+20000;
  while(!stopping){const wait=Math.min(next-Date.now(),deadline-Date.now());if(wait<=0){assert.ok(Date.now()<deadline,'Fixed browser commissioning interval expired');sync();next=Date.now()+20000;continue;}
   const result=await Promise.race([exited.then(code=>({exit:code})),new Promise(resolve=>setTimeout(()=>resolve({tick:true}),wait))]);if(Object.hasOwn(result,'exit')){browserExit=result.exit;break;}}
  assert.equal(browserFailure,undefined);assert.equal(browserExit,0);const text=readFileSync(log,'utf8');assert.match(text,/1 passed/);assert.ok(!/\d+ skipped|\d+ failed/.test(text));
 }catch(error){failure=true;writeFileSync(path.join(directory,'failure.json'),JSON.stringify({status:'FAIL',run_id:runID,step,error_name:error.name,source_id:sourceID||null,profile_id:profile?.id||null,raw_credentials_withheld:true})+'\n',{mode:0o600});}
 finally{
  stopping=true;if(browser&&browserExit===undefined){browser.kill('SIGTERM');await new Promise(resolve=>{const timer=setTimeout(()=>{browser.kill('SIGKILL');resolve();},5000);browser.once('close',()=>{clearTimeout(timer);resolve();});});}
  verifyDaemon();const errors=[];for(const name of [...owned.keys()])try{removeJob(name);}catch{errors.push('job');}
  if(roleCreated)try{validateRole();psql(`DROP ROLE ${login};`);assert.equal(psql(`SELECT count(*) FROM pg_roles WHERE rolname=${sqlLiteral(login)};`),'0');}catch{errors.push('operator_login');}
  if(image&&!retainImage)try{const current=inspect('image',tag);assert.equal(current.Id,image.Id);assert.equal(current.Config?.Labels?.[label],runID);run(['image','rm',tag]);}catch{errors.push('uninstalled_image');}
  assert.equal(errors.length,0,'Exact owned cleanup refused; private failure metadata retained');
 }
 if(failure)throw new Error('Isolated fixture commissioning/browser refused; bounded private metadata retained.');
 assert.equal(run(['ps','--all','--filter','label='+label+'='+runID,'--format','{{.ID}}']),'');
 const acceptance={schema_version:'1',status:'PASS',run_id:runID,source_id:sourceID,profile_id:profile.id,tooling_image_id:image.Id,tooling_image_retained_for_installed_profile:true,actual_git_version:installation.actual_git_version,actual_terraform_version:installation.actual_terraform_version,actual_platform:installation.actual_platform,source_manifest_sha256:sourceSHA,source_sha256:hashes,runner_sha256:runnerSHA,harness_dependency_sha256:dependencySHA,migration_sha256:expected,normal_pipeline_syncs:syncs,real_oidc_browser_cases:1,cleanup_succeeded:true,realm:'ISOLATED_FIXTURE',provider_adapter:'DETERMINISTIC_FIXTURE_READER_SEPTEMBER_2026',customer_native_authority:false,customer_execution_authorized:false,verified_saving:null};
 writeFileSync(path.join(directory,'acceptance.json'),JSON.stringify(acceptance,null,2)+'\n',{mode:0o600});console.log('Local deterministic fixture commissioning and exact connected browser journey PASS; customer-native authority and execution remain unavailable.');
 return {directory,acceptance};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)groupFixtureCommission().catch(()=>{console.error('Fixture commissioning failed; credentials and provider payloads are withheld. Inspect private bounded metadata.');process.exitCode=1;});
