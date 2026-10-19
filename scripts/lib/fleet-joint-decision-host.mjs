// Private host boundaries. Capture provenance is explicit: a private
// overlay is never presented as a Git-index acceptance snapshot.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,readdirSync,realpathSync} from 'node:fs';
import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {canonicalCapacityDaemonJSON,parseCapacityDaemonCutpoint,validateCapacityDaemonContainer,validateCapacityDaemonFiles} from './fleet-capacity-daemon.mjs';

const SHA=/^[a-f0-9]{64}$/, UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digest=raw=>createHash('sha256').update(raw).digest('hex');
const browserFailurePhases=new Set(['START_BROWSER','WAIT_REAL_IDP','REAL_PKCE_SIGN_IN','IDS_ONLY_UI_REQUEST','ACTUAL_DAEMON_RESULT','LAZY_NATIVE_MEMBER','PERSISTED_RELOAD','REAL_JOINT_FINANCE_PHASE']);
const browserFailureCodes=new Set(['PAGE_EXECUTION_ERROR','CAPACITY_RESULT_DEADLINE_EXCEEDED','BROWSER_CHECK_FAILED']);
// Only the owned browser's fixed wire shape may enter a public failure receipt.
// Unknown diagnostics leave the original failure and outer phase untouched.
export function projectJointBrowserFailure(raw,runID){
 try{
  if(!UUID.test(runID)||!Buffer.isBuffer(raw)||raw.length===0||raw.length>1024)return null;
  const v=JSON.parse(raw.toString('utf8'));
  if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join(',')!=='code,phase,run_id,schema_version,status')return null;
  if(!raw.equals(Buffer.from(JSON.stringify(v)+'\n')))return null;
  if(v.schema_version!=='1'||v.status!=='FAIL'||v.run_id!==runID||!browserFailurePhases.has(v.phase)||!browserFailureCodes.has(v.code))return null;
  if(v.code==='CAPACITY_RESULT_DEADLINE_EXCEEDED'&&v.phase!=='ACTUAL_DAEMON_RESULT')return null;
  return Object.freeze({phase:v.phase,code:v.code});
 }catch{return null;}
}
const jointFailurePhases=new Set(['JOINT_FINANCE_PKCE','JOINT_IDS_ONLY_POST','JOINT_REPLACEMENT_DAEMON_RESULT','JOINT_RESULT_VALIDATION','JOINT_RENDER','JOINT_PERSISTED_RELOAD']);
const pageErrorClasses=new Set(['TypeError','ReferenceError','SyntaxError','RangeError','URIError','EvalError','Error','PageError']);
// Preserve the inner fixed phase while withholding arbitrary error text and
// hashes. The original private diagnostic remains available to its operator.
export function projectJointBrowserDetail(raw,runID){
 try{
  if(typeof runID!=='string'||!UUID.test(runID)||!Buffer.isBuffer(raw)||!raw.length||raw.length>2048)return null;
  const v=JSON.parse(raw.toString('utf8'));
  if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join(',')!=='error,phase,run_id,schema_version,status'||!raw.equals(Buffer.from(JSON.stringify(v)+'\n')))return null;
  if(v.schema_version!=='1'||v.status!=='FAIL'||v.run_id!==runID||!jointFailurePhases.has(v.phase))return null;
  const e=v.error;
  if(!e||typeof e!=='object'||Array.isArray(e)||Object.keys(e).sort().join(',')!=='error_class,message,raw_message_sha256'||!pageErrorClasses.has(e.error_class)||typeof e.message!=='string'||!e.message.length||e.message.length>256||typeof e.raw_message_sha256!=='string'||!SHA.test(e.raw_message_sha256))return null;
  return Object.freeze({phase:v.phase,error_class:e.error_class,code:'BROWSER_CHECK_FAILED'});
 }catch{return null;}
}
const coordinatorFailureCodes=new Map([
 ['joint original database process remains','ORIGINAL_BACKEND_PRESENT_BEFORE_GRAPH_RELEASE'],
 ['joint original database process remains after guard release','ORIGINAL_BACKEND_DRAIN_FAILED'],
 ['joint replacement worker proof differs','REPLACEMENT_WITNESS_INVALID'],
 ['joint replacement terminal cardinality differs','TERMINAL_CARDINALITY_INVALID'],
 ['joint browser result differs from actual native publication','NATIVE_PUBLICATION_MISMATCH'],
 ['joint replacement immutable replay differs','IMMUTABLE_REPLAY_MISMATCH'],
 ['joint dimensions incomplete','PHYSICAL_DIMENSIONS_INCOMPLETE'],
 ['joint missing member was promoted','MISSING_MEMBER_PROMOTED'],
 ['joint browser proof differs','BROWSER_PROOF_MISMATCH'],
 ['context deadline exceeded','COORDINATOR_DEADLINE_EXCEEDED'],
]);
export function projectJointCoordinatorFailure(raw,runID){
 if(typeof runID!=='string'||!UUID.test(runID)||!Buffer.isBuffer(raw)||!raw.length||raw.length>(256<<10))return null;
 const messages=raw.toString('utf8').split(/\r?\n/).flatMap(line=>{
  const m=/^[\t ]+fleet_capacity_native_integration_test\.go:[1-9][0-9]*: actual joint native\/browser\/replacement phase (.{1,256})$/.exec(line);
  return m?[m[1]]:[];
 });
 if(messages.length!==1||!coordinatorFailureCodes.has(messages[0]))return null;
 return Object.freeze({code:coordinatorFailureCodes.get(messages[0])});
}
export function canonicalJointDecisionJSON(v){const sort=x=>Array.isArray(x)?x.map(sort):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])])):x;return JSON.stringify(sort(v));}
export function validateJointNativeResult(value,validateBase){const total=value?.archived_native_readbacks,additional=value?.joint_additional_native_readbacks;assert.ok(Number.isSafeInteger(total)&&Number.isSafeInteger(additional)&&additional>0&&additional<=128&&total-additional===20);const base={...value,archived_native_readbacks:total-additional};delete base.joint_additional_native_readbacks;validateBase(base);return Object.freeze({total_readbacks:total,base_readbacks:20,joint_additional_readbacks:additional});}
export function validateJointCURAnalytics(v,runID,tenant){assert.deepEqual(Object.keys(v).sort(),['schema_version','run_id','tenant_id','source_id','source_versions','expected_rows','readback_rows','canonical_sha256','actual_clickhouse','actual_source_pipeline','fixture','financial_execution_authorized'].sort());assert.equal(v.schema_version,'1');assert.equal(v.run_id,runID);assert.equal(v.tenant_id,tenant);assert.equal(v.source_id,'assessment-native');assert.ok(Array.isArray(v.source_versions)&&v.source_versions.length>=1&&v.source_versions.length<=2&&new Set(v.source_versions).size===v.source_versions.length);assert.deepEqual(v.source_versions,[...v.source_versions].sort());for(const x of v.source_versions)assert.match(x,SHA);assert.equal(v.expected_rows,1032);assert.equal(v.readback_rows,1032);assert.match(v.canonical_sha256,SHA);for(const k of ['actual_clickhouse','actual_source_pipeline','fixture'])assert.equal(v[k],true);assert.equal(v.financial_execution_authorized,false);return Object.freeze(v);}
export function validateJointSecretVolume(o,name,runID,purpose){assert.match(runID,UUID);assert.ok(purpose==='capacity'||purpose==='decision');assert.equal(name,'finops-joint-decision-'+runID.replaceAll('-','')+'-'+(purpose==='capacity'?'daemon-secrets':'decision-secrets'));assert.equal(o?.Name,name);assert.equal(o.Driver,'local');assert.equal(o.Scope,'local');assert.equal(o.Labels?.['finops.native-capacity.run'],runID);assert.equal(Object.keys(o.Options||{}).length,0);assert.match(o.CreatedAt,/^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/);const at=new Date(o.CreatedAt);assert.ok(Number.isFinite(at.valueOf())&&at.toISOString().slice(0,19)===o.CreatedAt.slice(0,19));return o.CreatedAt;}
// Reuse036's exact runtime/file/cutpoint validators; its volume validator is
// deliberately namespace-specific, so037 supplies its own exact name check.
export function validateJointCapacityReplacement(old,newer,oldSpec,newSpec,v,c,evidence){assert.notEqual(oldSpec.allowStopped,true);assert.notEqual(newSpec.allowStopped,true);validateCapacityDaemonContainer(old,oldSpec,v);validateCapacityDaemonContainer(newer,newSpec,v);assert.notEqual(old.Id,newer.Id);for(const k of ['imageID','networkName','networkID','compiledVolume','secretVolume'])assert.equal(oldSpec[k],newSpec[k]);assert.ok(Array.isArray(evidence.remainingContainerIDs)&&evidence.remainingContainerIDs.length<=32&&new Set(evidence.remainingContainerIDs).size===evidence.remainingContainerIDs.length&&evidence.remainingContainerIDs.every(x=>SHA.test(x))&&!evidence.remainingContainerIDs.includes(old.Id)&&evidence.remainingContainerIDs.includes(newer.Id));const before=validateCapacityDaemonFiles(evidence.filesBefore,v),after=validateCapacityDaemonFiles(evidence.filesAfter,v);assert.equal(before,after);assert.match(evidence.binaryBeforeSHA,SHA);assert.equal(evidence.binaryBeforeSHA,evidence.binaryAfterSHA);assert.equal(validateJointSecretVolume(evidence.volumeBefore,oldSpec.secretVolume,v.run_id,'capacity'),validateJointSecretVolume(evidence.volumeAfter,newSpec.secretVolume,v.run_id,'capacity'));parseCapacityDaemonCutpoint(Buffer.from(canonicalCapacityDaemonJSON(c)),v);return Object.freeze({schema_version:'1',run_id:v.run_id,request_id:v.request_id,old_container_id:old.Id,new_container_id:newer.Id,image_id:old.Image,compiled_binary_sha256:evidence.binaryBeforeSHA,configuration_sha256:v.configuration_sha256,files_sha256:before,first_member_id:c.first_member_id,first_member_sha256:c.first_member_sha256,first_member_created_at:c.first_member_created_at,blocked_instance_id:c.blocked_instance_id,old_absence_confirmed:true,distinct_process:true,readonly_worker:true,no_aws_signing_execution_credentials:true});}
const fixed=Object.freeze(['scripts/fleet-joint-decision-lab.mjs','scripts/lib/fleet-joint-decision-host.mjs','scripts/lib/fleet-joint-browser.mjs','scripts/tests/fleet-joint-decision-lab.test.mjs','scripts/tests/fleet-joint-browser.test.mjs','examples/fleet-joint-browser/main.mjs','examples/fleet-joint-browser/joint.mjs','migrations/037_fleet_joint_decisions.sql','migrations/038_fleet_decision_credential_scope.sql','migrations/039_commitment_portfolio.sql','migrations/040_commitment_decisions.sql','cmd/fleet-decision-worker/main.go','cmd/fleet-decision-worker/main_test.go']);
const reviewedJointMigrations=Object.freeze([
 Object.freeze({path:'migrations/037_fleet_joint_decisions.sql',sha256:'54a44013471e1ca3c8e6990d3f554a0f986133441a3a9762b37eabc0fb51f051'}),
 Object.freeze({path:'migrations/038_fleet_decision_credential_scope.sql',sha256:'789d53114532af2b831fc2e2c011b5d15e7df2b72affafb2068fc4a84a6ee984'}),
 Object.freeze({path:'migrations/039_commitment_portfolio.sql',sha256:'89d382c5d6b81af066774e5367aff9cd764fc53e6d79f5f49ff6359a0e8f0aaf'}),
 Object.freeze({path:'migrations/040_commitment_decisions.sql',sha256:'dec0a482c3cd0d0f1cdb11e1de02833817cd7a705b81c01d4f87dd2109a9b76f'}),
]);
export function validateJointMigrationCapture(names,files){
 assert.ok(Array.isArray(names)&&names.length===40&&new Set(names).size===40);
 const ordered=[...names].sort();assert.ok(ordered.every(p=>/^migrations\/\d{3}_[a-z0-9_]+\.sql$/.test(p)));
 assert.deepEqual(ordered.map(p=>Number(p.slice('migrations/'.length,'migrations/'.length+3))),Array.from({length:40},(_,n)=>n+1));
 for(const{path:p,sha256:sha}of reviewedJointMigrations){assert.ok(names.includes(p));assert.ok(Buffer.isBuffer(files.get(p))&&digest(files.get(p))===sha,'Reviewed joint migration bytes differ');}
 return true;
}
const hosts=fixed.filter(p=>p.startsWith('scripts/')&&!p.startsWith('scripts/tests/')),guards=fixed.filter(p=>p.startsWith('scripts/tests/'));
const knownFrontend=['Dockerfile','package.json','package-lock.json','index.html','tsconfig.json','vite.config.ts','playwright.config.ts','nginx.conf','nginx-root.conf'].map(p=>'frontend/'+p);
const sourcePath=p=>fixed.includes(p)||knownFrontend.includes(p)||p==='go.mod'||p==='go.sum'||p==='contracts/openapi.yaml'||/^internal\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.go$/.test(p)||/^frontend\/(?:src|tests)\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.(?:ts|tsx|mjs|css|html)$/.test(p);
function regular(root,p){const file=path.join(root,p),s=lstatSync(file);assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size>0&&s.size<=(2<<20),'Candidate source is not a bounded regular file');const rel=path.relative(realpathSync(root),realpathSync(file));assert.ok(rel&&!rel.startsWith('..')&&!path.isAbsolute(rel));const raw=readFileSync(file);assert.equal(raw.length,s.size);return raw;}
function walk(root,p,select,out){const s=lstatSync(path.join(root,p));assert.ok(s.isDirectory()&&!s.isSymbolicLink());for(const name of readdirSync(path.join(root,p)).sort()){const next=p+'/'+name,st=lstatSync(path.join(root,next));assert.ok(!st.isSymbolicLink());if(st.isDirectory())walk(root,next,select,out);else if(select(next)){assert.ok(sourcePath(next));out.add(next);}assert.ok(out.size<=2048);}}
function gitReader(root,empty){const env={};for(const k of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC'])if(process.env[k])env[k]=process.env[k];Object.assign(env,{LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_SYSTEM:empty,GIT_CONFIG_GLOBAL:empty,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0'});return(args,input)=>execFileSync('git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:root,env,encoding:null,windowsHide:true,stdio:['pipe','pipe','pipe'],input,maxBuffer:(34<<20),timeout:30000});}

// Public entry: fixed037/038/039/040 paths only, while the036 reader already
// captures every tracked internal Go and frontend source file.
export function readJointDecisionIndexedSource(root,empty,{readBase,parseObjects}){
 const c=readBase(root,empty),git=gitReader(root,empty);assert.equal(git(['write-tree']).toString('ascii').trim(),c.tree);
 const raw=git(['ls-tree','-r','-z','--long','--full-tree',c.tree,'--',...fixed]);assert.ok(raw.length>0&&raw.length<=(128<<10)&&raw.at(-1)===0);const entries=raw.toString('utf8').split('\0').slice(0,-1).map(row=>{const m=/^100644 blob ([a-f0-9]{40}|[a-f0-9]{64}) +([0-9]+)\t([^\0]+)$/.exec(row);assert.ok(m&&fixed.includes(m[3]));const size=Number(m[2]);assert.ok(Number.isSafeInteger(size)&&size>0&&size<=(2<<20));return{path:m[3],oid:m[1],size};});assert.deepEqual(entries.map(e=>e.path).sort(),[...fixed].sort());
 const files=parseObjects(git(['cat-file','--batch'],Buffer.from(entries.map(e=>e.oid+'\n').join(''))),entries);for(const[p,raw]of files)c.files.set(p,raw);const migrationNames=git(['ls-tree','-r','-z','--name-only',c.tree,'--','migrations']);assert.ok(migrationNames.length>0&&migrationNames.length<=(128<<10)&&migrationNames.at(-1)===0);validateJointMigrationCapture(migrationNames.toString('utf8').split('\0').slice(0,-1),c.files);for(const p of hosts){assert.ok(regular(root,p).equals(c.files.get(p)),'Executed joint host module differs from index');c.hostHashes[p]=digest(c.files.get(p));}c.guardHashes=Object.fromEntries(guards.map(p=>[p,digest(c.files.get(p))]));assert.ok([...c.files.values()].reduce((n,b)=>n+b.length,0)<=(32<<20));assert.equal(git(['write-tree']).toString('ascii').trim(),c.tree);c.snapshotKind='GIT_INDEX_BLOBS';return c;
}

// Work-only rehearsal. Its base index and every overlaid source byte are
// separately pinned. No caller source/URL/image/clock arguments are accepted.
export function readJointDecisionCandidateSource(root,candidate,empty,{readBase}){
 const c=readBase(root,empty),selected=new Set([...fixed,...knownFrontend,'go.mod','go.sum','contracts/openapi.yaml']);
 for(const[p,sha]of Object.entries(c.hostHashes))assert.equal(digest(regular(candidate,p)),sha,'Copied executed dependency differs from base index');
 walk(candidate,'internal',p=>p.endsWith('.go'),selected);walk(candidate,'frontend/src',()=>true,selected);walk(candidate,'frontend/tests',p=>/\.(?:ts|tsx|mjs|css|html)$/.test(p),selected);
 for(const[p,raw]of c.files)if(/^migrations\/0(?:0[1-9]|[12][0-9]|3[0-9])_/.test(p))assert.ok(regular(candidate,p).equals(raw),'Historical migration changed in candidate overlay');
 const overlay={};for(const p of [...selected].sort()){assert.ok(sourcePath(p));const raw=regular(candidate,p);c.files.set(p,raw);overlay[p]=digest(raw);}
 validateJointMigrationCapture(readdirSync(path.join(candidate,'migrations')).map(name=>'migrations/'+name),c.files);for(const p of hosts)c.hostHashes[p]=overlay[p];c.guardHashes=Object.fromEntries(guards.map(p=>[p,overlay[p]]));assert.ok(c.files.size<=2048&&[...c.files.values()].reduce((n,b)=>n+b.length,0)<=(32<<20));for(const p of selected)assert.equal(digest(regular(candidate,p)),overlay[p],'Candidate source changed while capturing');assert.equal(readBase(root,empty).tree,c.tree,'Base index changed during candidate overlay');c.snapshotKind='CANDIDATE_OVERLAY_ON_GIT_INDEX_BLOBS';c.baseTree=c.tree;c.overlayHashes=overlay;c.overlaySHA256=digest(JSON.stringify(overlay));return c;
}

export function jointDecisionEnvironment(ready){assert.equal(ready?.schema_version,'1');assert.match(ready.run_id,UUID);assert.match(ready.tenant_id,/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/);return{FLEET_DECISION_DATABASE_FILE:'/run/secrets/group-decision-database',FLEET_DECISION_DATABASE_MODE:'LOCAL_PRIVATE',FLEET_DECISION_ENABLED:'true',FLEET_DECISION_TENANT_ID:ready.tenant_id};}
export function parseJointWorkerReady(raw,runID){assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=8192);const v=JSON.parse(raw);assert.equal(canonicalJointDecisionJSON(v),raw.toString('utf8'));assert.deepEqual(Object.keys(v).sort(),['schema_version','run_id','tenant_id','purpose','database_file_sha256','database_file_size','configuration_sha256'].sort());assert.equal(v.run_id,runID);assert.equal(v.purpose,'group-decision-reader');assert.match(v.database_file_sha256,SHA);assert.ok(Number.isSafeInteger(v.database_file_size)&&v.database_file_size>0&&v.database_file_size<=8192);const env=jointDecisionEnvironment(v);assert.equal(v.configuration_sha256,digest(JSON.stringify(env)));return Object.freeze(v);}
export function validateJointWorkerFiles(v,ready){assert.deepEqual(Object.keys(v).sort(),['binary_sha256','directory_mode','files']);assert.equal(v.directory_mode,493);assert.deepEqual(Object.keys(v.files),['group-decision-database']);assert.deepEqual(v.files['group-decision-database'],{sha256:ready.database_file_sha256,size:ready.database_file_size,mode:292,nlink:1,is_file:true,is_symbolic_link:false});assert.match(v.binary_sha256,SHA);return digest(JSON.stringify(v));}
export function parseJointWorkerCutpoint(raw,ready,readySHA256){assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=8192);const v=JSON.parse(raw);assert.equal(canonicalJointDecisionJSON(v),raw.toString('utf8'));assert.deepEqual(Object.keys(v).sort(),['schema_version','run_id','ready_sha256','request_id','phase','pending','decision_exists'].sort());assert.equal(v.schema_version,'1');assert.equal(v.run_id,ready.run_id);assert.equal(v.ready_sha256,readySHA256);assert.match(v.request_id,UUID);assert.equal(v.phase,'QUEUED_GRAPH_FENCE_HELD');assert.equal(v.pending,true);assert.equal(v.decision_exists,false);return Object.freeze(v);}
function envMap(rows){assert.ok(Array.isArray(rows)&&rows.length<=64);const out={};for(const row of rows){const i=row.indexOf('=');assert.ok(i>0&&!Object.hasOwn(out,row.slice(0,i)));out[row.slice(0,i)]=row.slice(i+1);}return out;}
export function validateJointWorkerContainer(o,spec,ready){
 assert.match(spec.runtimeID,SHA);assert.equal(o.Id,spec.runtimeID);assert.equal(o.Image,spec.imageID);assert.equal(o.Name,'/'+spec.name);assert.equal(o.Config?.Labels?.['finops.native-capacity.run'],ready.run_id);assert.equal(o.Config?.User,'10001:10001');assert.equal(o.Config?.WorkingDir,'/tmp');assert.deepEqual(o.Config?.Entrypoint,['/compiled/fleet-decision-worker']);assert.deepEqual(o.Config?.Cmd||[],[]);assert.ok(!o.Config.Healthcheck||isDeepStrictEqual(o.Config.Healthcheck.Test,['NONE']));
 const expected={...envMap(spec.imageEnvironment||[]),...jointDecisionEnvironment(ready),GOMAXPROCS:'1',GOMEMLIMIT:'384MiB',HOME:'/tmp'},actual=envMap(o.Config?.Env);for(const k of Object.keys(actual))assert.ok(!/^(AWS_|AZURE_|GOOGLE_|PG|DB_|TF_|DOCKER_|SIGN|EXEC|TEST_|MC_HOST_|ECONOMICS_|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$)/i.test(k));assert.deepEqual(actual,expected);
 const h=o.HostConfig;assert.equal(h?.ReadonlyRootfs,true);assert.deepEqual(h.CapDrop,['ALL']);assert.deepEqual(h.CapAdd||[],[]);assert.deepEqual(h.SecurityOpt,['no-new-privileges']);assert.ok(!h.Privileged&&!h.AutoRemove&&!h.PublishAllPorts&&!h.PidMode&&(!h.IpcMode||h.IpcMode==='private')&&!h.UsernsMode&&!h.Devices?.length&&!h.DeviceRequests?.length&&!h.VolumesFrom?.length&&!Object.keys(h.PortBindings||{}).length);assert.equal(h.NetworkMode,spec.networkName);assert.equal(h.Memory,512*1024*1024);assert.equal(h.NanoCpus,1e9);assert.equal(h.PidsLimit,64);assert.equal(h.RestartPolicy?.Name,'no');assert.deepEqual(h.Tmpfs,{'/tmp':'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700'});
 const nets=o.NetworkSettings?.Networks;assert.deepEqual(Object.keys(nets||{}),[spec.networkName]);assert.ok(nets[spec.networkName].NetworkID===spec.networkID||spec.allowStopped===true&&o.State?.Status==='created'&&o.State.Running===false&&nets[spec.networkName].NetworkID==='');assert.ok(!o.NetworkSettings?.Ports||Object.values(o.NetworkSettings.Ports).every(x=>x===null));const mounts=(o.Mounts||[]).filter(m=>m.Type!=='tmpfs');assert.equal(mounts.length,2);for(const[destination,name]of[['/compiled',spec.compiledVolume],['/run/secrets',spec.secretVolume]]){const found=mounts.filter(m=>m.Destination===destination);assert.equal(found.length,1);assert.equal(found[0].Type,'volume');assert.equal(found[0].Name,name);assert.equal(found[0].RW,false);}
 if(o.State?.Running===true){assert.ok(Number.isSafeInteger(o.State.Pid)&&o.State.Pid>0&&!Number.isNaN(Date.parse(o.State.StartedAt)));}else assert.ok(spec.allowStopped===true&&o.State?.Running===false&&o.State.Pid===0&&['created','exited'].includes(o.State.Status)&&Number.isSafeInteger(o.State.ExitCode)&&o.State.ExitCode>=0&&o.State.ExitCode<=255);return true;
}
export function validateJointWorkerReplacement(old,newer,oldSpec,newSpec,ready,cutpoint,evidence){assert.notEqual(oldSpec.allowStopped,true);assert.notEqual(newSpec.allowStopped,true);validateJointWorkerContainer(old,oldSpec,ready);validateJointWorkerContainer(newer,newSpec,ready);assert.notEqual(old.Id,newer.Id);for(const k of ['imageID','networkID','networkName','compiledVolume','secretVolume'])assert.equal(oldSpec[k],newSpec[k]);assert.ok(Array.isArray(evidence.remainingContainerIDs)&&evidence.remainingContainerIDs.length<=48&&new Set(evidence.remainingContainerIDs).size===evidence.remainingContainerIDs.length&&evidence.remainingContainerIDs.every(x=>SHA.test(x))&&!evidence.remainingContainerIDs.includes(old.Id)&&evidence.remainingContainerIDs.includes(newer.Id));assert.deepEqual(evidence.volumeBefore,evidence.volumeAfter);validateJointSecretVolume(evidence.volumeBefore,oldSpec.secretVolume,ready.run_id,'decision');validateJointSecretVolume(evidence.volumeAfter,newSpec.secretVolume,ready.run_id,'decision');const before=validateJointWorkerFiles(evidence.filesBefore,ready),after=validateJointWorkerFiles(evidence.filesAfter,ready);assert.equal(before,after);parseJointWorkerCutpoint(Buffer.from(canonicalJointDecisionJSON(cutpoint)),ready,cutpoint.ready_sha256);return Object.freeze({schema_version:'1',run_id:ready.run_id,ready_sha256:cutpoint.ready_sha256,request_id:cutpoint.request_id,old_container_id:old.Id,new_container_id:newer.Id,image_id:old.Image,compiled_binary_sha256:evidence.filesBefore.binary_sha256,configuration_sha256:ready.configuration_sha256,files_sha256:before,old_absent:true,distinct_process:true});}
