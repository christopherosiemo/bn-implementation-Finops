import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync,writeFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {connectedEnvironment,connectedMountSource,validateConnectedContainer,validateConnectedNetwork,validateConnectedTooling,validateConnectedOperatingLoop,parseConnectedIndexListing,parseConnectedIndexObjects,readConnectedIndexedSource} from '../fleet-group-connected-lab.mjs';

const id='11111111-2222-3333-4444-555555555555',image='sha256:'+'a'.repeat(64),name='finops-connected-'+id.replaceAll('-','')+'-test';
const spec={id,name,image,network:'owned-private',user:'10001:10001',mounts:[['/src','bind','/public/source',false],['/compiled','volume','owned-compiled',false]],command:['/compiled/connected.test','-test.run=^FixedTest$']};
const container=()=>({Name:'/'+name,Image:image,Config:{Labels:{'finops.fleet-group-connected.run':id},User:spec.user,Cmd:spec.command,Env:['HOME=/tmp','FLEET_CONNECTED_FIXTURE=ISOLATED_FIXTURE']},HostConfig:{NetworkMode:spec.network,ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],SecurityOpt:['no-new-privileges'],PortBindings:{},Devices:[]},Mounts:[{Destination:'/src',Type:'bind',Source:'/public/source',RW:false},{Destination:'/compiled',Type:'volume',Name:'owned-compiled',Source:'/var/lib/docker/volumes/owned-compiled/_data',RW:false}]});

test('only exact reviewed digest-pinned local tooling accepted',()=>{
 const raw=readFileSync(new URL('../../examples/fleet-group-connected-fixture/Dockerfile',import.meta.url),'utf8');validateConnectedTooling(raw);
 for(const bad of [raw.replace('1.16.0@','1.16.1@'),raw.replace('USER 10001:10001','USER 0:0'),raw+'\nRUN curl https://example.invalid\n'])assert.throws(()=>validateConnectedTooling(bad));
});
test('private generated credentials stay fixed to owned services',()=>{
 const env=connectedEnvironment('p'.repeat(32),'u'.repeat(32),'s'.repeat(32),'a'.repeat(64),'b'.repeat(64));assert.ok(env.test.includes('@postgres:5432/postgres?sslmode=disable'));assert.ok(env.test.includes('FLEET_CONNECTED_S3_ENDPOINT=http://minio:9000'));assert.ok(!env.test.includes('AWS_'));
 for(const bad of ['short','p'.repeat(32)+'\nAWS_ACCESS_KEY_ID=bad','x@remote'])assert.throws(()=>connectedEnvironment(bad,'u'.repeat(32),'s'.repeat(32),'a'.repeat(64),'b'.repeat(64)));
});
test('exact command, native image, no grants or arbitrary mounts before dispatch and cleanup',()=>{
 validateConnectedContainer(container(),spec);
 for(const change of [o=>o.Image='sha256:'+'b'.repeat(64),o=>o.Config.Cmd=['sh','-c','unreviewed'],o=>o.Config.Env.push('AWS_ACCESS_KEY_ID=bad'),o=>o.Config.User='0:0',o=>o.HostConfig.NetworkMode='host',o=>o.HostConfig.CapAdd=['SYS_ADMIN'],o=>o.HostConfig.PortBindings={'80/tcp':[{}]},o=>o.Mounts[0].Source='/other/private',o=>o.Mounts[0].RW=true,o=>o.Mounts[0].Type='volume',o=>o.Mounts.push({Destination:'/var/run/docker.sock',Type:'bind',Source:'/var/run/docker.sock',RW:true}),o=>o.Config.Labels['finops.fleet-group-connected.run']='other']){const o=container();change(o);assert.throws(()=>validateConnectedContainer(o,spec));}
});
test('PostgreSQL build-list exception must match the exact pinned image bytes',()=>{
 const o=container();o.Config.Env.push('DOCKER_PG_LLVM_DEPS=llvm19-dev clang19');
 const pg={...spec,postgresImageEnvironment:['DOCKER_PG_LLVM_DEPS=llvm19-dev clang19']};validateConnectedContainer(o,pg);
 const wrong=structuredClone(o);wrong.Config.Env[2]='DOCKER_PG_LLVM_DEPS=changed';assert.throws(()=>validateConnectedContainer(wrong,pg));
 assert.throws(()=>validateConnectedContainer(o,{...spec,postgresImageEnvironment:['DOCKER_HOST=tcp://remote:2375']}));
 o.Config.Env.push('DOCKER_HOST=tcp://remote:2375');assert.throws(()=>validateConnectedContainer(o,pg));
});
test('owned internal network permits Docker IPv4 defaults without routing overrides',()=>{
 const o={Name:'owned-private',Labels:{'finops.fleet-group-connected.run':id},Internal:true,Driver:'bridge',EnableIPv4:true,EnableIPv6:false,Options:{'com.docker.network.enable_ipv4':'true','com.docker.network.enable_ipv6':'false'}};validateConnectedNetwork(o,id,'owned-private');
 for(const change of [o=>o.Internal=false,o=>o.Driver='host',o=>o.EnableIPv6=true,o=>o.Options['com.docker.network.bridge.name']='docker0',o=>o.Labels['finops.fleet-group-connected.run']='foreign']){const bad=structuredClone(o);change(bad);assert.throws(()=>validateConnectedNetwork(bad,id,'owned-private'));}
});
test('host mount normalization rejects traversal and preserves exact Windows path',()=>{
 assert.equal(connectedMountSource('C:\\Users\\fixture\\source','win32'),'/run/desktop/mnt/host/c/Users/fixture/source');
 for(const bad of ['/root/../private','relative','/tmp/secret\n'])assert.throws(()=>connectedMountSource(bad,'linux'));
});
test('operating-loop acceptance requires genuine unchanged observation windows and owned recovery',()=>{
 const start='2026-10-19T00:00:00.000Z';const window=(seconds,status)=>({verdict:{status,measurement_revision:'GO_MONOTONIC_HTTP_V2',monotonic_duration_ns:(status==='BREACH'?2:seconds)*1e9,baseline_monotonic_duration_ns:120e9,start,required_end:new Date(Date.parse(start)+seconds*1000).toISOString(),observed_through:new Date(Date.parse(start)+(status==='BREACH'?2000:seconds*1000)).toISOString(),reason_codes:status==='BREACH'?['LATENCY_REGRESSION_ABOVE_15_PERCENT']:[],p95_ns:135,baseline_p95_ns:100}});
 const incident='33333333-2222-3333-4444-555555555555',result={native_journal_runtime_accepted:true,artifacts:[{id,kind:'HEALTH_VERDICT',plain_sha256:'a'.repeat(64),version_id:'immutable-version'},{id:incident,kind:'HEALTH_VERDICT',plain_sha256:'b'.repeat(64),version_id:'immutable-version'}],native_operating_loop:{status:'PASS',fixture_only:true,native_saved_plan_exact_applies:5,owned_effects:2,fresh_lifo_inverse_commits:2,actual_subprocess_terminal_exit_unknown_reconciled:true,repeat_capture_and_apply_no_extra_terraform:true,baseline_actual_duration_seconds:120,baseline_measurement_revision:'GO_MONOTONIC_HTTP_V2',baseline_monotonic_duration_ns:120e9,customer_execution_authorized:false,verified_saving:null,warmup:window(120,'OBSERVED'),canary_breach:window(3600,'BREACH'),terminal:window(900,'OBSERVED'),terraform_invocations:{counts:{apply:6}},healthy_fixture_work_ns:1e9,baseline_anchor_sha256:'a'.repeat(64),baseline_anchor_ref:{id,version_id:'immutable-version',sha256:'a'.repeat(64)},permanent_forward_disqualification:true,financial_disqualified_forever:true,health_incident_refs:[{id:incident,version_id:'immutable-version',sha256:'b'.repeat(64)}],recovery_alert_delivery:'UNAVAILABLE_NO_COMMISSIONED_ADAPTER',production_durable_retry_accepted:false}};validateConnectedOperatingLoop(result);
 for(const change of [r=>r.native_journal_runtime_accepted=false,r=>r.native_operating_loop.terminal=window(120,'OBSERVED'),r=>r.native_operating_loop.canary_breach=window(120,'BREACH'),r=>r.native_operating_loop.owned_effects=1,r=>r.native_operating_loop.terminal.verdict.observed_through=start,r=>r.native_operating_loop.terraform_invocations.counts.apply=7,r=>r.native_operating_loop.baseline_monotonic_duration_ns=120e9-1,r=>r.native_operating_loop.warmup.verdict.monotonic_duration_ns=120e9-1,r=>r.native_operating_loop.terminal.verdict.monotonic_duration_ns=900e9-1,r=>delete r.native_operating_loop.terminal.verdict.measurement_revision]){const bad=structuredClone(result);change(bad);assert.throws(()=>validateConnectedOperatingLoop(bad));}
 for(const change of [r=>r.native_operating_loop.healthy_fixture_work_ns=300e6,r=>delete r.native_operating_loop.baseline_anchor_sha256,r=>r.native_operating_loop.baseline_anchor_ref.version_id='null',r=>r.native_operating_loop.baseline_anchor_ref.sha256='b'.repeat(64),r=>r.native_operating_loop.permanent_forward_disqualification=false,r=>r.native_operating_loop.financial_disqualified_forever=false,r=>r.native_operating_loop.health_incident_refs=[],r=>r.native_operating_loop.recovery_alert_delivery='DELIVERED',r=>r.native_operating_loop.production_durable_retry_accepted=true]){const bad=structuredClone(result);change(bad);assert.throws(()=>validateConnectedOperatingLoop(bad));}
 for(const change of [r=>r.artifacts.pop(),r=>r.artifacts[0].kind='FIXTURE_SLO',r=>r.artifacts[1].plain_sha256='c'.repeat(64),r=>r.artifacts[1].version_id='newer-version',r=>r.native_operating_loop.health_incident_refs.push(r.native_operating_loop.health_incident_refs[0])]){const bad=structuredClone(result);change(bad);assert.throws(()=>validateConnectedOperatingLoop(bad));}
});

const indexHosts=['scripts/fleet-group-connected-lab.mjs','scripts/kubernetes-bootstrap.mjs','scripts/fleet-history-lab.mjs','scripts/postgres-recovery-lab.mjs','scripts/lib/encrypted-backup.mjs','scripts/lib/fixture-go-modules.mjs','scripts/lib/group-connected-failure.mjs'];
const blob=b=>createHash('sha1').update(Buffer.from('blob '+b.length+'\0')).update(b).digest('hex');
function indexedFixture(){
 return new Map([['go.mod',Buffer.from('module isolated.example/fixture\n')],['go.sum',Buffer.alloc(0)],['internal/example/example.go',Buffer.from('package example\n// $Format:%H$\n')],['examples/fleet-group-connected-fixture/Dockerfile',Buffer.from('fixed synthetic Dockerfile\n')],...indexHosts.map(p=>[p,Buffer.from('// fixed indexed dependency '+p+'\n')]),...['029_fleet_fixture_proposals.sql','030_fleet_group_journal.sql','031_cross_family_admission.sql','032_group_artifacts.sql'].map(p=>['migrations/'+p,Buffer.from('-- synthetic fixture\n')])]);
}
const listing=files=>Buffer.from([...files].map(([p,b])=>'100644 blob '+blob(b)+' '+b.length+'\t'+p+'\0').join(''));
test('indexed listing rejects unsupported modes, unsafe tracked Go and bounded source overflows',()=>{
 const files=indexedFixture(),raw=listing(files);assert.equal(parseConnectedIndexListing(raw).length,files.size);
 for(const bad of [Buffer.from(raw.toString().replace('100644','120000')),Buffer.from(raw.toString().replace('blob','commit')),Buffer.from(raw.toString().replace('internal/example/example.go','internal/../example.go')),Buffer.from(raw.toString().replace('internal/example/example.go','internal/example/extra.name.go')),Buffer.concat([raw,raw.subarray(0,raw.indexOf(0)+1)]),raw.subarray(0,raw.length-1),Buffer.from(raw.toString().replace(' '+files.get('go.mod').length+'\tgo.mod',' 2097153\tgo.mod'))])assert.throws(()=>parseConnectedIndexListing(bad));
 const overflow=Buffer.from(raw.toString()+Array.from({length:17},(_,n)=>'100644 blob '+'a'.repeat(40)+' 2097152\tinternal/example/large'+n+'.go\0').join(''));assert.throws(()=>parseConnectedIndexListing(overflow));
});
test('raw indexed objects retain byte identity and refuse altered hash, size, trailer or extra bytes',()=>{
 const body=Buffer.from('exact raw source\n'),entry={path:'internal/example/source.go',oid:blob(body),size:body.length},raw=Buffer.concat([Buffer.from(entry.oid+' blob '+body.length+'\n'),body,Buffer.from('\n')]);assert.deepEqual(parseConnectedIndexObjects(raw,[entry]).get(entry.path),body);
 const changed=Buffer.from(raw);changed[changed.length-3]^=1;
 for(const bad of [changed,raw.subarray(0,raw.length-1),Buffer.concat([raw,Buffer.from('private-extra')]),Buffer.from(raw.toString().replace(' blob '+body.length,' blob '+(body.length+1)))])assert.throws(()=>parseConnectedIndexObjects(bad,[entry]));
});
test('actual Git index snapshot excludes untracked secrets and ordinary worktree drift without invoking filters',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-connected-index-')),repository=path.join(directory,'repository'),config=path.join(directory,'empty.config');mkdirSync(repository);writeFileSync(config,'',{mode:0o600});
 t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^finops-connected-index-/);rmSync(directory,{recursive:true,force:true});});
 const environment={};for(const key of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC'])if(process.env[key])environment[key]=process.env[key];Object.assign(environment,{GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:config,GIT_CONFIG_SYSTEM:config,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1'});
 const git=args=>execFileSync('git',['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{cwd:repository,env:environment,encoding:'utf8',windowsHide:true,stdio:'pipe'});
 git(['-c','init.templateDir=','init','--quiet']);const files=indexedFixture();for(const[p,b]of files){mkdirSync(path.dirname(path.join(repository,p)),{recursive:true});writeFileSync(path.join(repository,p),b);}git(['add','--all']);
 const original=readConnectedIndexedSource(repository,config);assert.equal(original.files.size,files.size);
 writeFileSync(path.join(repository,'internal/example/example.go'),'UNSTAGED_WIP');writeFileSync(path.join(repository,'internal/example/untracked.go'),'UNTRACKED_PRIVATE_DATA');writeFileSync(path.join(repository,'.env'),'NEVER_COPY_PRIVATE');writeFileSync(path.join(repository,'migrations/033_future.sql'),'-- deliberately later');git(['add','migrations/033_future.sql']);
 writeFileSync(path.join(repository,'.gitattributes'),'*.go filter=deliberately_forbidden export-subst\n');git(['add','.gitattributes']);git(['config','filter.deliberately_forbidden.clean','deliberately-forbidden-filter-command']);git(['config','filter.deliberately_forbidden.required','true']);
 const selected=readConnectedIndexedSource(repository,config);assert.ok(!selected.files.has('migrations/033_future.sql'));assert.ok(!selected.files.has('internal/example/untracked.go'));assert.ok(!selected.files.has('.env'));assert.deepEqual(selected.files.get('internal/example/example.go'),files.get('internal/example/example.go'));assert.ok(selected.files.get('internal/example/example.go').includes(Buffer.from('$Format:%H$')));
 writeFileSync(path.join(repository,indexHosts[0]),'CHANGED_EXECUTED_HOST_RUNNER');assert.throws(()=>readConnectedIndexedSource(repository,config));
});
