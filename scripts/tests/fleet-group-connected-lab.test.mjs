import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {connectedEnvironment,connectedMountSource,validateConnectedContainer,validateConnectedNetwork,validateConnectedTooling,validateConnectedOperatingLoop} from '../fleet-group-connected-lab.mjs';

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
 const result={native_journal_runtime_accepted:true,native_operating_loop:{status:'PASS',fixture_only:true,native_saved_plan_exact_applies:5,owned_effects:2,fresh_lifo_inverse_commits:2,actual_subprocess_terminal_exit_unknown_reconciled:true,repeat_capture_and_apply_no_extra_terraform:true,baseline_actual_duration_seconds:120,baseline_measurement_revision:'GO_MONOTONIC_HTTP_V2',baseline_monotonic_duration_ns:120e9,customer_execution_authorized:false,verified_saving:null,warmup:window(120,'OBSERVED'),canary_breach:window(3600,'BREACH'),terminal:window(900,'OBSERVED'),terraform_invocations:{counts:{apply:6}}}};validateConnectedOperatingLoop(result);
 for(const change of [r=>r.native_journal_runtime_accepted=false,r=>r.native_operating_loop.terminal=window(120,'OBSERVED'),r=>r.native_operating_loop.canary_breach=window(120,'BREACH'),r=>r.native_operating_loop.owned_effects=1,r=>r.native_operating_loop.terminal.verdict.observed_through=start,r=>r.native_operating_loop.terraform_invocations.counts.apply=7,r=>r.native_operating_loop.baseline_monotonic_duration_ns=120e9-1,r=>r.native_operating_loop.warmup.verdict.monotonic_duration_ns=120e9-1,r=>r.native_operating_loop.terminal.verdict.monotonic_duration_ns=900e9-1,r=>delete r.native_operating_loop.terminal.verdict.measurement_revision]){const bad=structuredClone(result);change(bad);assert.throws(()=>validateConnectedOperatingLoop(bad));}
});
