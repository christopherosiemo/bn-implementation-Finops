import assert from 'node:assert/strict';
import test from 'node:test';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {commissionLambdaPerformance,lambdaPerformanceClientScript,lambdaPerformanceCreateSQL,lambdaPerformanceGrants,lambdaPerformanceIdentity,validateLambdaPerformanceTarget} from '../commission-lambda-performance.mjs';

const env=()=>({FIXTURE_MODE:'true',COMPOSE_PROJECT_NAME:'fixture',CLICKHOUSE_PASSWORD:'operator-secret',LAMBDA_PERFORMANCE_ACCESS_KEY:'lambda-perf-01234567',LAMBDA_PERFORMANCE_SECRET_KEY:'a'.repeat(48),LAMBDA_PERFORMANCE_CLICKHOUSE_USER:'lambda_performance_0123456789abcdef',LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD:'b'.repeat(48)});
const target=()=>({Id:'c'.repeat(64),Image:'sha256:'+'d'.repeat(64),Running:true,Labels:{'com.docker.compose.service':'clickhouse','com.docker.compose.project':'fixture','com.docker.compose.project.working_dir':path.resolve('workspace'),'com.docker.compose.project.config_files':path.join(path.resolve('workspace'),'compose.yaml')},NetworkMode:'fixture_private',Networks:{fixture_private:{NetworkID:'e'.repeat(64)}},Ports:{'8123/tcp':null},Mounts:[{Destination:'/var/lib/clickhouse',Type:'volume',Name:'fixture_clickhouse'}]});
test('Lambda commissioning requires the independent complete local identity and exact existing private store',()=>{
  const identity=lambdaPerformanceIdentity(env());assert.equal(identity.user,env().LAMBDA_PERFORMANCE_CLICKHOUSE_USER);
  for(const mutate of [x=>x.FIXTURE_MODE='false',x=>delete x.LAMBDA_PERFORMANCE_SECRET_KEY,x=>x.LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD=x.LAMBDA_PERFORMANCE_SECRET_KEY,x=>x.LAMBDA_PERFORMANCE_CLICKHOUSE_USER='finops',x=>x.OBJECT_SECRET_KEY=x.LAMBDA_PERFORMANCE_SECRET_KEY]){const value=env();mutate(value);assert.throws(()=>lambdaPerformanceIdentity(value));}
  validateLambdaPerformanceTarget(target(),path.resolve('workspace'),'fixture');
  for(const mutate of [x=>x.Running=false,x=>x.Labels['com.docker.compose.project']='foreign',x=>x.Labels['com.docker.compose.project.working_dir']=path.resolve('elsewhere'),x=>x.NetworkMode='host',x=>x.Ports={'8123/tcp':[{HostIp:'0.0.0.0',HostPort:'8123'}]},x=>x.Mounts[0].Name='another_volume']){const value=target();mutate(value);assert.throws(()=>validateLambdaPerformanceTarget(value,path.resolve('workspace'),'fixture'));}
});
test('private stdin client uses scoped temporary files and SHA256 SQL, never credentials in command arguments',()=>{
  const identity=lambdaPerformanceIdentity(env()),sql=lambdaPerformanceCreateSQL(identity),script=lambdaPerformanceClientScript(identity,sql);
  assert.ok(sql.includes('IDENTIFIED WITH sha256_hash BY'));assert.ok(!sql.includes(identity.password));assert.ok(!sql.includes(identity.adminPassword));
  for(const forbidden of ['CREATE OR REPLACE','DROP ','ALTER ','WITH GRANT OPTION','GRANT ALL','native_metric_batches TO '+identity.user+';\nGRANT SELECT ON'])assert.ok(!sql.includes(forbidden));
  assert.ok(script.includes('umask 077'));assert.ok(script.includes('mktemp -d /tmp/finops-lambda-performance.XXXXXXXX'));assert.ok(script.includes('trap '));assert.ok(script.includes('--config-file "$commission_dir/client.xml"'));assert.ok(!script.includes('--password'));assert.ok(!script.includes('rm -rf'));
  assert.throws(()=>lambdaPerformanceClientScript(identity,'SELECT 1;\nFINOPS_LAMBDA_QUERY\nmalicious'));
});
function database(existing=false,{extraGrant=false,role=false,unrelatedChange=false}={}){
  const identity=lambdaPerformanceIdentity(env()),calls=[];let user=existing,metadataReads=0;
  const query=(sql,ingress=false)=>{
    calls.push({sql,ingress});
    if(sql.startsWith('CREATE USER')){assert.equal(user,false);user=true;return [];}
    if(sql.includes('FROM system.users WHERE name!=')){metadataReads++;return [{name:unrelatedChange&&metadataReads>1?'changed':'finops',id:'original'}];}
    if(sql.includes('FROM system.grants WHERE ifNull'))return [{user_name:'finops',access_type:'ALL'}];
    if(sql.includes('FROM system.tables'))return [{name:'native_metric_samples',uuid:'one',engine:'MergeTree'},{name:'native_metric_batches',uuid:'two',engine:'MergeTree'}];
    if(sql.includes('FROM system.users WHERE name='))return user?[{name:identity.user}]:[];
    if(sql.includes('FROM system.grants WHERE user_name='))return [...lambdaPerformanceGrants(),...(extraGrant?[{access_type:'SELECT',database:null,table:null,column:null,is_partial_revoke:0,grant_option:0,is_wildcard:0}]:[])];
    if(sql.includes('FROM system.role_grants'))return role?[{granted_role_name:'unrelated'}]:[];
    if(sql.startsWith('SELECT currentUser()')){assert.equal(ingress,true);return [{user:identity.user}];}
    if(sql.startsWith('CHECK GRANT')){assert.equal(ingress,true);return [{result:/^(CHECK GRANT INSERT ON finops.native_metric_|CHECK GRANT SELECT\(sample_id)/.test(sql)?1:0}];}
    throw Error('Unexpected fixture query');
  };
  return {identity,query,calls};
}
test('additive installation grants exactly both writes and six readback columns; replay never changes users',()=>{
  const fresh=database();const result=commissionLambdaPerformance(fresh.identity,fresh.query);assert.equal(result.replayed,false);assert.equal(result.database_row_level_isolation_claimed,false);assert.equal(fresh.calls.filter(call=>call.sql.startsWith('CREATE USER')).length,1);
  const replay=database(true);assert.equal(commissionLambdaPerformance(replay.identity,replay.query).replayed,true);assert.ok(!replay.calls.some(call=>/CREATE |GRANT (INSERT|SELECT)/.test(call.sql)&&!call.sql.startsWith('CHECK')));
});
test('existing broad permissions, role inheritance and unrelated metadata changes fail closed',()=>{
  for(const options of [{extraGrant:true},{role:true},{unrelatedChange:true}]){const fixture=database(true,options);assert.throws(()=>commissionLambdaPerformance(fixture.identity,fixture.query));assert.ok(!fixture.calls.some(call=>call.sql.startsWith('CREATE USER')));}
});
test('existing MinIO Lambda policy has only the narrow immutable wire archive operations',()=>{
  const policy=JSON.parse(readFileSync(new URL('../../config/minio/lambda-performance-policy.json',import.meta.url),'utf8'));
  assert.deepEqual(policy.Statement,[{Effect:'Allow',Action:['s3:PutObject','s3:GetObjectVersion'],Resource:['arn:aws:s3:::finops-raw/tenant/tenant-demo/native/lambda-performance-*/wire/*']}]);
});
test('targeted MinIO commissioning touches only the selected existing policy/user and refuses invalid modes',{skip:process.platform!=='linux'},()=>{
  const directory=mkdtempSync(path.join(tmpdir(),'lambda-minio-commission-')),log=path.join(directory,'calls');
  try {
    const input={PATH:'/usr/bin:/bin',MC_TEST_LOG:log,MINIO_ROOT_USER:'operator',MINIO_ROOT_PASSWORD:'fixture-operator',LAMBDA_PERFORMANCE_ACCESS_KEY:'lambda-perf-01234567',LAMBDA_PERFORMANCE_SECRET_KEY:'synthetic-performance-secret',SERVICE_ASSESSOR_ACCESS_KEY:'aws-service-assessor',SERVICE_ASSESSOR_SECRET_KEY:'synthetic-service-reader-secret'};
    const file=new URL('../../config/minio/init-buckets.sh',import.meta.url).pathname;
    // Docker's temporary mount is deliberately non-executable. Shell functions
    // retain real initializer parsing without executing a temporary mock file.
    const run=mode=>spawnSync('/bin/sh',['-c','script=$1; mode=$2; mc() { printf "%s\\n" "$*" >> "$MC_TEST_LOG"; }; timeout() { shift 3; "$@"; }; set -- "$mode"; . "$script"','lambda-minio-test',file,mode],{env:input,encoding:'utf8',timeout:15000});
    assert.equal(run('lambda-performance-only').status,0);
    const calls=readFileSync(log,'utf8').trim().split('\n');assert.equal(calls.length,4);assert.match(calls[0],/^alias set local /);assert.match(calls[1],/^admin policy create local lambda-performance /);assert.match(calls[2],/^admin user add local lambda-perf-01234567 /);assert.equal(calls[3],'admin policy attach local lambda-performance --user lambda-perf-01234567');
    assert.equal(run('service-assessor-only').status,0);const service=readFileSync(log,'utf8').trim().split('\n').slice(4);assert.equal(service.length,4);assert.match(service[0],/^alias set local /);assert.equal(service[1],'admin policy create local aws-service-assessor /config/group-assessor-policy.json');assert.match(service[2],/^admin user add local aws-service-assessor /);assert.equal(service[3],'admin policy attach local aws-service-assessor --user aws-service-assessor');
    assert.equal(run('invalid').status,1);assert.equal(readFileSync(log,'utf8').trim().split('\n').length,8);
    input.OBJECT_ACCESS_KEY=input.SERVICE_ASSESSOR_ACCESS_KEY;assert.equal(run('service-assessor-only').status,1);assert.equal(readFileSync(log,'utf8').trim().split('\n').length,9);
  }finally{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^lambda-minio-commission-/);rmSync(directory,{recursive:true,force:true});}
});
