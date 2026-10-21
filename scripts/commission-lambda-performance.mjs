// Explicit local operator action. No Docker or database work occurs on import.
// The runtime identity is a trusted ingress: machine authentication and source/
// tenant binding remain in activity.Server. These grants are not INSERT RLS.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {constants,fstatSync,lstatSync,openSync,closeSync,readFileSync,realpathSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {recoveryDockerEndpoint} from './lib/recovery-upgrade.mjs';

export const lambdaPerformanceReadColumns = Object.freeze(['tenant_id','connection_id','batch_id','raw_sha256','sample_id','payload']);
const digest = value => createHash('sha256').update(value).digest('hex');
const safe = (value, maximum=8192) => typeof value === 'string' && value.length>0 && value.length<=maximum && !/[\r\n\0]/.test(value);
const xml = value => value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
export function lambdaPerformanceIdentity(env) {
  assert.equal(env.FIXTURE_MODE,'true');
  assert.match(env.COMPOSE_PROJECT_NAME,/^[a-z0-9][a-z0-9_-]{0,62}$/);
  assert.match(env.LAMBDA_PERFORMANCE_ACCESS_KEY??'',/^lambda-perf-[a-f0-9]{8}$/);
  assert.match(env.LAMBDA_PERFORMANCE_CLICKHOUSE_USER??'',/^lambda_performance_[a-f0-9]{16}$/);
  for(const name of ['LAMBDA_PERFORMANCE_SECRET_KEY','LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD']) assert.match(env[name]??'',/^[a-f0-9]{48}$/);
  assert(safe(env.CLICKHOUSE_PASSWORD));
  const names=['LAMBDA_PERFORMANCE_ACCESS_KEY','LAMBDA_PERFORMANCE_SECRET_KEY','LAMBDA_PERFORMANCE_CLICKHOUSE_USER','LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD'];
  assert.equal(new Set(names.map(name=>env[name])).size,names.length);
  for(const name of names) assert(!Object.entries(env).some(([other,value])=>!names.includes(other)&&value&&value===env[name]));
  return {project:env.COMPOSE_PROJECT_NAME,user:env.LAMBDA_PERFORMANCE_CLICKHOUSE_USER,password:env.LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD,adminPassword:env.CLICKHOUSE_PASSWORD};
}
export function validateLambdaPerformanceTarget(value,workspace,project) {
  assert(value.Running===true&&/^[a-f0-9]{64}$/.test(value.Id)&&/^sha256:[a-f0-9]{64}$/.test(value.Image));
  assert.equal(value.Labels?.['com.docker.compose.service'],'clickhouse');
  assert.equal(value.Labels?.['com.docker.compose.project'],project);
  assert.equal(path.resolve(value.Labels?.['com.docker.compose.project.working_dir']??''),path.resolve(workspace));
  assert.deepEqual((value.Labels?.['com.docker.compose.project.config_files']??'').split(',').map(file=>path.resolve(file)),[path.join(path.resolve(workspace),'compose.yaml')]);
  assert.equal(value.NetworkMode,project+'_private');
  assert.deepEqual(Object.keys(value.Networks??{}),[project+'_private']);
  assert.match(value.Networks[project+'_private'].NetworkID,/^[a-f0-9]{64}$/);
  assert(!Object.values(value.Ports??{}).some(bindings=>bindings?.length));
  const volumes=(value.Mounts??[]).filter(mount=>mount.Destination==='/var/lib/clickhouse');
  assert.equal(volumes.length,1);assert.equal(volumes[0].Type,'volume');assert.equal(volumes[0].Name,project+'_clickhouse');
  return {id:value.Id,image:value.Image,network:value.Networks[project+'_private'].NetworkID,volume:volumes[0].Name};
}
export function lambdaPerformanceGrants() {
  return [
    ...['native_metric_samples','native_metric_batches'].map(table=>({access_type:'INSERT',database:'finops',table,column:null,is_partial_revoke:0,grant_option:0,is_wildcard:0})),
    ...lambdaPerformanceReadColumns.map(column=>({access_type:'SELECT',database:'finops',table:'native_metric_samples',column,is_partial_revoke:0,grant_option:0,is_wildcard:0})),
  ];
}
const sorted = rows => rows.map(row=>JSON.stringify(row)).sort();
export function lambdaPerformanceCreateSQL(identity) {
  assert.match(identity.user,/^lambda_performance_[a-f0-9]{16}$/);assert.match(identity.password,/^[a-f0-9]{48}$/);
  // Only the high-entropy password digest reaches SQL/query logs. Never rotate
  // or replace an existing user, and never create a role with inherited rights.
  return `CREATE USER ${identity.user} IDENTIFIED WITH sha256_hash BY '${digest(identity.password)}' DEFAULT ROLE NONE;\nGRANT INSERT ON finops.native_metric_samples TO ${identity.user};\nGRANT INSERT ON finops.native_metric_batches TO ${identity.user};\nGRANT SELECT(${lambdaPerformanceReadColumns.join(',')}) ON finops.native_metric_samples TO ${identity.user};\n`;
}
export function lambdaPerformanceClientScript(identity,query,ingress=false) {
  assert(safe(identity.adminPassword)&&safe(identity.password)&&safe(identity.user,100));
  assert(typeof query==='string'&&query.length>0&&query.length<=32768&&!query.includes('FINOPS_LAMBDA_')&&!query.includes('\0'));
  const config=`<config><host>127.0.0.1</host><port>9000</port><database>finops</database><user>${xml(ingress?identity.user:'finops')}</user><password>${xml(ingress?identity.password:identity.adminPassword)}</password></config>`;
  // The secret is supplied over Docker stdin, never argv, Config.Env or logs.
  // Only two known files under this mktemp directory are removed by the trap.
  return `set -eu\numask 077\ncommission_dir=$(mktemp -d /tmp/finops-lambda-performance.XXXXXXXX)\ntrap 'rm -f "$commission_dir/client.xml" "$commission_dir/query.sql"; rmdir "$commission_dir"' EXIT HUP INT TERM\ncat > "$commission_dir/client.xml" <<'FINOPS_LAMBDA_CLIENT'\n${config}\nFINOPS_LAMBDA_CLIENT\ncat > "$commission_dir/query.sql" <<'FINOPS_LAMBDA_QUERY'\n${query}\nFINOPS_LAMBDA_QUERY\nclickhouse-client --config-file "$commission_dir/client.xml" --multiquery --queries-file "$commission_dir/query.sql" --format JSONEachRow --send_logs_level fatal\n`;
}
export function commissionLambdaPerformance(identity,query) {
  const user=identity.user;
  const unrelated=()=>({
    users:query(`SELECT name,toString(id) AS id FROM system.users WHERE name!='${user}' ORDER BY name FORMAT JSONEachRow;`),
    grants:query(`SELECT user_name,role_name,access_type,database,table,column,is_partial_revoke,grant_option,is_wildcard FROM system.grants WHERE ifNull(user_name,'')!='${user}' ORDER BY user_name,role_name,access_type,database,table,column FORMAT JSONEachRow;`),
    tables:query("SELECT name,toString(uuid) AS uuid,engine FROM system.tables WHERE database='finops' ORDER BY name FORMAT JSONEachRow;"),
  });
  const before=unrelated();
  for(const name of ['native_metric_samples','native_metric_batches'])assert(before.tables.some(table=>table.name===name));
  const existing=query(`SELECT name FROM system.users WHERE name='${user}' FORMAT JSONEachRow;`);
  assert(existing.length<=1);
  if(existing.length===0)query(lambdaPerformanceCreateSQL(identity));
  const grants=query(`SELECT access_type,database,table,column,is_partial_revoke,grant_option,is_wildcard FROM system.grants WHERE user_name='${user}' ORDER BY access_type,table,column FORMAT JSONEachRow;`);
  assert.deepEqual(sorted(grants),sorted(lambdaPerformanceGrants()));
  assert.deepEqual(query(`SELECT granted_role_name FROM system.role_grants WHERE user_name='${user}' FORMAT JSONEachRow;`),[]);
  assert.deepEqual(query('SELECT currentUser() AS user FORMAT JSONEachRow;',true),[{user}]);
  // Non-mutating privilege checks: a failed write probe must never create a
  // foreign financial row or change a live table merely to test its refusal.
  for(const [permission,want]of [['INSERT ON finops.native_metric_samples',1],['INSERT ON finops.native_metric_batches',1],['SELECT(sample_id,payload,tenant_id,connection_id,batch_id,raw_sha256) ON finops.native_metric_samples',1],['SELECT ON finops.billing_facts',0],['INSERT ON finops.billing_facts',0],['SELECT ON finops.native_metric_batches',0],['CREATE USER ON *.*',0],['ALTER TABLE ON finops.native_metric_samples',0]]){
    const rows=query(`CHECK GRANT ${permission};`,true);assert.equal(rows.length,1);assert.equal(Number(Object.values(rows[0])[0]),want);
  }
  assert.deepEqual(unrelated(),before);
  return {schema_version:'1',purpose:'LOCAL_LAMBDA_PERFORMANCE_INGRESS',status:'COMPLETE',replayed:existing.length===1,analytics_user:user,grants_sha256:digest(JSON.stringify(sorted(grants))),tables:['native_metric_samples','native_metric_batches'],tenant_enforcement:'AUTHENTICATED_INGRESS_SOURCE_BINDING',database_row_level_isolation_claimed:false,provider_credentials:false,execution_authorized:false};
}
function readEnvironment(root) {
  const file=path.join(root,'.env'),before=lstatSync(file);
  assert(before.isFile()&&!before.isSymbolicLink()&&before.nlink===1&&before.size>0&&before.size<=131072);
  if(process.platform!=='win32')assert.equal(before.mode&0o777,0o600);
  const fd=openSync(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0));let raw;
  try{const stat=fstatSync(fd);assert.equal(stat.dev,before.dev);assert.equal(stat.ino,before.ino);raw=readFileSync(fd);assert.equal(raw.length,before.size);}finally{closeSync(fd);}
  const env={};for(const line of raw.toString('utf8').split(/\r?\n/)){if(!line||line.startsWith('#'))continue;const at=line.indexOf('=');assert(at>0);env[line.slice(0,at)]=line.slice(at+1);}
  return env;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  let stage='INPUT';
  try {
    assert.deepEqual(process.argv.slice(2),['--local-fixture']);
    const root=realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..')),identity=lambdaPerformanceIdentity(readEnvironment(root));
    const run=(args,input)=>{const result=spawnSync('docker',args,{cwd:root,env:process.env,input,encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:1<<20,stdio:['pipe','pipe','pipe']});if(result.error||result.status!==0)throw Error('DOCKER_REQUEST_FAILED');return result.stdout.trim();};
    const contextName=run(['context','show']),context=JSON.parse(run(['context','inspect',contextName]))[0],endpoint=recoveryDockerEndpoint(contextName,context,process.env.DOCKER_HOST);
    const docker=(args,input)=>run(['--host',endpoint,...args],input);
    stage='TARGET';
    const ids=docker(['ps','--filter','label=com.docker.compose.project='+identity.project,'--filter','label=com.docker.compose.service=clickhouse','--format','{{.ID}}']).split(/\r?\n/).filter(Boolean);assert.equal(ids.length,1);
    const format='{"Id":{{json .Id}},"Image":{{json .Image}},"Running":{{json .State.Running}},"Labels":{{json .Config.Labels}},"NetworkMode":{{json .HostConfig.NetworkMode}},"Networks":{{json .NetworkSettings.Networks}},"Ports":{{json .NetworkSettings.Ports}},"Mounts":{{json .Mounts}}}';
    const inspect=()=>JSON.parse(docker(['inspect','--type','container','--format',format,ids[0]]));
    const target=validateLambdaPerformanceTarget(inspect(),root,identity.project);
    stage='COMMISSION';
    const result=commissionLambdaPerformance(identity,(sql,ingress=false)=>{assert.deepEqual(validateLambdaPerformanceTarget(inspect(),root,identity.project),target);const output=docker(['exec','-i',target.id,'/bin/sh','-s'],lambdaPerformanceClientScript(identity,sql,ingress));return output?output.split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line)):[];});
    assert.deepEqual(validateLambdaPerformanceTarget(inspect(),root,identity.project),target);
    process.stdout.write(JSON.stringify(result)+'\n');
  } catch { process.stderr.write('LAMBDA_PERFORMANCE_'+stage+'_REFUSED\n');process.exitCode=1; }
}
