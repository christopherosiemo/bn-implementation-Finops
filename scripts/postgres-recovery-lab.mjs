// Consistent physical backup of this local fixture cluster only. The restored
// database is quarantined: no network, ports, services, workers or executors.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { authenticatedBackup, encryptBackup } from './lib/encrypted-backup.mjs';
import { localDockerEndpoint } from './kubernetes-bootstrap.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const labelKey = 'finops.local-recovery.run';
const sourceLabelKey = 'finops.local-recovery.source';
const coreRoles = ['finops_api', 'finops_worker', 'finops_signer', 'finops_executor', 'finops_ingester', 'finops_activity', 'finops_telemetry_reader', 'finops_telemetry_ingress', 'finops_deployment_observer', 'finops_hardware_reader'];
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const literal = value => "'" + String(value).replaceAll("'", "''") + "'";
const identifier = value => { assert.match(value, /^[a-z][a-z0-9_]*$/); return '"' + value + '"'; };
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

function run(args, input, timeout = 120_000) {
  try { return execFileSync('docker', args, { cwd: root, input, encoding: 'utf8', windowsHide: true, timeout, maxBuffer: 8 << 20, stdio: ['pipe', 'pipe', 'pipe'] }).trim(); }
  catch { throw new Error('An isolated local recovery Docker command failed; no raw command, SQL, credentials or database rows are logged'); }
}
const inspect = (type, id) => JSON.parse(run(['inspect', '--type', type, id]))[0];
const sql = (container, user, database, statement) => run(['exec', '-i', container, 'psql', '-X', '-w', '-v', 'ON_ERROR_STOP=1', '-U', user, '-h', '/tmp', '-d', database, '-Atq'], statement);
const sourceSQL = (container, user, database, statement) => run(['exec', '-i', container, 'psql', '-X', '-w', '-v', 'ON_ERROR_STOP=1', '-U', user, '-h', '/var/run/postgresql', '-d', database, '-Atq'], statement);
const environment = object => Object.fromEntries((object.Config?.Env || []).map(item => { const at = item.indexOf('='); return [item.slice(0, at), item.slice(at + 1)]; }));

export function validateRecoverySources(api, postgres, workspace) {
  assert.equal(api.State?.Running, true, 'The local fixture API must be running');
  assert.equal(postgres.State?.Running, true, 'The explicit local Compose PostgreSQL must be running');
  assert.equal(environment(api).FIXTURE_MODE, 'true', 'Recovery lab refuses a non-fixture API');
  assert.notEqual(environment(api).DATA_MODE, 'aws', 'Recovery lab refuses live provider mode');
  for (const [object, service] of [[api, 'api'], [postgres, 'postgres']]) {
    assert.equal(object.Config?.Labels?.['com.docker.compose.service'], service, 'Only the exact Compose service may be selected');
    assert.equal(path.resolve(object.Config?.Labels?.['com.docker.compose.project.working_dir'] || ''), path.resolve(workspace), 'Compose source belongs to a different workspace');
  }
  assert.equal(api.Config.Labels['com.docker.compose.project'], postgres.Config.Labels['com.docker.compose.project'], 'Sources must belong to the same local Compose project');
  assert.match(postgres.Image, /^sha256:[a-f0-9]{64}$/);
  assert.ok(!Object.keys(environment(postgres)).some(key => /^(AWS_|AZURE_|GOOGLE_|GCP_|ARM_)/.test(key)), 'PostgreSQL source may not carry cloud credentials');
}
export function validateOwnedRecoveryObject(object, runID, sourceID) {
  const labels = object.Labels || object.Config?.Labels || {};
  assert.equal(labels[labelKey], runID, 'Cleanup target is not owned by this recovery run');
  assert.equal(labels[sourceLabelKey], sourceID, 'Cleanup target belongs to a different source');
  const name = object.Name?.replace(/^\//, '');
  assert.ok(name?.startsWith('finops-pg-recovery-'), 'Unexpected cleanup target name');
}
function privateDirectory(relative) {
  const directory = path.join(root, relative);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(directory), suffix = path.relative(realpathSync(root), resolved);
  assert.ok(suffix && suffix !== '..' && !suffix.startsWith('..' + path.sep) && !path.isAbsolute(suffix), 'Recovery files must stay in this workspace');
  chmodSync(resolved, 0o700);
  if (process.platform === 'win32') {
    const account = execFileSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).trim();
    assert.match(account, /^[^\r\n]+\\[^\r\n]+$/);
    execFileSync('icacls.exe', [resolved, '/inheritance:r', '/grant:r', `${account}:(OI)(CI)F`], { windowsHide: true, stdio: 'pipe' });
  }
  return resolved;
}
function child(args) {
  const process = spawn('docker', args, { cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderrBytes = 0;
  process.stderr.on('data', chunk => { stderrBytes += chunk.length; if (stderrBytes > 2 << 20) process.kill(); });
  const timeout = setTimeout(() => process.kill(), 15 * 60_000);
  const completed = new Promise((resolve, reject) => {
    process.once('error', () => reject(new Error('Local recovery process could not start')));
    process.once('close', code => { clearTimeout(timeout); code === 0 ? resolve() : reject(new Error('Local recovery process failed; diagnostic data remains private')); });
  });
  completed.catch(() => {});
  return { process, completed };
}
function jsonSQL(query, container, user, database, source = true) { return JSON.parse((source ? sourceSQL : sql)(container, user, database, query)); }
const digestSQL = expression => `encode(sha256(convert_to(${expression},'UTF8')),'hex')`;
const metadataSQL = `SELECT json_build_object(
 'migrations',(SELECT json_agg(x ORDER BY x.filename) FROM (SELECT filename,sha256 FROM schema_migrations) x),
 'relations',(SELECT json_agg(x ORDER BY x.relname) FROM (SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relacl::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r') x),
 'policies',(SELECT json_agg(x ORDER BY x.tablename,x.policyname) FROM (SELECT tablename,policyname,roles::text,cmd,qual,with_check FROM pg_policies WHERE schemaname='public') x),
 'guards',(SELECT json_agg(x ORDER BY x.table_name,x.tgname) FROM (SELECT c.relname AS table_name,t.tgname,pg_get_triggerdef(t.oid) AS definition FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal) x),
 'indexes',(SELECT json_agg(x ORDER BY x.indexname) FROM (SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='public') x),
 'roles',(SELECT json_agg(x ORDER BY x.rolname) FROM (SELECT rolname,rolsuper,rolbypassrls,rolcanlogin,rolinherit FROM pg_roles WHERE rolname IN (${coreRoles.map(literal).join(',')})) x),
 'memberships',(SELECT json_agg(x ORDER BY x.role_name,x.member_name) FROM (SELECT parent.rolname AS role_name,member.rolname AS member_name,m.admin_option FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN (${coreRoles.map(literal).join(',')}) OR member.rolname IN (${coreRoles.map(literal).join(',')})) x)
);`;
function samples(container, user) {
  const groups = [];
  for (const [table, key] of [['audit_events','id'], ['savings_ledger','id'], ['signed_plans','plan_id'], ['provider_operations','execution_id']]) {
    const where = table === 'provider_operations' ? "WHERE restored AND updated_at < now()-interval '5 minutes'" : '';
    const rows = jsonSQL(`SELECT coalesce(json_agg(x),'[]') FROM (SELECT tenant_id,${key} AS id,${digestSQL('to_jsonb(t)::text')} AS hash FROM ${table} t ${where} ORDER BY tenant_id,${key} LIMIT 16) x;`, container, user, 'finops');
    assert.ok(rows.length > 0, `Existing ${table} evidence is required for actual recovery acceptance`);
    groups.push({ table, key, rows });
  }
  return groups;
}
function compareSamples(groups, container, user) {
  for (const { table, key, rows } of groups) {
    for (const row of rows) {
      const actual = sql(container, user, 'finops', `BEGIN READ ONLY; SELECT ${digestSQL('to_jsonb(t)::text')} FROM ${table} t WHERE tenant_id=${literal(row.tenant_id)} AND ${key}=${literal(row.id)}; COMMIT;`);
      assert.equal(actual, row.hash, `Restored immutable/completed evidence changed in ${table}`);
    }
  }
}
function temporalMetadata(container, user, source) {
  return ['temporal','temporal_visibility'].map(database => {
    const metadata = jsonSQL(`SELECT json_build_object('tables',(SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'),'versions',(SELECT json_agg(to_jsonb(v)) FROM schema_version v));`, container, user, database, source);
    assert.ok(metadata.tables.length > 0 && metadata.versions.length > 0, 'Existing Temporal database schema is required');
    return { database, hash:hash(metadata), tables:metadata.tables.length };
  });
}
function seedSentinel(source, user, database, runID, created) {
  sourceSQL(source,user,'postgres',`CREATE DATABASE ${identifier(database)}; COMMENT ON DATABASE ${identifier(database)} IS ${literal('finops-local-recovery:'+runID)};`);
  created();
  sourceSQL(source,user,database,`
    CREATE TABLE ledger(tenant_id text NOT NULL,id text NOT NULL,amount numeric(38,12) NOT NULL,PRIMARY KEY(tenant_id,id));
    ALTER TABLE ledger ENABLE ROW LEVEL SECURITY; ALTER TABLE ledger FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON ledger USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
    CREATE FUNCTION immutable_recovery_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append-only recovery evidence'; END $$;
    CREATE TRIGGER immutable_recovery_evidence BEFORE UPDATE OR DELETE ON ledger FOR EACH ROW EXECUTE FUNCTION immutable_recovery_evidence();
    CREATE TABLE active_intents(tenant_id text NOT NULL,resource_id text NOT NULL,execution_id text NOT NULL,active boolean NOT NULL,PRIMARY KEY(tenant_id,execution_id));
    ALTER TABLE active_intents ENABLE ROW LEVEL SECURITY; ALTER TABLE active_intents FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON active_intents USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
    CREATE UNIQUE INDEX one_active_intent ON active_intents(tenant_id,resource_id) WHERE active;
    INSERT INTO ledger VALUES('recovery-a','row-a',1.123456789012),('recovery-b','row-b',2.000000000001);
    INSERT INTO active_intents VALUES('recovery-a','resource-one','execution-one',true);
    GRANT USAGE ON SCHEMA public TO finops_api;
    GRANT SELECT,INSERT,UPDATE,DELETE ON ledger,active_intents TO finops_api;
  `);
}
function checkSentinel(container,user,database) {
  sql(container,user,database,`
    SET default_transaction_read_only=off; BEGIN; SET LOCAL ROLE finops_api; SELECT set_config('app.tenant_id','recovery-a',true);
    DO $$ BEGIN
      IF (SELECT count(*) FROM ledger)<>1 OR (SELECT amount FROM ledger)<>1.123456789012 THEN RAISE EXCEPTION 'tenant isolation or exact decimal failed'; END IF;
      BEGIN UPDATE ledger SET amount=9; RAISE EXCEPTION 'mutation incorrectly allowed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'append-only recovery evidence' THEN RAISE; END IF; END;
      BEGIN DELETE FROM ledger; RAISE EXCEPTION 'deletion incorrectly allowed'; EXCEPTION WHEN SQLSTATE 'P0001' THEN IF SQLERRM<>'append-only recovery evidence' THEN RAISE; END IF; END;
      BEGIN INSERT INTO ledger VALUES('recovery-b','cross-tenant',1); RAISE EXCEPTION 'cross-tenant insert incorrectly allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
      BEGIN INSERT INTO active_intents VALUES('recovery-a','resource-one','execution-two',true); RAISE EXCEPTION 'duplicate active intent incorrectly allowed'; EXCEPTION WHEN unique_violation THEN NULL; END;
    END $$;
    SELECT set_config('app.tenant_id','recovery-b',true);
    DO $$ BEGIN IF (SELECT count(*) FROM ledger)<>1 OR (SELECT amount FROM ledger)<>2.000000000001 THEN RAISE EXCEPTION 'second tenant isolation failed'; END IF; END $$;
    ROLLBACK;
  `);
}

export async function recoveryLab() {
  assert.equal(process.argv.length,2,'No alternate source, destination, credentials or remote target arguments are accepted');
  if (process.env.DOCKER_HOST) assert.ok(localDockerEndpoint(process.env.DOCKER_HOST),'Remote Docker hosts are forbidden');
  const contextName=run(['context','show']); const context=JSON.parse(run(['context','inspect',contextName]))[0];
  assert.ok(localDockerEndpoint(context.Endpoints?.docker?.Host),'Remote Docker contexts are forbidden');
  const source=run(['compose','ps','-q','postgres']),apiID=run(['compose','ps','-q','api']);
  assert.match(source,/^[a-f0-9]{64}$/);assert.match(apiID,/^[a-f0-9]{64}$/);
  const postgres=inspect('container',source),api=inspect('container',apiID);validateRecoverySources(api,postgres,root);
  const sourceEnv=environment(postgres),user=sourceEnv.POSTGRES_USER||'postgres';identifier(user);
  const prerequisites=jsonSQL(`SELECT json_build_object('version',current_setting('server_version_num')::int,'tablespaces',(SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')),'primary',NOT pg_is_in_recovery(),'wal_level',current_setting('wal_level'),'full_page_writes',current_setting('full_page_writes'),'senders',current_setting('max_wal_senders')::int);`,source,user,'finops');
  assert.ok(prerequisites.version>=170000&&prerequisites.version<180000,'This lab is pinned to PostgreSQL 17');assert.equal(prerequisites.tablespaces,0,'Tar stdout backup does not support extra tablespaces');assert.equal(prerequisites.primary,true);assert.notEqual(prerequisites.wal_level,'minimal');assert.equal(prerequisites.full_page_writes,'on');assert.ok(prerequisites.senders>0);
  const uid=run(['exec',source,'id','-u','postgres']),gid=run(['exec',source,'id','-g','postgres']);assert.match(uid,/^[0-9]+$/);assert.match(gid,/^[0-9]+$/);
  const runID=randomUUID(),short=runID.replaceAll('-',''),database='local_recovery_sentinel_'+short,volume='finops-pg-recovery-'+short,container='finops-pg-recovery-'+short;
  const directory=privateDirectory(path.join('work','private','postgres-recovery',runID)),backups=privateDirectory(path.relative(root,path.join(directory,'backups'))),keys=privateDirectory(path.relative(root,path.join(directory,'keys')));
  const key=randomBytes(32),keyFile=path.join(keys,'recovery.key'),partial=path.join(backups,'physical.partial.enc'),archive=path.join(backups,'physical.tar.gz.aes256gcm');
  writeFileSync(keyFile,key,{flag:'wx',mode:0o600});chmodSync(keyFile,0o600);
  const labels=['--label',`${labelKey}=${runID}`,'--label',`${sourceLabelKey}=${source}`];
  const isolation=['--pull','never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','768m','--cpus','1',...labels];
  const mount=['--mount',`type=volume,src=${volume},dst=/var/lib/postgresql/data`],ownedContainers=[];
  let sentinel=false,volumeCreated=false,passed=0;
  const started=Date.now(),pass=message=>{passed++;console.log('PostgreSQL recovery lab: '+message);};
  try {
    seedSentinel(source,user,database,runID,()=>{sentinel=true;});
    const metadata=jsonSQL(metadataSQL,source,user,'finops'),sampled=samples(source,user),temporal=temporalMetadata(source,user,true);
    assert.equal(metadata.roles.length,coreRoles.length);assert.ok(metadata.relations.filter(r=>r.relrowsecurity&&r.relforcerowsecurity).length>10);
    pass('explicit local fixture primary and test-owned sentinel; application rows remain read-only');
    const backup=child(['exec','--user','postgres',source,'pg_basebackup','-U',user,'-h','/var/run/postgresql','--no-password','--pgdata=-','--format=tar','--wal-method=fetch','--checkpoint=fast','--max-rate=64M','--manifest-checksums=SHA256','--label','finops-local-recovery-'+runID]);backup.process.stdin.end();
    let encryptedHash;
    try { [encryptedHash]=await Promise.all([encryptBackup(backup.process.stdout,partial,key),backup.completed]); } catch(error){backup.process.kill();throw error;}
    renameSync(partial,archive);const backedUp=Date.now();pass('whole-cluster physical tar streamed directly through gzip and AES-256-GCM; native backup process succeeded');
    let incorrectConsumer=false;await assert.rejects(authenticatedBackup(archive,randomBytes(32),async()=>{incorrectConsumer=true;}));assert.equal(incorrectConsumer,false);pass('wrong recovery key rejects the real archive before creating a restore consumer');
    await authenticatedBackup(archive,key,async()=>{
      run(['volume','create',...labels,volume]);volumeCreated=true;validateOwnedRecoveryObject(inspect('volume',volume),runID,source);
      run(['run','--rm',...isolation,'--user','0:0','--cap-add','CHOWN',...mount,'--entrypoint','chown',postgres.Image,`${uid}:${gid}`,'/var/lib/postgresql/data']);
      const extraction=container+'-extract';ownedContainers.push(extraction);
      const unpack=child(['run','--rm','-i','--name',extraction,...isolation,'--user',`${uid}:${gid}`,...mount,'--entrypoint','sh',postgres.Image,'-c','umask 077; chmod 700 /var/lib/postgresql/data; exec tar -xo -f - -C /var/lib/postgresql/data']);
      return {input:unpack.process.stdin,completed:unpack.completed,abort(){unpack.process.kill();}};
    });
    const verifyStarted=Date.now();run(['run','--rm',...isolation,'--user',`${uid}:${gid}`,...mount,'--entrypoint','pg_verifybackup',postgres.Image,'--exit-on-error','--quiet','/var/lib/postgresql/data'],undefined,10*60_000);const verified=Date.now();pass('AES-GCM authentication and native pg_verifybackup checksums plus required WAL parsing succeeded before startup');
    ownedContainers.push(container);
    run(['run','-d','--name',container,...isolation,'--user',`${uid}:${gid}`,...mount,'--tmpfs','/tmp:rw,noexec,nosuid,size=32m,mode=1777','--entrypoint','postgres',postgres.Image,'-D','/var/lib/postgresql/data','-c','listen_addresses=','-c','unix_socket_directories=/tmp','-c','archive_mode=off','-c','archive_command=','-c','restore_command=','-c','primary_conninfo=','-c','primary_slot_name=','-c','recovery_end_command=','-c','shared_preload_libraries=','-c','session_preload_libraries=','-c','local_preload_libraries=','-c','max_worker_processes=0','-c','max_parallel_workers=0','-c','max_logical_replication_workers=0','-c','autovacuum=off','-c','default_transaction_read_only=on','-c','log_statement=none','-c','log_min_error_statement=panic']);
    const recovered=inspect('container',container);validateOwnedRecoveryObject(recovered,runID,source);assert.equal(recovered.Image,postgres.Image);assert.equal(recovered.HostConfig.NetworkMode,'none');assert.equal(recovered.HostConfig.ReadonlyRootfs,true);assert.equal(Object.keys(recovered.NetworkSettings.Ports||{}).length,0);assert.equal(recovered.Mounts.filter(m=>m.Type==='volume').length,1);assert.ok(!Object.keys(environment(recovered)).some(key=>/^(AWS_|AZURE_|GOOGLE_|GCP_|ARM_)/.test(key)));
    const deadline=Date.now()+90_000;let ready=false;while(Date.now()<deadline){try{ready=sql(container,user,'postgres','SELECT 1;')==='1';}catch{}if(ready)break;await sleep(1000);}assert.equal(ready,true,'The isolated restored PostgreSQL failed to become readable');
    assert.equal(sql(container,user,'postgres',"SELECT current_setting('listen_addresses')='' AND current_setting('archive_mode')='off' AND current_setting('primary_conninfo')='' AND NOT pg_is_in_recovery();"),'t');pass('same exact PostgreSQL image starts as a socket-only quarantined primary with no ports, network, preload libraries or application workers');
    compareSamples(sampled,container,user);const restoredMetadata=jsonSQL(metadataSQL,container,user,'finops',false);assert.equal(hash(restoredMetadata),hash(metadata),'Application schema, grants, forced RLS, roles or immutable guards changed');pass('actual audit, ledger, signed-envelope and completed ownership rows survive with identical SHA-256 hashes and database authority metadata');
    assert.deepEqual(temporalMetadata(container,user,false),temporal);pass('Temporal and visibility databases retain their native schema-version readback');
    checkSentinel(container,user,database);pass('restored restricted API role enforces exact decimals, append-only UPDATE/DELETE denial, tenant isolation and active-intent uniqueness');
    const finished=Date.now();const acceptance={schema_version:'1',run_id:runID,local_fixture_only:true,hosted_cloud:false,source_image_id:postgres.Image,postgres_version:prerequisites.version,encrypted_sha256:encryptedHash,encrypted_bytes:statSync(archive).size,archive:path.relative(root,archive),key:path.relative(root,keyFile),physical_backup_includes_all_cluster_databases:true,checks:passed,sample_counts:Object.fromEntries(sampled.map(group=>[group.table,group.rows.length])),sample_commitment:hash(sampled),authority_metadata_sha256:hash(metadata),temporal,quarantined:true,network:'none',published_ports:0,application_workers_started:0,timings_seconds:{backup:(backedUp-started)/1000,offline_manifest_verification:(verified-verifyStarted)/1000,total:(finished-started)/1000},production_rto_proven:false,temporal_workflow_resume_proven:false,object_store_recovery_proven:false,clickhouse_recovery_proven:false};
    writeFileSync(path.join(directory,'acceptance.json'),JSON.stringify(acceptance,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(`PostgreSQL recovery lab: PASS ${passed}; encrypted backup and private acceptance record retained under work/private/postgres-recovery/${runID}`);
    return acceptance;
  } finally {
    for(const name of ownedContainers.reverse()){
      let object;try{object=inspect('container',name);}catch{continue;}
      validateOwnedRecoveryObject(object,runID,source);run(['rm','-f',name]);
    }
    if(volumeCreated){const object=inspect('volume',volume);validateOwnedRecoveryObject(object,runID,source);run(['volume','rm',volume]);}
    if(sentinel){const marker=sourceSQL(source,user,'postgres',`SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=${literal(database)};`);assert.equal(marker,'finops-local-recovery:'+runID,'Sentinel ownership changed; refusing cleanup');sourceSQL(source,user,'postgres',`DROP DATABASE ${identifier(database)};`);}
    key.fill(0);
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){try{await recoveryLab();}catch{console.error('PostgreSQL recovery lab failed safely; no raw database data or credentials are printed. Test-owned recovery resources are cleaned; any encrypted partial archive remains private.');process.exitCode=1;}}
