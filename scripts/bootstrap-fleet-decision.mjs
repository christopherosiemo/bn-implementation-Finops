// Candidate-only operator materialization. Never connects to PostgreSQL or AWS.
import assert from 'node:assert/strict';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {chmodSync,closeSync,constants,existsSync,fstatSync,fsyncSync,linkSync,lstatSync,mkdirSync,openSync,readFileSync,readdirSync,realpathSync,unlinkSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {isIP} from 'node:net';
import {fileURLToPath} from 'node:url';

const hash=raw=>createHash('sha256').update(raw).digest('hex');
const fileNames=['commission.sql','database','identity.json'];
const commission=(login,password)=>Buffer.from(`-- Apply only as operator after migration037. This file contains a password.\nCREATE ROLE "${login}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}' IN ROLE finops_group_decision;\n`);
function directory(folder,mode){
 if(!existsSync(folder))mkdirSync(folder,{mode});const stat=lstatSync(folder);assert.ok(stat.isDirectory()&&!stat.isSymbolicLink());assert.equal(realpathSync(folder),path.resolve(folder));
 if(process.platform!=='win32')assert.equal(stat.mode&0o777,mode);
}
function readPrivate(file,mode,maximum){
 const initial=lstatSync(file);assert.ok(initial.isFile()&&!initial.isSymbolicLink()&&initial.nlink===1&&initial.size>0&&initial.size<=maximum);
 if(process.platform!=='win32')assert.equal(initial.mode&0o777,mode);
 const fd=openSync(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0));try{const actual=fstatSync(fd);assert.equal(actual.dev,initial.dev);assert.equal(actual.ino,initial.ino);assert.equal(actual.size,initial.size);const raw=readFileSync(fd);assert.equal(raw.length,initial.size);return raw;}finally{closeSync(fd);}
}
function publish(folder,name,raw,mode){
 assert.ok(fileNames.includes(name)&&raw.length>0&&raw.length<=8192);const temporary=path.join(folder,'.'+randomUUID()+'.tmp');let fd;
 try{fd=openSync(temporary,'wx',mode);writeFileSync(fd,raw);fsyncSync(fd);closeSync(fd);fd=undefined;chmodSync(temporary,mode);linkSync(temporary,path.join(folder,name));}
 finally{if(fd!==undefined)closeSync(fd);try{unlinkSync(temporary);}catch(e){if(e.code!=='ENOENT')throw e;}}
 if(process.platform!=='win32'){const parent=openSync(folder,'r');try{fsyncSync(parent);}finally{closeSync(parent);}}
}

export function materializeDecisionIdentity(root,{tenant,mode='LOCAL_PRIVATE',host='postgres',database='finops'}={}){
 assert.match(tenant,/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/);assert.match(database,/^[A-Za-z][A-Za-z0-9_]{0,62}$/);assert.ok(['LOCAL_PRIVATE','HOSTED_TLS'].includes(mode));
 if(mode==='LOCAL_PRIVATE')assert.equal(host,'postgres');else{assert.match(host,/^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$/);assert.ok(host.includes('.')&&!isIP(host));}
 assert.ok(!host.includes('..')&&!host.includes(':')&&!host.includes('/')&&!host.includes('@'));
 const workspace=realpathSync(root),work=path.join(workspace,'work'),privateRoot=path.join(work,'private'),folder=path.join(privateRoot,'fleet-decision-secrets');
 directory(work,0o755);directory(privateRoot,0o700);directory(folder,0o700);
 const existing=readdirSync(folder).sort();
 if(existing.length){
  assert.deepEqual(existing,fileNames);const raw=readPrivate(path.join(folder,'identity.json'),0o600,4096),manifest=JSON.parse(raw.toString('utf8'));assert.equal(JSON.stringify(manifest)+'\n',raw.toString('utf8'));
  assert.deepEqual(Object.keys(manifest).sort(),['database','database_sha256','host','login','mode','purpose','schema_version','sql_sha256','tenant_id']);
  assert.equal(manifest.schema_version,'1');assert.equal(manifest.purpose,'group-decision-reader');assert.equal(manifest.tenant_id,tenant);assert.equal(manifest.mode,mode);assert.equal(manifest.host,host);assert.equal(manifest.database,database);assert.match(manifest.login,/^group_decision_[a-f0-9]{32}$/);
  const db=readPrivate(path.join(folder,'database'),0o444,8192),sql=readPrivate(path.join(folder,'commission.sql'),0o600,8192);assert.equal(hash(db),manifest.database_sha256);assert.equal(hash(sql),manifest.sql_sha256);
  const url=new URL(db.toString('utf8').trim());assert.equal(url.username,manifest.login);assert.equal(url.hostname,host);assert.equal(url.pathname,'/'+database);assert.equal(url.port,'5432');assert.equal(url.protocol,'postgres:');assert.match(url.password,/^[a-f0-9]{64}$/);assert.deepEqual(sql,commission(url.username,url.password));
  assert.deepEqual([...url.searchParams],mode==='LOCAL_PRIVATE'?[['sslmode','disable']]:[['sslmode','verify-full'],['sslrootcert','/run/ca/group-decision-root.crt']]);
  return {enabled:true,replayed:true,purpose:'group-decision-reader',files:fileNames};
 }
 const login='group_decision_'+randomUUID().replaceAll('-',''),password=randomBytes(32).toString('hex');
 const url=new URL('postgres://'+host+':5432/'+database);url.username=login;url.password=password;url.searchParams.set('sslmode',mode==='LOCAL_PRIVATE'?'disable':'verify-full');if(mode==='HOSTED_TLS')url.searchParams.set('sslrootcert','/run/ca/group-decision-root.crt');
 const db=Buffer.from(url.toString()+'\n'),sql=commission(login,password);
 const manifest={schema_version:'1',purpose:'group-decision-reader',tenant_id:tenant,mode,host,database,login,database_sha256:hash(db),sql_sha256:hash(sql)};
 // The manifest is committed last. A partial prior materialization refuses;
 // no password/identity is silently replaced after a possibly applied SQL file.
 publish(folder,'database',db,0o444);publish(folder,'commission.sql',sql,0o600);publish(folder,'identity.json',Buffer.from(JSON.stringify(manifest)+'\n'),0o600);
 return {enabled:true,replayed:false,purpose:'group-decision-reader',files:fileNames};
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{assert.equal(process.argv.length,2);const enabled=process.env.FLEET_DECISION_ENABLED??'false';assert.ok(['false','true'].includes(enabled));
  const result=enabled==='false'?{enabled:false}:materializeDecisionIdentity(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),{tenant:process.env.FLEET_DECISION_TENANT_ID,mode:process.env.FLEET_DECISION_DATABASE_MODE??'LOCAL_PRIVATE',host:process.env.FLEET_DECISION_BOOTSTRAP_DATABASE_HOST??'postgres',database:process.env.FLEET_DECISION_BOOTSTRAP_DATABASE_NAME??'finops'});
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch{process.stderr.write('FLEET_DECISION_BOOTSTRAP_REFUSED\n');process.exitCode=1;}
}
