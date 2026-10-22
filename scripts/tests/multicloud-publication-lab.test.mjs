import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { chmodSync,mkdtempSync,readdirSync,rmSync,statSync,writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { privatePublicationEnvironment,publicationSourceNames,publicationSourceSnapshot,validateOwnedPublicationContainer,validatePublicationSources } from '../multicloud-publication-lab.mjs';
const workspace=path.resolve('fixture-publication');
function fixtures(){const source=service=>({Image:'sha256:'+'a'.repeat(64),State:{Running:true},Config:{Env:[],Labels:{'com.docker.compose.service':service,'com.docker.compose.project':'fixture','com.docker.compose.project.working_dir':workspace}},NetworkSettings:{Networks:{fixture_private:{}}}});const sources=Object.fromEntries(['api','postgres','minio','clickhouse'].map(s=>[s,source(s)]));sources.api.Config.Env=['FIXTURE_MODE=true'];sources.postgres.Config.Env=['POSTGRES_USER=postgres','POSTGRES_PASSWORD=fixture-password'];sources.minio.Config.Env=['MINIO_ROOT_USER=fixture-user','MINIO_ROOT_PASSWORD=fixture-secret'];sources.clickhouse.Config.Env=['CLICKHOUSE_USER=fixture-user','CLICKHOUSE_PASSWORD=fixture-secret'];return sources;}
test('publication runner refuses live, unrelated, remote-network and cloud-credential storage sources',()=>{
 assert.equal(validatePublicationSources(fixtures(),workspace),'fixture_private');
 for(const fault of ['live','wrong-workspace','wrong-project','stopped','cloud','network']){const s=fixtures();if(fault==='live')s.api.Config.Env=['FIXTURE_MODE=false'];if(fault==='wrong-workspace')s.minio.Config.Labels['com.docker.compose.project.working_dir']=path.resolve('other');if(fault==='wrong-project')s.clickhouse.Config.Labels['com.docker.compose.project']='other';if(fault==='stopped')s.postgres.State.Running=false;if(fault==='cloud')s.minio.Config.Env.push('AWS_SECRET_ACCESS_KEY=not-a-key');if(fault==='network')s.clickhouse.NetworkSettings.Networks={other_private:{}};assert.throws(()=>validatePublicationSources(s,workspace),undefined,fault);}
});
test('only explicit local private credential variables are passed to the isolated test process',()=>{
 const s=fixtures(),env=privatePublicationEnvironment(s);assert.equal(env.trim().split('\n').length,8);assert.match(env,/TEST_MULTICLOUD_ADMIN_URL=postgres:\/\/postgres:fixture-password@postgres:5432\/postgres\?sslmode=disable/);assert.ok(!env.includes('AZURE_')&&!env.includes('GOOGLE_')&&!env.includes('AWS_ACCESS_KEY_ID'));
 s.minio.Config.Env.push('MINIO_ROOT_PASSWORD=bad\nTEST_MULTICLOUD_S3_ENDPOINT=https://customer');assert.throws(()=>privatePublicationEnvironment(s));
});
test('test-process cleanup requires the exact name and ownership label',()=>{const id='11111111-1111-1111-1111-111111111111';const o={Name:'/finops-multicloud-publication-'+id.replaceAll('-',''),Config:{Labels:{'finops.local-publication.run':id}}};validateOwnedPublicationContainer(o,id);assert.throws(()=>validateOwnedPublicationContainer({...o,Name:'/customer'},id));assert.throws(()=>validateOwnedPublicationContainer(o,'other'));});
test('source export excludes credentials, work artifacts and path traversal',()=>{assert.deepEqual(publicationSourceNames(['azure.go','publication_test.go','.env','credentials.json','../secrets.go','nested/key.go','work','README.md','.private.go']),['azure.go','publication_test.go']);});

test('only allowlisted public source is readable by the capability-free container identity',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-publication-source-'));chmodSync(directory,0o700);
 t.after(()=>{const writable=dir=>{chmodSync(dir,0o700);for(const entry of readdirSync(dir,{withFileTypes:true}))if(entry.isDirectory())writable(path.join(dir,entry.name));};writable(directory);rmSync(directory,{recursive:true,force:true});});
 const secret=path.join(directory,'acceptance.env');writeFileSync(secret,'PRIVATE_FIXTURE_SECRET=not-public-source\n',{mode:0o600});
 const source=publicationSourceSnapshot(directory);const files=[];
 const check=dir=>{if(process.platform!=='win32')assert.equal(statSync(dir).mode&0o777,0o555,'Public source directories must be readable/searchable without DAC_OVERRIDE');for(const entry of readdirSync(dir,{withFileTypes:true})){const name=path.join(dir,entry.name);assert.equal(entry.isSymbolicLink(),false);if(entry.isDirectory())check(name);else{files.push(path.relative(source,name).split(path.sep).join('/'));if(process.platform!=='win32')assert.equal(statSync(name).mode&0o777,0o444,'Public source must not require host ownership or permit writes');}}};
 check(source);assert.ok(files.includes('go.mod')&&files.includes('migrations/019_multicloud_observations.sql')&&files.includes('internal/multicloud/publication_postgres_test.go'));
 assert.ok(files.every(name=>['go.mod','go.sum','migrations/001_control_plane.sql','migrations/019_multicloud_observations.sql'].includes(name)||/^internal\/multicloud\/[a-z][a-z0-9_]*\.go$/.test(name)));
 if(process.platform!=='win32'){assert.equal(statSync(directory).mode&0o777,0o700,'Private run directory must stay private');assert.equal(statSync(secret).mode&0o777,0o600,'Credential file must stay private');}
});
