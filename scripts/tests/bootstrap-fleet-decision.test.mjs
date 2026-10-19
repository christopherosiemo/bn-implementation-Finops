import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,chmodSync,writeFileSync,lstatSync,symlinkSync,mkdirSync,readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import os from 'node:os';import path from 'node:path';
import {materializeDecisionIdentity,materializeDecisionCredentialBinding} from '../bootstrap-fleet-decision.mjs';

test('separate operator identity is private, atomic, replayable and never applied',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'joint-identity-'));const result=materializeDecisionIdentity(root,{tenant:'tenant'});assert.equal(result.replayed,false);
 const folder=path.join(root,'work/private/fleet-decision-secrets'),db=readFileSync(path.join(folder,'database')),sql=readFileSync(path.join(folder,'commission.sql'),'utf8');const u=new URL(db.toString().trim());
 assert.match(u.username,/^group_decision_[a-f0-9]{32}$/);assert.equal(u.hostname,'postgres');assert.equal(u.search,'?sslmode=disable');assert.ok(sql.includes('IN ROLE finops_group_decision;'));assert.ok(sql.includes('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'));
 assert.match(sql,/migration038/);assert.ok(sql.includes('BEGIN;\nCREATE ROLE'));assert.ok(sql.includes('INSERT INTO public.fleet_decision_credentials(id,database_login,role_oid,tenant_id) SELECT'));assert.ok(sql.endsWith('COMMIT;\n'));assert.equal(result.credential_scope_binding_required,false);
 if(process.platform!=='win32'){assert.equal(lstatSync(folder).mode&0o777,0o700);assert.equal(lstatSync(path.join(folder,'database')).mode&0o777,0o444);assert.equal(lstatSync(path.join(folder,'commission.sql')).mode&0o777,0o600)}
 assert.equal(materializeDecisionIdentity(root,{tenant:'tenant'}).replayed,true);assert.deepEqual(readFileSync(path.join(folder,'database')),db);assert.throws(()=>materializeDecisionIdentity(root,{tenant:'foreign'}));
 chmodSync(path.join(folder,'database'),0o600);writeFileSync(path.join(folder,'database'),'tampered');assert.throws(()=>materializeDecisionIdentity(root,{tenant:'tenant'}));
});
test('existing037 secrets remain byte-exact and require an explicit inspected-OID upgrade',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'joint-upgrade-'));materializeDecisionIdentity(root,{tenant:'tenant-a'});
 const folder=path.join(root,'work/private/fleet-decision-secrets'),db=readFileSync(path.join(folder,'database')),u=new URL(db.toString().trim());
 const legacy=Buffer.from(`-- Apply only as operator after migration037. This file contains a password.\nCREATE ROLE "${u.username}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${u.password}' IN ROLE finops_group_decision;\n`);
 const manifest=JSON.parse(readFileSync(path.join(folder,'identity.json'),'utf8'));manifest.sql_sha256=createHash('sha256').update(legacy).digest('hex');
 writeFileSync(path.join(folder,'commission.sql'),legacy);writeFileSync(path.join(folder,'identity.json'),JSON.stringify(manifest)+'\n');
 const before=new Map(readdirSync(folder).map(n=>[n,readFileSync(path.join(folder,n))]));
 assert.equal(materializeDecisionIdentity(root,{tenant:'tenant-a'}).credential_scope_binding_required,true);
 assert.throws(()=>materializeDecisionCredentialBinding(root,{tenant:'tenant-a'}));
 assert.throws(()=>materializeDecisionCredentialBinding(root,{tenant:'tenant-a',expectedRoleOID:'4294967296'}));
 assert.throws(()=>materializeDecisionCredentialBinding(root,{tenant:'tenant-b',expectedRoleOID:'16384'}));
 const result=materializeDecisionCredentialBinding(root,{tenant:'tenant-a',expectedRoleOID:'16384'});assert.equal(result.operator_apply_required,true);
 const bindingFolder=path.join(root,'work/private/fleet-decision-credential-binding'),sql=readFileSync(path.join(bindingFolder,'binding.sql'),'utf8');
 assert.ok(sql.includes(`rolname='${u.username}' AND oid=16384::oid`));assert.ok(sql.includes("'tenant-a'"));assert.ok(!sql.includes(u.password));assert.ok(sql.includes('IF actual IS NULL THEN RAISE EXCEPTION'));
 assert.equal(materializeDecisionCredentialBinding(root,{tenant:'tenant-a',expectedRoleOID:16384}).replayed,true);
 assert.throws(()=>materializeDecisionCredentialBinding(root,{tenant:'tenant-a',expectedRoleOID:'16385'}));
 for(const [n,raw] of before)assert.deepEqual(readFileSync(path.join(folder,n)),raw);
 if(process.platform!=='win32')for(const n of readdirSync(bindingFolder))assert.equal(lstatSync(path.join(bindingFolder,n)).mode&0o777,0o600);
});
test('operator upgrade never creates or replaces an absent or partial identity',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'joint-upgrade-empty-'));
 assert.throws(()=>materializeDecisionCredentialBinding(root,{tenant:'tenant',expectedRoleOID:'1'}));assert.deepEqual(readdirSync(root),[]);
 materializeDecisionIdentity(root,{tenant:'tenant'});const folder=path.join(root,'work/private/fleet-decision-credential-binding');mkdirSync(folder,{mode:0o700});writeFileSync(path.join(folder,'binding.sql'),'preserve',{mode:0o600});
 assert.throws(()=>materializeDecisionCredentialBinding(root,{tenant:'tenant',expectedRoleOID:'1'}));assert.equal(readFileSync(path.join(folder,'binding.sql'),'utf8'),'preserve');
});
test('partial identity and symlink directory refuse without replacing material',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'joint-partial-'));mkdirSync(path.join(root,'work'),{mode:0o755});mkdirSync(path.join(root,'work/private'),{mode:0o700});mkdirSync(path.join(root,'work/private/fleet-decision-secrets'),{mode:0o700});writeFileSync(path.join(root,'work/private/fleet-decision-secrets/database'),'preserve',{mode:0o444});assert.throws(()=>materializeDecisionIdentity(root,{tenant:'tenant'}));assert.equal(readFileSync(path.join(root,'work/private/fleet-decision-secrets/database'),'utf8'),'preserve');
 const root2=mkdtempSync(path.join(os.tmpdir(),'joint-link-'));mkdirSync(path.join(root2,'work'),{mode:0o755});symlinkSync(path.join(root,'work/private'),path.join(root2,'work/private'),'dir');assert.throws(()=>materializeDecisionIdentity(root2,{tenant:'tenant'}));
});
