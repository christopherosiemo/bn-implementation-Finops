import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,chmodSync,writeFileSync,lstatSync,symlinkSync,mkdirSync} from 'node:fs';
import os from 'node:os';import path from 'node:path';
import {materializeDecisionIdentity} from '../bootstrap-fleet-decision.mjs';

test('separate operator identity is private, atomic, replayable and never applied',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'joint-identity-'));const result=materializeDecisionIdentity(root,{tenant:'tenant'});assert.equal(result.replayed,false);
 const folder=path.join(root,'work/private/fleet-decision-secrets'),db=readFileSync(path.join(folder,'database')),sql=readFileSync(path.join(folder,'commission.sql'),'utf8');const u=new URL(db.toString().trim());
 assert.match(u.username,/^group_decision_[a-f0-9]{32}$/);assert.equal(u.hostname,'postgres');assert.equal(u.search,'?sslmode=disable');assert.ok(sql.includes('IN ROLE finops_group_decision;'));assert.ok(sql.includes('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'));
 if(process.platform!=='win32'){assert.equal(lstatSync(folder).mode&0o777,0o700);assert.equal(lstatSync(path.join(folder,'database')).mode&0o777,0o444);assert.equal(lstatSync(path.join(folder,'commission.sql')).mode&0o777,0o600)}
 assert.equal(materializeDecisionIdentity(root,{tenant:'tenant'}).replayed,true);assert.deepEqual(readFileSync(path.join(folder,'database')),db);assert.throws(()=>materializeDecisionIdentity(root,{tenant:'foreign'}));
 chmodSync(path.join(folder,'database'),0o600);writeFileSync(path.join(folder,'database'),'tampered');assert.throws(()=>materializeDecisionIdentity(root,{tenant:'tenant'}));
});
test('partial identity and symlink directory refuse without replacing material',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'joint-partial-'));mkdirSync(path.join(root,'work'),{mode:0o755});mkdirSync(path.join(root,'work/private'),{mode:0o700});mkdirSync(path.join(root,'work/private/fleet-decision-secrets'),{mode:0o700});writeFileSync(path.join(root,'work/private/fleet-decision-secrets/database'),'preserve',{mode:0o444});assert.throws(()=>materializeDecisionIdentity(root,{tenant:'tenant'}));assert.equal(readFileSync(path.join(root,'work/private/fleet-decision-secrets/database'),'utf8'),'preserve');
 const root2=mkdtempSync(path.join(os.tmpdir(),'joint-link-'));mkdirSync(path.join(root2,'work'),{mode:0o755});symlinkSync(path.join(root,'work/private'),path.join(root2,'work/private'),'dir');assert.throws(()=>materializeDecisionIdentity(root2,{tenant:'tenant'}));
});
