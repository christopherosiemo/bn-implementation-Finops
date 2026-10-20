import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,renameSync,rmSync,writeFileSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {commissionMigrationManifest} from '../group-fixture-commission.mjs';
import {assertMigrationManifest} from '../lib/recovery-upgrade.mjs';

test('fixture commissioning accepts the complete reviewed additive schema and refuses old prefixes, future runtime migrations and changed checksums',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-commission-schema-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^finops-commission-schema-/);rmSync(directory,{recursive:true,force:true});});
 const names=Array.from({length:42},(_,n)=>n===41?'042_storage_assessments.sql':n===40?'041_database_assessments.sql':n===39?'040_commitment_decisions.sql':n===38?'039_commitment_portfolio.sql':n===37?'038_fleet_decision_credential_scope.sql':n===36?'037_fleet_joint_decisions.sql':n===35?'036_fleet_native_capacity.sql':n===34?'035_group_native_assessments.sql':String(n+1).padStart(3,'0')+'_fixture.sql');
 const reviewed=Object.fromEntries(['037_fleet_joint_decisions.sql','038_fleet_decision_credential_scope.sql','039_commitment_portfolio.sql','040_commitment_decisions.sql','041_database_assessments.sql','042_storage_assessments.sql'].map(name=>[name,readFileSync(new URL('../../migrations/'+name,import.meta.url))]));
 for(const name of names)writeFileSync(path.join(directory,name),reviewed[name]??'-- exact synthetic schema '+name+'\n');
 const expected=commissionMigrationManifest(directory);
 assert.equal(Object.keys(expected).length,42);
 for(const [name,hash]of Object.entries(expected))assert.equal(hash,createHash('sha256').update(readFileSync(path.join(directory,name))).digest('hex'));
 assertMigrationManifest({...expected},expected);
 const old={...expected};delete old[names[41]];assert.throws(()=>assertMigrationManifest(old,expected));
 const current=readFileSync(path.join(directory,names[41]));unlinkSync(path.join(directory,names[41]));assert.throws(()=>commissionMigrationManifest(directory));writeFileSync(path.join(directory,names[41]),current);
 const unknown='043_unreviewed.sql';writeFileSync(path.join(directory,unknown),'-- future local WIP\n');assert.throws(()=>commissionMigrationManifest(directory));assert.throws(()=>assertMigrationManifest({...expected,[unknown]:'a'.repeat(64)},expected));unlinkSync(path.join(directory,unknown));
 for(const [name,raw]of Object.entries(reviewed)){writeFileSync(path.join(directory,name),Buffer.concat([raw,Buffer.from('\n-- changed reviewed SQL\n')]));assert.throws(()=>commissionMigrationManifest(directory));writeFileSync(path.join(directory,name),raw);}
 writeFileSync(path.join(directory,names[35]),'-- changed SQL bytes\n');assert.throws(()=>assertMigrationManifest(expected,commissionMigrationManifest(directory)));
 writeFileSync(path.join(directory,names[35]),'');assert.throws(()=>commissionMigrationManifest(directory));
 writeFileSync(path.join(directory,names[35]),'-- exact synthetic schema '+names[35]+'\n');renameSync(path.join(directory,names[10]),path.join(directory,'011_missing.sql.disabled'));assert.throws(()=>commissionMigrationManifest(directory));
});
