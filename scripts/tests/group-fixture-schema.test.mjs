import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {commissionMigrationManifest} from '../group-fixture-commission.mjs';
import {assertMigrationManifest} from '../lib/recovery-upgrade.mjs';

test('fixture commissioning accepts the complete reviewed additive schema and refuses old prefixes, future runtime migrations and changed checksums',t=>{
 const directory=mkdtempSync(path.join(tmpdir(),'finops-commission-schema-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(directory)),path.resolve(tmpdir()));assert.match(path.basename(directory),/^finops-commission-schema-/);rmSync(directory,{recursive:true,force:true});});
 const names=Array.from({length:35},(_,n)=>n===34?'035_group_native_assessments.sql':String(n+1).padStart(3,'0')+'_fixture.sql');
 for(const name of names)writeFileSync(path.join(directory,name),'-- exact synthetic schema '+name+'\n');
 const expected=commissionMigrationManifest(directory);
 assert.equal(Object.keys(expected).length,35);
 for(const [name,hash]of Object.entries(expected))assert.equal(hash,createHash('sha256').update(readFileSync(path.join(directory,name))).digest('hex'));
 assertMigrationManifest({...expected},expected);
 const old={...expected};delete old[names[34]];assert.throws(()=>assertMigrationManifest(old,expected));
 const unknown='036_unreviewed.sql';writeFileSync(path.join(directory,unknown),'-- future local WIP\n');assert.deepEqual(commissionMigrationManifest(directory),expected);assert.throws(()=>assertMigrationManifest({...expected,[unknown]:'a'.repeat(64)},expected));
 writeFileSync(path.join(directory,names[34]),'-- changed SQL bytes\n');assert.throws(()=>assertMigrationManifest(expected,commissionMigrationManifest(directory)));
 writeFileSync(path.join(directory,names[34]),'');assert.throws(()=>commissionMigrationManifest(directory));
 writeFileSync(path.join(directory,names[34]),'-- exact synthetic schema '+names[34]+'\n');renameSync(path.join(directory,names[10]),path.join(directory,'011_missing.sql.disabled'));assert.throws(()=>commissionMigrationManifest(directory));
});
