import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtempSync,writeFileSync,mkdirSync,symlinkSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {connectedFailurePhases,connectedDriverPhases,connectedDriverReasons,connectedFailureReceipt,parseConnectedDriverDiagnostic,readConnectedDriverDiagnostic} from '../lib/group-connected-failure.mjs';

const base={runID:'11111111-2222-3333-4444-555555555555',startedAt:'2026-10-19T05:00:00.000Z',observedAt:'2026-10-19T05:22:30.000Z',phase:'NATIVE_TEST',cleanupSucceeded:true};
const diagnostic={schema_version:'1',phase:'TERMINAL_OBSERVATION',reason_codes:['HEALTH_BREACH'],elapsed_ms:1200000};
const encode=v=>Buffer.from(JSON.stringify(v)+'\n');
const clean=d=>{assert.equal(path.dirname(path.resolve(d)),path.resolve(tmpdir()));assert.match(path.basename(d),/^group-failure-/);rmSync(d,{recursive:true,force:true});};

test('failure receipt exposes only fixed phase/reason and real UTC elapsed boundaries',()=>{
 for(const phase of Object.keys(connectedFailurePhases)){
  const r=connectedFailureReceipt({...base,phase,error:new Error('private-token'),stdout:'private-body'});
  assert.equal(r.reason_code,connectedFailurePhases[phase]);assert.equal(r.elapsed_ms,1350000);assert.equal(r.cleanup_succeeded,true);assert.equal(r.customer_execution_authorized,false);assert.equal(r.verified_saving,null);assert.ok(!JSON.stringify(r).includes('private'));
 }
 assert.throws(()=>connectedFailureReceipt({...base,phase:'private-endpoint'}));
 for(const patch of [{observedAt:'2026-10-19T04:59:00.000Z'},{observedAt:'2026-10-19T05:00:00Z'},{cleanupSucceeded:'true'},{runID:'../private'}])assert.throws(()=>connectedFailureReceipt({...base,...patch}));
});
test('bounded driver vocabulary retains the exact native phase without raw assertions',()=>{
 for(const phase of connectedDriverPhases)for(const reason of connectedDriverReasons){const d=parseConnectedDriverDiagnostic(encode({...diagnostic,phase,reason_codes:[reason]})),r=connectedFailureReceipt({...base,driver:d});assert.equal(r.driver_phase,phase);assert.deepEqual(r.driver_reason_codes,[reason]);}
 for(const patch of [{phase:'http://private'},{reason_codes:['private-key']},{reason_codes:['HEALTH_BREACH','HEALTH_BREACH']},{elapsed_ms:-1},{elapsed_ms:2**53},{elapsed_ms:48*60*60*1000+1},{extra:'private-body'},{schema_version:1}])assert.throws(()=>parseConnectedDriverDiagnostic(encode({...diagnostic,...patch})));
 for(const raw of [Buffer.from('{}'),Buffer.from('[]'),Buffer.from(JSON.stringify(diagnostic)+' '+JSON.stringify(diagnostic)),Buffer.from(JSON.stringify(diagnostic).replace('"schema_version":"1"','"schema_version":"1","schema_version":"1"')),Buffer.alloc(2049,0x20)])assert.throws(()=>parseConnectedDriverDiagnostic(raw));
 assert.throws(()=>connectedFailureReceipt({...base,driver:{status:'VALID',phase:'http://private',reason_codes:[],elapsed_ms:1}}));
});
test('missing or malformed driver files produce static safe labels and no plaintext',()=>{
 const d=mkdtempSync(path.join(tmpdir(),'group-failure-'));try{
  const f=path.join(d,'driver-phase.json');assert.deepEqual(readConnectedDriverDiagnostic(f),{status:'MISSING'});
  writeFileSync(f,encode(diagnostic));assert.equal(readConnectedDriverDiagnostic(f).status,'VALID');
  writeFileSync(f,JSON.stringify({...diagnostic,reason_codes:['SECRET-STRING']}));const r=connectedFailureReceipt({...base,driver:readConnectedDriverDiagnostic(f)});assert.equal(r.driver_diagnostic_status,'INVALID');assert.equal(r.driver_diagnostic_reason,'DRIVER_DIAGNOSTIC_INVALID');assert.ok(!JSON.stringify(r).includes('SECRET-STRING'));
  writeFileSync(f,Buffer.alloc(2049));assert.deepEqual(readConnectedDriverDiagnostic(f),{status:'INVALID'});
  mkdirSync(path.join(d,'directory'));assert.deepEqual(readConnectedDriverDiagnostic(path.join(d,'directory')),{status:'INVALID'});
 }finally{clean(d);}
});
test('driver diagnostic symlinks are refused before reading their targets',{skip:process.platform==='win32'},()=>{
 const d=mkdtempSync(path.join(tmpdir(),'group-failure-link-'));try{writeFileSync(path.join(d,'target'),encode(diagnostic));symlinkSync(path.join(d,'target'),path.join(d,'driver-phase.json'));assert.deepEqual(readConnectedDriverDiagnostic(path.join(d,'driver-phase.json')),{status:'INVALID'});}finally{clean(d);}
});
test('cleanup failure overrides runner phase but cannot erase a bounded native failure',()=>{
 const driver=parseConnectedDriverDiagnostic(encode(diagnostic)),r=connectedFailureReceipt({...base,phase:'OWNED_CLEANUP',cleanupSucceeded:false,driver});assert.equal(r.reason_code,'OWNED_CLEANUP_FAILED');assert.equal(r.cleanup_succeeded,false);assert.equal(r.driver_phase,'TERMINAL_OBSERVATION');assert.deepEqual(r.driver_reason_codes,['HEALTH_BREACH']);assert.ok(Buffer.byteLength(JSON.stringify(r))<2048);
});
test('hosted connected artifacts contain only acceptance and the bounded failure receipt',()=>{
 const workflow=readFileSync(new URL('../../.github/workflows/ci.yaml',import.meta.url),'utf8'),job=workflow.split('  fleet-group-connected:')[1].split('\n  kubernetes-lab:')[0],upload=job.split('name: fleet-group-connected-acceptance')[1].split('if-no-files-found:')[0];
 const paths=upload.split(/\r?\n/).map(x=>x.trim()).filter(x=>x.startsWith('work/'));
 assert.deepEqual(paths,['work/private/fleet-group-connected/*/acceptance.json','work/private/fleet-group-connected/*/failure-receipt.json','work/private/group-workspace-reconstruction/*/acceptance.json','work/private/group-workspace-reconstruction/*/failure-receipt.json']);
 for(const forbidden of ['failure.log','failure.json','driver-phase.json','archive.key','/encrypted','/source','bundle.json','retirement.json','workspace-result.json'])assert.ok(!upload.includes(forbidden));
});
