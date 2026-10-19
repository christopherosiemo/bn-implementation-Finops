// Only fixed diagnostic vocabulary crosses the hosted-artifact boundary.
// Never accept Error objects, assertion text, stdout, paths or provider bodies.
import assert from 'node:assert/strict';
import {lstatSync,readFileSync} from 'node:fs';

export const connectedFailurePhases=Object.freeze({
 INDEX_SNAPSHOT:'INDEX_SNAPSHOT_FAILED',
 BUILD_IMAGE:'BUILD_IMAGE_FAILED',
 PREPARE_MODULES:'MODULE_PREPARATION_FAILED',
 OFFLINE_COMPILE:'OFFLINE_COMPILE_FAILED',
 START_SERVICES:'OWNED_SERVICES_FAILED',
 NATIVE_TEST:'NATIVE_TEST_FAILED',
 VALIDATE_RESULT_SIZE:'RESULT_SIZE_OR_FILE_INVALID',
 VALIDATE_RESULT:'RESULT_CONTRACT_INVALID',
 VALIDATE_CIPHERTEXT:'CIPHERTEXT_VALIDATION_FAILED',
 OWNED_CLEANUP:'OWNED_CLEANUP_FAILED',
 FINAL_OWNERSHIP_CHECK:'FINAL_OWNERSHIP_CHECK_FAILED',
});
export const connectedDriverPhases=Object.freeze(['PREPARATION','APPROVAL','BOOTSTRAP','BASELINE','PREPARE_APPLY','CANDIDATE_APPLY','WARMUP','CANARY_APPLY','CANARY_OBSERVATION','OWNED_INVERSE','TERMINAL_OBSERVATION','RELEASE','RESULT_PUBLICATION']);
export const connectedDriverReasons=Object.freeze(['HEALTH_BREACH','HEALTH_EVIDENCE_INVALID','RECOVERY_WINDOW_RETRY','CONTEXT_EXPIRED','ASSERTION_FAILED']);
const maximumElapsedMS=48*60*60*1000;

export function parseConnectedDriverDiagnostic(raw){
 assert.ok(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=2048);
 const value=JSON.parse(raw.toString('utf8'));
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['elapsed_ms','phase','reason_codes','schema_version']);
 // Canonical byte equality also refuses duplicate keys, trailing values and
 // alternate encodings that could conceal a field from one of the readers.
 const canonical=JSON.stringify(value);assert.ok(raw.equals(Buffer.from(canonical))||raw.equals(Buffer.from(canonical+'\n')));
 assert.equal(value.schema_version,'1');assert.ok(connectedDriverPhases.includes(value.phase));
 assert.ok(Array.isArray(value.reason_codes)&&value.reason_codes.length<=8&&new Set(value.reason_codes).size===value.reason_codes.length);
 for(const code of value.reason_codes)assert.ok(connectedDriverReasons.includes(code));
 assert.ok(Number.isSafeInteger(value.elapsed_ms)&&value.elapsed_ms>=0&&value.elapsed_ms<=maximumElapsedMS);
 return {status:'VALID',phase:value.phase,reason_codes:[...value.reason_codes],elapsed_ms:value.elapsed_ms};
}

// The caller supplies only its fixed per-run /results/driver-phase.json path.
// Invalid/unreadable diagnostics become a static label, never an error message.
export function readConnectedDriverDiagnostic(file){
 try{
  const info=lstatSync(file);if(!info.isFile()||info.isSymbolicLink()||info.size<1||info.size>2048)return {status:'INVALID'};
  return parseConnectedDriverDiagnostic(readFileSync(file));
 }catch(error){return {status:error?.code==='ENOENT'?'MISSING':'INVALID'};}
}

export function connectedFailureReceipt({runID,startedAt,observedAt,phase,cleanupSucceeded,driver={status:'MISSING'}}){
 assert.match(runID,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
 assert.ok(Object.hasOwn(connectedFailurePhases,phase));assert.equal(typeof cleanupSucceeded,'boolean');
 const start=Date.parse(startedAt),end=Date.parse(observedAt);assert.ok(Number.isFinite(start)&&Number.isFinite(end));
 assert.equal(new Date(start).toISOString(),startedAt);assert.equal(new Date(end).toISOString(),observedAt);
 assert.ok(end>=start&&end-start<=maximumElapsedMS);assert.ok(['VALID','MISSING','INVALID'].includes(driver.status));
 const receipt={schema_version:'1',status:'FAIL',run_id:runID,phase,reason_code:connectedFailurePhases[phase],started_at:startedAt,observed_at:observedAt,elapsed_ms:end-start,cleanup_succeeded:cleanupSucceeded,driver_diagnostic_status:driver.status,fixture:true,customer_execution_authorized:false,verified_saving:null};
 if(driver.status==='VALID'){
  // Validate again even when a test/caller bypasses the bounded file reader.
  const checked=parseConnectedDriverDiagnostic(Buffer.from(JSON.stringify({schema_version:'1',phase:driver.phase,reason_codes:driver.reason_codes,elapsed_ms:driver.elapsed_ms})));
  receipt.driver_phase=checked.phase;receipt.driver_reason_codes=checked.reason_codes;receipt.driver_elapsed_ms=checked.elapsed_ms;
 }
 if(driver.status==='INVALID')receipt.driver_diagnostic_reason='DRIVER_DIAGNOSTIC_INVALID';
 assert.ok(Buffer.byteLength(JSON.stringify(receipt))<=2048);return receipt;
}
