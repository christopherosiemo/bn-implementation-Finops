// Diagnostic codes only. Private provider/SQL/browser error text never leaves
// the run directory and cannot become authority or an acceptance result.
const stages=Object.freeze([
  ['decision native declarations failed','NATIVE_DECLARATIONS'],
  ['decision monthly native source/history issuance failed','NATIVE_BILLING_HISTORY'],
  ['decision actual current attestor/readback failed','CURRENT_CONFIGURATION_READBACK'],
  ['decision actual original-version archive Pipeline failed','ORIGINAL_VERSION_OWNERSHIP_ARCHIVE'],
  ['decision current native financial refresh failed','CURRENT_FINANCIAL_REFRESH'],
  ['decision actual035/036/037 stage issuance failed','NATIVE_OPTIMIZATION_STAGES'],
  ['decision bounded customer constraint commissioning failed','OPTIMIZATION_POLICY'],
  ['decision controller raw reparse/source issuance failed','CURRENT_CONTROLLER_SOURCE'],
  ['decision two genuine issued offer receipts absent','NATIVE_COMMITMENT_OFFERS'],
]);
// The inner projection accepts only the exact owned Go test failure frame.
// Neither provider text, HTTP problem/check JSON nor arbitrary SQL messages
// are reflected. Values outside these literal diagnostic enums stay unknown.
const stageCodes = new Set([
  "DECISION_STAGE_ACTUAL_CURRENT_BASELINE_MODEL_REQUIRED",
  "DECISION_STAGE_ASSESSMENT_PROCESS_FAILED",
  "DECISION_STAGE_ASSESSMENT_QUEUE_REFUSED",
  "DECISION_STAGE_ATTESTED_INVENTORY_DIFFERS",
  "DECISION_STAGE_BASELINE_CANNOT_ISSUE_FLEET_MONEY",
  "DECISION_STAGE_CAPACITY_MEMBER_READ_FAILED",
  "DECISION_STAGE_CAPACITY_PROCESS_FAILED",
  "DECISION_STAGE_CAPACITY_QUEUE_REFUSED",
  "DECISION_STAGE_COMPLETE_CAPACITY_MEMBER_REQUIRED",
  "DECISION_STAGE_CURRENT_BASELINE_PHYSICAL_CHECK_FAILED",
  "DECISION_STAGE_CURRENT_SAFETY_PROFILE_REQUIRED",
  "DECISION_STAGE_DEMAND_DEFINITION_REFUSED",
  "DECISION_STAGE_DIAGNOSTIC_SELECTION_DIFFERS",
  "DECISION_STAGE_EXACT_TELEMETRY_ANALYTICS_READBACK_REQUIRED",
  "DECISION_STAGE_EXACT_TELEMETRY_ANALYTICS_REPLAY_REQUIRED",
  "DECISION_STAGE_EXACT_TEMPLATE_SELECTORS_REQUIRED",
  "DECISION_STAGE_FIXED_NATIVE_DEPENDENCIES_REQUIRED",
  "DECISION_STAGE_GROUP_AUTHORITY_REFUSED",
  "DECISION_STAGE_GROUP_PROPOSAL_REFUSED",
  "DECISION_STAGE_GROUP_SCOPE_REFUSED",
  "DECISION_STAGE_GROUP_XML_INVALID",
  "DECISION_STAGE_HISTORY_REGISTRATION_REFUSED",
  "DECISION_STAGE_ISSUED_PHYSICAL_JOIN_REQUIRED",
  "DECISION_STAGE_JOINT_QUEUE_REFUSED",
  "DECISION_STAGE_NATIVE_ARCHIVE_DIFFERS",
  "DECISION_STAGE_NATIVE_GROUP_SCOPE_DIFFERS",
  "DECISION_STAGE_OWNED_ANALYTICS_SCHEMA_REFUSED",
  "DECISION_STAGE_PRIVATE_ARCHIVE_ANALYTICS_IDENTITY_REQUIRED",
  "DECISION_STAGE_PRIVATE_TOKEN_FILES_REQUIRED",
  "DECISION_STAGE_SINGLE_MEMBER_CAPACITY_NOT_ISSUED",
  "DECISION_STAGE_TEMPLATE_XML_INVALID",
  "DECISION_STAGE_UNREGISTERED_GROUP"
]);
const sqlStates = new Set(['08006','23505','40001','40P01','42501','53100','53200','53300','53400','55P03','57014','P0001']);
const wrappedSQLCodes = new Set(['DECISION_STAGE_CAPACITY_PROCESS_FAILED','DECISION_STAGE_CAPACITY_MEMBER_READ_FAILED','DECISION_STAGE_ASSESSMENT_PROCESS_FAILED']);
function fixedStageDetail(text, stage) {
  const unknown = {stage_code:null,sqlstate:null};
  if (stage !== 'NATIVE_OPTIMIZATION_STAGES' || text.length > 4*1024*1024) return unknown;
  const frames = text.split(/\r?\n/).flatMap(line => {
    if (line.length > 8192) return [];
    const match = /^\s*commitment_decision_native_integration_test\.go:[1-9][0-9]{0,5}: decision actual035\/036\/037 stage issuance failed (DECISION_STAGE_[A-Z0-9_]{1,100})(?:: [^\r\n]*)?$/.exec(line);
    return match ? [{line:line.trim(),code:match[1]}] : [];
  });
  if (frames.length !== 1 || !stageCodes.has(frames[0].code)) return unknown;
  const frame = frames[0];
  let sqlstate = null;
  if (wrappedSQLCodes.has(frame.code)) {
    const leaf = frame.line.slice(frame.line.indexOf(frame.code)).split(' diagnostic=')[0];
    const pg = /^DECISION_STAGE_[A-Z0-9_]+: ERROR: [^\r\n]* \(SQLSTATE ([0-9A-Z]{5})\)$/.exec(leaf);
    if (pg && sqlStates.has(pg[1]) && [...leaf.matchAll(/SQLSTATE /g)].length === 1) sqlstate = pg[1];
  }
  return {stage_code:frame.code,sqlstate};
}

export function portfolioNativeFailure(log,state){
  const text=typeof log==='string'?log:'';
  const known=stages.filter(([marker])=>text.includes(marker));
  const stage=known.length===1?known[0][1]:'UNKNOWN';
  const exit=state?.Running===false&&Number.isInteger(state.ExitCode)&&state.ExitCode>=0&&state.ExitCode<=255?state.ExitCode:null;
  return Object.freeze({
    stage,
    reason_code:state?.OOMKilled===true?'NATIVE_COORDINATOR_OOM':stage==='UNKNOWN'?'PRIVATE_DIAGNOSTIC_REQUIRED':'NATIVE_STAGE_REJECTED',
    exit_code:exit,
    oom_killed:state?.OOMKilled===true,
    diagnostic_only:true,
    ...fixedStageDetail(text,stage),
  });
}
