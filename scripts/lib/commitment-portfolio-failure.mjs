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
  });
}
