import test from 'node:test';import assert from 'node:assert/strict';
import {portfolioNativeFailure} from '../lib/commitment-portfolio-failure.mjs';
test('native failure reports a fixed stage without publishing private error material',()=>{
  const privateText='postgres://private-user:private-password@private-host DATABASE_URL=private-token';
  const result=portfolioNativeFailure('decision actual original-version archive Pipeline failed '+privateText,{Running:false,ExitCode:1,OOMKilled:false});
  assert.deepEqual(result,{stage:'ORIGINAL_VERSION_OWNERSHIP_ARCHIVE',reason_code:'NATIVE_STAGE_REJECTED',exit_code:1,oom_killed:false,diagnostic_only:true,stage_code:null,sqlstate:null});
  assert.ok(!JSON.stringify(result).includes('private-'));
});
test('unknown, ambiguous and incomplete diagnostic data cannot invent a stage or exit',()=>{
  for(const log of[undefined,'arbitrary provider response','decision native declarations failed; decision actual original-version archive Pipeline failed']){
    assert.equal(portfolioNativeFailure(log,{Running:true,ExitCode:0,OOMKilled:false}).stage,'UNKNOWN');
    assert.equal(portfolioNativeFailure(log,{Running:true,ExitCode:0,OOMKilled:false}).exit_code,null);
  }
  assert.equal(portfolioNativeFailure('',{Running:false,ExitCode:-1}).exit_code,null);
  assert.equal(portfolioNativeFailure('',{Running:false,ExitCode:256}).exit_code,null);
});
test('OOM attribution requires the actual container state flag',()=>{
  assert.equal(portfolioNativeFailure('out of memory',{Running:false,ExitCode:137,OOMKilled:false}).reason_code,'PRIVATE_DIAGNOSTIC_REQUIRED');
  assert.equal(portfolioNativeFailure('',{Running:false,ExitCode:137,OOMKilled:true}).reason_code,'NATIVE_COORDINATOR_OOM');
});

const fixedFrame=(code,tail='')=>'    commitment_decision_native_integration_test.go:152: decision actual035/036/037 stage issuance failed '+code+tail;
test('native stage inner projection retains only a literal fixed code and canonical wrapped SQLSTATE',()=>{
  const log=fixedFrame('DECISION_STAGE_CAPACITY_PROCESS_FAILED',': ERROR: private SQL/body text (SQLSTATE P0001)');
  const value=portfolioNativeFailure(log,{Running:false,ExitCode:1});
  assert.equal(value.stage_code,'DECISION_STAGE_CAPACITY_PROCESS_FAILED');assert.equal(value.sqlstate,'P0001');
  assert.ok(!JSON.stringify(value).includes('private SQL/body text'));
  for(const state of ['42501','23505','55P03','40P01','40001','57014'])assert.equal(portfolioNativeFailure(fixedFrame('DECISION_STAGE_CAPACITY_MEMBER_READ_FAILED',': ERROR: withheld (SQLSTATE '+state+')')).sqlstate,state);
});
test('private problems, checks and reflected SQLSTATE strings cannot become PostgreSQL diagnostics',()=>{
  for(const [code,tail] of [
    ['DECISION_STAGE_CAPACITY_QUEUE_REFUSED',': http_status=422 problem={"secret":"SQLSTATE 42501"}'],
    ['DECISION_STAGE_CURRENT_BASELINE_PHYSICAL_CHECK_FAILED',': check_index=0 check={"message":"ERROR: x (SQLSTATE 23505)"}'],
    ['DECISION_STAGE_ASSESSMENT_PROCESS_FAILED',': FLEET_ASSESSMENT_JOB_REFUSED diagnostic=ERROR: x (SQLSTATE P0001)'],
    ['DECISION_STAGE_ASSESSMENT_PROCESS_FAILED',': ERROR: SQLSTATE 23505 reflected (SQLSTATE P0001)'],
    ['DECISION_STAGE_CAPACITY_PROCESS_FAILED',': ERROR: x (SQLSTATE ZZZZZ)'],
  ]){
    const value=portfolioNativeFailure(fixedFrame(code,tail));assert.equal(value.stage_code,code);assert.equal(value.sqlstate,null);
  }
});
test('foreign file, unframed, unknown, malformed, ambiguous and oversized stage details remain unknown',()=>{
  const valid=fixedFrame('DECISION_STAGE_GROUP_SCOPE_REFUSED');
  for(const log of [
    valid.replace('commitment_decision_native_integration_test.go','foreign_test.go'),
    'decision actual035/036/037 stage issuance failed DECISION_STAGE_GROUP_SCOPE_REFUSED',
    fixedFrame('DECISION_STAGE_UNREVIEWED_FUTURE_CODE'),
    valid.replace('DECISION_STAGE_GROUP_SCOPE_REFUSED','DECISION_STAGE_GROUP_SCOPE_REFUSED-reflected'),
    valid+'\n'+fixedFrame('DECISION_STAGE_GROUP_PROPOSAL_REFUSED'),
    valid+'\n'+valid,
    valid+': '+'x'.repeat(8192),
    valid+'\n'+'x'.repeat(4*1024*1024),
  ]){
    const value=portfolioNativeFailure(log);assert.equal(value.stage_code,null);assert.equal(value.sqlstate,null);
  }
  for(const log of [null,42,[],{}]){assert.equal(portfolioNativeFailure(log).stage_code,null);assert.equal(portfolioNativeFailure(log).sqlstate,null);}
});
test('outer-stage ambiguity suppresses even a correctly framed inner code',()=>{
  const value=portfolioNativeFailure(fixedFrame('DECISION_STAGE_GROUP_SCOPE_REFUSED')+'\ndecision native declarations failed');
  assert.equal(value.stage,'UNKNOWN');assert.equal(value.stage_code,null);assert.equal(value.sqlstate,null);
});
