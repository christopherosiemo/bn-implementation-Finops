import test from 'node:test';import assert from 'node:assert/strict';
import {portfolioNativeFailure} from '../lib/commitment-portfolio-failure.mjs';
test('native failure reports a fixed stage without publishing private error material',()=>{
  const privateText='postgres://private-user:private-password@private-host DATABASE_URL=private-token';
  const result=portfolioNativeFailure('decision actual original-version archive Pipeline failed '+privateText,{Running:false,ExitCode:1,OOMKilled:false});
  assert.deepEqual(result,{stage:'ORIGINAL_VERSION_OWNERSHIP_ARCHIVE',reason_code:'NATIVE_STAGE_REJECTED',exit_code:1,oom_killed:false,diagnostic_only:true});
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
