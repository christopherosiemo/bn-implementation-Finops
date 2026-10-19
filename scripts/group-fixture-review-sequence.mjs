// NEXT fixture-only CI sequence. Ordinary74 must already have completed; its
// demo/reset would invalidate an active commissioning/preparation selection.
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {groupFixtureCommission} from './group-fixture-commission.mjs';
import {groupFixturePrepare} from './group-fixture-prepare.mjs';
import {groupFixtureProgramReview} from './group-fixture-program-review.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export async function executeFixtureReviewSequence(jobs,environment){
 const installed=await jobs.commission();assert.equal(installed.acceptance.status,'PASS');assert.match(installed.acceptance.run_id,uuid);assert.equal(installed.acceptance.cleanup_succeeded,true);assert.equal(installed.acceptance.customer_execution_authorized,false);
 environment.FINOPS_GROUP_COMMISSION_RUN_ID=installed.acceptance.run_id;
 const prepared=await jobs.prepare();assert.equal(prepared.acceptance.status,'PASS');assert.match(prepared.acceptance.run_id,uuid);assert.equal(prepared.acceptance.commission_run_id,installed.acceptance.run_id);assert.equal(prepared.acceptance.cleanup_succeeded,true);assert.equal(prepared.acceptance.independent_program_approval,false);assert.equal(prepared.acceptance.customer_execution_authorized,false);
 environment.FINOPS_GROUP_PREPARER_RUN_ID=prepared.acceptance.run_id;
 const reviewed=await jobs.review();assert.equal(reviewed.status,'PASS');assert.equal(reviewed.preparer_run_id,prepared.acceptance.run_id);assert.equal(reviewed.proposal_id,prepared.acceptance.proposal_id);assert.equal(reviewed.prepared_program_id,prepared.acceptance.prepared_program_id);assert.equal(reviewed.cleanup_succeeded,true);assert.equal(reviewed.actual_independent_program_approval,true);assert.equal(reviewed.journal_authorization_approval,false);assert.equal(reviewed.native_execution_factory,false);assert.equal(reviewed.customer_execution_authorized,false);assert.equal(reviewed.verified_saving,null);
 return {commission_run_id:installed.acceptance.run_id,preparer_run_id:prepared.acceptance.run_id,review_run_id:reviewed.run_id,proposal_id:reviewed.proposal_id,prepared_program_id:reviewed.prepared_program_id};
}
export async function groupFixtureReviewSequence(){
 assert.equal(process.argv.length,2);assert.ok(!process.env.NODE_OPTIONS);const files=['scripts/group-fixture-review-sequence.mjs','scripts/group-fixture-commission.mjs','scripts/group-fixture-prepare.mjs','scripts/group-fixture-program-review.mjs'],sourcePins=Object.fromEntries(files.map(file=>[file,createHash('sha256').update(readFileSync(path.join(root,file))).digest('hex')]));
 const result=await executeFixtureReviewSequence({commission:groupFixtureCommission,prepare:groupFixturePrepare,review:groupFixtureProgramReview},process.env),runID=randomUUID(),directory=path.join(root,'work/private/group-fixture-review-sequence',runID);mkdirSync(directory,{recursive:true,mode:0o700});const acceptance={schema_version:'1',status:'PASS',run_id:runID,...result,commissioned_browser_cases:2,ordinary_browser_cases_executed_here:0,actual_independent_program_approval:true,journal_authorization_approval:false,native_execution_factory:false,customer_native_authority:false,customer_execution_authorized:false,verified_saving:null,source_sha256:sourcePins,cleanup_succeeded:true};writeFileSync(path.join(directory,'acceptance.json'),JSON.stringify(acceptance,null,2)+'\n',{mode:0o600});console.log(JSON.stringify({status:'FIXTURE_SELECTION_PREPARATION_REVIEW_PASS',run_id:runID,...result,customer_execution_authorized:false}));return acceptance;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)groupFixtureReviewSequence().catch(()=>{console.error('Fixture selection/preparation/review sequence refused; stage metadata retained, no execution accepted.');process.exitCode=1;});
