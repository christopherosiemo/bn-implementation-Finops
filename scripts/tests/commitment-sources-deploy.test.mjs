// Source wiring supplement. Actual Helm renders and Terraform mock plans are
// separate required checks; no source body or IAM action is exercised here.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

test('optional decision selectors are empty by default and reach only the existing ingester',()=>{
 const source=readFileSync(new URL('../../compose.yaml',import.meta.url),'utf8');
 const ingester=source.match(/^  ingester:\r?\n[\s\S]*?(?=^  [a-zA-Z0-9_-]+:\r?$)/m)?.[0];assert.ok(ingester);
 for(const key of ['AWS_SAVINGS_PLAN_QUOTE_TARGETS_JSON','AWS_CONTROLLER_DISCOVERY_BINDINGS_JSON','AWS_OWNERSHIP_ARCHIVE_TARGETS_JSON']){
  const lines=source.match(new RegExp('^\\s+'+key+':[^\\r\\n]*','gm'));assert.equal(lines?.length,1);assert.equal(lines[0].trim(),key+': ${'+key+':-}');assert.ok(ingester.includes(lines[0]));
 }
 assert.ok(!/^  (?:commitment-purchase|ownership-writer|controller-executor):/m.test(source));
});
