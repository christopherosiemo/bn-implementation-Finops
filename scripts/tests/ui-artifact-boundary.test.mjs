import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

test('browser failure uploads contain screenshots only; authenticated traces stay private',()=>{
 const ci=readFileSync(fileURLToPath(new URL('../../.github/workflows/ci.yaml',import.meta.url)),'utf8');
 const block=ci.match(/name: pilot-ui-failure\r?\n([\s\S]*?)\r?\n      - name:/)?.[1];
 assert.ok(block,'the browser failure upload must remain explicit');
 const paths=block.match(/path: \|\r?\n([\s\S]*?)\r?\n          if-no-files-found:/)?.[1].split(/\r?\n/).map(x=>x.trim());
 assert.deepEqual(paths,[
  'frontend/test-results/**/test-failed-*.png',
  'work/private/group-fixture-commission/*/browser/results/**/test-failed-*.png',
 ]);
 assert.doesNotMatch(block,/trace\.zip|playwright-report|\/html\//);
});
