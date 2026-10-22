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
  'work/private/group-fixture-program-review/*/results/**/test-failed-*.png',
 ]);
 assert.doesNotMatch(block,/trace\.zip|playwright-report|\/html\//);
});


test('commissioned cases are excluded from ordinary browsers and run through ordered private helpers without skips',()=>{
 const text=relative=>readFileSync(fileURLToPath(new URL('../../'+relative,import.meta.url)),'utf8');
 const ci=text('.github/workflows/ci.yaml'),pattern=ci.match(/--grep-invert '([^']+)'/)?.[1];
 assert.ok(pattern,'ordinary browsers must explicitly exclude the two commissioned cases');
 const titles=[
  'real OIDC two registered groups produce a persisted isolated fixture selection while unknown-program approval and runtime remain refused',
  'real OIDC privately prepared fixture program receives an independent exact-program approval without execution authority',
 ];
 assert.deepEqual(pattern.split('|'),titles);
 const excluded=new RegExp(pattern);
 for(const [index,file]of ['frontend/tests/fleet-fixture-live.spec.ts','frontend/tests/fleet-fixture-prepared-live.spec.ts'].entries()){
  const spec=text(file);assert.ok(spec.includes('test("'+titles[index]+'"'));assert.ok(excluded.test('[production] '+titles[index]));assert.doesNotMatch(spec,/test\.(skip|fixme)\s*\(/);
 }
 assert.equal(excluded.test('ordinary operating loop and owned recovery'),false);
 assert.match(ci,/node scripts\/group-fixture-review-sequence\.mjs/);
 const sequence=text('scripts/group-fixture-review-sequence.mjs'),positions=['await jobs.commission()','await jobs.prepare()','await jobs.review()'].map(call=>sequence.indexOf(call));
 assert.ok(positions.every(position=>position>=0));assert.ok(positions[0]<positions[1]&&positions[1]<positions[2]);
 assert.doesNotMatch(sequence,/test\.(skip|fixme)\s*\(|Promise\.all/);
});
