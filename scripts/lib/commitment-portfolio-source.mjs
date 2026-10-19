// Extend the accepted indexed readers; never accept a caller-selected source,
// ref, path, clock or credential. Lower readers keep their historical scopes.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import path from 'node:path';
import {parseConnectedIndexObjects} from '../fleet-group-connected-lab.mjs';
import {readNativeCapacityIndexedSource} from '../fleet-native-capacity-lab.mjs';
import {readJointDecisionIndexedSource} from './fleet-joint-decision-host.mjs';

const extraPaths = Object.freeze([
  'scripts/commitment-portfolio-lab.mjs',
  'scripts/lib/commitment-portfolio-source.mjs',
  'scripts/lib/commitment-portfolio-browser.mjs',
  'scripts/lib/commitment-portfolio-browser-host.mjs',
  'scripts/tests/commitment-portfolio-browser.test.mjs',
  'examples/commitment-portfolio-browser/main.mjs',
  'examples/commitment-portfolio-browser/portfolio.mjs',
  'cmd/commitment-portfolio-worker/main.go',
  'internal/commitmentportfolio/testdata/python-id-unicode.json',
]);
const hash = raw => createHash('sha256').update(raw).digest('hex');

export function readPortfolioIndexedSource(root, emptyConfig) {
  const capture = readJointDecisionIndexedSource(root, emptyConfig, {
    readBase: readNativeCapacityIndexedSource, parseObjects: parseConnectedIndexObjects,
  });
  const environment = {};
  for (const key of ['PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','COMSPEC']) if (process.env[key]) environment[key] = process.env[key];
  Object.assign(environment, {LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_SYSTEM:emptyConfig,GIT_CONFIG_GLOBAL:emptyConfig,GIT_CONFIG_COUNT:'0',GIT_NO_LAZY_FETCH:'1',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0'});
  const git = (args,input) => execFileSync('git', ['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args], {cwd:root,env:environment,encoding:null,windowsHide:true,stdio:['pipe','pipe','pipe'],input,maxBuffer:4<<20,timeout:30000});
  assert.equal(git(['write-tree']).toString('ascii').trim(),capture.tree);
  const listing = git(['ls-tree','-r','-z','--long','--full-tree',capture.tree,'--',...extraPaths]);
  assert.ok(listing.length > 0 && listing.length < 65536 && listing.at(-1) === 0);
  const entries = listing.toString('utf8').split('\0').slice(0,-1).map(row => {
    const match = /^100644 blob ([a-f0-9]{40}|[a-f0-9]{64}) +([0-9]+)\t([^\0]+)$/.exec(row);
    assert.ok(match && extraPaths.includes(match[3])); const size = Number(match[2]);
    assert.ok(Number.isSafeInteger(size) && size > 0 && size <= 2<<20);
    return {path:match[3],oid:match[1],size};
  });
  assert.deepEqual(entries.map(entry => entry.path).sort(),[...extraPaths].sort());
  const files = parseConnectedIndexObjects(git(['cat-file','--batch'],Buffer.from(entries.map(entry => entry.oid+'\n').join(''))),entries);
  for (const [file,raw] of files) {
    capture.files.set(file,raw);
    if (file.startsWith('scripts/') && !file.startsWith('scripts/tests/')) {
      const actual = path.join(root,file), stat = lstatSync(actual);
      assert.ok(stat.isFile() && !stat.isSymbolicLink());
      assert.ok(readFileSync(actual).equals(raw),'Executed portfolio host differs from Git index');
      capture.hostHashes[file] = hash(raw);
    }
  }
  assert.ok(capture.files.size <= 2048 && [...capture.files.values()].reduce((sum,raw) => sum+raw.length,0) <= 32<<20);
  assert.equal(git(['write-tree']).toString('ascii').trim(),capture.tree);
  return capture;
}
