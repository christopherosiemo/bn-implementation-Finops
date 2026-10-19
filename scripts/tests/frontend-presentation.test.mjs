import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {presentationOptions,presentationOrigin,presentationRequestAllowed} from '../../frontend/tests/presentation-server.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
test('presentation server pins loopback and has no configuration/env loading or API proxy',()=>{
 const o=presentationOptions();assert.equal(presentationOrigin,'http://127.0.0.1:4177');assert.equal(o.configFile,false);assert.equal(o.envFile,false);assert.equal(o.envDir,false);assert.equal(o.server.host,'127.0.0.1');assert.equal(o.server.port,4177);assert.equal(o.server.strictPort,true);assert.equal(o.server.hmr,false);assert.deepEqual(o.server.proxy,{});assert.equal(o.server.fs.strict,true);assert.equal(o.server.fs.allow.length,1);
 assert.equal(presentationRequestAllowed({headers:{host:'127.0.0.1:4177'},socket:{remoteAddress:'127.0.0.1'}}),true);
 for(const request of [{headers:{host:'localhost:4177'},socket:{remoteAddress:'127.0.0.1'}},{headers:{host:'127.0.0.1:4177'},socket:{remoteAddress:'10.0.0.1'}},{headers:{host:'customer:4177'},socket:{remoteAddress:'127.0.0.1'}}])assert.equal(presentationRequestAllowed(request),false);
});
test('only declared presentation files use Vite, all other browser cases retain production URL',()=>{
 const config=readFileSync(path.join(root,'frontend/playwright.config.ts'),'utf8');assert.match(config,/name: "production"/);assert.match(config,/name: "isolated-presentation"/);assert.equal((config.match(/fleet-group-authorization\.spec\.ts/g)||[]).length,2);assert.equal((config.match(/fleet-fixture-runs\.spec\.ts/g)||[]).length,2);assert.match(config,/reuseExistingServer: false/);assert.match(config,/FINOPS_WEB_URL \|\| "http:\/\/localhost:3000"/);assert.match(config,/retries: 0/);
 const boundary=readFileSync(path.join(root,'frontend/tests/presentation.ts'),'utf8');assert.match(boundary,/route\.abort\("blockedbyclient"\)/);assert.match(boundary,/auto: true/);
 for(const file of ['fleet-native-assessment.spec.ts','fleet-native-capacity.spec.ts'])assert.equal(config.split('"'+file+'"').length-1,2,'isolated case must be excluded from production and included once in the presentation project');
 const server=readFileSync(path.join(root,'frontend/tests/presentation-server.mjs'),'utf8');assert.match(server,/UNMOCKED_PRESENTATION_REQUEST/);assert.match(server,/await server\.close\(\)/);assert.match(server,/process\.once\('SIGTERM',close\)/);
 const build=readFileSync(path.join(root,'frontend/vite.config.ts'),'utf8');assert.ok(!build.includes('tests/fixtures'));assert.ok(!build.includes('rollupOptions'));
});
