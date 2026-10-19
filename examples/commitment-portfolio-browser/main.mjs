// Real FINANCE PKCE against the production App and the isolated actual API.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {existsSync,lstatSync,readFileSync,writeFileSync,openSync,closeSync,fsyncSync,linkSync,unlinkSync} from 'node:fs';
import {capacityBrowserPageError} from '../../scripts/lib/fleet-capacity-browser.mjs';
import {portfolioBrowserSHA,validatePortfolioBrowserReady,validatePortfolioBrowserResult} from '../../scripts/lib/commitment-portfolio-browser.mjs';
import {portfolioBrowserPhase} from './portfolio.mjs';
const {chromium}=createRequire('/browser-modules/package.json')('playwright');
assert.equal(process.argv.length,2);const runID=process.env.COMMITMENT_PORTFOLIO_BROWSER_RUN_ID;assert.match(runID||'',/^[a-f0-9-]{36}$/);
const root='/results';
const read=(name,max=8192)=>{const file=root+'/'+name,s=lstatSync(file);assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.size>0&&s.size<=max);return readFileSync(file);};
const write=(name,value)=>{assert.match(name,/^portfolio-[a-z-]+\.json$/);const target=root+'/'+name,tmp=target+'.tmp',fd=openSync(tmp,'wx',0o600);try{writeFileSync(fd,JSON.stringify(value)+'\n');fsyncSync(fd);}finally{closeSync(fd);}try{linkSync(tmp,target);}finally{unlinkSync(tmp);}};
const readyRaw=read('portfolio-browser-ready.json'),ready=validatePortfolioBrowserReady(JSON.parse(readyRaw),runID),secret='/run/secrets/browser.json',st=lstatSync(secret);assert.ok(st.isFile()&&!st.isSymbolicLink()&&st.size>0&&st.size<=4096);const credentials=JSON.parse(readFileSync(secret,'utf8'));assert.deepEqual(Object.keys(credentials).sort(),['password','run_id']);assert.equal(credentials.run_id,runID);assert.match(credentials.password,/^[a-f0-9]{64}$/);
let browser,phase='PORTFOLIO_BROWSER_LAUNCH';try{browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});write('portfolio-browser-start.json',{schema_version:'1',run_id:runID,ready_sha256:portfolioBrowserSHA(readyRaw)});phase='PORTFOLIO_BROWSER_PHASE';const result=await portfolioBrowserPhase({browser,ready,inputs:{selection:ready.selection},password:credentials.password,root,write});validatePortfolioBrowserResult(result.proof,{ready});console.log('Isolated portfolio FINANCE browser PASS; actual daemon and immutable native analysis read/reload.');}catch(error){if(!existsSync(root+'/portfolio-browser-failure.json'))write('portfolio-browser-failure.json',{schema_version:'1',run_id:runID,status:'FAIL',phase,error:capacityBrowserPageError(error)});process.exitCode=1;}finally{credentials.password='';await browser?.close();}
