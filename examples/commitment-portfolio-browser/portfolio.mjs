import assert from 'node:assert/strict';
import {setTimeout as sleep} from 'node:timers/promises';
import {capacityBrowserOrigins,capacityBrowserPageError} from '../../scripts/lib/fleet-capacity-browser.mjs';
import {jointFinanceSubject,jointFinanceUsername,jointBodySHA} from '../../scripts/lib/fleet-joint-browser.mjs';

// Thin actual-browser phase. The native fixture supplies only its issued IDs
// and interval. Every observation displayed here comes from the production API.
// This module never supplies evidence, money or an execution instruction.
export async function portfolioBrowserPhase({browser,ready,inputs,password,root,write}) {
 const selection={...inputs.selection,billing_receipt_ids:[...inputs.selection.billing_receipt_ids].sort()};
 assert.deepEqual(Object.keys(selection).sort(),['billing_receipt_ids','commitment_receipt_id','period','source_id']);
 assert.ok(Array.isArray(selection.billing_receipt_ids)&&selection.billing_receipt_ids.length>0&&selection.billing_receipt_ids.length<=24);
 const context=await browser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});
 let phase='PORTFOLIO_FINANCE_PKCE',pageError,apiToken='',pkce=false,code=false,writes=0;
 const short=id=>id.length>22?id.slice(0,12)+'…'+id.slice(-6):id;
 // Waiters may start before a dependent UI action. Mark their rejection as
 // handled immediately; awaiting the original promise still throws normally.
 const handled=promise=>{void promise.catch(()=>{});return promise;};
 const poll=async(fn,message)=>{const end=Date.now()+60000;for(;;){if(await fn())return;if(Date.now()>=end)throw Error(message);await sleep(200);}};
 try {
  const page=await context.newPage();page.setDefaultTimeout(15000);page.setDefaultNavigationTimeout(30000);
  page.once('pageerror',error=>{pageError=capacityBrowserPageError(error);void page.close().catch(()=>{});});
  await context.route('**/*',route=>capacityBrowserOrigins.includes(new URL(route.request().url()).origin)?route.continue():route.abort('blockedbyclient'));
  page.on('request',r=>{const u=new URL(r.url());
   if(u.origin==='http://localhost:8081'&&u.pathname.endsWith('/auth'))pkce=u.searchParams.get('response_type')==='code'&&u.searchParams.get('code_challenge_method')==='S256'&&/^[A-Za-z0-9_-]{43}$/.test(u.searchParams.get('code_challenge')||'');
   if(u.origin==='http://localhost:8081'&&u.pathname.endsWith('/token')){const body=new URLSearchParams(r.postData()||'');if(body.get('grant_type')==='authorization_code')code=body.get('client_id')==='console'&&/^[A-Za-z0-9_-]{43,128}$/.test(body.get('code_verifier')||'');}
   if(u.pathname.startsWith('/v1/')&&r.method()!=='GET'){writes++;assert.equal(r.method(),'POST');assert.equal(u.pathname,'/v1/commitment-portfolio-analyses');assert.deepEqual(r.postDataJSON(),selection);}
  });
  const responseFor=(path,{method='GET',cursor,kind}={})=>handled(page.waitForResponse(r=>{const u=new URL(r.url());return u.pathname===path&&r.request().method()===method&&(kind===undefined||u.searchParams.get('kind')===kind)&&(cursor===undefined?!u.searchParams.has('cursor'):u.searchParams.get('cursor')===cursor);}));
  const json=async response=>{const r=await response;assert.equal(r.status(),200);return r.json();};
  async function signIn(){
   await page.goto('http://localhost:8080/');await page.getByRole('button',{name:'Sign in',exact:false}).click();
   await page.locator('#username').fill(jointFinanceUsername);await page.locator('#password').fill(password);
   const response=responseFor('/v1/dashboard');await page.locator('#kc-login').click();const r=await response;assert.equal(r.status(),200);
   const dashboard=await r.json();assert.equal(dashboard.fixture,true);assert.equal(dashboard.org.id,ready.tenant_id);apiToken=r.request().headers().authorization;assert.match(apiToken||'',/^Bearer .+/);
   await page.getByRole('link',{name:'Connections & quality',exact:true}).click();
   const history=responseFor('/v1/commitment-portfolio-analyses');await page.getByText('Commitment portfolio evidence',{exact:true}).click();return json(history);
  }
  async function choosePaged({data,path,group,id,label,kind='radio',receiptKind}) {
   for(;;){assert.ok(Array.isArray(data.items));if(data.items.some(row=>row.id===id))break;
    assert.ok(typeof data.next_cursor==='string'&&data.next_cursor.length>0,'issued portfolio choice absent from scoped pages');
    const next=responseFor(path,{cursor:data.next_cursor,kind:receiptKind});await group.getByRole('button',{name:'Load more '+label.toLowerCase(),exact:true}).click();data=await json(next);
   }
   await group.locator('label.choice-card').filter({has:page.getByText(id,{exact:true})}).getByRole(kind).check();return data;
  }
  await signIn();assert.equal(pkce,true);assert.equal(code,true);
  phase='PORTFOLIO_IDS_ONLY_REQUEST';
  const source=responseFor('/v1/commitment-portfolio-sources');await page.getByRole('button',{name:'Analyze commitment portfolio',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Analyze commitment portfolio',exact:true});
  const native=responseFor('/v1/commitment-portfolio-sources/'+selection.source_id+'/receipts',{kind:'AWS_COMMITMENT'});
  const cur=handled(page.waitForResponse(r=>{const u=new URL(r.url());return u.pathname==='/v1/commitment-portfolio-sources/'+selection.source_id+'/receipts'&&u.searchParams.get('kind')==='AWS_CUR2'&&!u.searchParams.has('cursor');}));
  await choosePaged({data:await json(source),path:'/v1/commitment-portfolio-sources',group:dialog.getByRole('group',{name:'Authenticated billing source',exact:true}),id:selection.source_id,label:'Commitment portfolio sources'});
  const nativeResponse=await native;assert.equal(nativeResponse.status(),200);const nativeURL=new URL(nativeResponse.url());let nativeData=nativeURL.searchParams.get('kind')==='AWS_COMMITMENT'?await nativeResponse.json():null;
  if(nativeData===null)throw Error('native commitment selector response did not match its kind');
  await choosePaged({data:nativeData,path:'/v1/commitment-portfolio-sources/'+selection.source_id+'/receipts',group:dialog.getByRole('group',{name:'Native commitment point',exact:true}),id:selection.commitment_receipt_id,label:'Native commitment receipts',receiptKind:'AWS_COMMITMENT'});
  let billingData=await json(cur);const billingGroup=dialog.getByRole('group',{name:'Observed billing windows',exact:true});
  for(const id of selection.billing_receipt_ids)billingData=await choosePaged({data:billingData,path:'/v1/commitment-portfolio-sources/'+selection.source_id+'/receipts',group:billingGroup,id,label:'Canonical billing receipts',kind:'checkbox',receiptKind:'AWS_CUR2'});
  await dialog.getByLabel('Portfolio interval start',{exact:true}).fill(selection.period.start.slice(0,10));await dialog.getByLabel('Portfolio interval end (exclusive)',{exact:true}).fill(selection.period.end.slice(0,10));
  const submitted=responseFor('/v1/commitment-portfolio-analyses',{method:'POST'});await dialog.getByRole('button',{name:'Request commitment analysis',exact:true}).click();
  const response=await submitted;assert.equal(response.status(),202);assert.equal(response.request().headers()['if-match'],'"0"');assert.ok(response.request().headers()['idempotency-key']);
  const queued=await response.json();assert.equal(queued.status,'QUEUED');assert.equal(queued.analysis,null);assert.equal(queued.refusal,null);assert.equal(queued.creator_id,jointFinanceSubject);assert.deepEqual(queued.selection,selection);
  write('portfolio-request.json',{schema_version:'1',run_id:ready.run_id,request_id:queued.id});
  const get=async()=>{const r=await context.request.get('http://localhost:8080/v1/commitment-portfolio-analyses/'+queued.id,{headers:{Authorization:apiToken},timeout:30000,maxRedirects:0});assert.equal(r.status(),200);return r.json();};
  phase='PORTFOLIO_ACTUAL_DAEMON_RESULT';let record;await poll(async()=>{record=await get();assert.notEqual(record.status,'REFUSED','actual portfolio inputs were refused');return record.status==='ASSESSED';},'actual portfolio worker did not publish');
  phase='PORTFOLIO_OBSERVED_METRICS';const a=record.analysis;assert.equal(a.request_id,queued.id);assert.deepEqual(a.selection,selection);assert.equal(record.creator_id,jointFinanceSubject);
  assert.equal(a.recommendation_status,'BLOCKED');for(const key of ['expected_savings','estimated_saving','verified_saving'])assert.equal(a[key],null);for(const key of ['recommendation_authorized','purchase_authorized','execution_authorized'])assert.equal(a[key],false);
  const observed=a.positions.find(row=>row.utilization!==null&&row.observed_unused_commitment!==null&&row.observed_used_commitment!==null&&row.position.currency!==null);assert.ok(observed,'positive observed commitment metrics unavailable');
  assert.ok(a.positions.some(row=>['EC2_RI_UNCLASSIFIED','EC2_STANDARD_RI'].includes(row.position.class)&&(row.position.currency===null||row.utilization===null)),'sparse RI observations were promoted');
  assert.ok(a.unmatched_billing.length>0,'retired commitment billing was dropped');assert.ok(a.partitions.some(row=>row.hourly_commitment_rate!==null&&row.position_shares.some(share=>share.share!==null)),'native concentration unavailable');
  assert.deepEqual(a.optimization_order.map(row=>row.stage),['REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE','RECALCULATE_STABLE_DEMAND']);assert.ok(a.optimization_order.every(row=>row.status==='BLOCKED'&&row.decision_ref===null&&row.outcome_ref===null));
  phase='PORTFOLIO_UI_RENDER';await page.getByRole('button',{name:'Refresh selected commitment analysis',exact:true}).click();
  const selected=page.getByRole('region',{name:'Selected commitment portfolio analysis',exact:true});await selected.getByRole('region',{name:'Observed commitment positions',exact:true}).waitFor({state:'visible'});
  await selected.getByLabel('Find observed commitment',{exact:true}).fill(observed.position.id);await selected.locator('summary').filter({hasText:observed.position.id}).click();
  const metrics=selected.getByRole('region',{name:'Observed commitment metrics '+observed.position.id,exact:true});
  for(const [label,field]of [['Observed used commitment','observed_used_commitment'],['Observed unused commitment','observed_unused_commitment']])assert.ok((await metrics.getByRole('row').filter({hasText:new RegExp('^'+label)}).innerText()).includes(observed[field]+' '+observed.position.currency));
  assert.ok((await metrics.getByRole('row').filter({hasText:/^Utilization/}).innerText()).includes(observed.utilization+' (fraction)'));
  const expiry=selected.getByRole('region',{name:'Commitment expiry '+observed.position.id,exact:true});assert.ok((await expiry.innerText()).includes(observed.expiry.remaining_seconds??'Unavailable'));
  await selected.getByLabel('Find observed commitment',{exact:true}).fill('');assert.ok((await selected.innerText()).includes('Recommendation, purchase and execution disabled.'));assert.match(await page.locator('body').innerText(),/Local fixture evidence.*Provider transports and historical billing are simulated/s);
  const hash=jointBodySHA(a);await page.screenshot({path:root+'/browser-portfolio-desktop.png',fullPage:true});
  phase='PORTFOLIO_PERSISTED_RELOAD';await context.clearCookies();await page.reload();let history=await signIn();
  const inspect=page.getByRole('button',{name:'Inspect commitment analysis '+short(queued.id),exact:true});
  for(;;){assert.ok(Array.isArray(history.items));if(history.items.some(row=>row.id===queued.id))break;assert.ok(typeof history.next_cursor==='string'&&history.next_cursor.length>0,'persisted portfolio analysis absent from history');const next=responseFor('/v1/commitment-portfolio-analyses',{cursor:history.next_cursor});await page.getByRole('button',{name:'Load more commitment portfolio analyses',exact:true}).click();history=await json(next);}
  await inspect.click();await page.getByRole('region',{name:'Observed commitment positions',exact:true}).waitFor({state:'visible'});record=await get();assert.equal(jointBodySHA(record.analysis),hash);assert.deepEqual(record.input_refs,a.input_refs);assert.equal(record.creator_id,jointFinanceSubject);
  await page.setViewportSize({width:390,height:844});assert.equal(await page.locator('html').evaluate(e=>e.scrollWidth),await page.locator('html').evaluate(e=>e.clientWidth));await page.screenshot({path:root+'/browser-portfolio-mobile.png',fullPage:true});assert.equal(writes,1);
  const proof={schema_version:'1',status:'PASS',run_id:ready.run_id,tenant_id:ready.tenant_id,request_id:queued.id,analysis_id:a.id,analysis_sha256:hash,selection_sha256:jointBodySHA(selection),creator_id:jointFinanceSubject,position_count:a.positions.length,unmatched_billing_count:a.unmatched_billing.length,oidc_pkce:true,oidc_authorization_code:true,ui_ids_only_request:true,actual_portfolio_worker:true,observed_utilization:true,observed_unused_commitment:true,sparse_ri_unknown:true,native_concentration:true,persisted_reload:true,fixture:true,recommendation_authorized:false,purchase_authorized:false,customer_execution_authorized:false,expected_savings:null,estimated_saving:null,verified_saving:null};write('portfolio-browser-result.json',proof);return{proof,record};
 }catch(error){write('portfolio-browser-failure.json',{schema_version:'1',run_id:ready.run_id,status:'FAIL',phase,error:pageError||capacityBrowserPageError(error)});throw Error('Real portfolio browser phase failed at '+phase);}finally{apiToken='';await context.close();}
}
