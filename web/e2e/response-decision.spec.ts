import {expect,test,type Route} from '@playwright/test';
const json=(r:Route,v:unknown)=>r.fulfill({contentType:'application/json',body:JSON.stringify(v)});
for(const capability of ['Ready','Unsupported action'])test(`response ${capability}`,async({page})=>{
 const decisions:unknown[]=[];
 const incident={id:'INC-TEST',status:'OPEN',severity:'low',rule_description:'Lab evidence',summary:'Test',recommended_actions:[],agent_name:'target',created_at:new Date().toISOString()};
 const proposal={proposal_id:'proposal-test',digest:'a'.repeat(64),title:'Review response',action:'response.wazuh_ip_block',origin:'system',rationale:'Cited evidence',capability,source_ip:'10.77.0.10',target_ip:'10.77.0.20',agent_id:'001',duration_seconds:60,cooldown_seconds:300,max_actions:3,impact:'Only lab source blocked',verification:'Independent checks',recovery:capability==='Ready'?'Timed recovery':'File restoration execution unavailable',exclusions:['management'],evidence:[],decision:null};
 const response={proposals:[proposal],authorizations:[],intents:[],events:[],operation_id:null};
 await page.route('**/*',r=>{
  const path=new URL(r.request().url()).pathname;
  if(path==='/auth/me')return json(r,{user_id:'admin',email:'admin@example.test',display_name:'Admin',created_at:new Date().toISOString()});
  if(path==='/orgs')return json(r,[{org_id:'org',name:'SOC'}]);
  if(path==='/orgs/current')return json(r,{organization:{org_id:'org',name:'SOC'},role:'admin',members:[],license:null});
  if(path==='/system')return json(r,{version:'test',integrations:[],live_response:false});
  if(path.endsWith('/decision')){decisions.push(r.request().postDataJSON());return json(r,response);}
  if(path==='/incidents/INC-TEST/response')return json(r,response);
  if(path==='/incidents/INC-TEST')return json(r,incident);
  if(path==='/incidents')return json(r,[incident]);
  if(path==='/investigation/graph/network')return json(r,{total_events:0,shown_events:0,events:[]});
  if(['/assets','/agents/actions','/workflows/approvals/pending'].includes(path))return json(r,[]);
  return r.continue();
 });
 await page.goto('/console/incidents/INC-TEST');
 await page.getByRole('tab',{name:'Response',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Response decision',exact:true})).toBeVisible();
 if(capability==='Ready'){
  await page.getByRole('button',{name:'Enable autonomy for this incident',exact:true}).click();
  await expect(page.getByRole('dialog')).toContainText('30 minutes or incident closure');
  await expect(page.getByRole('dialog')).toContainText('Maximum 3 actions');
  await page.getByRole('button',{name:'Enable incident autonomy',exact:true}).click();
  await expect.poll(()=>decisions.length).toBe(1);
  expect(decisions[0]).toEqual({digest:'a'.repeat(64),decision:'autonomy',note:''});
 }else{
  await expect(page.getByRole('button',{name:'Approve once',exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Reject',exact:true}).click();
  await expect(page.getByRole('button',{name:'Save decision',exact:true})).toBeDisabled();
  await page.getByLabel('Decision note').fill('Authorized lab change');
  await page.getByRole('button',{name:'Save decision',exact:true}).click();
  await expect.poll(()=>decisions.length).toBe(1);
 }
});
