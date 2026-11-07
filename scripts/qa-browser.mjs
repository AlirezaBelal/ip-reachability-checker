import {chromium} from 'playwright';import AxeBuilder from '@axe-core/playwright';import assert from 'node:assert/strict';import {createServer} from 'node:http';import {readFile,writeFile,mkdir} from 'node:fs/promises';import {resolve,extname} from 'node:path';
const out=resolve(process.env.QA_OUTPUT||'evidence/browser');await mkdir(out,{recursive:true});const root=resolve('docs');
const server=createServer(async(req,res)=>{try{let p=new URL(req.url,'http://localhost').pathname;if(p.endsWith('/'))p+='index.html';const f=resolve(root,'.'+decodeURIComponent(p));if(!f.startsWith(root))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.css':'text/css','.svg':'image/svg+xml'})[extname(f)]||'application/octet-stream');res.end(await readFile(f));}catch{res.statusCode=404;res.end();}});await new Promise(r=>server.listen(0,'127.0.0.1',r));
const url=process.env.PRODUCT_URL||`http://127.0.0.1:${server.address().port}/`,b=await chromium.launch(),results=[];
try{for(const [width,height] of [[320,700],[375,812],[390,844],[768,1024],[1024,768],[1440,1000],[1920,1080]]){
 const c=await b.newContext({viewport:{width,height},reducedMotion:'reduce'}),p=await c.newPage(),errors=[],external=[],bad=[];
 p.on('pageerror',e=>errors.push(e.message));p.on('console',m=>{if(m.type()==='error')errors.push(m.text());});p.on('request',r=>{if(new URL(r.url()).origin!==new URL(url).origin)external.push(r.url());});p.on('response',r=>{if(r.status()>=400)bad.push(r.url());});await p.goto(url,{waitUntil:'networkidle'});
 assert.equal(await p.locator('h1').textContent(),'Check connectivity from where you actually work.');assert.equal(await p.locator('script,input,textarea,form,button').count(),0);
 assert.equal(await p.locator('.hero .primary').getAttribute('href'),'#installation');assert(await p.locator('h1').evaluate(e=>parseFloat(getComputedStyle(e).fontSize)<=60));
 await p.keyboard.press('Tab');assert.match(await p.locator(':focus').textContent(),/Skip to main/);await p.keyboard.press('Enter');assert.equal(await p.locator(':focus').getAttribute('id'),'main-content');
 await p.locator('.hero .primary').focus();assert(await p.locator(':focus').evaluate(e=>getComputedStyle(e).outlineStyle!=='none'));await p.keyboard.press('Enter');await p.waitForTimeout(100);assert(await p.locator('#installation').evaluate(e=>e.getBoundingClientRect().top<100));
 for(const a of await p.locator('a[href^="#"]').all())assert(await p.locator(await a.getAttribute('href')).count());
 assert.equal(await p.locator('.origin-map li').count(),3);
 assert(await p.evaluate(()=>getComputedStyle(document.documentElement).scrollBehavior==='auto'));
 const axe=await new AxeBuilder({page:p}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();await writeFile(`${out}/axe-${width}.json`,JSON.stringify(axe,null,2));assert.deepEqual(axe.violations.map(v=>({id:v.id,targets:v.nodes.map(n=>n.target)})),[]);
 await p.locator('h1').click();await p.evaluate(()=>scrollTo(0,0));await p.screenshot({path:`${out}/arrival-${width}.png`,fullPage:true});
 await p.locator('#how-it-works').screenshot({path:`${out}/architecture-${width}.png`});
 for(const s of await p.locator('summary').all()){if(!(await s.evaluate(e=>e.parentElement.open))){await s.focus();await p.keyboard.press('Enter');}assert(await s.evaluate(e=>e.parentElement.open));}
 await p.locator('#installation').screenshot({path:`${out}/installation-${width}.png`});
 const openAxe=await new AxeBuilder({page:p}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();assert.deepEqual(openAxe.violations.map(v=>v.id),[]);
 assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert.deepEqual(bad,[]);
 results.push({width,height,url,axeViolations:0,keyboard:'passed',anchors:'passed',disclosures:'passed',overflow:'passed',simulator:'absent',externalRequests:external,consoleErrors:errors});await c.close();
}}finally{await writeFile(`${out}/results.json`,JSON.stringify(results,null,2));await b.close();await new Promise(r=>server.close(r));}console.log(JSON.stringify(results,null,2));
