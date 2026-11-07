const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const html=fs.readFileSync('docs/index.html','utf8'),source=fs.readFileSync('ip_reachability_checker.py','utf8');
test('static product has no simulator or network execution surface',()=>{
 assert.match(html,/script-src 'none'/);assert.match(html,/connect-src 'none'/);
 assert.doesNotMatch(html,/<(?:script|input|textarea|select|form|button)\b/i);
 assert(!fs.existsSync('docs/app.js'));
});
test('origin is explicit in hero, architecture and installation',()=>{
 for(const s of ['IP Reachability Checker','Check connectivity from where you actually work.','Real checks run locally.','This website does not probe IP addresses.','VPN','remote server','GitHub Pages is documentation','computer whose connectivity'])assert(html.includes(s),s);
});
test('literal input bounds reflect the unchanged source',()=>{
 for(const [constant,value] of [['MAX_TARGETS',256],['MAX_WORKERS',32],['MAX_FILE_LINES',4096],['MAX_LINE_LENGTH',512]])assert(source.includes(`${constant} = ${value}`));
 for(const s of ['256','32','4,096 / 512','without a shell','No CIDR expansion','No multi-port scan'])assert(html.includes(s),s);
});
test('timing and status claims preserve compatibility semantics',()=>{
 for(const s of ['reachable','unreachable','error','130','latency_ms','overall check duration','not packet RTT','not immediately cancel running threads','not application health'])assert(html.includes(s),s);
 const json=html.match(/<code>(\{[\s\S]*?\})<\/code>/)[1];const sample=JSON.parse(json);assert.equal(sample.results[0].ip,'127.0.0.1');assert.equal(sample.summary.total,1);
});
test('cross-platform commands remain install-first and use loopback',()=>{
 for(const s of ['Python 3.10+','Windows · PowerShell','macOS / Linux','py -3','python3','--tcp-port 8000','actual local listener','::1'])assert(html.includes(s),s);
 assert.match(html,/Loopback[\s\S]*?that machine itself/);
});
test('anchors are unique and local assets exist',()=>{
 const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(ids.length,new Set(ids).size);
 for(const [,id]of html.matchAll(/href="#([^"]+)"/g))assert(ids.includes(id),id);
 for(const [,asset]of html.matchAll(/(?:href|src)="([^"#:]+\.(?:css|svg))"/g))assert(fs.existsSync('docs/'+asset),asset);
});
