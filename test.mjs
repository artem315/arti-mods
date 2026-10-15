import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
const dir=await mkdtemp(path.join(os.tmpdir(),'arti-test-'));
process.env.NODE_ENV='test';process.env.DATA_DIR=dir;
const {server,verdict,scanNext,closeResources}=await import('./server.mjs');
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base='http://127.0.0.1:'+server.address().port;
const req=(p,init={})=>fetch(base+p,init);
let cookie='',id='';
test('scan decisions fail closed',()=>{assert.equal(verdict({status:'queued',stats:{undetected:70}}),'scanning');assert.equal(verdict({status:'completed',stats:{}}),'review');assert.equal(verdict({status:'completed',stats:{malicious:1,undetected:69}}),'blocked');assert.equal(verdict({status:'completed',stats:{suspicious:1,undetected:69}}),'blocked');assert.equal(verdict({status:'completed',stats:{undetected:70}}),'clean');});
test('register, quarantine upload, privacy and download gate',async()=>{
let r=await req('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'TestCreator',password:'a-long-test-password'})});assert.equal(r.status,200);cookie=r.headers.get('set-cookie').split(';')[0];
const metadata={title:'Test mod',description:'A disposable test mod for quarantine checks.',kind:'Моды',category:'Мир',loader:'Fabric',minecraft:'1.21.1',version:'1.0',license:'MIT',filename:'test.jar',consent:true};
r=await req('/api/mods',{method:'POST',headers:{cookie,'X-Mod-Metadata':encodeURIComponent(JSON.stringify(metadata))},body:Buffer.from([0x50,0x4b,3,4,0])});assert.equal(r.status,201);id=(await r.json()).id;
assert.equal((await req('/api/mods/'+id+'/download',{headers:{cookie}})).status,403);
assert.equal((await req('/api/mods/'+id)).status,404);
assert.equal((await (await req('/api/mods')).json()).mods.length,0);
assert.equal((await (await req('/api/mods?mine=1',{headers:{cookie}})).json()).mods[0].status,'pending');
r=await req('/api/mods',{method:'POST',headers:{cookie,'X-Mod-Metadata':encodeURIComponent(JSON.stringify({...metadata,consent:false}))},body:'PKxx'});assert.equal(r.status,400);
r=await req('/api/logout',{method:'POST',headers:{cookie,origin:'https://evil.example'}});assert.equal(r.status,403);
assert.equal((await req('/server.mjs')).status,404);
assert.equal((await req('/api/config')).status,200);
});
test('VirusTotal queue submits actual file and releases only a completed clean analysis',async()=>{
const original=globalThis.fetch;let calls=0;
process.env.VIRUSTOTAL_API_KEY='test-only-not-a-real-key';
globalThis.fetch=async(url,init)=>{calls++;assert.equal(init.headers['x-apikey'],'test-only-not-a-real-key');assert.equal(url,'https://www.virustotal.com/api/v3/files');assert.equal(init.body.get('file').size,5);return new Response(JSON.stringify({data:{id:'test-analysis'}}));};
try{await scanNext();}finally{globalThis.fetch=original;delete process.env.VIRUSTOTAL_API_KEY;}
assert.equal(calls,1);assert.equal((await (await req('/api/mods/'+id,{headers:{cookie}})).json()).mod.status,'scanning');assert.equal((await req('/api/mods/'+id+'/download',{headers:{cookie}})).status,403);
const now=Date.now;Date.now=()=>now()+61000;process.env.VIRUSTOTAL_API_KEY='test-only-not-a-real-key';
globalThis.fetch=async(url)=>{assert.equal(url,'https://www.virustotal.com/api/v3/analyses/test-analysis');return new Response(JSON.stringify({data:{attributes:{status:'completed',stats:{malicious:0,suspicious:0,undetected:70}}}}));};
try{await scanNext();}finally{globalThis.fetch=original;Date.now=now;delete process.env.VIRUSTOTAL_API_KEY;}
assert.equal((await (await req('/api/mods')).json()).mods[0].status,'clean');
const download=await req('/api/mods/'+id+'/download');assert.equal(download.status,200);assert.deepEqual(Buffer.from(await download.arrayBuffer()),Buffer.from([0x50,0x4b,3,4,0]));
});
test.after(async()=>{await new Promise(r=>server.close(r));await closeResources();await rm(dir,{recursive:true,force:true});});
