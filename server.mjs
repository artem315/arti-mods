import http from 'node:http';
import {openDatabase} from './database.mjs';
import {openFiles} from './filestore.mjs';
import {randomBytes,randomUUID,scrypt,timingSafeEqual,createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url)), data=process.env.DATA_DIR||path.join(root,'data');
const db=await openDatabase(data);
const blobs=await openFiles(data);
if(process.env.RENDER && process.env.DEMO_MODE!=='true' && (!db.persistent||!blobs.persistent))throw Error('Production requires persistent database AND private storage');
const derive=promisify(scrypt), LIMIT=30*1024*1024;
const demo=process.env.DEMO_MODE==='true';
export async function closeResources(){clearInterval(timer);await db.close();}
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
const json=(res,status,obj)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj));};
const hash=v=>createHash('sha256').update(v).digest('hex');
const publicMod=m=>{const {owner,analysis,next_scan,...p}=m;return {...p,stats:m.stats?JSON.parse(m.stats):null};};
const userOf=async req=>{const t=/am_session=([a-f0-9]+)/.exec(req.headers.cookie||'')?.[1];return t?(await db.prepare('SELECT u.id,u.name FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires>?').get(hash(t),Date.now())):null;};
async function body(req,limit=16384){let n=0,parts=[];for await(const p of req){n+=p.length;if(n>limit)fail(413,'Файл или запрос слишком большой');parts.push(p);}return Buffer.concat(parts);}
async function object(req){try{return JSON.parse((await body(req)).toString());}catch(e){if(e.status)throw e;fail(400,'Некорректный JSON');}}
const clean=(v,min,max,label)=>{if(typeof v!=='string'||v.trim().length<min||v.length>max)fail(400,`Проверьте поле «${label}»`);return v.trim();};
const options={kind:['Моды','Модпаки','Ресурспаки','Шейдеры'],category:['Оптимизация','Приключения','Технологии','Строительство','Мир','Интерфейс'],loader:['Fabric','Forge','NeoForge','Quilt','Не требуется']};
const rates=new Map();
function rate(req,key,max){const ip=req.socket.remoteAddress||'unknown';const k=ip+key,now=Date.now();let r=rates.get(k);if(!r||r.until<now){r={count:0,until:now+3600000};rates.set(k,r);}if(++r.count>max)fail(429,'Слишком много запросов. Попробуйте позже.');}
async function vt(endpoint,init={}){const r=await fetch(`https://www.virustotal.com/api/v3/${endpoint}`,{...init,headers:{'x-apikey':process.env.VIRUSTOTAL_API_KEY,...init.headers},signal:AbortSignal.timeout(45000)});if(!r.ok)throw new Error(`VirusTotal ${r.status}`);return r.json();}
export function verdict(a){const s=a?.stats;if(a?.status!=='completed'||!s)return 'scanning';if((s.malicious||0)>0||(s.suspicious||0)>0)return 'blocked';if((s.harmless||0)+(s.undetected||0)<=0)return 'review';return 'clean';}
let scanning=false;
export async function scanNext(){if(scanning||!process.env.VIRUSTOTAL_API_KEY)return;scanning=true;try{const m=(await db.prepare("SELECT * FROM mods WHERE status IN ('pending','scanning') AND next_scan<=? ORDER BY next_scan,created LIMIT 1").get(Date.now()));if(!m)return;
(await db.prepare('UPDATE mods SET next_scan=? WHERE id=?').run(Date.now()+60000,m.id));
if(!m.analysis){const form=new FormData();form.append('file',new Blob([await blobs.get(m.id)]),m.filename);const j=await vt('files',{method:'POST',body:form});if(!j.data?.id)throw Error('Missing analysis');(await db.prepare("UPDATE mods SET analysis=?,status='scanning' WHERE id=?").run(j.data.id,m.id));}else{const j=await vt('analyses/'+encodeURIComponent(m.analysis));const a=j.data?.attributes;(await db.prepare('UPDATE mods SET status=?,stats=? WHERE id=?').run(verdict(a),JSON.stringify(a?.stats||{}),m.id));}
}catch(e){console.error('Scan deferred:',e.message);}finally{scanning=false;}}
const timer=setInterval(async()=>{try{await scanNext();(await db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()));for(const [k,v]of rates)if(v.until<Date.now())rates.delete(k);}catch{console.error('Maintenance deferred');}},21000);timer.unref();
export const server=http.createServer(async(req,res)=>{try{
res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
const url=new URL(req.url,'http://localhost'),p=url.pathname,method=req.method,u=await userOf(req);
if(!['GET','HEAD'].includes(method)){const origin=req.headers.origin;const expected=process.env.APP_ORIGIN||process.env.RENDER_EXTERNAL_URL||`http://${req.headers.host}`;if(origin&&origin!==expected)fail(403,'Недопустимый источник запроса');if(req.headers['sec-fetch-site']==='cross-site')fail(403,'Недопустимый источник запроса');if(demo)fail(503,'Демонстрационный режим: регистрация и загрузка откроются после подключения постоянного хранилища.');}
if(p==='/api/health')return json(res,200,{ok:true});
if(p==='/api/config')return json(res,200,{scannerConfigured:!!process.env.VIRUSTOTAL_API_KEY,demo,options});
if(p==='/api/me')return json(res,200,{user:u||null});
if(['/api/register','/api/login'].includes(p)&&method==='POST'){rate(req,'auth',30);const b=await object(req),name=clean(b.name,3,24,'Имя');if(!/^[\p{L}\p{N}_-]+$/u.test(name))fail(400,'Имя: буквы, цифры, _ или -');const password=clean(b.password,10,128,'Пароль (10–128 символов)');let person=(await db.prepare('SELECT * FROM users WHERE lower(name)=lower(?)').get(name));
if(p==='/api/register'){if(person)fail(409,'Это имя уже занято');const salt=randomBytes(16).toString('hex'),key=Buffer.from(await derive(password,salt,64)).toString('hex');person={id:randomUUID(),name};(await db.prepare('INSERT INTO users VALUES(?,?,?)').run(person.id,name,salt+':'+key));}else{const [salt,key]=(person?.password||('0'.repeat(32)+':'+ '0'.repeat(128))).split(':');const actual=Buffer.from(await derive(password,salt,64));if(!person||!timingSafeEqual(actual,Buffer.from(key,'hex')))fail(401,'Неверное имя или пароль');}
const token=randomBytes(32).toString('hex');(await db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hash(token),person.id,Date.now()+7*86400000));res.setHeader('Set-Cookie',`am_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${process.env.NODE_ENV==='production'?'; Secure':''}`);return json(res,200,{user:{id:person.id,name:person.name}});}
if(p==='/api/logout'&&method==='POST'){const t=/am_session=([a-f0-9]+)/.exec(req.headers.cookie||'')?.[1];if(t)(await db.prepare('DELETE FROM sessions WHERE token=?').run(hash(t)));res.setHeader('Set-Cookie','am_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');return json(res,200,{ok:true});}
if(p==='/api/mods'&&method==='GET'){let rows=(await db.prepare("SELECT m.*,u.name AS author FROM mods m JOIN users u ON m.owner=u.id WHERE m.status='clean' OR m.owner=? ORDER BY created DESC LIMIT 500").all(u?.id||''));if(url.searchParams.get('mine')==='1')rows=rows.filter(m=>m.owner===u?.id);if(url.searchParams.get('favorites')==='1'){const ids=new Set(u?(await db.prepare('SELECT mod_id FROM favorites WHERE user_id=?').all(u.id)).map(x=>x.mod_id):[]);rows=rows.filter(m=>ids.has(m.id));}return json(res,200,{mods:rows.map(publicMod)});}
if(p==='/api/mods'&&method==='POST'){if(!u)fail(401,'Войдите, чтобы загрузить проект');rate(req,'upload',10);if((await db.prepare('SELECT COUNT(*) AS n FROM mods WHERE owner=?').get(u.id)).n>=30)fail(429,'Лимит: 30 проектов на автора');let b;try{b=JSON.parse(decodeURIComponent(req.headers['x-mod-metadata']||''));}catch{fail(400,'Нет описания проекта');}const title=clean(b.title,3,80,'Название'),description=clean(b.description,20,6000,'Описание'),minecraft=clean(b.minecraft,3,24,'Minecraft'),version=clean(b.version,1,24,'Версия'),license=clean(b.license,2,80,'Лицензия'),filename=clean(b.filename,1,120,'Файл');if(!/^[\w .()-]+\.(jar|zip|mrpack)$/i.test(filename))fail(400,'Допустимы .jar, .zip и .mrpack с латинским именем');if(b.consent!==true)fail(400,'Подтвердите отправку в VirusTotal и права на файл');for(const key of Object.keys(options))if(!options[key].includes(b[key]))fail(400,'Недопустимый '+key);
const count=(await db.prepare('SELECT COALESCE(SUM(size),0) AS n FROM mods').get()).n;if(count+LIMIT>800*1024*1024)fail(507,'Хранилище заполнено');const bytes=await body(req,LIMIT);if(bytes.length<4||bytes[0]!==0x50||bytes[1]!==0x4b)fail(400,'Файл должен быть архивом ZIP/JAR/MRPACK');const id=randomUUID(),sha=hash(bytes);await blobs.put(id,bytes);(await db.prepare('INSERT INTO mods(id,owner,title,description,kind,category,loader,minecraft,version,license,filename,sha,size,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,u.id,title,description,b.kind,b.category,b.loader,minecraft,version,license,filename,sha,bytes.length,Date.now()));return json(res,201,{id,status:'pending'});}
const match=/^\/api\/mods\/([a-f0-9-]+)(?:\/(download|favorite))?$/.exec(p);
if(match){const m=(await db.prepare('SELECT m.*,u.name AS author FROM mods m JOIN users u ON m.owner=u.id WHERE m.id=?').get(match[1]));if(!m||(m.status!=='clean'&&m.owner!==u?.id))fail(404,'Проект не найден');
if(match[2]==='favorite'&&method==='POST'){if(!u)fail(401,'Войдите, чтобы сохранить проект');const exists=(await db.prepare('SELECT 1 FROM favorites WHERE user_id=? AND mod_id=?').get(u.id,m.id));if(exists)(await db.prepare('DELETE FROM favorites WHERE user_id=? AND mod_id=?').run(u.id,m.id));else (await db.prepare('INSERT INTO favorites VALUES(?,?)').run(u.id,m.id));return json(res,200,{favorite:!exists});}
if(match[2]==='download'&&method==='GET'){if(m.status!=='clean')fail(403,'Скачивание закрыто до успешной проверки VirusTotal');const downloadBytes=await blobs.get(m.id);if(hash(downloadBytes)!==m.sha)fail(409,'Контрольная сумма файла изменилась. Скачивание заблокировано.');(await db.prepare('UPDATE mods SET downloads=downloads+1 WHERE id=?').run(m.id));res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${m.filename}"`,'Content-Length':m.size});res.end(downloadBytes);return;}
if(!match[2]&&method==='GET')return json(res,200,{mod:publicMod(m)});}
if(p.startsWith('/api/'))fail(404,'Не найдено');
if(!['GET','HEAD'].includes(method))fail(405,'Метод не поддерживается');
const files={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/style.css':'style.css','/favicon.svg':'favicon.svg'};const f=files[p];if(!f)fail(404,'Страница не найдена');const bytes=await readFile(path.join(root,'public',f));const types={html:'text/html',js:'text/javascript',css:'text/css',svg:'image/svg+xml'};res.writeHead(200,{'Content-Type':types[f.split('.').pop()]+'; charset=utf-8'});res.end(method==='HEAD'?undefined:bytes);
}catch(e){if(!res.headersSent)json(res,e.status||500,{error:e.status?e.message:'Ошибка сервера. Попробуйте позже.'});else res.end();if(!e.status)console.error('Request failed:',e.code||'internal');}});
if(process.env.NODE_ENV!=='test')server.listen(Number(process.env.PORT)||3000,'0.0.0.0',()=>console.log('Арти Модс: http://localhost:'+(process.env.PORT||3000)));
