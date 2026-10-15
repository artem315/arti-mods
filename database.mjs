import {DatabaseSync} from 'node:sqlite';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {readFileSync} from 'node:fs';

// PostgreSQL tables live outside the public/Data API schema.
export const schema = `
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,password TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS users_name_unique ON users(lower(name));
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),expires BIGINT);
CREATE TABLE IF NOT EXISTS mods(id TEXT PRIMARY KEY,owner TEXT REFERENCES users(id),title TEXT,description TEXT,kind TEXT,category TEXT,loader TEXT,minecraft TEXT,version TEXT,license TEXT,filename TEXT,sha TEXT,size BIGINT,status TEXT DEFAULT 'pending',analysis TEXT,stats TEXT,downloads BIGINT DEFAULT 0,created BIGINT,next_scan BIGINT DEFAULT 0);
CREATE TABLE IF NOT EXISTS favorites(user_id TEXT REFERENCES users(id),mod_id TEXT REFERENCES mods(id),PRIMARY KEY(user_id,mod_id));
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
CREATE INDEX IF NOT EXISTS mods_queue ON mods(status,next_scan);
CREATE INDEX IF NOT EXISTS mods_owner ON mods(owner);`;

export function postgresQuery(sql) {
  let index=0;
  return sql.replace(/'(?:''|[^'])*'|\?/g,part=>part==='?'?'$'+(++index):part);
}
const numeric=new Set(['size','downloads','created','next_scan','expires','n']);
function normalize(row){return row&&Object.fromEntries(Object.entries(row).map(([k,v])=>[k,numeric.has(k)&&v!==null?Number(v):v]));}

export async function openDatabase(data) {
  if(process.env.DATABASE_URL){
    const {Pool}=await import('pg');
    const connection=new URL(process.env.DATABASE_URL);
    let ssl;
    const certificate=process.env.DATABASE_CA_CERT||(process.env.SUPABASE_URL?new URL('./supabase-ca.crt',import.meta.url):null);
    if(certificate){
      // pg's URL SSL options override the object; keep verification explicit.
      for(const key of ['sslmode','sslcert','sslkey','sslrootcert'])connection.searchParams.delete(key);
      ssl={ca:readFileSync(certificate,'utf8'),rejectUnauthorized:true};
    }
    const pool=new Pool({connectionString:connection.toString(),...(ssl?{ssl}:{}),max:3,connectionTimeoutMillis:15000,idleTimeoutMillis:30000,options:'-c search_path=arti'});
    pool.on('error',()=>console.error('Database connection interrupted'));
    await pool.query('CREATE SCHEMA IF NOT EXISTS arti');
    await pool.query('REVOKE ALL ON SCHEMA arti FROM PUBLIC');
    await pool.query(schema);
    return {persistent:true,prepare(sql){const query=(args)=>pool.query(postgresQuery(sql),args);return {async get(...args){return normalize((await query(args)).rows[0]);},async all(...args){return (await query(args)).rows.map(normalize);},async run(...args){return {changes:(await query(args)).rowCount};}};},close:()=>pool.end()};
  }
  await mkdir(data,{recursive:true});
  const sqlite=new DatabaseSync(path.join(data,'catalog.sqlite'));
  sqlite.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;'+schema);
  return {persistent:false,prepare:sql=>sqlite.prepare(sql),close:()=>sqlite.close()};
}
