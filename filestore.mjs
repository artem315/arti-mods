import {mkdir,readFile,writeFile,unlink} from 'node:fs/promises';
import path from 'node:path';
export async function openFiles(data){
  if(process.env.SUPABASE_URL||process.env.SUPABASE_SERVICE_ROLE_KEY){
    if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY)throw Error('Both Supabase storage settings are required');
    if(!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(process.env.SUPABASE_URL))throw Error('Invalid Supabase URL');
    const {createClient}=await import('@supabase/supabase-js');
    const client=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false}});
    const bucket=process.env.SUPABASE_BUCKET||'arti-mods-private';
    const info=await client.storage.getBucket(bucket);
    if(info.error)throw Error('Private storage bucket is unavailable');
    if(info.data.public)throw Error('Storage bucket must be PRIVATE; refusing to expose quarantined files');
    const storage=client.storage.from(bucket);
    return {persistent:true,async put(id,bytes){const r=await storage.upload(id,bytes,{contentType:'application/octet-stream',upsert:false});if(r.error)throw Error('Storage upload failed');},async get(id){const r=await storage.download(id);if(r.error)throw Error('Storage download failed');return Buffer.from(await r.data.arrayBuffer());},async remove(id){const r=await storage.remove([id]);if(r.error)throw Error('Storage cleanup failed');}};
  }
  const dir=path.join(data,'files');await mkdir(dir,{recursive:true});
  return {persistent:false,put:(id,bytes)=>writeFile(path.join(dir,id),bytes),get:id=>readFile(path.join(dir,id)),remove:id=>unlink(path.join(dir,id))};
}
