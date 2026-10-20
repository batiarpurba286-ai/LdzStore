import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import 'dotenv/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{
 defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],
 fontSrc:["'self'","https://fonts.gstatic.com","data:"],imgSrc:["'self'","data:","https:"],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"]
}}}));
app.use(express.json({limit:'20kb'}));
app.use('/api/',rateLimit({windowMs:60_000,limit:100,standardHeaders:true,legacyHeaders:false}));
const db = new Database(path.join(__dirname,'store.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS keys_inventory(id INTEGER PRIMARY KEY AUTOINCREMENT, product_id TEXT NOT NULL, key_value TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'available', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, product_id TEXT NOT NULL, product_name TEXT NOT NULL, amount INTEGER NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', provider_ref TEXT, key_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL, FOREIGN KEY(key_id) REFERENCES keys_inventory(id));
CREATE TABLE IF NOT EXISTS admin_sessions(token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
`);
const products = {
 basic:{id:'basic',name:'Key Basic',term:'1 Hari',price:5000},
 weekly:{id:'weekly',name:'Key Weekly',term:'7 Hari',price:20000},
 monthly:{id:'monthly',name:'Key Monthly',term:'30 Hari',price:50000}
};
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const timingSafeEqual = (a,b)=>{const aa=Buffer.from(a),bb=Buffer.from(b);return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb)};
function requireAdmin(req,res,next){
 const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
 if(!token)return res.status(401).json({error:'Login admin diperlukan'});
 const row=db.prepare('SELECT expires_at FROM admin_sessions WHERE token_hash=?').get(sha(token));
 if(!row||Date.parse(row.expires_at)<Date.now())return res.status(401).json({error:'Sesi admin tidak valid atau kedaluwarsa'});
 next();
}
function assignKey(orderId){
 const order=db.prepare('SELECT * FROM orders WHERE id=?').get(orderId);
 if(!order||order.status!=='paid'||order.key_id)return;
 const key=db.prepare("SELECT id FROM keys_inventory WHERE product_id=? AND status='available' ORDER BY id LIMIT 1").get(order.product_id);
 if(!key)return;
 const tx=db.transaction(()=>{
   const claimed=db.prepare("UPDATE keys_inventory SET status='sold' WHERE id=? AND status='available'").run(key.id);
   if(!claimed.changes)return;
   db.prepare("UPDATE orders SET key_id=? WHERE id=? AND status='paid' AND key_id IS NULL").run(key.id,orderId);
 });
 tx();
}
function publicOrder(id){
 const o=db.prepare('SELECT id,product_id AS productId,product_name AS product,amount,status,created_at AS createdAt,expires_at AS expiresAt,key_id AS keyId FROM orders WHERE id=?').get(id);
 if(!o)return null;
 const key=o.keyId?db.prepare('SELECT key_value FROM keys_inventory WHERE id=?').get(o.keyId)?.key_value:null;
 return {...o,key:key||null,payment:{provider:process.env.PAYMENT_PROVIDER||'manual',instructions:'Pembayaran nyata memerlukan integrasi gateway QRIS dan webhook terverifikasi.'}};
}
app.post('/api/orders',(req,res)=>{
 const {productId,name,email}=req.body||{};
 const p=products[productId];
 if(!p)return res.status(400).json({error:'Paket tidak valid'});
 if(typeof name!=='string'||name.trim().length<2||name.trim().length>80)return res.status(400).json({error:'Nama harus 2–80 karakter'});
 if(typeof email!=='string'||email.length>180||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'Email tidak valid'});
 const id='LDZ-'+crypto.randomBytes(6).toString('hex').toUpperCase();
 const expiresAt=new Date(Date.now()+15*60_000).toISOString();
 db.prepare('INSERT INTO orders(id,product_id,product_name,amount,name,email,expires_at) VALUES(?,?,?,?,?,?,?)').run(id,p.id,p.name,p.price,name.trim(),email.trim().toLowerCase(),expiresAt);
 res.status(201).json({...publicOrder(id),status:'pending'});
});
app.get('/api/orders/:id',(req,res)=>{
 const o=publicOrder(req.params.id);
 if(!o)return res.status(404).json({error:'Pesanan tidak ditemukan'});
 // Intentionally never accepts client-side claims that a payment was made.
 res.json(o);
});
app.post('/api/payments/webhook',(req,res)=>{
 // SECURITY: This endpoint deliberately fails closed until a real provider's signature
 // validation and event schema are implemented. Never mark orders paid from a browser request.
 const provider=process.env.PAYMENT_PROVIDER;
 if(!provider||provider==='manual')return res.status(503).json({error:'Payment gateway belum dikonfigurasi; pesanan tetap pending.'});
 // Integrator TODO: validate provider signature over the RAW request body, amount, currency,
 // merchant account, order reference, and final successful state before updating order to paid.
 return res.status(501).json({error:'Implementasi webhook spesifik provider belum ditambahkan. Tidak ada key yang diterbitkan.'});
});
app.post('/api/admin/login',rateLimit({windowMs:15*60_000,limit:8,standardHeaders:true,legacyHeaders:false}), (req,res)=>{
 const password=req.body?.password;
 const hash=process.env.ADMIN_PASSWORD_HASH;
 if(!hash||hash==='replace-with-scrypt-hash')return res.status(503).json({error:'Admin belum dikonfigurasi. Set ADMIN_PASSWORD_HASH pada .env.'});
 // Hash format is scrypt$<salt hex>$<derived-key hex>.
 const parts=hash.split('$');
 if(parts.length!==3||parts[0]!=='scrypt')return res.status(503).json({error:'Format ADMIN_PASSWORD_HASH tidak valid.'});
 const computed=crypto.scryptSync(String(password||''),Buffer.from(parts[1],'hex'),32).toString('hex');
 if(!timingSafeEqual(computed,parts[2]))return res.status(401).json({error:'Password salah'});
 const token=crypto.randomBytes(32).toString('base64url');
 db.prepare('INSERT INTO admin_sessions(token_hash,expires_at) VALUES(?,?)').run(sha(token),new Date(Date.now()+8*60*60_000).toISOString());
 res.json({token,expiresIn:28800});
});
app.get('/api/admin/overview',requireAdmin,(req,res)=>{
 const orders=db.prepare('SELECT id,product_name AS productName,amount,status,email,created_at AS createdAt FROM orders ORDER BY created_at DESC LIMIT 100').all();
 const stats={
  orders:db.prepare('SELECT count(*) n FROM orders').get().n,
  paid:db.prepare("SELECT count(*) n FROM orders WHERE status='paid'").get().n,
  keys:db.prepare("SELECT count(*) n FROM keys_inventory WHERE status='available'").get().n
 };
 const keys=db.prepare('SELECT k.id,k.product_id AS productId,k.status,p.name AS productName,k.key_value FROM keys_inventory k LEFT JOIN (SELECT id,name FROM (SELECT "basic" id,"Key Basic" name UNION SELECT "weekly","Key Weekly" UNION SELECT "monthly","Key Monthly")) p ON p.id=k.product_id ORDER BY k.id DESC LIMIT 100').all().map(k=>({...k,maskedKey:k.key_value.length>8?k.key_value.slice(0,3)+'••••••'+k.key_value.slice(-3):'••••••'}));
 res.json({orders,stats,keys});
});
app.post('/api/admin/keys',requireAdmin,(req,res)=>{
 const {productId,key}=req.body||{};
 if(!products[productId])return res.status(400).json({error:'Paket tidak valid'});
 if(typeof key!=='string'||key.trim().length<8||key.trim().length>256)return res.status(400).json({error:'Key harus 8–256 karakter'});
 try{const info=db.prepare('INSERT INTO keys_inventory(product_id,key_value) VALUES(?,?)').run(productId,key.trim());res.status(201).json({id:info.lastInsertRowid,status:'available'});}
 catch(e){if(String(e.message).includes('UNIQUE'))return res.status(409).json({error:'Key sudah ada'});throw e;}
});
app.post('/api/admin/logout',requireAdmin,(req,res)=>{const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(sha(token));res.json({ok:true});});
app.use(express.static(path.join(__dirname,'dist')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'dist','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Kesalahan server'});});
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Ldz Mods server running on :${port}`));
