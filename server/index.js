const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, '..', 'db', 'subscribers.db');
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscribers (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, phone TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));`);
const admin = db.prepare('SELECT id FROM admin WHERE id=1').get();
if (!admin) db.prepare('INSERT INTO admin(id,password_hash) VALUES(1,?)').run(bcrypt.hashSync(process.env.ADMIN_PASSWORD || '123456', 12));

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'10kb'}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));

const loginLimiter = rateLimit({windowMs: 15*60*1000, max: 10, standardHeaders: true, legacyHeaders:false});
const addLimiter = rateLimit({windowMs: 10*60*1000, max: 30, standardHeaders:true, legacyHeaders:false});

function validPhone(phone){ return /^(?:\+?20|0)?1[0125][0-9]{8}$/.test(phone.replace(/[\s-]/g,'')); }
function auth(req,res,next){
  try { const token=req.cookies.admin_token; if(!token) return res.status(401).json({error:'غير مصرح'}); req.admin=jwt.verify(token,JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'انتهت الجلسة أو غير مصرح'}); }
}

app.post('/api/login', loginLimiter, (req,res)=>{
  const password=String(req.body?.password||'');
  const row=db.prepare('SELECT password_hash FROM admin WHERE id=1').get();
  if(!bcrypt.compareSync(password,row.password_hash)) return res.status(401).json({error:'كلمة المرور غير صحيحة'});
  const token=jwt.sign({role:'admin'},JWT_SECRET,{expiresIn:'8h'});
  res.cookie('admin_token',token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000});
  res.json({ok:true});
});
app.post('/api/logout',(req,res)=>{res.clearCookie('admin_token');res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({ok:true,role:'admin'}));
app.post('/api/subscribers',addLimiter,(req,res)=>{
  const fullName=String(req.body?.fullName||'').trim(); const phone=String(req.body?.phone||'').trim();
  if(fullName.length<2) return res.status(400).json({error:'يرجى إدخال الاسم بالكامل'});
  if(!validPhone(phone)) return res.status(400).json({error:'يرجى إدخال رقم هاتف مصري صحيح'});
  const result=db.prepare('INSERT INTO subscribers(full_name,phone) VALUES(?,?)').run(fullName,phone);
  res.status(201).json({ok:true,id:Number(result.lastInsertRowid)});
});
app.get('/api/subscribers',auth,(req,res)=>{
  const q=String(req.query.q||'').trim();
  const rows=q ? db.prepare(`SELECT id,full_name,phone,created_at FROM subscribers WHERE full_name LIKE ? OR phone LIKE ? ORDER BY id DESC`).all(`%${q}%`,`%${q}%`) : db.prepare('SELECT id,full_name,phone,created_at FROM subscribers ORDER BY id DESC').all();
  const total=db.prepare('SELECT COUNT(*) c FROM subscribers').get().c;
  res.json({total,items:rows});
});
app.patch('/api/admin/password',auth,(req,res)=>{
  const next=String(req.body?.password||'');
  if(next.length<6) return res.status(400).json({error:'كلمة المرور يجب ألا تقل عن 6 أحرف'});
  db.prepare('UPDATE admin SET password_hash=? WHERE id=1').run(bcrypt.hashSync(next,12)); res.json({ok:true});
});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.listen(PORT,()=>console.log(`http://localhost:${PORT}`));
