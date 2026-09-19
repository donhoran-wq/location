import express from 'express';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'temp-fallback-change-me',
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true, secure:true, sameSite:'lax', maxAge:30*60*1000}
}));

// CSV location - on free Render this is temporary, export often
const CSV_PATH = process.env.CSV_PATH || './data/audit_log.csv';
fs.mkdirSync(path.dirname(CSV_PATH),{recursive:true});
if(!fs.existsSync(CSV_PATH)) fs.writeFileSync(CSV_PATH,'timestamp,lat,lng,accuracy,insideFlorida,ip,userAgent,language\n');

const STAFF_USER = process.env.STAFF_USER || 'donny';
const STAFF_PASSWORD = process.env.STAFF_PASSWORD; // <-- plain password, ONLY in Render, never in GitHub

app.use('/api/staff-login', rateLimit({windowMs:15*60*1000, max:5}));
app.post('/api/staff-login', (req,res)=>{
  const {username,password}=req.body;
  if(username !== STAFF_USER) return res.status(401).end();
  if(!STAFF_PASSWORD || password !== STAFF_PASSWORD) return res.status(401).end();
  req.session.staff=username; res.json({ok:true});
});
app.post('/api/staff-logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',(req,res)=>res.json({authed:!!req.session.staff}));
const requireStaff=(req,res,next)=>req.session.staff?next():res.status(401).end();

app.post('/api/audit-log',(req,res)=>{
  const {timestamp,lat,lng,accuracy,insideFlorida,userAgent,language}=req.body;
  const ip=(req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '').slice(0,45);
  const clean=s=>String(s||'').replace(/"/g,'').slice(0,300);
  fs.appendFileSync(CSV_PATH, `"${clean(timestamp)}","${lat??''}","${lng??''}","${accuracy??''}","${insideFlorida??''}","${clean(ip)}","${clean(userAgent)}","${clean(language)}"\n`);
  res.json({ok:true});
});
app.get('/api/audit-logs',requireStaff,(req,res)=>{
  if(!fs.existsSync(CSV_PATH)) return res.json([]);
  const lines=fs.readFileSync(CSV_PATH,'utf8').trim().split('\n').slice(1).slice(-200).reverse();
  if(lines.length===1 && lines[0]==='') return res.json([]);
  res.json(lines.map(l=>{const p=l.split('","').map(s=>s.replace(/^"|"$/g,'')); return {timestamp:p[0],lat:p[1],lng:p[2],accuracy:p[3],insideFlorida:p[4],ip:p[5],userAgent:p[6],language:p[7]};}));
});
app.get('/api/audit-export',requireStaff,(req,res)=>res.download(CSV_PATH,'audit_log.csv'));
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`Running ${PORT}`));
