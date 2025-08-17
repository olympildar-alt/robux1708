// SSO через одноразовый токен + Telegram Login Widget + WebApp + сессии + админка + вебхук
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const Datastore = require("nedb-promises");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const fetchFn = globalThis.fetch || require("node-fetch");

const app = express();
const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN || "";
const ADMIN_ID = process.env.ADMIN_ID || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "supersecret";
const NOTIFY_COOLDOWN_MIN = Number(process.env.NOTIFY_COOLDOWN_MIN || 5);
const WEBAPP_NOTIFY = Number(process.env.WEBAPP_NOTIFY ?? 1);
const PUBLIC_URL = process.env.PUBLIC_URL || "";
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "change_me_secret";
const DEBUG_AUTH = Number(process.env.DEBUG_AUTH || 0);
const AFTER_LOGIN_URL = process.env.AFTER_LOGIN_URL || (PUBLIC_URL ? PUBLIC_URL.replace(/\/$/,"") + "/" : "/");

console.log("[startup]", { hasBOT_TOKEN: !!BOT_TOKEN, PUBLIC_URL, AFTER_LOGIN_URL, PORT });

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const users = Datastore.create({ filename: path.join(dataDir, "users.db"), autoload: true });
const logins = Datastore.create({ filename: path.join(dataDir, "logins.db"), autoload: true });
const tokens = Datastore.create({ filename: path.join(dataDir, "tokens.db"), autoload: true }); // одноразовые SSO-токены

const TEN_MIN = 600;

function getIp(req){ const xf=req.headers["x-forwarded-for"]; return xf?String(xf).split(",")[0].trim():(req.ip||req.connection?.remoteAddress||""); }
function eqHex(a,b){try{const A=Buffer.from(a,"hex");const B=Buffer.from(b,"hex");return A.length===B.length&&crypto.timingSafeEqual(A,B)}catch{return false}}

function verifyLoginWidget(q){
  const d={...q}; const {hash}=d; if(!hash) return null; delete d.hash;
  const str=Object.keys(d).sort().map(k=>`${k}=${d[k]}`).join("\n");
  const secret=crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const exp=crypto.createHmac("sha256", secret).update(str).digest("hex");
  if(!eqHex(hash,exp)) return null;
  const now=Math.floor(Date.now()/1000), ad=Number(q.auth_date||0);
  if(!(ad>0 && now-ad < TEN_MIN)) return null;
  return { telegram_id:String(q.id||""), username:q.username||null, first_name:q.first_name||null, last_name:q.last_name||null, photo_url:q.photo_url||null };
}

function verifyWebApp(initDataStr){
  if(!initDataStr) return {ok:false, reason:"no_initData"};
  const usp=new URLSearchParams(initDataStr);
  const entries=[]; for(const [k,v] of usp.entries()) if(k!=="hash") entries.push([k,v]);
  entries.sort(([a],[b])=>a.localeCompare(b));
  const dcs=entries.map(([k,v])=>`${k}=${v}`).join("\n");
  const hash=usp.get("hash"); if(!hash) return {ok:false, reason:"no_hash"};
  const secret=crypto.createHmac("sha256","WebAppData").update(BOT_TOKEN).digest();
  const exp=crypto.createHmac("sha256", secret).update(dcs).digest("hex");
  if(!eqHex(hash,exp)) return {ok:false, reason:"hash_mismatch"};
  const now=Math.floor(Date.now()/1000), ad=Number(usp.get("auth_date")||0);
  if(!(ad>0 && now-ad < TEN_MIN)) return {ok:false, reason:"stale_auth_date"};
  let u={}; try{u=JSON.parse(usp.get("user")||"{}")}catch{}
  return { ok:true, user:{ telegram_id:String(u.id||""), username:u.username||null, first_name:u.first_name||null, last_name:u.last_name||null, photo_url:u.photo_url||null } };
}

async function safeFetch(url, init={}, to=8000){
  const c=new AbortController(); const t=setTimeout(()=>c.abort(),to);
  try{const r=await fetchFn(url,{...init,signal:c.signal}); clearTimeout(t); return r}catch(e){clearTimeout(t); console.error("fetch",e); return null}
}
async function tgSend(chat_id, payload){
  const url=`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  return safeFetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({chat_id,...payload})});
}
async function notifyAdmin(text){ if(!ADMIN_ID) return; await tgSend(ADMIN_ID,{text,parse_mode:"HTML",disable_web_page_preview:true}); }

async function completeLogin(req, source, user){
  await users.update({telegram_id:user.telegram_id},{ $set:{...user,updated_at:Date.now()} },{upsert:true});
  const loginDoc={ telegram_id:user.telegram_id, source, ts:Date.now(), ip:getIp(req), user_agent:req.headers["user-agent"]||"" };
  await logins.insert(loginDoc);

  const arr=await logins.find({telegram_id:user.telegram_id});
  const sorted=arr.sort((a,b)=>(b.ts||0)-(a.ts||0));
  const prev=sorted[1];
  const cooldown=NOTIFY_COOLDOWN_MIN*60*1000;
  const shouldNotify=!prev || Date.now()-(prev?.ts||0)>cooldown;
  if(shouldNotify && (source!=="webapp" || WEBAPP_NOTIFY)){
    await notifyAdmin(`👤 <b>${user.first_name||""}${user.username?" @"+user.username:""}</b>\nID: <code>${user.telegram_id}</code>\nИсточник: ${source}\nIP: <code>${loginDoc.ip||"-"}</code>`);
  }

  req.session.user={ id:user.telegram_id, username:user.username, first_name:user.first_name, last_name:user.last_name, photo_url:user.photo_url };
}

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy:false, crossOriginEmbedderPolicy:false }));
app.use(morgan("tiny"));
app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave:false,
  saveUninitialized:false,
  cookie:{ httpOnly:true, sameSite:"none", secure:true, maxAge:1000*60*60*24*7 }
}));

const loginLimiter = rateLimit({ windowMs:60_000, max:30 });
app.use("/webapp-auth", loginLimiter);
app.use("/auth/telegram-redirect", loginLimiter);

app.use(express.static(path.join(__dirname,"public"),{maxAge:"1h",etag:true}));

// Login Widget (redirect)
app.get("/auth/telegram-redirect", async (req,res)=>{
  try{
    const user=verifyLoginWidget(req.query);
    if(!user) return res.status(401).send("Auth failed");
    await completeLogin(req,"widget",user);
    req.session.save(()=>res.redirect("/"));
  }catch(e){ console.error("redirect auth",e); res.status(500).send("Internal error"); }
});

// WebApp → логин + выдача одноразового SSO-токена
app.post("/webapp-auth", async (req,res)=>{
  try{
    const result=verifyWebApp(req.body.initData);
    if (DEBUG_AUTH) console.log("[auth:webapp]", result.ok ? "ok" : `fail:${result.reason}`);
    if(!result.ok || !result.user?.telegram_id) return res.status(401).json({ok:false});

    await completeLogin(req,"webapp",result.user);

    // одноразовый токен на 2 минуты
    const token=crypto.randomBytes(32).toString("hex");
    const exp=Date.now()+2*60*1000;
    await tokens.insert({ token, user:req.session.user, exp, used:false });

    req.session.save(()=>res.json({ok:true, sso:token}));
  }catch(e){ console.error("webapp-auth",e); res.status(500).json({ok:false}); }
});

// SSO: внешний браузер приходит сюда с ?token=...
app.get("/sso", async (req,res)=>{
  try{
    const t = String(req.query.token||"");
    if(!t) return res.status(400).send("Bad token");
    const rec = (await tokens.find({ token:t }))[0];
    if(!rec) return res.status(400).send("Token not found");
    if(rec.used) return res.status(410).send("Token used");
    if((rec.exp||0) < Date.now()) return res.status(410).send("Token expired");

    // логиним и помечаем токен использованным
    req.session.user = rec.user;
    await tokens.update({ token:t }, { $set:{ used:true, used_at:Date.now() } });

    req.session.save(()=>res.redirect("/"));
  }catch(e){ console.error("sso",e); res.status(500).send("SSO error"); }
});

// API/прочее
app.get("/api/me",(req,res)=>{ if(!req.session.user) return res.status(401).json({ok:false}); res.json({ok:true,user:req.session.user}); });
app.post("/logout",(req,res)=>{ try{ req.session.destroy(()=>res.json({ok:true})) }catch{ res.json({ok:true}) }});
app.get("/logout",(req,res)=>{ try{ req.session.destroy(()=>res.redirect("/")) }catch{ res.redirect("/") }});

app.get("/admin", async (req,res)=>{
  if(!ADMIN_PASS || req.query.pass!==ADMIN_PASS) return res.status(401).send("Unauthorized");
  const all=await logins.find({}); const rows=all.sort((a,b)=>(b.ts||0)-(a.ts||0)).slice(0,200);
  const html=`<!doctype html><html><head><meta charset="utf-8"><title>Admin</title>
  <style>body{font:14px system-ui;background:#0f1115;color:#e6e6e6;margin:24px}table{border-collapse:collapse;width:100%}
  th,td{border:1px solid #2a2d36;padding:8px}th{background:#151821}.small{color:#9aa0a6;font-size:12px}</style></head><body>
  <h2>Последние логины (${rows.length})</h2><table><tr><th>Время</th><th>ID</th><th>Источник</th><th>IP</th><th>User-Agent</th></tr>
  ${rows.map(r=>{const d=new Date(r.ts).toISOString().replace("T"," ").slice(0,19); return `<tr><td class="small">${d}</td><td><code>${r.telegram_id}</code></td><td>${r.source}</td><td>${r.ip||"—"}</td><td class="small">${(r.user_agent||"").slice(0,180)}</td></tr>`}).join("")}
  </table></body></html>`;
  res.send(html);
});

// Вебхук
app.get("/bot/set-webhook", async (req,res)=>{
  if(!ADMIN_PASS || req.query.pass!==ADMIN_PASS) return res.status(401).send("Unauthorized");
  if(!PUBLIC_URL) return res.status(400).send("PUBLIC_URL not set");
  const hook = `${PUBLIC_URL.replace(/\/$/,"")}/bot/webhook?secret=${encodeURIComponent(WEBHOOK_SECRET)}`;
  const r=await safeFetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`,{
    method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ url:hook, allowed_updates:["message"] })
  });
  const j=r && await r.json();
  res.json({ok:true,result:j});
});

app.post("/bot/webhook", async (req,res)=>{
  try{
    if(req.query.secret!==WEBHOOK_SECRET) return res.status(401).json({ok:false});
    const up=req.body||{}; const msg=up.message; if(!msg?.chat) return res.json({ok:true});
    const chatId=msg.chat.id; const text=(msg.text||"").trim();
    if(text==="/start" || text.startsWith("/start ")){
      const webAppUrl = `${PUBLIC_URL.replace(/\/$/,"")}/webapp.html?to=${encodeURIComponent(AFTER_LOGIN_URL)}`;
      await tgSend(chatId,{ text:"Нажми кнопку, чтобы открыть приложение:", reply_markup:{ inline_keyboard:[[ {text:"Открыть приложение", web_app:{ url:webAppUrl } } ]] } });
    }
    res.json({ok:true});
  }catch(e){ console.error("webhook",e); res.json({ok:true}); }
});

process.on("unhandledRejection",e=>console.error("unhandledRejection",e));
process.on("uncaughtException",e=>console.error("uncaughtException",e));

app.listen(PORT,()=>console.log(`Server on 0.0.0.0:${PORT}`));
