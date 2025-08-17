// server.js — Telegram Login Widget + WebApp + сессии + уведомления + админка + вебхук
// Совместимость с nedb-promises без cfind(): сортировка/лимиты через массивы

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

// --- стартовые проверки + лог
const startupIssues = [];
if (!BOT_TOKEN) startupIssues.push("BOT_TOKEN is missing");
if (!PUBLIC_URL || !PUBLIC_URL.startsWith("https://")) startupIssues.push("PUBLIC_URL must be https");
if (!SESSION_SECRET) startupIssues.push("SESSION_SECRET is missing");
if (!ADMIN_PASS) startupIssues.push("ADMIN_PASS is missing");

console.log("[startup] env summary:", {
  hasBOT_TOKEN: !!BOT_TOKEN,
  hasADMIN_ID: !!ADMIN_ID,
  hasADMIN_PASS: !!ADMIN_PASS,
  hasSESSION_SECRET: !!SESSION_SECRET,
  PUBLIC_URL,
  PORT,
});
if (startupIssues.length) console.warn("[startup] issues:", startupIssues);

// --- БД
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const users = Datastore.create({ filename: path.join(dataDir, "users.db"), autoload: true });
const logins = Datastore.create({ filename: path.join(dataDir, "logins.db"), autoload: true });

// --- утилиты
const TEN_MIN = 600;

function getIp(req) {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) return String(xfwd).split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "";
}
function timingSafeEq(aHex, bHex) {
  try {
    const a = Buffer.from(aHex, "hex");
    const b = Buffer.from(bHex, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

// Проверка Login Widget
function verifyLoginWidget(query) {
  const data = { ...query };
  const { hash } = data;
  if (!hash) return null;
  delete data.hash;

  const checkString = Object.keys(data).sort().map(k => `${k}=${data[k]}`).join("\n");
  const secret = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256", secret).update(checkString).digest("hex");
  if (!timingSafeEq(hash, expected)) return null;

  const nowSec = Math.floor(Date.now()/1000);
  const authDate = Number(query.auth_date || 0);
  if (!(authDate > 0 && nowSec - authDate < TEN_MIN)) return null;

  return {
    telegram_id: String(query.id || ""),
    username: query.username || null,
    first_name: query.first_name || null,
    last_name: query.last_name || null,
    photo_url: query.photo_url || null,
  };
}

// Проверка WebApp initData — строго по докам
function verifyWebApp(initDataStr) {
  if (!initDataStr) return { ok:false, reason:"no_initData" };

  const usp = new URLSearchParams(initDataStr);
  const entries = [];
  for (const [k, v] of usp.entries()) {
    if (k === "hash") continue;
    entries.push([k, v]);
  }
  entries.sort(([a],[b]) => a.localeCompare(b));
  const dataCheckString = entries.map(([k,v]) => `${k}=${v}`).join("\n");

  const hash = usp.get("hash");
  if (!hash) return { ok:false, reason:"no_hash" };

  const secret = crypto.createHmac("sha256", "WebAppData").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256", secret).update(dataCheckString).digest("hex");
  if (!timingSafeEq(hash, expected)) return { ok:false, reason:"hash_mismatch" };

  const nowSec = Math.floor(Date.now()/1000);
  const authDate = Number(usp.get("auth_date") || 0);
  if (!(authDate > 0 && nowSec - authDate < TEN_MIN)) return { ok:false, reason:"stale_auth_date" };

  let user = {};
  try { user = JSON.parse(usp.get("user") || "{}"); } catch { user = {}; }

  return {
    ok:true,
    user: {
      telegram_id: String(user.id || ""),
      username: user.username || null,
      first_name: user.first_name || null,
      last_name: user.last_name || null,
      photo_url: user.photo_url || null,
    }
  };
}

async function safeFetch(url, init = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, { ...init, signal: ctrl.signal });
    clearTimeout(t);
    return res;
  } catch (e) {
    clearTimeout(t);
    console.error("fetch error", e?.message || e);
    return null;
  }
}
async function tgSend(chatId, payload) {
  try {
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    return await safeFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, ...payload }),
    });
  } catch (e) {
    console.error("tgSend error", e?.message || e);
    return null;
  }
}
async function notifyAdmin(text) {
  if (!ADMIN_ID) return;
  await tgSend(ADMIN_ID, { text, parse_mode: "HTML", disable_web_page_preview: true });
}

async function completeLogin(req, source, user) {
  await users.update(
    { telegram_id: user.telegram_id },
    { $set: { ...user, updated_at: Date.now() } },
    { upsert: true }
  );

  const loginDoc = {
    telegram_id: user.telegram_id,
    source,
    ts: Date.now(),
    ip: getIp(req),
    user_agent: req.headers["user-agent"] || "",
  };
  await logins.insert(loginDoc);

  // >>> Без cfind: берём все, сортируем в памяти и берём предыдущий
  const arr = await logins.find({ telegram_id: user.telegram_id });
  const sorted = arr.sort((a,b) => (b.ts||0) - (a.ts||0));
  const prev = sorted[1]; // предыдущая запись

  const cooldown = NOTIFY_COOLDOWN_MIN * 60 * 1000;
  const shouldNotify = !prev || Date.now() - (prev?.ts || 0) > cooldown;

  if (shouldNotify && (source !== "webapp" || WEBAPP_NOTIFY)) {
    await notifyAdmin(
      `👤 <b>${user.first_name || ""}${user.username ? " @" + user.username : ""}</b>\n` +
      `ID: <code>${user.telegram_id}</code>\n` +
      `Источник: ${source}\n` +
      `IP: <code>${loginDoc.ip || "-"}</code>`
    );
  }

  req.session.user = {
    id: user.telegram_id,
    username: user.username,
    first_name: user.first_name,
    last_name: user.last_name,
    photo_url: user.photo_url,
  };
}

// --- middleware
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(morgan("tiny"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "none", secure: true, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

const loginLimiter = rateLimit({ windowMs: 60_000, max: 30 });
app.use("/webapp-auth", loginLimiter);
app.use("/auth/telegram-redirect", loginLimiter);

// статика
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h", etag: true }));

// --- routes
app.get("/auth/telegram-redirect", async (req, res) => {
  try {
    const user = verifyLoginWidget(req.query);
    if (!user) return res.status(401).send("Auth failed");
    await completeLogin(req, "widget", user);
    req.session.save(() => res.redirect("/"));
  } catch (e) {
    console.error("redirect auth error:", e?.message || e);
    res.status(500).send("Internal error");
  }
});

app.post("/webapp-auth", async (req, res) => {
  try {
    const result = verifyWebApp(req.body.initData);
    if (DEBUG_AUTH) console.log("[auth:webapp]", result.ok ? "ok" : `fail:${result.reason}`);
    if (!result.ok || !result.user?.telegram_id) return res.status(401).json({ ok: false });

    await completeLogin(req, "webapp", result.user);
    req.session.save(() => res.json({ ok: true }));
  } catch (e) {
    console.error("webapp-auth error:", e?.message || e);
    res.status(500).json({ ok: false });
  }
});

app.get("/api/me", (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok: false });
    res.json({ ok: true, user: req.session.user });
  } catch {
    res.status(500).json({ ok: false });
  }
});

app.post("/logout", (req, res) => { try { req.session.destroy(() => res.json({ ok: true })); } catch { res.json({ ok: true }); } });
app.get("/logout", (req, res) => { try { req.session.destroy(() => res.redirect("/")); } catch { res.redirect("/"); } });

// admin (без cfind)
app.get("/admin", async (req, res) => {
  try {
    if (!ADMIN_PASS || req.query.pass !== ADMIN_PASS) return res.status(401).send("Unauthorized");
    const all = await logins.find({});
    const rows = all.sort((a,b) => (b.ts||0) - (a.ts||0)).slice(0, 200);

    const html = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"/><title>Admin — logins</title>
<style>body{font:14px system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:24px;color:#e6e6e6;background:#0f1115}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #2a2d36;padding:8px 10px;text-align:left}
th{background:#151821}.small{color:#9aa0a6;font-size:12px}</style></head><body>
<h2>Последние логины (${rows.length})</h2><table>
<tr><th>Время</th><th>ID</th><th>Источник</th><th>IP</th><th>User-Agent</th></tr>
${rows.map(r=>{
  const d=new Date(r.ts).toISOString().replace("T"," ").slice(0,19);
  return `<tr><td class="small">${d}</td><td><code>${r.telegram_id}</code></td><td>${r.source}</td><td>${r.ip||"—"}</td><td class="small">${(r.user_agent||"").slice(0,180)}</td></tr>`
}).join("")}
</table></body></html>`;
    res.send(html);
  } catch (e) {
    console.error("admin error:", e?.message || e);
    res.status(500).send("Admin error");
  }
});

// health + debug
app.get("/ping", (_req, res) => res.type("text").send("pong"));
app.get("/healthz", (_req, res) => res.json({ ok: true }));
app.get("/debug", (req, res) => {
  if (!ADMIN_PASS || req.query.pass !== ADMIN_PASS) return res.status(401).send("Unauthorized");
  res.json({
    ok: true,
    env: {
      BOT_TOKEN: !!BOT_TOKEN,
      ADMIN_ID: !!ADMIN_ID,
      ADMIN_PASS: !!ADMIN_PASS,
      SESSION_SECRET: !!SESSION_SECRET,
      PUBLIC_URL,
      WEBHOOK_SECRET: !!WEBHOOK_SECRET,
      PORT: PORT,
      DEBUG_AUTH: !!DEBUG_AUTH
    },
    notes: startupIssues
  });
});

// webhook install
app.get("/bot/set-webhook", async (req, res) => {
  try {
    if (!ADMIN_PASS || req.query.pass !== ADMIN_PASS) return res.status(401).send("Unauthorized");
    if (!PUBLIC_URL) return res.status(400).send("PUBLIC_URL not set");
    const hookUrl = `${PUBLIC_URL.replace(/\/$/,"")}/bot/webhook?secret=${encodeURIComponent(WEBHOOK_SECRET)}`;
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`;
    const r = await safeFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: hookUrl, allowed_updates: ["message"] })
    });
    const j = r && await r.json();
    res.json({ ok: true, result: j });
  } catch (e) {
    console.error("set-webhook error:", e?.message || e);
    res.status(500).json({ ok: false });
  }
});

// webhook — /start с INLINE web_app
app.post("/bot/webhook", async (req, res) => {
  try {
    if (req.query.secret !== WEBHOOK_SECRET) return res.status(401).json({ ok: false });
    const update = req.body || {};
    const msg = update.message;
    if (!msg || !msg.chat) return res.json({ ok: true });

    const chatId = msg.chat.id;
    const text = (msg.text || "").trim();

    if (text === "/start" || text.startsWith("/start ")) {
      const webAppUrl = `${PUBLIC_URL.replace(/\/$/,"")}/webapp.html`;
      await tgSend(chatId, {
        text: "Нажми кнопку, чтобы открыть приложение:",
        reply_markup: { inline_keyboard: [[ { text: "Открыть приложение", web_app: { url: webAppUrl } } ]] }
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("webhook error:", e?.message || e);
    res.json({ ok: true }); // не ретраим
  }
});

// ловушки — логируем, но НЕ падаем
process.on("unhandledRejection", (e) => { console.error("unhandledRejection", e); });
process.on("uncaughtException", (e) => { console.error("uncaughtException", e); });

app.listen(PORT, () => {
  console.log(`Server running on 0.0.0.0:${PORT}`);
});
