// server.js — Telegram Login Widget + Telegram WebApp, сессии, уведомления админу и админ-таблица (NeDB)

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

// В Node 18+ fetch глобальный; ниже подключите node-fetch@2 при необходимости
const fetchFn = globalThis.fetch || require("node-fetch");

const app = express();
const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN || "";
const ADMIN_ID = process.env.ADMIN_ID || "";
const ADMIN_PASS = process.env.ADMIN_PASS || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "supersecret";
const NOTIFY_COOLDOWN_MIN = Number(process.env.NOTIFY_COOLDOWN_MIN || 5); // анти-спам уведомлений
const WEBAPP_NOTIFY = Number(process.env.WEBAPP_NOTIFY ?? 1); // уведомлять ли про входы из WebApp

if (!BOT_TOKEN) {
  console.error("❌ BOT_TOKEN не задан в .env");
  process.exit(1);
}

// --- БД (NeDB) --------------------------------------------------------------
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const users = Datastore.create({
  filename: path.join(dataDir, "users.db"),
  autoload: true,
});

const logins = Datastore.create({
  filename: path.join(dataDir, "logins.db"),
  autoload: true,
});

// --- Утилиты ----------------------------------------------------------------
const FIVE_MIN = 300;

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
  } catch {
    return false;
  }
}

// Проверка Telegram Login Widget (redirect с хэшем)
function verifyLoginWidget(query) {
  const data = { ...query };
  const { hash } = data;
  if (!hash) return null;

  delete data.hash;

  const checkString = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join("\n");

  // secret = sha256(bot_token)
  const secret = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const expected = crypto
    .createHmac("sha256", secret)
    .update(checkString)
    .digest("hex");

  if (!timingSafeEq(hash, expected)) return null;

  const nowSec = Math.floor(Date.now() / 1000);
  const authDate = Number(query.auth_date || 0);
  if (!(authDate > 0 && nowSec - authDate < FIVE_MIN)) return null;

  // Нормализация пользователя
  return {
    telegram_id: String(query.id || ""),
    username: query.username || null,
    first_name: query.first_name || null,
    last_name: query.last_name || null,
    photo_url: query.photo_url || null,
  };
}

// Проверка Telegram WebApp initData
function parseInitData(initDataStr) {
  const params = {};
  for (const kv of String(initDataStr).split("&")) {
    const [k, v] = kv.split("=");
    if (!k) continue;
    params[decodeURIComponent(k)] = decodeURIComponent(v || "");
  }
  // user в initData — JSON
  if (params.user) {
    try {
      params.user = JSON.parse(params.user);
    } catch {
      // ignore
    }
  }
  return params;
}

function verifyWebApp(initDataStr) {
  if (!initDataStr) return null;
  const params = parseInitData(initDataStr);
  const hash = params.hash;
  if (!hash) return null;

  const sorted = Object.keys(params)
    .filter((k) => k !== "hash")
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("\n");

  // secret = HMAC_SHA256(key="WebAppData", message=BOT_TOKEN)
  const secret = crypto.createHmac("sha256", "WebAppData").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256", secret).update(sorted).digest("hex");
  if (!timingSafeEq(hash, expected)) return null;

  const nowSec = Math.floor(Date.now() / 1000);
  const authDate = Number(params.auth_date || 0);
  if (!(authDate > 0 && nowSec - authDate < FIVE_MIN)) return null;

  const u = params.user || {};
  return {
    telegram_id: String(u.id || ""),
    username: u.username || null,
    first_name: u.first_name || null,
    last_name: u.last_name || null,
    photo_url: u.photo_url || null,
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
    console.error("fetch error", e);
    return null;
  }
}

async function notifyAdmin(text) {
  if (!ADMIN_ID) return;
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  await safeFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: ADMIN_ID,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
    }),
  });
}

async function completeLogin(req, source, user) {
  // upsert пользователя
  await users.update(
    { telegram_id: user.telegram_id },
    { $set: { ...user, updated_at: Date.now() } },
    { upsert: true }
  );

  const loginDoc = {
    telegram_id: user.telegram_id,
    source,                        // "widget" | "webapp"
    ts: Date.now(),
    ip: getIp(req),
    user_agent: req.headers["user-agent"] || "",
  };
  await logins.insert(loginDoc);

  // анти-спам уведомлений админу
  const lastArr = await logins
    .cfind({ telegram_id: user.telegram_id })
    .sort({ ts: -1 })
    .limit(2)
    .exec();

  const prev = lastArr[1]; // предыдущий вход
  const cooldown = NOTIFY_COOLDOWN_MIN * 60 * 1000;
  const shouldNotify =
    !prev || Date.now() - (prev?.ts || 0) > cooldown;

  if (shouldNotify && (source !== "webapp" || WEBAPP_NOTIFY)) {
    await notifyAdmin(
      `👤 <b>${user.first_name || ""}${user.username ? " @" + user.username : ""}</b>\n` +
      `ID: <code>${user.telegram_id}</code>\n` +
      `Источник: ${source}\n` +
      `IP: <code>${loginDoc.ip || "-"}</code>`
    );
  }

  // сохранить в сессию
  req.session.user = {
    id: user.telegram_id,
    username: user.username,
    first_name: user.first_name,
    last_name: user.last_name,
    photo_url: user.photo_url,
  };
}

// --- Middleware -------------------------------------------------------------
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false, // проще для виджета/iframe
    crossOriginEmbedderPolicy: false,
  })
);
app.use(morgan("tiny"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "none",
      secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 дней
    },
  })
);

// rate-limit на входы
const loginLimiter = rateLimit({ windowMs: 60_000, max: 30 });
app.use("/webapp-auth", loginLimiter);
app.use("/auth/telegram-redirect", loginLimiter);

// статика
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h", etag: true }));

// --- Маршруты ---------------------------------------------------------------

// Login Widget redirect ?id=...&hash=...
app.get("/auth/telegram-redirect", async (req, res) => {
  const user = verifyLoginWidget(req.query);
  if (!user) return res.status(401).send("Auth failed");

  await completeLogin(req, "widget", user);
  req.session.save(() => res.redirect("/"));
});

// WebApp — POST { initData }
app.post("/webapp-auth", async (req, res) => {
  const user = verifyWebApp(req.body.initData);
  if (!user || !user.telegram_id) return res.status(401).json({ ok: false });

  await completeLogin(req, "webapp", user);
  req.session.save(() => res.json({ ok: true }));
});

// Профиль
app.get("/api/me", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user: req.session.user });
});

// Выход
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Примитивная админка со списком логинов
app.get("/admin", async (req, res) => {
  if (!ADMIN_PASS || req.query.pass !== ADMIN_PASS) {
    return res.status(401).send("Unauthorized");
  }
  const rows = await logins.cfind({}).sort({ ts: -1 }).limit(200).exec();

  const html = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8" />
<title>Admin — logins</title>
<style>
body{font:14px system-ui, -apple-system, Segoe UI, Roboto, Arial; margin:24px; color:#e6e6e6; background:#0f1115}
table{border-collapse:collapse; width:100%}
th,td{border:1px solid #2a2d36; padding:8px 10px; text-align:left}
th{background:#151821}
.small{color:#9aa0a6; font-size:12px}
</style>
</head>
<body>
<h2>Последние логины (${rows.length})</h2>
<table>
<tr><th>Время</th><th>ID</th><th>Источник</th><th>IP</th><th>User-Agent</th></tr>
${rows
  .map((r) => {
    const d = new Date(r.ts).toISOString().replace("T", " ").slice(0, 19);
    return `<tr>
      <td class="small">${d}</td>
      <td><code>${r.telegram_id}</code></td>
      <td>${r.source}</td>
      <td>${r.ip || "—"}</td>
      <td class="small">${(r.user_agent || "").slice(0, 180)}</td>
    </tr>`;
  })
  .join("")}
</table>
</body>
</html>`;
  res.send(html);
});

// Healthcheck
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// Старт
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
