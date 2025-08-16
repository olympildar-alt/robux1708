// server.js — Telegram redirect + session + admin notify + /admin (NeDB, без нативных модулей)

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const session = require("express-session");
const Datastore = require("nedb-promises");
require("dotenv").config();

// В Node 18+ fetch глобальный; ниже подключите node-fetch@2 при необходимости
const fetchFn = globalThis.fetch || require("node-fetch");

const app = express();
const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN || "";
const ADMIN_ID = process.env.ADMIN_ID || "";              // chat id для уведомлений
const NOTIFY_COOLDOWN_MIN = Number(process.env.NOTIFY_COOLDOWN_MIN || 5);
const SESSION_SECRET = process.env.SESSION_SECRET || "supersecret";
const ADMIN_PASS = process.env.ADMIN_PASS || "";          // пароль для /admin

if (!BOT_TOKEN) {
  console.error("❌ BOT_TOKEN не задан в .env");
  process.exit(1);
}

// --- БД (файловая, без сборки)
const users = Datastore.create({ filename: path.join(__dirname, "data/users.db"), autoload: true });
const logins = Datastore.create({ filename: path.join(__dirname, "data/logins.db"), autoload: true });
users.ensureIndex({ fieldName: "telegram_id", unique: true }).catch(() => {});

app.set("trust proxy", true);

// --- Middleware
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production" // на HTTPS в проде
  }
}));

// --- Проверка подписи Telegram
function isTelegramAuthValid(data) {
  if (!data || !data.hash) return false;
  const { hash, ...rest } = data;
  const checkString = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join("\n");

  const secretKey = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const hmac = crypto.createHmac("sha256", secretKey).update(checkString).digest("hex");

  // защита по времени (24ч)
  const nowSec = Math.floor(Date.now() / 1000);
  const authDate = Number(rest.auth_date || 0);
  const fresh = authDate > 0 && nowSec - authDate < 86400;

  return hmac === hash && fresh;
}

// --- Уведомление админу
async function notifyAdmin(text) {
  if (!ADMIN_ID) return;
  try {
    const res = await fetchFn(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: ADMIN_ID, text, parse_mode: "HTML", disable_web_page_preview: true })
    });
    if (!res.ok) console.error("Telegram notify error:", await res.text());
  } catch (e) {
    console.error("Telegram notify exception:", e);
  }
}

const fmtDate = d => d.toISOString().replace("T", " ").slice(0, 19);

// --- Редирект от Telegram Login Widget
app.get("/auth/telegram-redirect", async (req, res) => {
  console.log("TG redirect query:", req.query);

  const data = req.query || {};
  if (!isTelegramAuthValid(data)) return res.status(401).send("Invalid Telegram auth");

  const user = {
    telegram_id: Number(data.id),
    first_name: data.first_name || "",
    last_name: data.last_name || "",
    username: data.username || "",
    photo_url: data.photo_url || ""
  };

  await users.update({ telegram_id: user.telegram_id }, { $set: user }, { upsert: true });

  const now = new Date();
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString();
  const ua = req.get("user-agent") || "";

  await logins.insert({
    telegram_id: user.telegram_id,
    ts: now.toISOString(),
    ip,
    user_agent: ua
  });

  req.session.user = {
    id: user.telegram_id,
    first_name: user.first_name,
    username: user.username,
    photo_url: user.photo_url
  };

  // антиспам уведомлений
  let shouldNotify = true;
  if (NOTIFY_COOLDOWN_MIN > 0) {
    const last = await logins.findOne({ telegram_id: user.telegram_id }).sort({ ts: -1 });
    if (last?.ts) {
      const diffMin = (now - new Date(last.ts)) / 60000;
      if (diffMin < NOTIFY_COOLDOWN_MIN) shouldNotify = false;
    }
  }

  if (shouldNotify) {
    const full = [user.first_name, user.last_name].filter(Boolean).join(" ");
    const handle = user.username ? `@${user.username}` : "—";
    const when = fmtDate(now);
    const msg = `🔔 <b>Новый вход через Telegram</b>\n` +
                `👤 <b>${full || "Без имени"}</b> (${handle})\n` +
                `🆔 <code>${user.telegram_id}</code>\n` +
                `🕒 ${when}\n` +
                `🌐 IP: <code>${ip}</code>`;
    await notifyAdmin(msg);
  }

  res.redirect("/"); // фронт подхватит сессию через /api/me
});

// --- API для фронта
app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});
app.get("/me", (req, res) => {
  res.json(req.session.user || null);
});

// --- Logout (GET и POST)
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// --- Простая админ-страница логов (по паролю ?pass=)
app.get("/admin", async (req, res) => {
  if (!ADMIN_PASS || req.query.pass !== ADMIN_PASS) return res.status(401).send("Unauthorized");
  const rows = await logins.find({}).sort({ ts: -1 }).limit(300);
  const ulist = await users.find({});
  const uMap = Object.fromEntries(ulist.map(u => [u.telegram_id, u]));

  const html = `
  <meta charset="utf-8"><title>Logins</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial;padding:16px}
    table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #e5e5e5;padding:6px;font-size:14px}
    th{background:#f8f8f8;text-align:left}
    code{background:#f4f4f4;padding:1px 4px;border-radius:4px}
  </style>
  <h2>Последние входы (${rows.length})</h2>
  <table>
    <tr><th>Время</th><th>Имя</th><th>Username</th><th>ID</th><th>IP</th><th>User-Agent</th></tr>
    ${rows.map(r=>{
      const u=uMap[r.telegram_id]||{};
      const name=[u.first_name,u.last_name].filter(Boolean).join(" ")||"—";
      const uname=u.username?("@"+u.username):"—";
      return `<tr>
        <td>${r.ts}</td>
        <td>${name}</td>
        <td>${uname}</td>
        <td><code>${r.telegram_id}</code></td>
        <td>${r.ip||"—"}</td>
        <td>${(r.user_agent||"").slice(0,160)}</td>
      </tr>`;
    }).join("")}
  </table>`;
  res.send(html);
});

// --- Healthcheck
app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
