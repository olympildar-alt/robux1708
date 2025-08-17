function qs(id){ return document.getElementById(id); }

/** Динамически вставляем виджет Telegram только когда юзер не залогинен */
function injectTelegramLoginWidget(){
  const container = qs("tg-widget");
  container.innerHTML = "";
  if(!window.BOT_USERNAME || !window.BOT_USERNAME.trim()){
    container.innerHTML = `<div class="muted">Укажите имя бота в &lt;head&gt;: <code>window.BOT_USERNAME</code></div>`;
    return;
  }
  const s = document.createElement("script");
  s.async = true;
  s.src = "https://telegram.org/js/telegram-widget.js?22";
  s.setAttribute("data-telegram-login", window.BOT_USERNAME);
  s.setAttribute("data-size", "large");
  s.setAttribute("data-userpic", "false");
  s.setAttribute("data-request-access", "write");
  s.setAttribute("data-auth-url", "/auth/telegram-redirect");
  container.appendChild(s);
}

/** Получить текущего пользователя */
async function getMe(){
  try{
    const r = await fetch("/api/me", { credentials: "include" });
    if(!r.ok) return null;
    const j = await r.json();
    return j.ok ? j.user : null;
  }catch{
    return null;
  }
}

/** Показать UI после входа */
function showAuthedUI(user){
  // спрятать авторизацию, показать приложение
  qs("auth").hidden = true;
  qs("app").hidden = false;

  // приветствие
  qs("hello-text").textContent =
    `Вы вошли как ${user.first_name || ""}${user.username ? " @" + user.username : ""} (ID: ${user.id}).`;

  // чип в хедере
  const chip = qs("user-chip");
  const avatar = qs("user-avatar");
  const name = qs("user-name");

  if (user.photo_url) {
    avatar.src = user.photo_url;
    avatar.style.display = "inline-block";
  } else {
    avatar.style.display = "none";
  }
  name.textContent = user.first_name || user.username || ("ID " + user.id);
  chip.hidden = false;
}

/** Показать экран входа */
function showLoginUI(){
  qs("app").hidden = true;
  qs("auth").hidden = false;
  injectTelegramLoginWidget();
}

/** Инициализация страницы */
document.addEventListener("DOMContentLoaded", async () => {
  // ссылка «Открыть бота»
  const link = qs("open-bot");
  link.href = window.BOT_USERNAME ? `https://t.me/${window.BOT_USERNAME}` : "https://t.me/";

  // выход
  qs("logout").addEventListener("click", async () => {
    await fetch("/logout", { method: "POST", credentials: "include" });
    location.reload();
  });

  // главное: переключаем экраны в зависимости от сессии
  const user = await getMe();
  if (user) showAuthedUI(user);
  else showLoginUI();
});
