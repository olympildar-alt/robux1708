function qs(id){ return document.getElementById(id); }

function injectTelegramLoginWidget(){
  const container = qs("tg-widget");
  container.innerHTML = "";
  if(!window.BOT_USERNAME){
    container.innerHTML = `<div class="warn">Укажите BOT_USERNAME в index.html</div>`;
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

async function getMe(){
  try{
    const r = await fetch("/api/me",{ credentials:"include" });
    if(!r.ok) return null; const j = await r.json();
    return j.ok ? j.user : null;
  }catch{ return null; }
}

function showAuthedUI(user){
  qs("auth").hidden = true;
  qs("app").hidden = false;
  qs("hello-text").textContent = `Вы вошли как ${user.first_name||""}${user.username?" @"+user.username:""} (ID: ${user.id}).`;
  const chip = qs("user-chip"), avatar=qs("user-avatar"), name=qs("user-name");
  if(user.photo_url){ avatar.src=user.photo_url; avatar.style.display="inline-block"; } else { avatar.style.display="none"; }
  name.textContent = user.first_name || user.username || ("ID "+user.id);
  chip.hidden = false;
}

function showLoginUI(){
  qs("app").hidden = true;
  qs("auth").hidden = false;
  injectTelegramLoginWidget();
}

document.addEventListener("DOMContentLoaded", async ()=>{
  const link = qs("open-bot");
  link.href = window.BOT_USERNAME ? `https://t.me/${window.BOT_USERNAME}` : "https://t.me/";

  qs("logout").addEventListener("click", async ()=>{
    await fetch("/logout",{ method:"POST", credentials:"include" });
    location.reload();
  });

  const user = await getMe();
  if(user) showAuthedUI(user); else showLoginUI();
});
