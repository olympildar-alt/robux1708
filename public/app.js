async function refreshMe() {
  try {
    const res = await fetch("/api/me", { credentials: "include" });
    if (!res.ok) throw new Error("not ok");
    const data = await res.json();
    if (data.ok) {
      const me = data.user || {};
      const el = document.getElementById("me");
      el.innerHTML = `
        <div class="me">
          ${me.photo_url ? `<img src="${me.photo_url}" alt="avatar">` : ""}
          <div>
            <div><b>${me.first_name || ""}</b> ${me.username ? "@" + me.username : ""}</div>
            <div class="muted small">ID: ${me.id}</div>
          </div>
        </div>`;
      document.getElementById("me-card").hidden = false;
    } else {
      document.getElementById("me-card").hidden = true;
    }
  } catch {
    document.getElementById("me-card").hidden = true;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Кнопка "Открыть бота"
  const link = document.getElementById("open-bot");
  if (window.BOT_USERNAME) {
    link.href = `https://t.me/${window.BOT_USERNAME}`;
  } else {
    link.href = "https://t.me/";
  }

  // Выход
  document.getElementById("logout")?.addEventListener("click", async () => {
    await fetch("/logout", { method: "POST", credentials: "include" });
    location.reload();
  });

  refreshMe();
});
