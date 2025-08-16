async function refreshMe() {
  try {
    const r = await fetch('/api/me');
    const { user } = await r.json();

    const box = document.getElementById('loginBox');
    const me = document.getElementById('me');

    if (user) {
      box.classList.add('hidden');
      me.classList.remove('hidden');
      document.getElementById('name').textContent = user.first_name || 'Пользователь';
      document.getElementById('username').textContent = user.username ? '@' + user.username : '';
      const avatar = document.getElementById('avatar');
      avatar.src = user.photo_url || 'https://avatars.githubusercontent.com/u/583231?v=4';
    } else {
      me.classList.add('hidden');
      box.classList.remove('hidden');
    }
  } catch (e) {
    console.error(e);
  }
}

window.onTelegramAuth = async function(user) {
  try {
    const r = await fetch('/auth/telegram', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(user)
    });
    const data = await r.json();
    if (!data.ok) {
      alert('Ошибка авторизации: ' + (data.error || 'unknown'));
      return;
    }
    await refreshMe();
  } catch (e) {
    console.error(e);
    alert('Сеть/сервер недоступен.');
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const w = document.querySelector('script[src*="telegram-widget.js"]');
  if (w && window.BOT_USERNAME) {
    w.setAttribute('data-telegram-login', window.BOT_USERNAME);
  }

  const logoutBtn = document.getElementById('logoutBtn');
  logoutBtn?.addEventListener('click', () => {
    location.href = '/logout';
  });

  refreshMe();
});
