const form = document.querySelector('#auth-form');
const nameField = document.querySelector('#name-field');
const title = document.querySelector('#form-title');
const subtitle = document.querySelector('#form-subtitle');
const submitLabel = document.querySelector('#submit-label');
const switchCopy = document.querySelector('#switch-copy');
const switchButton = document.querySelector('#switch-mode');
const step = document.querySelector('#step-label');
const errorBox = document.querySelector('#form-error');
const password = form.elements.password;
const toggle = document.querySelector('.password-toggle');
let mode = 'login';

function setMode(next) {
  mode = next;
  const register = mode === 'register';
  nameField.hidden = !register;
  form.elements.name.required = register;
  password.autocomplete = register ? 'new-password' : 'current-password';
  title.textContent = register ? 'Создай аккаунт' : 'С возвращением';
  subtitle.textContent = register ? 'Пара деталей — и ты внутри.' : 'Рады видеть тебя снова. Войди в аккаунт.';
  submitLabel.textContent = register ? 'Создать аккаунт' : 'Войти в аккаунт';
  step.textContent = register ? '02 — 02' : '01 — 02';
  switchCopy.firstChild.textContent = register ? 'Уже есть аккаунт? ' : 'Впервые здесь? ';
  switchButton.innerHTML = register ? 'Войти <span>↗</span>' : 'Создать аккаунт <span>↗</span>';
  errorBox.textContent = '';
}

switchButton.addEventListener('click', () => setMode(mode === 'login' ? 'register' : 'login'));
toggle.addEventListener('click', () => {
  const visible = password.type === 'password';
  password.type = visible ? 'text' : 'password';
  toggle.textContent = visible ? 'СКРЫТЬ' : 'ПОКАЗАТЬ';
  toggle.setAttribute('aria-label', visible ? 'Скрыть пароль' : 'Показать пароль');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.textContent = '';
  if (!form.reportValidity()) return;
  const button = form.querySelector('.submit-button');
  button.disabled = true;
  submitLabel.textContent = 'Секунду…';
  const payload = { email: form.elements.email.value, password: password.value };
  if (mode === 'register') payload.name = form.elements.name.value;
  try {
    const response = await fetch(`/api/${mode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Не удалось выполнить запрос.');
    showUser(result.user);
  } catch (error) {
    errorBox.textContent = error.message || 'Сервер недоступен. Попробуй ещё раз.';
    submitLabel.textContent = mode === 'register' ? 'Создать аккаунт' : 'Войти в аккаунт';
    button.disabled = false;
  }
});

function showUser(user) {
  document.querySelector('#auth-view').hidden = true;
  const panel = document.querySelector('#signed-in'); panel.hidden = false;
  document.querySelector('#account-name').textContent = user.name;
  document.querySelector('#account-email').textContent = user.email;
  document.querySelector('#account-avatar').textContent = (user.name || user.email).trim().charAt(0).toUpperCase();
  document.querySelector('#account-provider').textContent = user.provider;
  document.querySelector('#welcome-copy').textContent = `Добро пожаловать, ${user.name}. Твоя сессия защищена.`;
}

document.querySelector('#logout-button').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  location.href = '/';
});

const params = new URLSearchParams(location.search);
if (params.has('error')) {
  const error = params.get('error');
  errorBox.textContent = error === 'email' ? 'Провайдер не передал подтверждённую почту. Войди через почту и пароль.' : error.endsWith('-not-configured') ? `Вход через ${error.split('-')[0]} пока не настроен. Добавь ключи в .env.` : 'Не получилось войти через провайдера. Попробуй ещё раз.';
  history.replaceState({}, '', '/');
}
fetch('/api/me').then((response) => response.json()).then((result) => { if (result.user) showUser(result.user); }).catch(() => {});
