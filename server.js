const http = require('node:http');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

try {
  const envFile = fsSync.readFileSync(path.join(__dirname, '.env'), 'utf8');
  for (const line of envFile.split(/\r?\n/)) {
    const entry = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (entry && process.env[entry[1]] === undefined) process.env[entry[1]] = entry[2].replace(/^(["'])(.*)\1$/, '$2');
  }
} catch (error) { if (error.code !== 'ENOENT') throw error; }

const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const USERS = path.join(DATA, 'users.json');
const PORT = Number(process.env.PORT || 3000);
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SECRET = process.env.SESSION_SECRET || 'development-only-change-me-before-deploying';
const COOKIE = 'auth_session';

const b64 = (value) => Buffer.from(value).toString('base64url');
const sign = (value) => crypto.createHmac('sha256', SECRET).update(value).digest('base64url');
const safeEqual = (a, b) => {
  const aa = Buffer.from(a || ''); const bb = Buffer.from(b || '');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
function cookieOptions(maxAge) {
  return `${COOKIE}=${maxAge ? 'TOKEN' : ''}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${APP_URL.startsWith('https:') ? '; Secure' : ''}`;
}
function setSession(res, user) {
  const payload = b64(JSON.stringify({ id: user.id, exp: Date.now() + 7 * 864e5 }));
  res.setHeader('Set-Cookie', cookieOptions(604800).replace('TOKEN', `${payload}.${sign(payload)}`));
}
function clearSession(res) { res.setHeader('Set-Cookie', cookieOptions(0)); }
function readSession(req) {
  const token = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !safeEqual(signature, sign(payload))) return null;
  try { const session = JSON.parse(Buffer.from(payload, 'base64url').toString()); return session.exp > Date.now() ? session : null; } catch { return null; }
}
async function users() { await fs.mkdir(DATA, { recursive: true }); try { return JSON.parse(await fs.readFile(USERS, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return []; throw error; } }
async function saveUsers(list) { await fs.mkdir(DATA, { recursive: true }); await fs.writeFile(USERS, JSON.stringify(list, null, 2), { mode: 0o600 }); }
function json(res, status, body, extra = {}) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra }); res.end(JSON.stringify(body)); }
async function body(req) {
  let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 16_384) throw Object.assign(new Error('Request too large'), { status: 413 }); }
  try { return JSON.parse(raw || '{}'); } catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, provider: user.provider }; }
async function getCurrentUser(req) { const session = readSession(req); if (!session) return null; return (await users()).find((user) => user.id === session.id) || null; }
function validEmail(value) { return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(`${salt}:${key.toString('hex')}`)));
}
async function staticFile(pathname, res) {
  const file = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1));
  if (file.includes('..') || file.includes('\\')) return json(res, 404, { error: 'Not found' });
  const full = path.join(ROOT, 'public', file);
  try {
    const content = await fs.readFile(full);
    const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
    res.writeHead(200, { 'Content-Type': types[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" }); res.end(content);
  } catch { json(res, 404, { error: 'Not found' }); }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, APP_URL);
  try {
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = await getCurrentUser(req); return json(res, 200, { user: user ? publicUser(user) : null });
    }
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const { name, email, password } = await body(req);
      if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60) return json(res, 400, { error: 'Имя должно содержать от 2 до 60 символов.' });
      if (!validEmail(email)) return json(res, 400, { error: 'Введите корректный адрес почты.' });
      if (typeof password !== 'string' || password.length < 8 || password.length > 128) return json(res, 400, { error: 'Пароль должен содержать от 8 до 128 символов.' });
      const list = await users(); const normalized = email.trim().toLowerCase();
      if (list.some((user) => user.email === normalized)) return json(res, 409, { error: 'Аккаунт с такой почтой уже существует.' });
      const user = { id: crypto.randomUUID(), name: name.trim(), email: normalized, provider: 'email', passwordHash: await passwordHash(password), createdAt: new Date().toISOString() };
      list.push(user); await saveUsers(list); setSession(res, user); return json(res, 201, { user: publicUser(user) });
    }
    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { email, password } = await body(req);
      if (!validEmail(email) || typeof password !== 'string') return json(res, 400, { error: 'Проверьте почту и пароль.' });
      const user = (await users()).find((item) => item.email === email.trim().toLowerCase() && item.passwordHash);
      let match = false;
      if (user) { const [salt, key] = user.passwordHash.split(':'); match = safeEqual(await passwordHash(password, salt), `${salt}:${key}`); }
      if (!match) return json(res, 401, { error: 'Неверная почта или пароль.' });
      setSession(res, user); return json(res, 200, { user: publicUser(user) });
    }
    if (req.method === 'POST' && url.pathname === '/api/logout') { clearSession(res); return json(res, 200, { ok: true }); }
    if (req.method === 'GET') return await staticFile(url.pathname, res);
    return json(res, 404, { error: 'Not found' });
  } catch (error) { console.error(error); return json(res, error.status || 500, { error: error.status ? error.message : 'Внутренняя ошибка сервера.' }); }
});

server.listen(PORT, () => console.log(`Auth Starter running at ${APP_URL}`));
