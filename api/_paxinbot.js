'use strict';

const crypto = require('node:crypto');

function config() {
  const url = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const key = String(process.env.SUPABASE_PUBLISHABLE_KEY || '');
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url) || !key.startsWith('sb_publishable_')) throw new Error('Configuração Supabase ausente no ambiente da Vercel.');
  return { url, key };
}
function json(res, status, body, headers = {}) { res.status(status).set({ 'cache-control': 'no-store', ...headers }).json(body); }
function cookies(req) { return Object.fromEntries(String(req.headers.cookie || '').split(';').map(v => v.trim().split(/=(.*)/s)).filter(([k]) => k).map(([k, v]) => [k, decodeURIComponent(v || '')])); }
function secure(req) { return process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https'); }
function sessionCookies(req, accessToken, refreshToken, maxAge = 60 * 60 * 24 * 30) {
  const suffix = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure(req) ? '; Secure' : ''}`;
  return [`paxinbot_access=${encodeURIComponent(accessToken || '')}; ${suffix}`, `paxinbot_refresh=${encodeURIComponent(refreshToken || '')}; ${suffix}`];
}
function clearSession(req) { return sessionCookies(req, '', '', 0); }
async function upstream(path, options = {}) {
  const { url, key } = config();
  const response = await fetch(`${url}${path}`, { method: options.method || 'GET', headers: { apikey: key, 'content-type': 'application/json', ...(options.headers || {}) }, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  let payload = null; try { payload = await response.json(); } catch {}
  return { response, payload };
}
async function readBody(req) { if (req.body && typeof req.body === 'object') return req.body; const chunks = []; for await (const chunk of req) chunks.push(chunk); try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { return {}; } }
async function userFromAccess(access) {
  if (!access) return null;
  const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${access}` } });
  return response.ok ? payload : null;
}
async function refreshSession(refresh) {
  if (!refresh) return null;
  const { response, payload } = await upstream('/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: refresh } });
  return response.ok ? payload : null;
}
async function browserSession(req, res) {
  const jar = cookies(req); let access = jar.paxinbot_access; let user = await userFromAccess(access);
  if (user) return { user, access };
  const refreshed = await refreshSession(jar.paxinbot_refresh);
  if (!refreshed) return null;
  access = refreshed.access_token; user = await userFromAccess(access); if (!user) return null;
  res.setHeader('Set-Cookie', sessionCookies(req, refreshed.access_token, refreshed.refresh_token));
  return { user, access };
}
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function publicOrigin(req) { return String(process.env.PUBLIC_SITE_URL || `${secure(req) ? 'https' : 'http'}://${req.headers.host || 'localhost'}`).replace(/\/$/, ''); }
module.exports = { json, cookies, sessionCookies, clearSession, upstream, readBody, browserSession, sha256, publicOrigin };
