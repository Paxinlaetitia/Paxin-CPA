'use strict';

const PaxinbotAuth = (() => {
  const baseUrl = location.protocol === 'file:' ? 'http://127.0.0.1:8787' : location.origin;
  const request = async (route, options = {}) => {
    const response = await fetch(`${baseUrl}${route}`, { method: options.method || 'GET', credentials: 'include', headers: { 'content-type': 'application/json', ...(options.headers || {}) }, body: options.body ? JSON.stringify(options.body) : undefined });
    let payload = null; try { payload = await response.json(); } catch {}
    if (!response.ok || payload?.ok === false) throw Object.assign(new Error(payload?.error || 'Não foi possível concluir a operação.'), { code: payload?.code, status: response.status });
    return payload;
  };
  return { baseUrl, request };
})();

let passkeySession = null;
let passkeyClient = null;

function setClientStatus(message, active = false) {
  const box = document.getElementById('auth-service-status'); if (!box) return;
  box.classList.toggle('is-active', active); box.querySelector('span').textContent = message;
}

function setAuthMode(mode) {
  const creating = mode === 'signup';
  document.getElementById('client-login-form').hidden = creating;
  document.getElementById('client-signup-form').hidden = !creating;
  document.querySelectorAll('.google-button, .passkey-button, .auth-divider').forEach(item => { item.hidden = creating; });
  document.querySelector('.auth-head h2').textContent = creating ? 'Crie sua conta' : 'Entre na sua conta';
  document.getElementById('auth-mode-copy').textContent = creating ? 'Crie uma conta para acompanhar acessos, dispositivos e compras.' : 'Use seu e-mail, Google ou uma passkey cadastrada.';
  document.getElementById('auth-switch').textContent = creating ? 'Já tem conta? Entrar' : 'Não tem conta? Criar agora';
}

function renderClientDashboard(payload) {
  const user = payload?.user; const entitlement = payload?.entitlement || {}; const email = String(user?.email || ''); const name = email ? email.split('@')[0] : 'Cliente';
  document.body.classList.toggle('client-authenticated', Boolean(user));
  document.getElementById('dashboard-initials').textContent = (name.slice(0, 2).toUpperCase() || 'PB');
  document.getElementById('dashboard-email').textContent = email || 'Entre para consultar';
  document.getElementById('dashboard-greeting').textContent = user ? `Olá, ${name}` : 'Entre na sua conta';
  document.getElementById('dashboard-access').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Vitalício' : 'Por tempo') : 'Sem acesso';
  document.getElementById('dashboard-access-state').textContent = entitlement.active ? 'Ativo' : user ? 'Aguardando liberação' : 'Aguardando login';
  const expires = entitlement.expiresAt ? new Intl.DateTimeFormat('pt-BR', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(entitlement.expiresAt)) : 'Não expira';
  document.getElementById('dashboard-expiry').textContent = entitlement.active ? expires : '—';
  document.getElementById('dashboard-expiry-state').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : 'Definido pelo acesso contratado') : 'Sem dados';
  document.getElementById('dashboard-devices').textContent = user ? 'Prontos' : 'Protegidos';
  document.getElementById('dashboard-devices-state').textContent = user ? 'Autorize pelo navegador' : 'Autorize depois do login';
  document.getElementById('client-logout').hidden = !user;
  const register = document.getElementById('passkey-register'); register.disabled = !passkeySession;
  document.getElementById('passkey-state').textContent = passkeySession ? 'DISPONÍVEL' : 'OPCIONAL';
  document.getElementById('passkey-copy').textContent = passkeySession ? 'Cadastre uma passkey neste dispositivo agora.' : user ? 'Para adicionar uma passkey, entre novamente com e-mail e senha.' : 'Entre para cadastrar uma passkey neste dispositivo.';
}

function setAccountView(view, moveFocus = false) {
  const target = document.querySelector(`[data-account-panel="${view}"]`);
  if (!target) return;
  document.querySelectorAll('[data-account-panel]').forEach(panel => {
    const active = panel === target;
    panel.hidden = !active;
    panel.classList.toggle('is-active', active);
  });
  document.querySelectorAll('[data-account-view]').forEach(button => {
    const active = button.dataset.accountView === view;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && moveFocus) button.focus();
  });
}

async function syncOwnerPanelLink(user) {
  const link = document.getElementById('owner-panel-link');
  if (!link) return;
  link.hidden = true;
  if (!user) return;
  try { await PaxinbotAuth.request('/api/admin?action=overview'); link.hidden = false; } catch {}
}

async function getPasskeyClient() {
  if (passkeyClient) return passkeyClient;
  const config = await PaxinbotAuth.request('/api/auth/config');
  const module = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.105.0/+esm');
  passkeyClient = module.createClient(config.url, config.key, { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false, experimental: { passkey: true } } });
  return passkeyClient;
}

async function bridgeSession(session) {
  if (!session?.access_token || !session?.refresh_token) throw new Error('A autenticação não retornou uma sessão válida.');
  await PaxinbotAuth.request('/api/auth/session', { method: 'POST', body: { accessToken: session.access_token, refreshToken: session.refresh_token } });
}

async function loginWithPasskey() {
  const button = document.getElementById('passkey-login'); if (!window.PublicKeyCredential) throw new Error('Este navegador não oferece suporte a passkeys.'); button.disabled = true;
  try { const client = await getPasskeyClient(); const { data, error } = await client.auth.signInWithPasskey(); if (error) throw error; await bridgeSession(data.session); const current = await PaxinbotAuth.request('/api/auth/me'); renderClientDashboard(current); setClientStatus('Conta conectada com passkey.', true); window.showToast?.('Login concluído.'); }
  finally { button.disabled = false; }
}

async function registerPasskey() {
  const button = document.getElementById('passkey-register'); if (!passkeySession) throw new Error('Entre com e-mail e senha para cadastrar uma passkey.'); if (!window.PublicKeyCredential) throw new Error('Este navegador não oferece suporte a passkeys.'); button.disabled = true;
  try { const client = await getPasskeyClient(); await client.auth.setSession({ access_token: passkeySession.accessToken, refresh_token: passkeySession.refreshToken }); const { error } = await client.auth.registerPasskey(); if (error) throw error; passkeySession = null; document.getElementById('passkey-state').textContent = 'CADASTRADA'; document.getElementById('passkey-copy').textContent = 'Esta conta agora pode entrar usando a passkey cadastrada.'; window.showToast?.('Passkey cadastrada com segurança.'); }
  finally { button.disabled = !passkeySession; }
}

async function initClientPage() {
  const form = document.getElementById('client-login-form'); if (!form) return; const submit = form.querySelector('[type="submit"]');
  try { const current = await PaxinbotAuth.request('/api/auth/me'); renderClientDashboard(current); await syncOwnerPanelLink(current.user); setClientStatus('Conta conectada ao serviço seguro.', true); } catch { renderClientDashboard(null); await syncOwnerPanelLink(null); setClientStatus('Entre com sua conta Paxinbot para continuar.'); }
  form.addEventListener('submit', async event => { event.preventDefault(); submit.disabled = true; try { const data = new FormData(form); const result = await PaxinbotAuth.request('/api/auth/login', { method: 'POST', body: { email: data.get('email'), password: data.get('password') } }); passkeySession = result.passkeySession || null; const current = await PaxinbotAuth.request('/api/auth/me'); renderClientDashboard(current); await syncOwnerPanelLink(current.user); setAccountView('overview'); setClientStatus('Conta conectada ao serviço seguro.', true); window.showToast?.('Login realizado.'); document.getElementById('client-password').value = ''; document.getElementById('client-dashboard')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (error) { setClientStatus(error.message || 'Não foi possível entrar.'); window.showToast?.(error.message || 'Não foi possível entrar.'); } finally { submit.disabled = false; } });
  document.getElementById('client-signup-form')?.addEventListener('submit', async event => { event.preventDefault(); const signup = event.currentTarget; const submitButton = signup.querySelector('[type="submit"]'); const data = new FormData(signup); if (data.get('password') !== data.get('passwordConfirm')) { window.showToast?.('As senhas precisam ser iguais.'); return; } submitButton.disabled = true; try { const result = await PaxinbotAuth.request('/api/auth/signup', { method: 'POST', body: { email: data.get('email'), password: data.get('password') } }); setClientStatus(result.message, true); signup.reset(); setAuthMode('login'); window.showToast?.('Conta criada. Confira seu e-mail.'); } catch (error) { setClientStatus(error.message || 'Não foi possível criar a conta.'); window.showToast?.(error.message || 'Não foi possível criar a conta.'); } finally { submitButton.disabled = false; } });
  document.getElementById('auth-switch')?.addEventListener('click', () => setAuthMode(document.getElementById('client-login-form').hidden ? 'login' : 'signup'));
  document.getElementById('passkey-login')?.addEventListener('click', () => loginWithPasskey().catch(error => { setClientStatus(error.message || 'Não foi possível usar a passkey.'); window.showToast?.(error.message || 'Não foi possível usar a passkey.'); }));
  document.getElementById('passkey-register')?.addEventListener('click', () => registerPasskey().catch(error => window.showToast?.(error.message || 'Não foi possível cadastrar a passkey.')));
  document.querySelectorAll('[data-account-view]').forEach(button => button.addEventListener('click', () => setAccountView(button.dataset.accountView)));
  document.querySelectorAll('[data-account-open]').forEach(button => button.addEventListener('click', () => setAccountView(button.dataset.accountOpen, true)));
  document.querySelector('.portal-nav')?.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const tabs = [...document.querySelectorAll('[data-account-view]')];
    const current = tabs.indexOf(document.activeElement);
    if (current < 0) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    setAccountView(tabs[next].dataset.accountView, true);
  });
  document.getElementById('client-logout')?.addEventListener('click', async () => { try { await PaxinbotAuth.request('/api/auth/logout', { method: 'POST' }); } catch {} passkeySession = null; renderClientDashboard(null); await syncOwnerPanelLink(null); setAccountView('overview'); setClientStatus('Sessão encerrada.'); window.scrollTo({ top: 0, behavior: 'smooth' }); });
}

async function initActivationPage() {
  const approve = document.getElementById('activate-approve'); if (!approve) return; const copy = document.getElementById('activate-copy'); const status = document.getElementById('activate-status'); const note = document.getElementById('activate-login-note'); const query = new URLSearchParams(location.search); const requestId = query.get('request'); const userCode = query.get('code');
  if (!requestId || !userCode) { copy.textContent = 'A solicitação de dispositivo é inválida ou está incompleta.'; return; }
  try { const current = await PaxinbotAuth.request('/api/auth/me'); copy.textContent = `Você está conectado como ${current.user.email}. Confirme para autorizar este computador.`; note.hidden = true; approve.disabled = !current.entitlement.active; if (!current.entitlement.active) status.textContent = 'Esta conta ainda não possui um acesso ativo.'; } catch { copy.textContent = 'Entre na Área do Cliente nesta mesma janela e volte para confirmar o computador.'; status.textContent = 'A solicitação continuará válida apenas por alguns minutos.'; }
  approve.addEventListener('click', async () => { approve.disabled = true; try { const result = await PaxinbotAuth.request('/api/v1/devices/approve', { method: 'POST', body: { requestId, userCode } }); copy.textContent = `Computador “${result.deviceName}” autorizado.`; status.textContent = 'Você já pode voltar ao Paxinbot.'; window.showToast?.('Computador autorizado.'); } catch (error) { approve.disabled = false; status.textContent = error.message || 'Não foi possível autorizar este computador.'; } });
}

window.PaxinbotAuth = PaxinbotAuth; void initClientPage(); void initActivationPage();
