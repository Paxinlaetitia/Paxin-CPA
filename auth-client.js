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

const accountRoutes = { overview: '/conta', subscription: '/conta/assinatura', devices: '/conta/dispositivos', security: '/conta/seguranca', downloads: '/conta/downloads', account: '/conta/configuracoes', support: '/conta/suporte' };
let passkeySession = null;
let passkeyClient = null;
let currentAccount = null;

function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]); }
function formatDate(value, withTime = true) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat('pt-BR', withTime ? { dateStyle:'medium', timeStyle:'short' } : { dateStyle:'medium' }).format(date); }
function money(cents, currency = 'BRL') { return new Intl.NumberFormat('pt-BR', { style:'currency', currency }).format((Number(cents) || 0) / 100); }

function consumePasskeySession() {
  try { const raw = sessionStorage.getItem('paxinbot_passkey_session'); sessionStorage.removeItem('paxinbot_passkey_session'); if (raw) { const value = JSON.parse(raw); if (value?.accessToken) passkeySession = value; } } catch {}
}

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
  currentAccount = payload || null;
  const user = payload?.user; const entitlement = payload?.entitlement || {}; const email = String(user?.email || '');
  const displayName = payload?.profile?.displayName || (email ? email.split('@')[0] : 'Cliente');
  document.body.classList.toggle('client-authenticated', Boolean(user));
  document.getElementById('dashboard-initials').textContent = displayName.slice(0, 2).toUpperCase() || 'PB';
  document.getElementById('dashboard-email').textContent = email || 'Entre para consultar';
  document.getElementById('dashboard-greeting').textContent = user ? `Olá, ${displayName}` : 'Entre na sua conta';
  document.getElementById('dashboard-access').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Vitalício' : 'Por tempo') : 'Sem acesso';
  document.getElementById('dashboard-access-state').textContent = entitlement.active ? 'Ativo' : user ? 'Aguardando liberação' : 'Aguardando login';
  const expires = entitlement.expiresAt ? formatDate(entitlement.expiresAt) : 'Não expira';
  document.getElementById('dashboard-expiry').textContent = entitlement.active ? expires : '—';
  document.getElementById('dashboard-expiry-state').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : 'Definido pelo acesso contratado') : 'Sem dados';
  document.getElementById('subscription-plan').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : 'Acesso por tempo') : 'Sem acesso ativo';
  document.getElementById('subscription-expiry').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Este acesso não expira.' : `Válido até ${expires}.`) : 'Escolha uma modalidade para começar.';
  document.getElementById('dashboard-devices').textContent = payload?.account?.activeDevices ?? (user ? '—' : 'Protegidos');
  document.getElementById('dashboard-devices-state').textContent = user ? 'Sessões ativas do aplicativo' : 'Autorize depois do login';
  document.getElementById('client-logout').hidden = !user;
  document.getElementById('account-email').value = email;
  document.getElementById('account-display-name').value = displayName;
  const providers = user?.providers || [];
  document.getElementById('account-providers').textContent = providers.length ? providers.map(item => item === 'google' ? 'Google' : item === 'email' ? 'E-mail e senha' : item).join(' e ') : 'E-mail e senha';
  document.getElementById('passkey-state').textContent = passkeySession ? 'PRONTA PARA CADASTRO' : 'OPCIONAL';
  document.getElementById('passkey-copy').textContent = passkeySession ? 'Sua identidade foi confirmada. Cadastre a passkey neste dispositivo.' : 'Use biometria ou PIN para entrar com segurança.';
}

function viewFromPath() {
  const path = location.pathname.replace(/\/$/, '') || '/conta';
  return Object.entries(accountRoutes).find(([, route]) => route === path)?.[0] || 'overview';
}

function setAccountView(view, moveFocus = false, updateUrl = true) {
  const target = document.querySelector(`[data-account-panel="${view}"]`); if (!target) return;
  document.querySelectorAll('[data-account-panel]').forEach(panel => { const active = panel === target; panel.hidden = !active; panel.classList.toggle('is-active', active); });
  document.querySelectorAll('[data-account-view]').forEach(button => { const active = button.dataset.accountView === view; button.classList.toggle('is-active', active); button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1; if (active && moveFocus) button.focus(); });
  if (updateUrl && location.protocol !== 'file:' && accountRoutes[view] && location.pathname !== accountRoutes[view]) history.pushState({ accountView:view }, '', accountRoutes[view]);
}

async function syncOwnerPanelLink(user) {
  const link = document.getElementById('owner-panel-link'); if (!link) return; link.hidden = true; if (!user) return;
  try { await PaxinbotAuth.request('/api/admin?action=overview'); link.hidden = false; } catch {}
}

function renderDevices(devices) {
  const root = document.getElementById('account-device-list');
  if (!devices?.length) { root.innerHTML = '<div class="portal-empty">Nenhum computador autorizado.</div>'; return; }
  root.innerHTML = devices.map(device => `<article class="portal-list-row"><span class="portal-icon"><svg><use href="#i-device"></use></svg></span><div><b>${escapeHtml(device.deviceName)}</b><small>Último acesso: ${formatDate(device.lastSeenAt)} · Expira: ${formatDate(device.expiresAt)}</small></div><span class="portal-status ${device.status}">${device.status === 'active' ? 'Ativo' : device.status === 'revoked' ? 'Revogado' : 'Expirado'}</span>${device.status === 'active' ? `<button type="button" data-revoke-device="${escapeHtml(device.id)}">Revogar</button>` : ''}</article>`).join('');
}

function renderOrders(orders) {
  const root = document.getElementById('account-order-list');
  if (!orders?.length) { root.innerHTML = '<div class="portal-empty">Nenhum pedido encontrado.</div>'; return; }
  root.innerHTML = orders.map(order => `<article class="portal-list-row"><span class="portal-icon"><svg><use href="#i-card"></use></svg></span><div><b>${escapeHtml(order.productName || 'Pedido Paxinbot')}</b><small>${formatDate(order.createdAt)} · ${money(order.amountCents, order.currency)}</small></div><span class="portal-status ${escapeHtml(order.status)}">${escapeHtml(order.status)}</span></article>`).join('');
}

function productDuration(product) {
  if (product.accessKind === 'lifetime') return 'SEM EXPIRAÇÃO';
  const minutes = Number(product.durationMinutes) || 0;
  if (minutes >= 1440 && minutes % 1440 === 0) { const days = minutes / 1440; return `${days} ${days === 1 ? 'DIA' : 'DIAS'}`; }
  if (minutes >= 60 && minutes % 60 === 0) { const hours = minutes / 60; return `${hours} ${hours === 1 ? 'HORA' : 'HORAS'}`; }
  return `${minutes} MINUTOS`;
}

function renderProducts(products, error = '') {
  const root = document.getElementById('account-products-list'); if (!root) return;
  if (error) { root.innerHTML = `<div class="portal-empty portal-plan-loading">${escapeHtml(error)}</div>`; return; }
  if (!products?.length) { root.innerHTML = '<div class="portal-empty portal-plan-loading">Nenhuma modalidade ativa foi publicada.</div>'; return; }
  const featured = products.length === 1 ? 0 : Math.min(1, products.length - 1);
  root.innerHTML = products.map((product, index) => `<article class="${index === featured ? 'is-featured' : ''}"><span>${escapeHtml(productDuration(product))}</span><h3>${escapeHtml(product.name)}</h3><p>${escapeHtml(product.description || 'Acesso completo ao Paxinbot durante a validade contratada.')}</p><div class="portal-plan-price"><strong>${money(product.priceCents)}</strong><small>valor da modalidade</small></div><ul><li>Todos os recursos do aplicativo</li><li>${product.accessKind === 'lifetime' ? 'Acesso sem data de expiração' : `Validade de ${escapeHtml(productDuration(product).toLocaleLowerCase('pt-BR'))}`}</li></ul><div class="portal-plan-availability"><i></i>Disponível para aquisição</div></article>`).join('');
}

async function loadPortalData(basePayload) {
  let account = null; const notice = document.getElementById('portal-system-notice'); notice.hidden = true;
  try { account = (await PaxinbotAuth.request('/api/account?action=overview')).data; } catch (error) { notice.textContent = error.message; notice.hidden = false; document.getElementById('account-device-list').innerHTML = `<div class="portal-empty">${escapeHtml(error.message)}</div>`; }
  const merged = { ...basePayload, profile: account?.profile || null, account };
  renderClientDashboard(merged);
  const [devices, orders, products] = await Promise.all([
    PaxinbotAuth.request('/api/account?action=devices').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=orders').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=products').then(result => ({ data:result.data })).catch(error => ({ error:error.message }))
  ]);
  renderDevices(devices); renderOrders(orders); renderProducts(products.data, products.error);
}

async function getPasskeyClient() {
  if (passkeyClient) return passkeyClient;
  const config = await PaxinbotAuth.request('/api/auth/config');
  const module = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.105.0/+esm');
  passkeyClient = module.createClient(config.url, config.key, { auth: { persistSession:false, autoRefreshToken:false, detectSessionInUrl:false, experimental:{ passkey:true } } });
  return passkeyClient;
}

async function bridgeSession(session) {
  if (!session?.access_token || !session?.refresh_token) throw new Error('A autenticação não retornou uma sessão válida.');
  await PaxinbotAuth.request('/api/auth/session', { method:'POST', body:{ accessToken:session.access_token, refreshToken:session.refresh_token } });
}

async function loginWithPasskey() {
  const button = document.getElementById('passkey-login'); if (!window.PublicKeyCredential) throw new Error('Este navegador não oferece suporte a passkeys.'); button.disabled = true;
  try { const client = await getPasskeyClient(); const { data, error } = await client.auth.signInWithPasskey(); if (error) throw error; await bridgeSession(data.session); const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); setAccountView('overview'); setClientStatus('Conta conectada com passkey.', true); window.showToast?.('Login concluído.'); }
  finally { button.disabled = false; }
}

async function registerPasskey() {
  if (!window.PublicKeyCredential) throw new Error('Este navegador não oferece suporte a passkeys.');
  if (!passkeySession?.accessToken || !passkeySession?.refreshToken) { document.getElementById('passkey-dialog').showModal(); return; }
  const button = document.getElementById('passkey-register'); button.disabled = true;
  try { const client = await getPasskeyClient(); await client.auth.setSession({ access_token:passkeySession.accessToken, refresh_token:passkeySession.refreshToken }); const { error } = await client.auth.registerPasskey(); if (error) throw error; passkeySession = null; document.getElementById('passkey-state').textContent = 'CADASTRADA'; document.getElementById('passkey-copy').textContent = 'Esta conta agora pode entrar usando a passkey cadastrada.'; window.showToast?.('Passkey cadastrada com segurança.'); }
  finally { button.disabled = false; }
}

async function initClientPage() {
  const form = document.getElementById('client-login-form'); if (!form) return; const submit = form.querySelector('[type="submit"]'); consumePasskeySession();
  try { const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); setAccountView(viewFromPath(), false, false); setClientStatus('Conta conectada ao serviço seguro.', true); } catch { renderClientDashboard(null); await syncOwnerPanelLink(null); setClientStatus('Entre com sua conta Paxinbot para continuar.'); }
  form.addEventListener('submit', async event => { event.preventDefault(); submit.disabled = true; try { const data = new FormData(form); const result = await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:data.get('email'), password:data.get('password') } }); passkeySession = result.passkeySession || null; const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); setAccountView('overview'); setClientStatus('Conta conectada ao serviço seguro.', true); window.showToast?.('Login realizado.'); document.getElementById('client-password').value = ''; } catch (error) { setClientStatus(error.message || 'Não foi possível entrar.'); window.showToast?.(error.message || 'Não foi possível entrar.'); } finally { submit.disabled = false; } });
  document.getElementById('client-signup-form')?.addEventListener('submit', async event => { event.preventDefault(); const signup = event.currentTarget; const submitButton = signup.querySelector('[type="submit"]'); const data = new FormData(signup); if (data.get('password') !== data.get('passwordConfirm')) return window.showToast?.('As senhas precisam ser iguais.'); submitButton.disabled = true; try { const result = await PaxinbotAuth.request('/api/auth/signup', { method:'POST', body:{ email:data.get('email'), password:data.get('password') } }); setClientStatus(result.message, true); signup.reset(); setAuthMode('login'); window.showToast?.('Conta criada. Confira seu e-mail.'); } catch (error) { setClientStatus(error.message || 'Não foi possível criar a conta.'); window.showToast?.(error.message || 'Não foi possível criar a conta.'); } finally { submitButton.disabled = false; } });
  document.getElementById('auth-switch')?.addEventListener('click', () => setAuthMode(document.getElementById('client-login-form').hidden ? 'login' : 'signup'));
  document.getElementById('passkey-login')?.addEventListener('click', () => loginWithPasskey().catch(error => window.showToast?.(error.message)));
  document.getElementById('passkey-register')?.addEventListener('click', () => registerPasskey().catch(error => window.showToast?.(error.message)));
  document.getElementById('passkey-password-confirm')?.addEventListener('click', async () => { const password = document.getElementById('passkey-password').value; if (!currentAccount?.user?.email || !password) return window.showToast?.('Informe sua senha.'); try { const result = await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:currentAccount.user.email, password } }); passkeySession = result.passkeySession; document.getElementById('passkey-dialog').close(); document.getElementById('passkey-password').value = ''; await registerPasskey(); } catch (error) { window.showToast?.(error.message); } });
  document.querySelectorAll('[data-account-view]').forEach(button => button.addEventListener('click', () => setAccountView(button.dataset.accountView)));
  document.querySelectorAll('[data-account-open]').forEach(button => button.addEventListener('click', () => setAccountView(button.dataset.accountOpen, true)));
  document.getElementById('view-account-products')?.addEventListener('click', () => document.getElementById('account-products-list')?.scrollIntoView({ behavior:'smooth', block:'center' }));
  document.querySelector('.portal-nav')?.addEventListener('keydown', event => { if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return; const tabs = [...document.querySelectorAll('[data-account-view]')]; const current = tabs.indexOf(document.activeElement); if (current < 0) return; event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length; setAccountView(tabs[next].dataset.accountView, true); });
  window.addEventListener('popstate', () => setAccountView(viewFromPath(), false, false));
  document.getElementById('account-profile-form')?.addEventListener('submit', async event => { event.preventDefault(); const button = event.currentTarget.querySelector('button'); button.disabled = true; try { const displayName = new FormData(event.currentTarget).get('displayName'); const result = await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'profile', displayName } }); currentAccount.profile = result.data; renderClientDashboard(currentAccount); window.showToast?.('Dados atualizados.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  document.getElementById('account-device-list')?.addEventListener('click', async event => { const button = event.target.closest('[data-revoke-device]'); if (!button || !confirm('Revogar o acesso deste computador?')) return; button.disabled = true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'revokeDevice', sessionId:button.dataset.revokeDevice } }); renderDevices((await PaxinbotAuth.request('/api/account?action=devices')).data); window.showToast?.('Dispositivo revogado.'); } catch (error) { button.disabled = false; window.showToast?.(error.message); } });
  document.getElementById('revoke-all-devices')?.addEventListener('click', async event => { if (!confirm('Revogar todas as sessões do aplicativo?')) return; event.currentTarget.disabled = true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'revokeAllDevices' } }); renderDevices((await PaxinbotAuth.request('/api/account?action=devices')).data); window.showToast?.('Sessões do aplicativo revogadas.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled = false; } });
  document.querySelector('[data-open-password]')?.addEventListener('click', () => document.getElementById('password-dialog').showModal());
  document.querySelector('[data-close-password]')?.addEventListener('click', () => document.getElementById('password-dialog').close());
  document.getElementById('account-password-form')?.addEventListener('submit', async event => { event.preventDefault(); const data = new FormData(event.currentTarget); if (data.get('password') !== data.get('passwordConfirm')) return window.showToast?.('As senhas precisam ser iguais.'); const button = event.currentTarget.querySelector('[type="submit"]'); button.disabled = true; try { await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:currentAccount.user.email, password:data.get('currentPassword') } }); await PaxinbotAuth.request('/api/auth/password', { method:'POST', body:{ password:data.get('password') } }); event.currentTarget.reset(); document.getElementById('password-dialog').close(); window.showToast?.('Senha alterada.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  document.getElementById('password-recovery-link')?.addEventListener('click', async () => { if (!currentAccount?.user?.email) return; try { await PaxinbotAuth.request('/api/auth/recover', { method:'POST', body:{ email:currentAccount.user.email } }); window.showToast?.('Enviamos um link para criar ou redefinir sua senha.'); } catch (error) { window.showToast?.(error.message); } });
  document.getElementById('client-logout')?.addEventListener('click', async () => { try { await PaxinbotAuth.request('/api/auth/logout', { method:'POST' }); } catch {} passkeySession = null; renderClientDashboard(null); await syncOwnerPanelLink(null); setAccountView('overview', false, false); history.replaceState({}, '', '/conta'); setClientStatus('Sessão encerrada.'); window.scrollTo({ top:0, behavior:'smooth' }); });
}

async function initActivationPage() {
  const approve = document.getElementById('activate-approve'); if (!approve) return; const copy = document.getElementById('activate-copy'); const status = document.getElementById('activate-status'); const note = document.getElementById('activate-login-note'); const query = new URLSearchParams(location.search); const requestId = query.get('request'); const userCode = query.get('code');
  if (!requestId || !userCode) { copy.textContent = 'A solicitação de dispositivo é inválida ou está incompleta.'; return; }
  try { const current = await PaxinbotAuth.request('/api/auth/me'); copy.textContent = `Você está conectado como ${current.user.email}. Confirme para autorizar este computador.`; note.hidden = true; approve.disabled = !current.entitlement.active; if (!current.entitlement.active) status.textContent = 'Esta conta ainda não possui um acesso ativo.'; } catch { copy.textContent = 'Entre na Área do Cliente nesta mesma janela e volte para confirmar o computador.'; status.textContent = 'A solicitação continuará válida apenas por alguns minutos.'; }
  approve.addEventListener('click', async () => { approve.disabled = true; try { const result = await PaxinbotAuth.request('/api/v1/devices/approve', { method:'POST', body:{ requestId, userCode } }); copy.textContent = `Computador “${result.deviceName}” autorizado.`; status.textContent = 'Você já pode voltar ao Paxinbot.'; window.showToast?.('Computador autorizado.'); } catch (error) { approve.disabled = false; status.textContent = error.message || 'Não foi possível autorizar este computador.'; } });
}

window.PaxinbotAuth = PaxinbotAuth; void initClientPage(); void initActivationPage();
