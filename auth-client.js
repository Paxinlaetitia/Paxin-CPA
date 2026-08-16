'use strict';

const PaxinbotAuth = (() => {
  const baseUrl = location.protocol === 'file:' ? 'http://127.0.0.1:8787' : location.origin;
  let csrfToken = '';
  const csrf = async () => {
    if (csrfToken) return csrfToken;
    const response = await fetch(`${baseUrl}/api/auth/csrf`, { credentials:'include', headers:{ accept:'application/json' } });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload?.token) throw new Error('Não foi possível preparar a solicitação segura.');
    csrfToken = payload.token; return csrfToken;
  };
  const request = async (route, options = {}) => {
    const method = String(options.method || 'GET').toUpperCase();
    const hasBody = options.body !== undefined;
    const headers = { accept:'application/json', ...(hasBody ? { 'content-type':'application/json' } : {}), ...(options.headers || {}) };
    if (!['GET','HEAD','OPTIONS'].includes(method)) headers['x-paxinbot-csrf'] = await csrf();
    const response = await fetch(`${baseUrl}${route}`, { method, credentials:'include', headers, body:hasBody ? JSON.stringify(options.body) : undefined });
    let payload = null; try { payload = await response.json(); } catch {}
    if (!response.ok || payload?.ok === false) throw Object.assign(new Error(payload?.error || 'Não foi possível concluir a operação.'), { code: payload?.code, status: response.status });
    return payload;
  };
  return { baseUrl, request };
})();
const CLIENT_UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLIENT_PAYER_NAME=/^[\p{L}\p{M}][\p{L}\p{M}' .-]{1,99}$/u;
const CLIENT_CHECKOUT_INTENT_KEY='paxinbot_checkout_intent';
const CHECKOUT_INTENT_MAX_AGE=2*60*60*1000;

const accountRoutes = { overview: '/conta', subscription: '/conta/assinatura', checkout:'/conta/checkout', downloads: '/conta/downloads', account: '/conta/configuracoes', support: '/conta/suporte' };
const accountSectionRoutes = { profile: '/conta/configuracoes', security: '/conta/configuracoes/seguranca', devices: '/conta/configuracoes/dispositivos', preferences:'/conta/configuracoes/notificacoes', activity:'/conta/configuracoes/atividade' };
let passkeySession = null;
let passkeyClient = null;
let currentAccount = null;
let availableProducts = [];
let checkoutProduct = null;
let checkoutQuote = null;
let checkoutClientRequestId = null;
let checkoutPollTimer = null;
let checkoutCountdownTimer = null;
let currentOrderId = null;
let pendingEmailCode = null;
let accessClock = null;
let accessClockTimer = null;
let accessSyncTimer = null;
let accessSyncInFlight = false;

function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]); }
function formatDate(value, withTime = true) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat('pt-BR', withTime ? { dateStyle:'medium', timeStyle:'short' } : { dateStyle:'medium' }).format(date); }
function money(cents, currency = 'BRL') { return new Intl.NumberFormat('pt-BR', { style:'currency', currency }).format((Number(cents) || 0) / 100); }
function formatUsageTime(value) { const seconds = Math.max(0, Math.floor(Number(value) || 0)); const days = Math.floor(seconds / 86400); const hours = Math.floor((seconds % 86400) / 3600); const minutes = Math.ceil((seconds % 3600) / 60); const parts = []; if (days) parts.push(`${days} ${days === 1 ? 'dia' : 'dias'}`); if (hours) parts.push(`${hours} ${hours === 1 ? 'hora' : 'horas'}`); if (minutes && parts.length < 2) parts.push(`${minutes} min`); return parts.join(' e ') || 'menos de 1 minuto'; }
function formatUsageCountdown(value) { const seconds = Math.max(0, Math.floor(Number(value) || 0)); const days = Math.floor(seconds / 86400); const hours = Math.floor((seconds % 86400) / 3600); const minutes = Math.floor((seconds % 3600) / 60); const rest = seconds % 60; const pad = number => String(number).padStart(2, '0'); return days ? `${days}d ${pad(hours)}h ${pad(minutes)}min ${pad(rest)}s` : hours ? `${hours}h ${pad(minutes)}min ${pad(rest)}s` : `${minutes}min ${pad(rest)}s`; }
function remainingUntil(value) { const timestamp = value ? new Date(value).valueOf() : NaN; return Number.isFinite(timestamp) ? Math.max(0, Math.ceil((timestamp - Date.now()) / 1000)) : 0; }

function accessSeconds(entitlement = accessClock?.entitlement || {}) {
  if (entitlement.kind !== 'usage') return remainingUntil(entitlement.expiresAt);
  const elapsed = accessClock?.running ? Math.max(0, Math.floor((Date.now() - accessClock.syncedAt) / 1000)) : 0;
  return Math.max(0, (Number(accessClock?.remainingSeconds) || 0) - elapsed);
}

function renderAccessSummary(payload = currentAccount) {
  const entitlement = payload?.entitlement || {};
  accessClock = entitlement.active && entitlement.kind !== 'lifetime' ? {
    entitlement,
    remainingSeconds: entitlement.kind === 'usage' ? Math.max(0, Number(entitlement.remainingSeconds) || 0) : remainingUntil(entitlement.expiresAt),
    running: entitlement.kind === 'usage' ? entitlement.usageRunning === true : true,
    syncedAt: Date.now()
  } : null;
  document.getElementById('dashboard-access').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Vitalício' : entitlement.kind === 'usage' ? 'Saldo em uso' : 'Por tempo') : entitlement.availableGrant ? 'Saldo disponível' : 'Sem acesso';
  document.getElementById('dashboard-access-state').textContent = entitlement.active ? 'Ativo' : entitlement.availableGrant ? 'Aguardando sua ativação' : payload?.user ? 'Aguardando liberação' : 'Aguardando login';
  updateAccessCountdown();
  document.getElementById('subscription-plan').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : entitlement.kind === 'usage' ? 'Saldo de uso ativo' : 'Acesso por tempo') : 'Sem acesso ativo';
}

function updateAccessCountdown() {
  const entitlement = currentAccount?.entitlement || {};
  const remaining = accessSeconds(entitlement);
  document.getElementById('dashboard-expiry').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Não expira' : formatUsageCountdown(remaining)) : '—';
  document.getElementById('dashboard-expiry-state').textContent = entitlement.kind === 'usage' ? (entitlement.usageRunning ? 'Sincronizado · aplicativo em uso' : 'Pausado · aplicativo desconectado') : entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : 'Acesso antigo: contagem contínua') : 'Sem dados';
  document.getElementById('subscription-expiry').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Este acesso não expira.' : entitlement.kind === 'usage' ? `${formatUsageCountdown(remaining)} restantes. ${entitlement.usageRunning ? 'Sincronizado com o aplicativo.' : 'O saldo está pausado.'}` : `${formatUsageCountdown(remaining)} restantes neste acesso antigo.`) : 'Escolha uma modalidade para começar.';
}

async function syncAccessSummary() {
  if (accessSyncInFlight || document.hidden || !currentAccount?.user || !currentAccount?.entitlement?.active || currentAccount.entitlement.kind === 'lifetime') return;
  accessSyncInFlight = true;
  try {
    const fresh = await PaxinbotAuth.request('/api/auth/me');
    if (!currentAccount?.user || fresh.user?.id !== currentAccount.user.id) return;
    currentAccount = { ...currentAccount, user:fresh.user, entitlement:fresh.entitlement, serverNow:fresh.serverNow };
    renderAccessSummary(currentAccount);
  } catch {}
  finally { accessSyncInFlight = false; }
}

function startAccessClock() {
  if (accessClockTimer === null) accessClockTimer = window.setInterval(updateAccessCountdown, 1000);
  if (accessSyncTimer === null) accessSyncTimer = window.setInterval(syncAccessSummary, 10000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void syncAccessSummary(); }, { passive:true });
}

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
  document.getElementById('client-email-code-form').hidden = true;
  document.querySelectorAll('.google-button, .passkey-button, .auth-divider').forEach(item => { item.hidden = creating; });
  document.querySelector('.auth-head h2').textContent = creating ? 'Crie sua conta' : 'Entre na sua conta';
  document.getElementById('auth-mode-copy').textContent = creating ? 'Crie uma conta para acompanhar acessos, dispositivos e compras.' : 'Use seu e-mail, Google ou uma passkey já cadastrada.';
  document.getElementById('auth-switch').textContent = creating ? 'Já tem conta? Entrar' : 'Não tem conta? Criar agora';
  document.getElementById('auth-switch').hidden = false;
}

function requestedAuthMode() {
  return new URLSearchParams(location.search).get('mode') === 'signup' ? 'signup' : 'login';
}

function clearAuthModeQuery() {
  if (location.protocol === 'file:') return;
  const query=new URLSearchParams(location.search); if (!query.has('mode')) return; query.delete('mode');
  history.replaceState(history.state || {},'',`${location.pathname}${query.size ? `?${query}` : ''}`);
}

function setEmailCodeStep(result, purpose = result?.flow || 'login') {
  pendingEmailCode = { purpose };
  document.getElementById('client-login-form').hidden = true;
  document.getElementById('client-signup-form').hidden = true;
  document.getElementById('client-email-code-form').hidden = false;
  document.querySelectorAll('.google-button, .passkey-button, .auth-divider').forEach(item => { item.hidden = true; });
  document.getElementById('auth-switch').hidden = true;
  document.querySelector('.auth-head h2').textContent = purpose === 'signup' ? 'Confirme seu e-mail' : 'Verificação em duas etapas';
  document.getElementById('auth-mode-copy').textContent = purpose === 'signup' ? 'Confirme que este e-mail pertence a você para concluir o cadastro.' : 'Sua senha foi confirmada. Falta apenas o código enviado por e-mail.';
  document.getElementById('client-email-code-copy').textContent = `${result?.message || 'Enviamos um código de seis dígitos para seu e-mail.'}${result?.emailMasked ? ` Destino: ${result.emailMasked}.` : ''}`;
  const status = document.getElementById('client-email-code-status'); status.textContent = ''; status.classList.remove('is-error');
  document.getElementById('client-email-code').focus();
}

function cancelEmailCode() {
  pendingEmailCode = null; document.getElementById('client-email-code-form').reset(); setAuthMode('login');
}

function friendlyPasskeyError(error) {
  const name = String(error?.name || ''); const message = String(error?.message || '');
  if (name === 'NotAllowedError' || /not.?allowed|ceremony.*failed/i.test(message)) return 'A passkey não foi confirmada. A operação pode ter sido cancelada, expirado ou não existir neste dispositivo.';
  if (name === 'InvalidStateError' || /already.*registered|credential.*exists/i.test(message)) return 'Esta passkey já está cadastrada para a conta.';
  if (name === 'SecurityError' || /relying party|rp.?id|origin/i.test(message)) return 'O domínio da passkey não corresponde ao domínio aberto. Use https://www.paxincpa.store e tente novamente.';
  if (/passkey.*disabled|not enabled/i.test(message)) return 'As passkeys ainda não estão habilitadas no servidor de autenticação.';
  return message || 'Não foi possível concluir a operação com a passkey.';
}

function renderClientDashboard(payload) {
  currentAccount = payload || null;
  const user = payload?.user; const entitlement = payload?.entitlement || {}; const email = String(user?.email || '');
  const displayName = payload?.profile?.displayName || (email ? email.split('@')[0] : 'Cliente');
  document.body.classList.toggle('client-authenticated', Boolean(user));
  document.body.classList.toggle('client-guest', !user);
  document.body.classList.remove('client-auth-pending');
  document.body.setAttribute('aria-busy', 'false');
  document.getElementById('dashboard-initials').textContent = displayName.slice(0, 2).toUpperCase() || 'PB';
  document.getElementById('dashboard-email').textContent = email || 'Entre para consultar';
  document.getElementById('dashboard-greeting').textContent = user ? `Olá, ${displayName}` : 'Entre na sua conta';
  renderAccessSummary(payload);
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

function renderUsageGrants(grants) {
  const card = document.getElementById('usage-credit-card'); if (!card) return;
  const available = (grants || []).find(grant => grant.status === 'available');
  card.hidden = !available; card.dataset.grantId = available?.id || '';
  if (available) { const active=Boolean(currentAccount?.entitlement?.active); document.getElementById('usage-credit-title').textContent = `${formatUsageTime(available.remainingSeconds)}${active ? ' na fila' : ''}`; document.getElementById('usage-credit-copy').textContent=active ? 'Este saldo fica guardado e poderá ser ativado quando o acesso atual terminar.' : 'O tempo só começa a diminuir depois da ativação e enquanto o aplicativo estiver conectado.'; document.getElementById('activate-usage-credit').hidden=active; }
}

function renderPromotions(promotions) {
  const card=document.getElementById('portal-promotion-card'); if (!card) return;
  const promotion=Array.isArray(promotions) ? promotions[0] : null;
  card.hidden=!promotion; card.dataset.promotionId=promotion?.id || '';
  if (!promotion) return;
  document.getElementById('promotion-name').textContent=String(promotion.name || 'Presente Paxinbot').toUpperCase();
  document.getElementById('promotion-headline').textContent=promotion.headline || 'Você ganhou um presente';
  document.getElementById('promotion-description').textContent=promotion.description || 'Resgate seu benefício e ative-o quando estiver pronto para usar o aplicativo.';
  document.getElementById('promotion-duration').textContent=`${formatUsageTime(promotion.rewardSeconds)} de uso · só começa após a ativação`;
  try { const key=`paxinbot_promotion_seen_${promotion.id}`; if (!sessionStorage.getItem(key)) { sessionStorage.setItem(key,'1'); window.showToast?.(`${promotion.headline || 'Você ganhou um presente'}.`); } } catch {}
}

function viewFromPath() {
  const path = location.pathname.replace(/\/$/, '') || '/conta';
  if (Object.values(accountSectionRoutes).includes(path) || ['/conta/seguranca','/conta/dispositivos'].includes(path)) return 'account';
  return Object.entries(accountRoutes).find(([, route]) => route === path)?.[0] || 'overview';
}

function selectedCheckoutProductId() {
  const productId = new URLSearchParams(location.search).get('product');
  return CLIENT_UUID.test(productId || '') ? productId : '';
}

function selectedCheckoutIntentMatches(productId) {
  try { const intent=JSON.parse(sessionStorage.getItem(CLIENT_CHECKOUT_INTENT_KEY) || 'null'); return intent?.productId===productId && Number.isFinite(intent?.selectedAt) && Date.now()-intent.selectedAt>=0 && Date.now()-intent.selectedAt<=CHECKOUT_INTENT_MAX_AGE; }
  catch { return false; }
}

function newCheckoutRequestId() {
  if (typeof crypto.randomUUID==='function') return crypto.randomUUID();
  const bytes=new Uint8Array(16); crypto.getRandomValues(bytes); bytes[6]=(bytes[6]&15)|64; bytes[8]=(bytes[8]&63)|128;
  return [...bytes].map((value,index)=>([4,6,8,10].includes(index)?'-':'')+value.toString(16).padStart(2,'0')).join('');
}

async function renderAuthPurchaseContext() {
  const root=document.getElementById('auth-purchase-context'); if (!root) return;
  root.hidden=true; document.getElementById('auth-purchase-name').textContent='—'; document.getElementById('auth-purchase-price').textContent='—';
  const productId=selectedCheckoutProductId();
  if (viewFromPath() !== 'checkout' || !productId || !selectedCheckoutIntentMatches(productId)) { try { sessionStorage.removeItem(CLIENT_CHECKOUT_INTENT_KEY); } catch {} if (viewFromPath()==='checkout' && location.protocol!=='file:') history.replaceState({},'',accountRoutes.overview); return; }
  try { const response=await fetch('/api/catalog',{ credentials:'include' }); const payload=await response.json(); const product=(payload.data || []).find(item=>item.id===productId); if (!product) { sessionStorage.removeItem(CLIENT_CHECKOUT_INTENT_KEY); if (location.protocol!=='file:') history.replaceState({},'',accountRoutes.overview); return; } root.hidden=false; document.getElementById('auth-purchase-name').textContent=product.name; document.getElementById('auth-purchase-price').textContent=`${money(product.priceCents)} · ${productDuration(product)}`; } catch {}
}

function accountSectionFromPath() {
  const path = location.pathname.replace(/\/$/, '') || '/conta';
  if (path === '/conta/seguranca') return 'security';
  if (path === '/conta/dispositivos') return 'devices';
  return Object.entries(accountSectionRoutes).find(([, route]) => route === path)?.[0] || 'profile';
}

function setAccountView(view, moveFocus = false, updateUrl = true) {
  const target = document.querySelector(`[data-account-panel="${view}"]`); if (!target) return;
  document.querySelectorAll('[data-account-panel]').forEach(panel => { const active = panel === target; panel.hidden = !active; panel.classList.toggle('is-active', active); });
  document.querySelectorAll('[data-account-view]').forEach(button => { const active = button.dataset.accountView === view; button.classList.toggle('is-active', active); button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1; if (active && moveFocus) button.focus(); });
  document.body.classList.toggle('client-checkout-view', view === 'checkout');
  if (updateUrl && location.protocol !== 'file:' && accountRoutes[view] && location.pathname !== accountRoutes[view]) history.pushState({ accountView:view }, '', accountRoutes[view]);
}

function setAccountSection(section, moveFocus = false, updateUrl = true) {
  const target = document.querySelector(`[data-account-section-panel="${section}"]`); if (!target) return;
  document.querySelectorAll('[data-account-section-panel]').forEach(panel => { const active = panel === target; panel.hidden = !active; panel.classList.toggle('is-active', active); });
  document.querySelectorAll('[data-account-section]').forEach(button => { const active = button.dataset.accountSection === section; button.classList.toggle('is-active', active); button.setAttribute('aria-selected', String(active)); if (active && moveFocus) button.focus(); });
  if (updateUrl && location.protocol !== 'file:' && accountSectionRoutes[section] && location.pathname !== accountSectionRoutes[section]) history.pushState({ accountView:'account', accountSection:section }, '', accountSectionRoutes[section]);
}

async function syncOwnerPanelLink(user) {
  const link = document.getElementById('owner-panel-link'); if (!link) return; link.hidden = true; if (!user) return;
  try { const result=await PaxinbotAuth.request('/api/admin?action=overview'); if (!result.adminPath) return; link.href=result.adminPath; link.hidden = false; } catch {}
}

function renderDevices(devices) {
  const root = document.getElementById('account-device-list');
  if (!devices?.length) { root.innerHTML = '<div class="portal-empty">Nenhum computador autorizado.</div>'; return; }
  root.innerHTML = devices.map(device => `<article class="portal-list-row"><span class="portal-icon"><svg><use href="#i-device"></use></svg></span><div><b>${escapeHtml(device.deviceName)}</b><small>Último acesso: ${formatDate(device.lastSeenAt)} · Expira: ${formatDate(device.expiresAt)}</small></div><span class="portal-status ${device.status}">${device.status === 'active' ? 'Ativo' : device.status === 'revoked' ? 'Revogado' : 'Expirado'}</span>${device.status === 'active' ? `<button type="button" data-revoke-device="${escapeHtml(device.id)}">Revogar</button>` : ''}</article>`).join('');
}

function renderOrders(orders) {
  const root = document.getElementById('account-order-list');
  if (!orders?.length) { root.innerHTML = '<div class="portal-empty">Nenhum pedido encontrado.</div>'; return; }
  const labels = { pending:'Aguardando', paid:'Pago', refunded:'Reembolsado', cancelled:'Cancelado', chargeback:'Contestado' };
  root.innerHTML = orders.map(order => `<article class="portal-list-row"><span class="portal-icon"><svg><use href="#i-card"></use></svg></span><div><b>${escapeHtml(order.productName || 'Pedido Paxinbot')}</b><small>${formatDate(order.createdAt)} · ${money(order.amountCents, order.currency)}${Number(order.discountCents) > 0 ? ` · Desconto ${money(order.discountCents, order.currency)}` : ''}</small></div><span class="portal-status ${escapeHtml(order.status)}">${escapeHtml(labels[order.status] || order.status)}</span><button class="portal-row-action" type="button" data-order-details="${escapeHtml(order.id)}">Detalhes</button></article>`).join('');
}

function renderPreferences(preferences) {
  document.getElementById('preference-product-updates').checked = preferences?.productUpdates === true;
  document.getElementById('preference-support-updates').checked = preferences?.supportUpdates !== false;
}

function renderActivity(activity) {
  const root = document.getElementById('account-activity-list'); if (!root) return;
  const labels = { 'account.created':'Conta criada', 'account.profile_updated':'Perfil atualizado', 'account.preferences_updated':'Preferências atualizadas', 'device.approved':'Dispositivo autorizado', 'device.signed_in':'Aplicativo conectado', 'device.revoked':'Dispositivo revogado', 'device.revoked_all':'Todas as sessões foram revogadas', 'checkout.started':'Pagamento iniciado', 'checkout.resumed':'Pagamento retomado', 'payment.approved':'Pagamento confirmado', 'payment.refunded':'Pagamento reembolsado', 'payment.charged_back':'Pagamento contestado', 'support.ticket_created':'Chamado aberto' };
  if (!activity?.length) { root.innerHTML = '<div class="portal-empty">Sua atividade aparecerá aqui após as primeiras ações.</div>'; return; }
  root.innerHTML = activity.map(item => `<article class="portal-list-row activity-row"><span class="portal-icon"><svg><use href="#i-file"></use></svg></span><div><b>${escapeHtml(labels[item.eventType] || 'Atividade da conta')}</b><small>${formatDate(item.createdAt)}</small></div></article>`).join('');
}

function renderTickets(tickets) {
  const root = document.getElementById('support-ticket-list'); if (!root) return;
  const status = { open:'Aberto', in_progress:'Em atendimento', resolved:'Resolvido', closed:'Encerrado' };
  const category = { technical:'Técnico', payment:'Pagamento', access:'Acesso', other:'Outro' };
  if (!tickets?.length) { root.innerHTML = '<div class="portal-empty">Você ainda não abriu chamados. Use o formulário acima quando precisar.</div>'; return; }
  root.innerHTML = tickets.map(ticket => `<details class="support-ticket" data-ticket-id="${escapeHtml(ticket.id)}"><summary><div><span>${escapeHtml(category[ticket.category] || 'Suporte')}</span><b>${escapeHtml(ticket.subject)}</b><small>Atualizado em ${formatDate(ticket.updatedAt)}</small></div><span class="portal-status ${escapeHtml(ticket.status)}">${escapeHtml(status[ticket.status] || ticket.status)}</span></summary><div class="support-thread">${(ticket.messages || []).map(message => `<article class="${message.authorKind === 'owner' ? 'is-owner' : ''}"><b>${message.authorKind === 'owner' ? 'Suporte Paxinbot' : 'Você'}</b><p>${escapeHtml(message.body)}</p><small>${formatDate(message.createdAt)}</small></article>`).join('')}${ticket.status !== 'closed' ? `<form data-ticket-reply><label>Responder<textarea name="message" minlength="2" maxlength="3000" required></textarea></label><button class="button button-secondary" type="submit">Enviar resposta</button></form>` : ''}</div></details>`).join('');
}

async function openOrderDetails(orderId) {
  const result = await PaxinbotAuth.request(`/api/account?action=order&orderId=${encodeURIComponent(orderId)}`); const order = result.data;
  currentOrderId = order.id; const labels = { pending:'Aguardando pagamento', paid:'Pago', refunded:'Reembolsado', cancelled:'Cancelado', chargeback:'Contestado' };
  document.getElementById('order-dialog-title').textContent = order.product?.name || 'Pedido Paxinbot';
  document.getElementById('order-dialog-copy').textContent = labels[order.status] || order.status;
  document.getElementById('order-detail-grid').innerHTML = `<div><span>VALOR</span><b>${money(order.amountCents, order.currency)}</b></div><div><span>DESCONTO</span><b>${Number(order.discountCents) > 0 ? money(order.discountCents, order.currency) : 'Sem desconto'}</b></div><div><span>CRIADO EM</span><b>${formatDate(order.createdAt)}</b></div><div><span>CONFIRMAÇÃO</span><b>${order.paidAt ? formatDate(order.paidAt) : 'Aguardando'}</b></div>`;
  document.getElementById('order-resume').hidden = order.status !== 'pending' || order.paymentMethod === 'pix'; document.getElementById('order-receipt').hidden = order.status !== 'paid';
  document.getElementById('order-dialog').showModal();
}

function productDuration(product) {
  if (product.accessKind === 'lifetime') return 'SEM EXPIRAÇÃO';
  const minutes = Number(product.durationMinutes) || 0;
  if (minutes >= 1440 && minutes % 1440 === 0) { const days = minutes / 1440; return `${days} ${days === 1 ? 'DIA' : 'DIAS'}`; }
  if (minutes >= 60 && minutes % 60 === 0) { const hours = minutes / 60; return `${hours} ${hours === 1 ? 'HORA' : 'HORAS'}`; }
  return `${minutes} MINUTOS`;
}

function renderProducts(products, error = '', checkoutReady = false) {
  const root = document.getElementById('account-products-list'); if (!root) return;
  availableProducts = Array.isArray(products) ? products : [];
  if (error) { root.innerHTML = `<div class="portal-empty portal-plan-loading">${escapeHtml(error)}</div>`; return; }
  if (!products?.length) { root.innerHTML = '<div class="portal-empty portal-plan-loading">Nenhuma modalidade ativa foi publicada.</div>'; return; }
  const featured = products.length === 1 ? 0 : Math.min(1, products.length - 1);
  root.innerHTML = products.map((product, index) => `<article class="${index === featured ? 'is-featured' : ''}"><span>${escapeHtml(productDuration(product))}</span><h3>${escapeHtml(product.name)}</h3><p>${escapeHtml(product.description || 'Acesso completo ao Paxinbot durante o período contratado.')}</p><div class="portal-plan-price"><strong>${money(product.priceCents)}</strong><small>valor da modalidade</small></div><ul><li>Todos os recursos do aplicativo</li><li>${product.accessKind === 'lifetime' ? 'Acesso sem data de expiração' : `Saldo de ${escapeHtml(productDuration(product).toLocaleLowerCase('pt-BR'))}`}</li>${product.accessKind === 'lifetime' ? '' : '<li>O tempo pausa quando o aplicativo é fechado</li>'}</ul><button class="portal-plan-buy" type="button" data-buy-product="${escapeHtml(product.id)}" ${checkoutReady ? '' : 'disabled'}>${checkoutReady ? 'Comprar agora <svg><use href="#i-arrow"></use></svg>' : 'Checkout em configuração'}</button></article>`).join('');
  if (viewFromPath() === 'checkout') prepareCheckoutPage(selectedCheckoutProductId());
}

function openCheckout(productId) {
  checkoutProduct = availableProducts.find(product => product.id === productId) || null;
  if (!checkoutProduct) return window.showToast?.('Esta modalidade não está mais disponível.');
  history.pushState({ accountView:'checkout', productId }, '', `/conta/checkout?product=${encodeURIComponent(productId)}`);
  setAccountView('checkout', false, false); prepareCheckoutPage(productId); window.scrollTo({ top:0, behavior:'smooth' });
}

function renderCheckoutQuote(quote) {
  if (!quote) return;
  checkoutQuote = quote;
  document.getElementById('checkout-product-name').textContent = quote.productName || checkoutProduct?.name || '—';
  document.getElementById('checkout-product-duration').textContent = quote.accessKind ? productDuration(quote) : productDuration(checkoutProduct || {});
  document.getElementById('checkout-product-description').textContent = quote.productDescription || checkoutProduct?.description || 'Acesso ao Paxinbot vinculado à sua conta.';
  document.getElementById('checkout-subtotal').textContent = money(quote.subtotalCents ?? checkoutProduct?.priceCents);
  const discount = Number(quote.discountCents) || 0; document.getElementById('checkout-discount-row').hidden = discount <= 0;
  document.getElementById('checkout-discount').textContent = discount > 0 ? `− ${money(discount)}` : '—';
  document.getElementById('checkout-total').textContent = money(quote.amountCents ?? checkoutProduct?.priceCents);
}

function prepareCheckoutPage(productId) {
  checkoutProduct = availableProducts.find(product => product.id === productId) || null;
  const error = document.getElementById('checkout-error');
  if (!checkoutProduct) { if (error) { error.hidden=false; error.textContent='A modalidade selecionada não está mais disponível.'; } return; }
  error.hidden=true; checkoutClientRequestId=null;
  const displayName = String(currentAccount?.profile?.displayName || '').trim().replace(/\s+/g, ' ');
  const payerName = document.getElementById('checkout-payer-name');
  if (payerName && !payerName.value && CLIENT_PAYER_NAME.test(displayName)) payerName.value=displayName;
  document.getElementById('checkout-payer-email').value=currentAccount?.user?.email || '';
  renderCheckoutQuote({ ...checkoutProduct, productName:checkoutProduct.name, productDescription:checkoutProduct.description, subtotalCents:checkoutProduct.priceCents, discountCents:0, amountCents:checkoutProduct.priceCents });
}

async function quoteCheckout() {
  if (!checkoutProduct) throw new Error('Selecione uma modalidade válida.');
  const couponCode=document.getElementById('checkout-coupon').value.trim().toUpperCase();
  const result=await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ action:'quote', productId:checkoutProduct.id, couponCode } });
  renderCheckoutQuote(result.quote); checkoutClientRequestId=null; return result.quote;
}

function updateCheckoutPaymentButton() {
  const method=document.querySelector('input[name="paymentMethod"]:checked')?.value || 'pix';
  document.getElementById('checkout-submit').innerHTML=method === 'pix' ? 'Gerar PIX <svg><use href="#i-arrow"></use></svg>' : 'Continuar para pagamento <svg><use href="#i-arrow"></use></svg>';
}

function stopCheckoutPolling() {
  if (checkoutPollTimer) window.clearInterval(checkoutPollTimer); if (checkoutCountdownTimer) window.clearInterval(checkoutCountdownTimer);
  checkoutPollTimer=null; checkoutCountdownTimer=null;
}

function showPixResult(orderId, pix) {
  stopCheckoutPolling();
  document.getElementById('checkout-form').hidden=true; document.querySelector('.checkout-order-summary').hidden=true;
  const result=document.getElementById('checkout-pix-result'); result.hidden=false;
  document.getElementById('checkout-pix-code').value=pix.qrCode;
  document.getElementById('checkout-pix-qr').src=`data:image/png;base64,${pix.qrCodeBase64}`;
  const expiration=new Date(pix.expiresAt).valueOf();
  const update=()=>{ const seconds=Math.max(0,Math.ceil((expiration-Date.now())/1000)); document.getElementById('checkout-pix-countdown').textContent=`${String(Math.floor(seconds/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`; if (!seconds) { document.getElementById('checkout-pix-status').textContent='PIX expirado'; stopCheckoutPolling(); } };
  update(); checkoutCountdownTimer=window.setInterval(update,1000);
  const poll=async()=>{ try { const response=await PaxinbotAuth.request(`/api/checkout?orderId=${encodeURIComponent(orderId)}`); if (response.order?.status==='paid') { stopCheckoutPolling(); document.getElementById('checkout-pix-status').textContent='Pagamento confirmado'; document.getElementById('checkout-pix-countdown').textContent='CONFIRMADO'; await refreshOrderData(); window.showToast?.('Pagamento confirmado e acesso liberado.'); } else if (['cancelled','refunded','chargeback'].includes(response.order?.status)) { stopCheckoutPolling(); document.getElementById('checkout-pix-status').textContent='Pagamento não concluído'; } } catch {} };
  checkoutPollTimer=window.setInterval(poll,3500);
}

function setCheckoutReturn(kind, title, copy) {
  const root = document.getElementById('checkout-return'); if (!root) return;
  root.hidden = false; root.className = `checkout-return is-${kind}`;
  document.getElementById('checkout-return-title').textContent = title;
  document.getElementById('checkout-return-copy').textContent = copy;
}

async function refreshOrderData() {
  const [current, orders] = await Promise.all([PaxinbotAuth.request('/api/auth/me'), PaxinbotAuth.request('/api/account?action=orders')]);
  const account = await PaxinbotAuth.request('/api/account?action=overview').then(result => result.data).catch(() => null);
  renderClientDashboard({ ...current, profile:account?.profile || null, account });
  renderOrders(orders.data);
}

async function handleCheckoutReturn() {
  const query = new URLSearchParams(location.search); const flow = query.get('checkout'); const orderId = query.get('order');
  if (!flow || !/^[0-9a-f-]{36}$/i.test(orderId || '')) return;
  setAccountView('subscription', false, false);
  setCheckoutReturn('pending', 'Confirmando o pagamento', 'A confirmação é feita diretamente com o Mercado Pago. Isso pode levar alguns segundos.');
  for (let attempt = 0; attempt < 7; attempt += 1) {
    try {
      const result = await PaxinbotAuth.request(`/api/checkout?orderId=${encodeURIComponent(orderId)}`); const order = result.order;
      if (order.status === 'paid') {
        setCheckoutReturn('success', 'Pagamento confirmado', 'Seu saldo foi liberado. Ative-o quando estiver pronto para usar o aplicativo.');
        await refreshOrderData(); history.replaceState({ accountView:'subscription' }, '', '/conta/assinatura'); return;
      }
      if (['cancelled','refunded','chargeback'].includes(order.status)) {
        setCheckoutReturn('failure', 'Pagamento não concluído', 'O pedido não foi aprovado. Você pode escolher a modalidade e tentar novamente.'); return;
      }
    } catch {}
    if (attempt < 6) await new Promise(resolve => setTimeout(resolve, 1800));
  }
  setCheckoutReturn(flow === 'failure' ? 'failure' : 'pending', flow === 'failure' ? 'Pagamento não concluído' : 'Pagamento em análise', flow === 'failure' ? 'Você pode tentar novamente quando desejar.' : 'Assim que o Mercado Pago confirmar, o acesso será liberado automaticamente.');
}

async function loadPortalData(basePayload) {
  let account = null; const notice = document.getElementById('portal-system-notice'); notice.hidden = true;
  try { account = (await PaxinbotAuth.request('/api/account?action=overview')).data; } catch (error) { notice.textContent = error.message; notice.hidden = false; document.getElementById('account-device-list').innerHTML = `<div class="portal-empty">${escapeHtml(error.message)}</div>`; }
  const merged = { ...basePayload, profile: account?.profile || null, account };
  renderClientDashboard(merged);
  const [devices, orders, products, preferences, activity, tickets, usageGrants, promotions] = await Promise.all([
    PaxinbotAuth.request('/api/account?action=devices').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=orders').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=products').then(result => ({ data:result.data, checkoutReady:result.checkoutReady })).catch(error => ({ error:error.message })),
    PaxinbotAuth.request('/api/account?action=preferences').then(result => result.data).catch(() => ({})),
    PaxinbotAuth.request('/api/account?action=activity').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=tickets').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=usageGrants').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=promotions').then(result => result.data).catch(() => [])
  ]);
  renderDevices(devices); renderOrders(orders); renderProducts(products.data, products.error, products.checkoutReady);
  renderPreferences(preferences); renderActivity(activity); renderTickets(tickets); renderUsageGrants(usageGrants); renderPromotions(promotions);
}

async function getPasskeyClient() {
  if (passkeyClient) return passkeyClient;
  const config = await PaxinbotAuth.request('/api/auth/config');
  if (!window.supabase?.createClient) throw new Error('O módulo seguro de autenticação não foi carregado.');
  passkeyClient = window.supabase.createClient(config.url, config.key, { auth: { persistSession:false, autoRefreshToken:false, detectSessionInUrl:false, experimental:{ passkey:true } } });
  return passkeyClient;
}

async function bridgeSession(session) {
  if (!session?.access_token || !session?.refresh_token) throw new Error('A autenticação não retornou uma sessão válida.');
  await PaxinbotAuth.request('/api/auth/session', { method:'POST', body:{ accessToken:session.access_token, refreshToken:session.refresh_token } });
}

async function loginWithPasskey() {
  const button = document.getElementById('passkey-login'); if (!window.PublicKeyCredential) throw new Error('Este navegador não oferece suporte a passkeys.'); button.disabled = true;
  try { const client = await getPasskeyClient(); const { data, error } = await client.auth.signInWithPasskey(); if (error) throw new Error(friendlyPasskeyError(error)); await bridgeSession(data.session); const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); setAccountView(viewFromPath(),false,false); setClientStatus('Conta conectada com passkey.', true); window.showToast?.('Login concluído.'); }
  catch (error) { throw new Error(friendlyPasskeyError(error)); }
  finally { button.disabled = false; }
}

async function registerPasskey() {
  if (!window.PublicKeyCredential) throw new Error('Este navegador não oferece suporte a passkeys.');
  if (!passkeySession?.accessToken || !passkeySession?.refreshToken) { document.getElementById('passkey-dialog').showModal(); return; }
  const button = document.getElementById('passkey-register'); button.disabled = true;
  try { const client = await getPasskeyClient(); await client.auth.setSession({ access_token:passkeySession.accessToken, refresh_token:passkeySession.refreshToken }); const { error } = await client.auth.registerPasskey(); if (error) throw new Error(friendlyPasskeyError(error)); passkeySession = null; document.getElementById('passkey-state').textContent = 'CADASTRADA'; document.getElementById('passkey-copy').textContent = 'Esta conta agora pode entrar usando a passkey cadastrada.'; window.showToast?.('Passkey cadastrada com segurança.'); }
  catch (error) { throw new Error(friendlyPasskeyError(error)); }
  finally { button.disabled = false; }
}

async function completeClientLogin(result, message = 'Login realizado.') {
  passkeySession = result?.passkeySession || null; pendingEmailCode = null;
  const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user);
  const targetView=viewFromPath(); const returningFromPayment=new URLSearchParams(location.search).has('checkout'); clearAuthModeQuery(); setAccountView(returningFromPayment ? 'subscription' : targetView, false, false);
  setClientStatus('Conta conectada ao serviço seguro.', true); window.showToast?.(message); document.getElementById('client-password').value = ''; document.getElementById('client-email-code-form').reset(); void handleCheckoutReturn();
}

async function initClientPage() {
  const form = document.getElementById('client-login-form'); if (!form) return; const submit = form.querySelector('[type="submit"]'); consumePasskeySession();
  void renderAuthPurchaseContext();
  startAccessClock();
  try { const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); clearAuthModeQuery(); setAccountView(viewFromPath(), false, false); setAccountSection(accountSectionFromPath(), false, false); setClientStatus('Conta conectada ao serviço seguro.', true); } catch { renderClientDashboard(null); await syncOwnerPanelLink(null); setAuthMode(requestedAuthMode()); setClientStatus('Entre com sua conta Paxinbot para continuar.'); }
  form.addEventListener('submit', async event => { event.preventDefault(); submit.disabled = true; try { const data = new FormData(form); const result = await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:data.get('email'), password:data.get('password') } }); if (result.verificationRequired) return setEmailCodeStep(result, 'login'); await completeClientLogin(result); } catch (error) { setClientStatus(error.message || 'Não foi possível entrar.'); window.showToast?.(error.message || 'Não foi possível entrar.'); } finally { submit.disabled = false; } });
  document.getElementById('client-email-code-form')?.addEventListener('submit', async event => { event.preventDefault(); if (!pendingEmailCode) return cancelEmailCode(); const codeForm = event.currentTarget; const button = codeForm.querySelector('[type="submit"]'); const status = document.getElementById('client-email-code-status'); const code = new FormData(codeForm).get('code'); button.disabled = true; status.textContent = ''; status.classList.remove('is-error'); try { const result = await PaxinbotAuth.request('/api/auth/verify-email-code', { method:'POST', body:{ code } }); await completeClientLogin(result, pendingEmailCode?.purpose === 'signup' ? 'E-mail confirmado e conta criada.' : 'Verificação concluída.'); } catch (error) { status.textContent = error.message || 'Não foi possível confirmar o código.'; status.classList.add('is-error'); setClientStatus(error.message || 'Não foi possível confirmar o código.'); } finally { button.disabled = false; } });
  document.getElementById('client-email-code-resend')?.addEventListener('click', async event => { const button = event.currentTarget; const status = document.getElementById('client-email-code-status'); button.disabled = true; status.classList.remove('is-error'); try { const result = await PaxinbotAuth.request('/api/auth/resend-email-code', { method:'POST' }); status.textContent = result.message; } catch (error) { status.textContent = error.message; status.classList.add('is-error'); } finally { button.disabled = false; } });
  document.getElementById('client-email-code-cancel')?.addEventListener('click', cancelEmailCode);
  document.getElementById('client-signup-form')?.addEventListener('submit', async event => { event.preventDefault(); const signup = event.currentTarget; const submitButton = signup.querySelector('[type="submit"]'); const data = new FormData(signup); submitButton.disabled = true; try { const result = await PaxinbotAuth.request('/api/auth/signup', { method:'POST', body:{ username:data.get('username'), email:data.get('email'), password:data.get('password') } }); setClientStatus(result.message, true); signup.reset(); if (result.verificationRequired) return setEmailCodeStep(result, 'signup'); await completeClientLogin(result, 'Conta criada.'); } catch (error) { setClientStatus(error.message || 'Não foi possível criar a conta.'); window.showToast?.(error.message || 'Não foi possível criar a conta.'); } finally { submitButton.disabled = false; } });
  document.getElementById('auth-switch')?.addEventListener('click', () => setAuthMode(document.getElementById('client-login-form').hidden ? 'login' : 'signup'));
  document.querySelectorAll('.google-button').forEach(link=>link.addEventListener('click',()=>{ const view=viewFromPath(); if (view==='checkout' && selectedCheckoutProductId()) sessionStorage.setItem('paxinbot_auth_return',`${location.pathname}?product=${encodeURIComponent(selectedCheckoutProductId())}`); else if (view==='downloads') sessionStorage.setItem('paxinbot_auth_return',accountRoutes.downloads); }));
  document.getElementById('passkey-login')?.addEventListener('click', () => loginWithPasskey().catch(error => window.showToast?.(error.message)));
  document.getElementById('passkey-register')?.addEventListener('click', () => registerPasskey().catch(error => window.showToast?.(error.message)));
  document.getElementById('passkey-password-confirm')?.addEventListener('click', async () => { const password = document.getElementById('passkey-password').value; if (!currentAccount?.user?.email || !password) return window.showToast?.('Informe sua senha.'); try { const result = await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:currentAccount.user.email, password, purpose:'passkey' } }); document.getElementById('passkey-dialog').close(); document.getElementById('passkey-password').value = ''; if (result.verificationRequired) { pendingEmailCode = { purpose:'passkey' }; document.getElementById('security-code-copy').textContent = `${result.message}${result.emailMasked ? ` Destino: ${result.emailMasked}.` : ''}`; document.getElementById('security-code-status').textContent = ''; document.getElementById('security-code-dialog').showModal(); return; } } catch (error) { window.showToast?.(error.message); } });
  document.querySelectorAll('[data-account-view]').forEach(button => button.addEventListener('click', () => { setAccountView(button.dataset.accountView); if (button.dataset.accountView === 'account') setAccountSection('profile', false, false); }));
  document.querySelectorAll('[data-account-section]').forEach(button => button.addEventListener('click', () => setAccountSection(button.dataset.accountSection)));
  document.querySelectorAll('[data-account-open]').forEach(button => button.addEventListener('click', () => { const section = button.dataset.accountSectionOpen; setAccountView(button.dataset.accountOpen, true, !section); if (section) setAccountSection(section, false, true); }));
  document.getElementById('view-account-products')?.addEventListener('click', () => document.getElementById('account-products-list')?.scrollIntoView({ behavior:'smooth', block:'center' }));
  document.getElementById('account-download-installer')?.addEventListener('click', async event => {
    const button=event.currentTarget; const original=button.innerHTML; button.disabled=true; button.setAttribute('aria-busy','true'); button.textContent='Preparando download…';
    try {
      const result=await PaxinbotAuth.request('/api/account?action=download');
      const anchor=document.createElement('a'); anchor.href=result.data.url; anchor.download=result.data.fileName || 'PaxinbotSetup.exe'; anchor.rel='noopener'; document.body.appendChild(anchor); anchor.click(); anchor.remove();
      window.showToast?.('Download seguro iniciado. O link expira em dois minutos.');
    } catch (error) { window.showToast?.(error.message || 'Não foi possível preparar o download.'); }
    finally { button.disabled=false; button.removeAttribute('aria-busy'); button.innerHTML=original; }
  });
  document.getElementById('activate-usage-credit')?.addEventListener('click', async event => { const card=document.getElementById('usage-credit-card'); const grantId=card?.dataset.grantId; if (!grantId || !confirm('Ativar este saldo agora? Depois da ativação, ele será consumido enquanto o aplicativo estiver conectado.')) return; event.currentTarget.disabled=true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'activateUsage', grantId } }); const current=await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); window.showToast?.('Saldo ativado. Agora você pode autorizar o aplicativo.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled=false; } });
  document.getElementById('claim-promotion')?.addEventListener('click', async event => { const card=document.getElementById('portal-promotion-card'); const promotionId=card?.dataset.promotionId; if (!promotionId) return; event.currentTarget.disabled=true; event.currentTarget.setAttribute('aria-busy','true'); try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'claimPromotion', promotionId } }); const current=await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); setAccountView('subscription'); window.showToast?.('Presente resgatado. Seu saldo está guardado até você ativá-lo.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled=false; event.currentTarget.removeAttribute('aria-busy'); } });
  document.getElementById('account-products-list')?.addEventListener('click', event => { const button = event.target.closest('[data-buy-product]'); if (button) openCheckout(button.dataset.buyProduct); });
  document.getElementById('account-order-list')?.addEventListener('click', event => { const button = event.target.closest('[data-order-details]'); if (button) openOrderDetails(button.dataset.orderDetails).catch(error => window.showToast?.(error.message)); });
  document.querySelector('[data-close-order]')?.addEventListener('click', () => document.getElementById('order-dialog').close());
  document.querySelectorAll('input[name="paymentMethod"]').forEach(input=>input.addEventListener('change',()=>{ checkoutClientRequestId=null; updateCheckoutPaymentButton(); }));
  document.getElementById('checkout-apply-coupon')?.addEventListener('click',async event=>{ const status=document.getElementById('checkout-coupon-status'); event.currentTarget.disabled=true; status.classList.remove('is-error'); status.textContent='Validando…'; try { const quote=await quoteCheckout(); status.textContent=Number(quote.discountCents)>0 ? 'Cupom aplicado ao resumo.' : 'Preço confirmado.'; } catch(error) { status.textContent=error.message; status.classList.add('is-error'); } finally { event.currentTarget.disabled=false; } });
  document.getElementById('checkout-form')?.addEventListener('submit', async event => {
    event.preventDefault(); if (!checkoutProduct) return;
    const button = document.getElementById('checkout-submit'); const errorBox=document.getElementById('checkout-error'); const data=new FormData(event.currentTarget); const paymentMethod=String(data.get('paymentMethod') || 'pix'); const payerName=String(data.get('payerName') || '').trim().replace(/\s+/g, ' ');
    if (!CLIENT_PAYER_NAME.test(payerName)) { errorBox.hidden=false; errorBox.textContent='Informe seu nome completo usando apenas letras.'; document.getElementById('checkout-payer-name')?.focus(); return; }
    button.disabled = true; button.textContent = 'Preparando pagamento…'; errorBox.hidden=true;
    try {
      const couponCode = document.getElementById('checkout-coupon').value.trim().toUpperCase();
      checkoutClientRequestId ||= newCheckoutRequestId();
      const result = await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ productId:checkoutProduct.id, couponCode, payerName, paymentMethod, clientRequestId:checkoutClientRequestId } });
      if (paymentMethod==='pix') { showPixResult(result.orderId,result.pix); return; }
      const popup=window.open(result.checkoutUrl,'_blank','noopener,noreferrer'); if (!popup) location.assign(result.checkoutUrl); else { button.disabled=false; updateCheckoutPaymentButton(); window.showToast?.('O pagamento foi aberto em uma nova aba.'); }
    } catch (error) {
      button.disabled = false; updateCheckoutPaymentButton(); errorBox.hidden=false; errorBox.textContent=error.message || 'Não foi possível preparar o pagamento.';
    }
  });
  document.getElementById('checkout-copy-pix')?.addEventListener('click',async()=>{ const code=document.getElementById('checkout-pix-code').value; try { await navigator.clipboard.writeText(code); window.showToast?.('Código PIX copiado.'); } catch { document.getElementById('checkout-pix-code').select(); document.execCommand('copy'); window.showToast?.('Código PIX copiado.'); } });
  document.getElementById('order-resume')?.addEventListener('click', async event => { if (!currentOrderId) return; event.currentTarget.disabled = true; try { const result = await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ action:'resume', orderId:currentOrderId } }); location.assign(result.checkoutUrl); } catch (error) { event.currentTarget.disabled = false; window.showToast?.(error.message); } });
  document.getElementById('order-receipt')?.addEventListener('click', async event => { if (!currentOrderId) return; event.currentTarget.disabled = true; try { await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ action:'receipt', orderId:currentOrderId } }); window.showToast?.('Comprovante enviado para o e-mail da conta.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled = false; } });
  document.querySelector('.portal-nav')?.addEventListener('keydown', event => { if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return; const tabs = [...document.querySelectorAll('[data-account-view]')]; const current = tabs.indexOf(document.activeElement); if (current < 0) return; event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length; setAccountView(tabs[next].dataset.accountView, true); });
  window.addEventListener('popstate', () => { setAccountView(viewFromPath(), false, false); setAccountSection(accountSectionFromPath(), false, false); void renderAuthPurchaseContext(); });
  document.getElementById('account-profile-form')?.addEventListener('submit', async event => { event.preventDefault(); const button = event.currentTarget.querySelector('button'); button.disabled = true; try { const displayName = new FormData(event.currentTarget).get('displayName'); const result = await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'profile', displayName } }); currentAccount.profile = result.data; renderClientDashboard(currentAccount); window.showToast?.('Dados atualizados.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  document.getElementById('account-preferences-form')?.addEventListener('submit', async event => { event.preventDefault(); const button = event.currentTarget.querySelector('[type="submit"]'); button.disabled = true; try { const result = await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'preferences', productUpdates:document.getElementById('preference-product-updates').checked, supportUpdates:document.getElementById('preference-support-updates').checked } }); renderPreferences(result.data); renderActivity((await PaxinbotAuth.request('/api/account?action=activity')).data); window.showToast?.('Preferências atualizadas.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  document.getElementById('account-device-list')?.addEventListener('click', async event => { const button = event.target.closest('[data-revoke-device]'); if (!button || !confirm('Revogar o acesso deste computador?')) return; button.disabled = true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'revokeDevice', sessionId:button.dataset.revokeDevice } }); renderDevices((await PaxinbotAuth.request('/api/account?action=devices')).data); window.showToast?.('Dispositivo revogado.'); } catch (error) { button.disabled = false; window.showToast?.(error.message); } });
  document.getElementById('revoke-all-devices')?.addEventListener('click', async event => { if (!confirm('Revogar todas as sessões do aplicativo?')) return; event.currentTarget.disabled = true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'revokeAllDevices' } }); renderDevices((await PaxinbotAuth.request('/api/account?action=devices')).data); window.showToast?.('Sessões do aplicativo revogadas.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled = false; } });
  document.querySelector('[data-close-security-code]')?.addEventListener('click', () => { pendingEmailCode = null; document.getElementById('security-code-dialog').close(); document.getElementById('security-code-form').reset(); });
  document.getElementById('security-code-resend')?.addEventListener('click', async event => { const button = event.currentTarget; const status = document.getElementById('security-code-status'); button.disabled = true; status.classList.remove('is-error'); try { const result = await PaxinbotAuth.request('/api/auth/resend-email-code', { method:'POST' }); status.textContent = result.message; } catch (error) { status.textContent = error.message; status.classList.add('is-error'); } finally { button.disabled = false; } });
  document.getElementById('security-code-form')?.addEventListener('submit', async event => { event.preventDefault(); const codeForm = event.currentTarget; const button = codeForm.querySelector('[type="submit"]'); const status = document.getElementById('security-code-status'); const code = new FormData(codeForm).get('code'); button.disabled = true; status.textContent = ''; status.classList.remove('is-error'); try { if (pendingEmailCode?.purpose !== 'passkey') throw new Error('A confirmação expirou. Tente cadastrar a passkey novamente.'); const result = await PaxinbotAuth.request('/api/auth/verify-email-code', { method:'POST', body:{ code } }); passkeySession = result.passkeySession; pendingEmailCode = null; document.getElementById('security-code-dialog').close(); codeForm.reset(); await registerPasskey(); } catch (error) { status.textContent = error.message || 'Não foi possível confirmar o código.'; status.classList.add('is-error'); } finally { button.disabled = false; } });
  document.querySelector('[data-open-password]')?.addEventListener('click', () => document.getElementById('password-dialog').showModal());
  document.querySelector('[data-close-password]')?.addEventListener('click', () => document.getElementById('password-dialog').close());
  document.getElementById('account-password-form')?.addEventListener('submit', async event => { event.preventDefault(); const data = new FormData(event.currentTarget); if (data.get('password') !== data.get('passwordConfirm')) return window.showToast?.('As senhas precisam ser iguais.'); const button = event.currentTarget.querySelector('[type="submit"]'); button.disabled = true; try { await PaxinbotAuth.request('/api/auth/password', { method:'POST', body:{ currentPassword:data.get('currentPassword'), password:data.get('password') } }); event.currentTarget.reset(); document.getElementById('password-dialog').close(); window.showToast?.('Senha alterada.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  document.getElementById('password-recovery-link')?.addEventListener('click', async () => { if (!currentAccount?.user?.email) return; try { await PaxinbotAuth.request('/api/auth/recover', { method:'POST', body:{ email:currentAccount.user.email } }); window.showToast?.('Enviamos um link para criar ou redefinir sua senha.'); } catch (error) { window.showToast?.(error.message); } });
  document.getElementById('support-ticket-form')?.addEventListener('submit', async event => { event.preventDefault(); const form = event.currentTarget; const button = form.querySelector('[type="submit"]'); const data = new FormData(form); button.disabled = true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'createTicket', category:data.get('category'), subject:data.get('subject'), message:data.get('message') } }); form.reset(); renderTickets((await PaxinbotAuth.request('/api/account?action=tickets')).data); window.showToast?.('Chamado aberto.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  document.getElementById('support-ticket-list')?.addEventListener('submit', async event => { const form = event.target.closest('[data-ticket-reply]'); if (!form) return; event.preventDefault(); const ticketId = form.closest('[data-ticket-id]')?.dataset.ticketId; const button = form.querySelector('[type="submit"]'); const message = new FormData(form).get('message'); button.disabled = true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'replyTicket', ticketId, message } }); renderTickets((await PaxinbotAuth.request('/api/account?action=tickets')).data); window.showToast?.('Resposta enviada.'); } catch (error) { button.disabled = false; window.showToast?.(error.message); } });
  document.getElementById('client-logout')?.addEventListener('click', async () => { try { await PaxinbotAuth.request('/api/auth/logout', { method:'POST' }); } catch {} passkeySession = null; pendingEmailCode = null; renderClientDashboard(null); await syncOwnerPanelLink(null); setAccountView('overview', false, false); history.replaceState({}, '', '/conta'); setClientStatus('Sessão encerrada.'); window.scrollTo({ top:0, behavior:'smooth' }); });
  if (currentAccount?.user) void handleCheckoutReturn();
}

async function initActivationPage() {
  const approve = document.getElementById('activate-approve'); if (!approve) return; const copy = document.getElementById('activate-copy'); const status = document.getElementById('activate-status'); const usagePanel=document.getElementById('activate-usage-panel'); const usageButton=document.getElementById('activate-usage'); const query = new URLSearchParams(location.search); const requestId = query.get('request'); const userCode = query.get('code'); let availableGrant=null; let approvalPending=false; let approvalComplete=false;
  if (!requestId || !userCode) { copy.textContent = 'A solicitação de dispositivo é inválida ou está incompleta.'; return; }
  try { const current = await PaxinbotAuth.request('/api/auth/me'); copy.textContent = `Você está conectado como ${current.user.email}. Confirme para autorizar este computador.`; approve.disabled = !current.entitlement.active; availableGrant=current.entitlement.availableGrant || null; if (!current.entitlement.active && availableGrant) { usagePanel.hidden=false; document.getElementById('activate-usage-duration').textContent=formatUsageTime(availableGrant.remainingSeconds); status.textContent='Ative o saldo antes de autorizar este computador.'; } else if (!current.entitlement.active) status.textContent = 'Esta conta ainda não possui um acesso ativo.'; else status.textContent='O Paxinbot será trazido para frente após a confirmação.'; } catch { copy.textContent = 'Entre na Área do Cliente nesta mesma janela e volte para confirmar o computador.'; status.textContent = 'A solicitação continuará válida apenas por alguns minutos.'; }
  usageButton?.addEventListener('click', async () => { if (!availableGrant) return; usageButton.disabled=true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'activateUsage', grantId:availableGrant.id } }); usagePanel.hidden=true; approve.disabled=false; status.textContent='Saldo ativado. Agora autorize este computador.'; window.showToast?.('Saldo ativado.'); } catch (error) { status.textContent=error.message || 'Não foi possível ativar o saldo.'; usageButton.disabled=false; } });
  approve.addEventListener('click', async () => { if (approvalPending || approvalComplete) return; approvalPending=true; approve.disabled=true; approve.setAttribute('aria-busy','true'); approve.textContent='Autorizando…'; try { const result = await PaxinbotAuth.request('/api/v1/devices/approve', { method:'POST', body:{ requestId, userCode } }); approvalComplete=true; copy.textContent = `Computador “${result.deviceName}” autorizado.`; status.textContent = 'Autorização concluída. O Paxinbot será trazido para frente automaticamente.'; approve.hidden=true; window.showToast?.('Computador autorizado.'); } catch (error) { approve.disabled=false; approve.removeAttribute('aria-busy'); approve.innerHTML='Autorizar computador <svg><use href="#i-check"></use></svg>'; status.textContent=error.message || 'Não foi possível autorizar este computador.'; } finally { approvalPending=false; } });
}

window.PaxinbotAuth = PaxinbotAuth; void initClientPage(); void initActivationPage();
