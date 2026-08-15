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

const accountRoutes = { overview: '/conta', subscription: '/conta/assinatura', downloads: '/conta/downloads', account: '/conta/configuracoes', support: '/conta/suporte' };
const accountSectionRoutes = { profile: '/conta/configuracoes', security: '/conta/configuracoes/seguranca', devices: '/conta/configuracoes/dispositivos', preferences:'/conta/configuracoes/notificacoes', activity:'/conta/configuracoes/atividade' };
let passkeySession = null;
let passkeyClient = null;
let currentAccount = null;
let availableProducts = [];
let checkoutProduct = null;
let currentOrderId = null;
let pendingEmailCode = null;

function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]); }
function formatDate(value, withTime = true) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat('pt-BR', withTime ? { dateStyle:'medium', timeStyle:'short' } : { dateStyle:'medium' }).format(date); }
function money(cents, currency = 'BRL') { return new Intl.NumberFormat('pt-BR', { style:'currency', currency }).format((Number(cents) || 0) / 100); }
function formatUsageTime(value) { const seconds = Math.max(0, Math.floor(Number(value) || 0)); const days = Math.floor(seconds / 86400); const hours = Math.floor((seconds % 86400) / 3600); const minutes = Math.ceil((seconds % 3600) / 60); const parts = []; if (days) parts.push(`${days} ${days === 1 ? 'dia' : 'dias'}`); if (hours) parts.push(`${hours} ${hours === 1 ? 'hora' : 'horas'}`); if (minutes && parts.length < 2) parts.push(`${minutes} min`); return parts.join(' e ') || 'menos de 1 minuto'; }
function remainingUntil(value) { const timestamp = value ? new Date(value).valueOf() : NaN; return Number.isFinite(timestamp) ? Math.max(0, Math.ceil((timestamp - Date.now()) / 1000)) : 0; }

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
  document.getElementById('dashboard-access').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Vitalício' : entitlement.kind === 'usage' ? 'Saldo em uso' : 'Por tempo') : entitlement.availableGrant ? 'Saldo disponível' : 'Sem acesso';
  document.getElementById('dashboard-access-state').textContent = entitlement.active ? 'Ativo' : entitlement.availableGrant ? 'Aguardando sua ativação' : user ? 'Aguardando liberação' : 'Aguardando login';
  const remaining = entitlement.kind === 'usage' ? Number(entitlement.remainingSeconds) || 0 : remainingUntil(entitlement.expiresAt);
  document.getElementById('dashboard-expiry').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Não expira' : formatUsageTime(remaining)) : '—';
  document.getElementById('dashboard-expiry-state').textContent = entitlement.kind === 'usage' ? 'Diminui somente com o app conectado' : entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : 'Acesso antigo: contagem contínua') : 'Sem dados';
  document.getElementById('subscription-plan').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : entitlement.kind === 'usage' ? 'Saldo de uso ativo' : 'Acesso por tempo') : 'Sem acesso ativo';
  document.getElementById('subscription-expiry').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Este acesso não expira.' : entitlement.kind === 'usage' ? `${formatUsageTime(remaining)} restantes. O saldo pausa quando o aplicativo é fechado.` : `${formatUsageTime(remaining)} restantes neste acesso antigo.`) : 'Escolha uma modalidade para começar.';
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

function viewFromPath() {
  const path = location.pathname.replace(/\/$/, '') || '/conta';
  if (Object.values(accountSectionRoutes).includes(path) || ['/conta/seguranca','/conta/dispositivos'].includes(path)) return 'account';
  return Object.entries(accountRoutes).find(([, route]) => route === path)?.[0] || 'overview';
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
  document.getElementById('order-resume').hidden = order.status !== 'pending'; document.getElementById('order-receipt').hidden = order.status !== 'paid';
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
}

function openCheckout(productId) {
  checkoutProduct = availableProducts.find(product => product.id === productId) || null;
  if (!checkoutProduct) return window.showToast?.('Esta modalidade não está mais disponível.');
  document.getElementById('checkout-product-name').textContent = checkoutProduct.name;
  document.getElementById('checkout-product-duration').textContent = productDuration(checkoutProduct);
  document.getElementById('checkout-product-price').textContent = money(checkoutProduct.priceCents);
  document.getElementById('checkout-coupon').value = '';
  document.getElementById('checkout-dialog').showModal();
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
  const [devices, orders, products, preferences, activity, tickets, usageGrants] = await Promise.all([
    PaxinbotAuth.request('/api/account?action=devices').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=orders').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=products').then(result => ({ data:result.data, checkoutReady:result.checkoutReady })).catch(error => ({ error:error.message })),
    PaxinbotAuth.request('/api/account?action=preferences').then(result => result.data).catch(() => ({})),
    PaxinbotAuth.request('/api/account?action=activity').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=tickets').then(result => result.data).catch(() => []),
    PaxinbotAuth.request('/api/account?action=usageGrants').then(result => result.data).catch(() => [])
  ]);
  renderDevices(devices); renderOrders(orders); renderProducts(products.data, products.error, products.checkoutReady);
  renderPreferences(preferences); renderActivity(activity); renderTickets(tickets); renderUsageGrants(usageGrants);
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
  try { const client = await getPasskeyClient(); const { data, error } = await client.auth.signInWithPasskey(); if (error) throw new Error(friendlyPasskeyError(error)); await bridgeSession(data.session); const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); setAccountView('overview'); setClientStatus('Conta conectada com passkey.', true); window.showToast?.('Login concluído.'); }
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
  const returningFromCheckout = new URLSearchParams(location.search).has('checkout'); setAccountView(returningFromCheckout ? 'subscription' : 'overview', false, !returningFromCheckout);
  setClientStatus('Conta conectada ao serviço seguro.', true); window.showToast?.(message); document.getElementById('client-password').value = ''; document.getElementById('client-email-code-form').reset(); void handleCheckoutReturn();
}

async function initClientPage() {
  const form = document.getElementById('client-login-form'); if (!form) return; const submit = form.querySelector('[type="submit"]'); consumePasskeySession();
  try { const current = await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); await syncOwnerPanelLink(current.user); setAccountView(viewFromPath(), false, false); setAccountSection(accountSectionFromPath(), false, false); setClientStatus('Conta conectada ao serviço seguro.', true); } catch { renderClientDashboard(null); await syncOwnerPanelLink(null); setClientStatus('Entre com sua conta Paxinbot para continuar.'); }
  form.addEventListener('submit', async event => { event.preventDefault(); submit.disabled = true; try { const data = new FormData(form); const result = await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:data.get('email'), password:data.get('password') } }); if (result.verificationRequired) return setEmailCodeStep(result, 'login'); await completeClientLogin(result); } catch (error) { setClientStatus(error.message || 'Não foi possível entrar.'); window.showToast?.(error.message || 'Não foi possível entrar.'); } finally { submit.disabled = false; } });
  document.getElementById('client-email-code-form')?.addEventListener('submit', async event => { event.preventDefault(); if (!pendingEmailCode) return cancelEmailCode(); const codeForm = event.currentTarget; const button = codeForm.querySelector('[type="submit"]'); const status = document.getElementById('client-email-code-status'); const code = new FormData(codeForm).get('code'); button.disabled = true; status.textContent = ''; status.classList.remove('is-error'); try { const result = await PaxinbotAuth.request('/api/auth/verify-email-code', { method:'POST', body:{ code } }); await completeClientLogin(result, pendingEmailCode?.purpose === 'signup' ? 'E-mail confirmado e conta criada.' : 'Verificação concluída.'); } catch (error) { status.textContent = error.message || 'Não foi possível confirmar o código.'; status.classList.add('is-error'); setClientStatus(error.message || 'Não foi possível confirmar o código.'); } finally { button.disabled = false; } });
  document.getElementById('client-email-code-resend')?.addEventListener('click', async event => { const button = event.currentTarget; const status = document.getElementById('client-email-code-status'); button.disabled = true; status.classList.remove('is-error'); try { const result = await PaxinbotAuth.request('/api/auth/resend-email-code', { method:'POST' }); status.textContent = result.message; } catch (error) { status.textContent = error.message; status.classList.add('is-error'); } finally { button.disabled = false; } });
  document.getElementById('client-email-code-cancel')?.addEventListener('click', cancelEmailCode);
  document.getElementById('client-signup-form')?.addEventListener('submit', async event => { event.preventDefault(); const signup = event.currentTarget; const submitButton = signup.querySelector('[type="submit"]'); const data = new FormData(signup); if (data.get('password') !== data.get('passwordConfirm')) return window.showToast?.('As senhas precisam ser iguais.'); submitButton.disabled = true; try { const result = await PaxinbotAuth.request('/api/auth/signup', { method:'POST', body:{ email:data.get('email'), password:data.get('password') } }); setClientStatus(result.message, true); signup.reset(); if (result.verificationRequired) return setEmailCodeStep(result, 'signup'); await completeClientLogin(result, 'Conta criada.'); } catch (error) { setClientStatus(error.message || 'Não foi possível criar a conta.'); window.showToast?.(error.message || 'Não foi possível criar a conta.'); } finally { submitButton.disabled = false; } });
  document.getElementById('auth-switch')?.addEventListener('click', () => setAuthMode(document.getElementById('client-login-form').hidden ? 'login' : 'signup'));
  document.getElementById('passkey-login')?.addEventListener('click', () => loginWithPasskey().catch(error => window.showToast?.(error.message)));
  document.getElementById('passkey-register')?.addEventListener('click', () => registerPasskey().catch(error => window.showToast?.(error.message)));
  document.getElementById('passkey-password-confirm')?.addEventListener('click', async () => { const password = document.getElementById('passkey-password').value; if (!currentAccount?.user?.email || !password) return window.showToast?.('Informe sua senha.'); try { const result = await PaxinbotAuth.request('/api/auth/login', { method:'POST', body:{ email:currentAccount.user.email, password, purpose:'passkey' } }); document.getElementById('passkey-dialog').close(); document.getElementById('passkey-password').value = ''; if (result.verificationRequired) { pendingEmailCode = { purpose:'passkey' }; document.getElementById('security-code-copy').textContent = `${result.message}${result.emailMasked ? ` Destino: ${result.emailMasked}.` : ''}`; document.getElementById('security-code-status').textContent = ''; document.getElementById('security-code-dialog').showModal(); return; } } catch (error) { window.showToast?.(error.message); } });
  document.querySelectorAll('[data-account-view]').forEach(button => button.addEventListener('click', () => { setAccountView(button.dataset.accountView); if (button.dataset.accountView === 'account') setAccountSection('profile', false, false); }));
  document.querySelectorAll('[data-account-section]').forEach(button => button.addEventListener('click', () => setAccountSection(button.dataset.accountSection)));
  document.querySelectorAll('[data-account-open]').forEach(button => button.addEventListener('click', () => { const section = button.dataset.accountSectionOpen; setAccountView(button.dataset.accountOpen, true, !section); if (section) setAccountSection(section, false, true); }));
  document.getElementById('view-account-products')?.addEventListener('click', () => document.getElementById('account-products-list')?.scrollIntoView({ behavior:'smooth', block:'center' }));
  document.getElementById('activate-usage-credit')?.addEventListener('click', async event => { const card=document.getElementById('usage-credit-card'); const grantId=card?.dataset.grantId; if (!grantId || !confirm('Ativar este saldo agora? Depois da ativação, ele será consumido enquanto o aplicativo estiver conectado.')) return; event.currentTarget.disabled=true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'activateUsage', grantId } }); const current=await PaxinbotAuth.request('/api/auth/me'); await loadPortalData(current); window.showToast?.('Saldo ativado. Agora você pode autorizar o aplicativo.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled=false; } });
  document.getElementById('account-products-list')?.addEventListener('click', event => { const button = event.target.closest('[data-buy-product]'); if (button) openCheckout(button.dataset.buyProduct); });
  document.getElementById('account-order-list')?.addEventListener('click', event => { const button = event.target.closest('[data-order-details]'); if (button) openOrderDetails(button.dataset.orderDetails).catch(error => window.showToast?.(error.message)); });
  document.querySelector('[data-close-checkout]')?.addEventListener('click', () => document.getElementById('checkout-dialog').close());
  document.querySelector('[data-close-order]')?.addEventListener('click', () => document.getElementById('order-dialog').close());
  document.getElementById('checkout-form')?.addEventListener('submit', async event => {
    event.preventDefault(); if (!checkoutProduct) return;
    const button = document.getElementById('checkout-submit'); button.disabled = true; button.textContent = 'Preparando pagamento…';
    try {
      const couponCode = document.getElementById('checkout-coupon').value.trim().toUpperCase();
      const result = await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ productId:checkoutProduct.id, couponCode } });
      location.assign(result.checkoutUrl);
    } catch (error) {
      button.disabled = false; button.innerHTML = 'Ir para o Mercado Pago <svg><use href="#i-arrow"></use></svg>'; window.showToast?.(error.message);
    }
  });
  document.getElementById('order-resume')?.addEventListener('click', async event => { if (!currentOrderId) return; event.currentTarget.disabled = true; try { const result = await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ action:'resume', orderId:currentOrderId } }); location.assign(result.checkoutUrl); } catch (error) { event.currentTarget.disabled = false; window.showToast?.(error.message); } });
  document.getElementById('order-receipt')?.addEventListener('click', async event => { if (!currentOrderId) return; event.currentTarget.disabled = true; try { await PaxinbotAuth.request('/api/checkout', { method:'POST', body:{ action:'receipt', orderId:currentOrderId } }); window.showToast?.('Comprovante enviado para o e-mail da conta.'); } catch (error) { window.showToast?.(error.message); } finally { event.currentTarget.disabled = false; } });
  document.querySelector('.portal-nav')?.addEventListener('keydown', event => { if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return; const tabs = [...document.querySelectorAll('[data-account-view]')]; const current = tabs.indexOf(document.activeElement); if (current < 0) return; event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length; setAccountView(tabs[next].dataset.accountView, true); });
  window.addEventListener('popstate', () => { setAccountView(viewFromPath(), false, false); setAccountSection(accountSectionFromPath(), false, false); });
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
  const approve = document.getElementById('activate-approve'); if (!approve) return; const openApp = document.getElementById('activate-open-app'); const copy = document.getElementById('activate-copy'); const status = document.getElementById('activate-status'); const note = document.getElementById('activate-login-note'); const usagePanel=document.getElementById('activate-usage-panel'); const usageButton=document.getElementById('activate-usage'); const query = new URLSearchParams(location.search); const requestId = query.get('request'); const userCode = query.get('code'); let availableGrant=null;
  if (!requestId || !userCode) { copy.textContent = 'A solicitação de dispositivo é inválida ou está incompleta.'; return; }
  try { const current = await PaxinbotAuth.request('/api/auth/me'); copy.textContent = `Você está conectado como ${current.user.email}. Confirme para autorizar este computador.`; note.hidden = true; approve.disabled = !current.entitlement.active; availableGrant=current.entitlement.availableGrant || null; if (!current.entitlement.active && availableGrant) { usagePanel.hidden=false; document.getElementById('activate-usage-duration').textContent=formatUsageTime(availableGrant.remainingSeconds); status.textContent='Ative o saldo antes de autorizar este computador.'; } else if (!current.entitlement.active) status.textContent = 'Esta conta ainda não possui um acesso ativo.'; } catch { copy.textContent = 'Entre na Área do Cliente nesta mesma janela e volte para confirmar o computador.'; status.textContent = 'A solicitação continuará válida apenas por alguns minutos.'; }
  usageButton?.addEventListener('click', async () => { if (!availableGrant) return; usageButton.disabled=true; try { await PaxinbotAuth.request('/api/account', { method:'POST', body:{ action:'activateUsage', grantId:availableGrant.id } }); usagePanel.hidden=true; approve.disabled=false; status.textContent='Saldo ativado. Agora autorize este computador.'; window.showToast?.('Saldo ativado.'); } catch (error) { status.textContent=error.message || 'Não foi possível ativar o saldo.'; usageButton.disabled=false; } });
  approve.addEventListener('click', async () => { approve.disabled = true; try { const result = await PaxinbotAuth.request('/api/v1/devices/approve', { method:'POST', body:{ requestId, userCode } }); copy.textContent = `Computador “${result.deviceName}” autorizado.`; status.textContent = 'Confirme no navegador para retornar ao Paxinbot.'; approve.hidden = true; openApp.hidden = false; window.showToast?.('Computador autorizado.'); window.location.assign('paxinbot://auth-complete'); } catch (error) { approve.disabled = false; status.textContent = error.message || 'Não foi possível autorizar este computador.'; } });
}

window.PaxinbotAuth = PaxinbotAuth; void initClientPage(); void initActivationPage();
