'use strict';

// Publicado no mesmo domínio da API. O fallback local permite validar o fluxo
// antes de configurar DNS e hospedagem.
const PaxinbotAuth = (() => {
  const baseUrl = location.protocol === 'file:' ? 'http://127.0.0.1:8787' : location.origin;
  const request = async (route, options = {}) => {
    const response = await fetch(`${baseUrl}${route}`, {
      method: options.method || 'GET', credentials: 'include',
      headers: { 'content-type': 'application/json', ...(options.headers || {}) },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    let payload = null;
    try { payload = await response.json(); } catch {}
    if (!response.ok || payload?.ok === false) throw Object.assign(new Error(payload?.error || 'Não foi possível concluir a operação.'), { code: payload?.code, status: response.status });
    return payload;
  };
  return { baseUrl, request };
})();

function setClientStatus(message, active = false) {
  const box = document.getElementById('auth-service-status');
  if (!box) return;
  box.classList.toggle('is-active', active);
  box.querySelector('span').textContent = message;
}

function renderClientDashboard(payload) {
  const user = payload?.user; const entitlement = payload?.entitlement || {};
  const email = String(user?.email || ''); const name = email ? email.split('@')[0] : 'Cliente';
  document.getElementById('dashboard-initials').textContent = (name.slice(0, 2).toUpperCase() || 'PB');
  document.getElementById('dashboard-email').textContent = email || 'Entre para consultar';
  document.getElementById('dashboard-greeting').textContent = user ? `Olá, ${name}` : 'Entre na sua conta';
  document.getElementById('dashboard-access').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Vitalício' : 'Por tempo') : 'Sem acesso';
  document.getElementById('dashboard-access-state').textContent = entitlement.active ? 'Ativo' : 'Aguardando liberação';
  const expires = entitlement.expiresAt ? new Intl.DateTimeFormat('pt-BR', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(entitlement.expiresAt)) : 'Não expira';
  document.getElementById('dashboard-expiry').textContent = entitlement.active ? expires : '—';
  document.getElementById('dashboard-expiry-state').textContent = entitlement.active ? (entitlement.kind === 'lifetime' ? 'Acesso vitalício' : 'Definido pelo acesso contratado') : 'Sem dados';
  document.getElementById('client-logout').hidden = !user;
}

async function initClientPage() {
  const form = document.getElementById('client-login-form');
  if (!form) return;
  const submit = form.querySelector('[type="submit"]');
  try {
    const current = await PaxinbotAuth.request('/api/auth/me');
    renderClientDashboard(current); setClientStatus('Conta conectada ao serviço seguro.', true);
  } catch {
    renderClientDashboard(null); setClientStatus('Entre com sua conta Paxinbot para continuar.');
  }
  form.addEventListener('submit', async event => {
    event.preventDefault(); submit.disabled = true;
    try {
      const data = new FormData(form);
      await PaxinbotAuth.request('/api/auth/login', { method: 'POST', body: { email: data.get('email'), password: data.get('password') } });
      const current = await PaxinbotAuth.request('/api/auth/me');
      renderClientDashboard(current); setClientStatus('Conta conectada ao serviço seguro.', true);
      window.showToast?.('Login realizado com segurança.'); document.getElementById('client-password').value = '';
    } catch (error) {
      setClientStatus(error.message || 'Não foi possível entrar.'); window.showToast?.(error.message || 'Não foi possível entrar.');
    } finally { submit.disabled = false; }
  });
  document.getElementById('client-logout')?.addEventListener('click', async () => {
    try { await PaxinbotAuth.request('/api/auth/logout', { method: 'POST' }); } catch {}
    renderClientDashboard(null); setClientStatus('Sessão encerrada.');
  });
}

async function initActivationPage() {
  const approve = document.getElementById('activate-approve');
  if (!approve) return;
  const copy = document.getElementById('activate-copy'); const status = document.getElementById('activate-status'); const note = document.getElementById('activate-login-note');
  const query = new URLSearchParams(location.search); const requestId = query.get('request'); const userCode = query.get('code');
  if (!requestId || !userCode) { copy.textContent = 'A solicitação de dispositivo é inválida ou está incompleta.'; return; }
  try {
    const current = await PaxinbotAuth.request('/api/auth/me');
    copy.textContent = `Você está conectado como ${current.user.email}. Confirme para autorizar este computador.`;
    note.hidden = true; approve.disabled = !current.entitlement.active;
    if (!current.entitlement.active) status.textContent = 'Esta conta ainda não possui um acesso ativo.';
  } catch {
    copy.textContent = 'Entre na Área do Cliente nesta mesma janela e volte para confirmar o computador.';
    status.textContent = 'A solicitação continuará válida apenas por alguns minutos.';
  }
  approve.addEventListener('click', async () => {
    approve.disabled = true;
    try {
      const result = await PaxinbotAuth.request('/api/v1/devices/approve', { method: 'POST', body: { requestId, userCode } });
      copy.textContent = `Computador “${result.deviceName}” autorizado.`; status.textContent = 'Você já pode voltar ao Paxinbot.'; window.showToast?.('Computador autorizado.');
    } catch (error) { approve.disabled = false; status.textContent = error.message || 'Não foi possível autorizar este computador.'; }
  });
}

window.PaxinbotAuth = PaxinbotAuth;
void initClientPage();
void initActivationPage();
