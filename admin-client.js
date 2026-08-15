'use strict';

const Admin = (() => {
  const routes = { overview:'/admin', customers:'/admin/clientes', access:'/admin/acessos', products:'/admin/produtos', coupons:'/admin/cupons', orders:'/admin/pedidos', tickets:'/admin/atendimento', audit:'/admin/auditoria' };
  const state = { users:[], products:[], coupons:[], orders:[], tickets:[], audit:[], currentTicket:null };
  const call = async (path, options = {}) => { const response = await fetch(`/api/admin${path}`, { method:options.method || 'GET', credentials:'include', headers:{ 'content-type':'application/json' }, body:options.body ? JSON.stringify(options.body) : undefined }); const payload = await response.json().catch(() => ({})); if (!response.ok || !payload.ok) throw new Error(payload.error || 'Não foi possível concluir a operação.'); return payload.data; };
  const escape = value => String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]);
  const money = (cents, currency = 'BRL') => new Intl.NumberFormat('pt-BR', { style:'currency', currency }).format((Number(cents) || 0) / 100);
  const date = value => value ? new Intl.DateTimeFormat('pt-BR', { dateStyle:'medium', timeStyle:'short' }).format(new Date(value)) : '—';
  const rows = (selector, html, empty, colspan) => { document.querySelector(selector).innerHTML = html || `<tr><td colspan="${colspan}">${empty}</td></tr>`; };
  const viewFromPath = () => Object.entries(routes).find(([, route]) => route === location.pathname.replace(/\/$/, ''))?.[0] || 'overview';

  function setView(view, updateUrl = true) {
    document.querySelectorAll('[data-admin-panel]').forEach(panel => { const active = panel.dataset.adminPanel === view; panel.hidden = !active; panel.classList.toggle('is-active', active); });
    document.querySelectorAll('[data-admin-view]').forEach(button => { const active = button.dataset.adminView === view; button.classList.toggle('is-active', active); button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1; });
    if (updateUrl && routes[view] && location.pathname !== routes[view]) history.pushState({ adminView:view }, '', routes[view]);
  }

  function renderOverview(data) {
    document.getElementById('admin-customers').textContent = data.customers ?? 0;
    document.getElementById('admin-accesses').textContent = data.activeAccesses ?? 0;
    document.getElementById('admin-products').textContent = data.activeProducts ?? 0;
    document.getElementById('admin-paid-orders').textContent = data.paidOrders ?? 0;
    document.getElementById('admin-revenue').textContent = money(data.revenueCents);
    document.getElementById('admin-pending-orders').textContent = data.pendingOrders ?? 0;
    document.getElementById('admin-open-tickets').textContent = data.openTickets ?? 0;
  }

  function renderUsers(users) {
    state.users = users || [];
    rows('#admin-users-list', state.users.map(user => `<tr><td>${escape(user.email)}</td><td>${date(user.created_at)}</td><td>${user.access ? escape(user.access.kind === 'lifetime' ? 'Vitalício' : 'Por tempo') : 'Sem acesso'}</td><td>${user.access?.expiresAt ? date(user.access.expiresAt) : user.access ? 'Não expira' : '—'}</td><td><div class="admin-row-actions">${user.access ? `<button class="danger" type="button" data-revoke-access="${escape(user.id)}">Revogar acesso</button>` : `<button type="button" data-grant-email="${escape(user.email)}">Liberar acesso</button>`}</div></td></tr>`).join(''), 'Nenhum cliente encontrado.', 5);
  }

  function renderProducts(products) {
    state.products = products || [];
    rows('#admin-products-list', state.products.map(product => `<tr><td>${escape(product.name)}</td><td>${escape(product.code)}</td><td>${product.access_kind === 'lifetime' ? 'Vitalício' : `${product.duration_minutes} min.`}</td><td>${money(product.price_cents)}</td><td><span class="admin-status ${product.active ? 'active' : 'paused'}">${product.active ? 'Ativo' : 'Pausado'}</span></td><td><div class="admin-row-actions"><button type="button" data-edit-product="${escape(product.id)}">Editar</button><button class="${product.active ? 'danger' : ''}" type="button" data-toggle-product="${escape(product.id)}">${product.active ? 'Pausar' : 'Reativar'}</button></div></td></tr>`).join(''), 'Nenhum produto cadastrado.', 6);
  }

  function renderCoupons(coupons) {
    state.coupons = coupons || [];
    rows('#admin-coupons-list', state.coupons.map(coupon => `<tr><td>${escape(coupon.code)}</td><td>${coupon.discount_type === 'percent' ? `${coupon.discount_value}%` : money(coupon.discount_value)}</td><td>${coupon.redemptions}${coupon.max_redemptions ? ` / ${coupon.max_redemptions}` : ''}</td><td>${coupon.expires_at ? date(coupon.expires_at) : 'Sem expiração'}</td><td><span class="admin-status ${coupon.active ? 'active' : 'paused'}">${coupon.active ? 'Ativo' : 'Pausado'}</span></td><td><div class="admin-row-actions"><button type="button" data-edit-coupon="${escape(coupon.id)}">Editar</button><button class="${coupon.active ? 'danger' : ''}" type="button" data-toggle-coupon="${escape(coupon.id)}">${coupon.active ? 'Pausar' : 'Reativar'}</button></div></td></tr>`).join(''), 'Nenhum cupom cadastrado.', 6);
  }

  function renderOrders(orders) {
    state.orders = orders || [];
    const labels = { pending:'Aguardando', paid:'Pago', refunded:'Reembolsado', cancelled:'Cancelado', chargeback:'Contestado' };
    rows('#admin-orders-list', state.orders.map(order => `<tr><td>${escape(order.email)}</td><td>${escape(order.productName || '—')}</td><td><b>${money(order.amountCents, order.currency)}</b>${Number(order.discountCents) > 0 ? `<small class="admin-cell-note">Desconto ${money(order.discountCents, order.currency)}</small>` : ''}</td><td>${order.paymentProvider === 'mercado_pago' ? 'Mercado Pago' : escape(order.paymentProvider || '—')}<small class="admin-cell-note">${escape(order.providerStatus || 'Sem retorno')}</small></td><td><span class="admin-status ${escape(order.status)}">${escape(labels[order.status] || order.status)}</span></td><td>${date(order.createdAt)}</td></tr>`).join(''), 'Nenhum pedido registrado.', 6);
  }

  function renderAudit(events) {
    state.audit = events || [];
    rows('#admin-audit-list', state.audit.map(event => `<tr><td>${escape(event.eventType)}</td><td>${escape(event.email || 'Sistema')}</td><td>${date(event.createdAt)}</td></tr>`).join(''), 'Nenhum evento de auditoria encontrado.', 3);
  }

  function renderTickets(tickets) {
    state.tickets = tickets || []; const root = document.getElementById('admin-ticket-list');
    const labels = { open:'Aberto', in_progress:'Em atendimento', resolved:'Resolvido', closed:'Encerrado' };
    if (!state.tickets.length) { root.innerHTML = '<div class="admin-empty">Nenhum chamado encontrado.</div>'; return; }
    root.innerHTML = state.tickets.map(ticket => `<article><div><span>${escape(ticket.category)}</span><h3>${escape(ticket.subject)}</h3><p>${escape(ticket.email)} · Atualizado em ${date(ticket.updatedAt)}</p></div><span class="admin-status ${escape(ticket.status)}">${escape(labels[ticket.status] || ticket.status)}</span><button type="button" data-open-ticket="${escape(ticket.id)}">Abrir conversa</button></article>`).join('');
  }

  function openTicket(ticket) {
    if (!ticket) return; state.currentTicket = ticket;
    document.getElementById('admin-ticket-title').textContent = ticket.subject; document.getElementById('admin-ticket-customer').textContent = ticket.email;
    document.getElementById('admin-ticket-status').value = ticket.status;
    document.getElementById('admin-support-thread').innerHTML = (ticket.messages || []).map(message => `<article class="${message.authorKind === 'owner' ? 'is-owner' : ''}"><b>${message.authorKind === 'owner' ? 'Você' : escape(ticket.email)}</b><p>${escape(message.body)}</p><small>${date(message.createdAt)}</small></article>`).join('');
    const replyForm = document.getElementById('admin-ticket-reply-form'); const closed = ticket.status === 'closed'; replyForm.elements.message.disabled = closed; replyForm.querySelector('[type="submit"]').hidden = closed; const dialog = document.getElementById('admin-ticket-dialog'); if (!dialog.open) dialog.showModal();
  }

  function exportOrders() {
    if (!state.orders.length) return window.showToast?.('Não há pedidos para exportar.');
    const safe = value => { let text = String(value ?? '').replace(/"/g, '""'); if (/^[=+\-@]/.test(text)) text = `'${text}`; return `"${text}"`; };
    const labels = { pending:'Aguardando', paid:'Pago', refunded:'Reembolsado', cancelled:'Cancelado', chargeback:'Contestado' };
    const lines = [['Pedido','Cliente','Produto','Valor','Moeda','Desconto','Status','Provedor','Criado em','Pago em'], ...state.orders.map(order => [order.id,order.email,order.productName,Number(order.amountCents)/100,order.currency,Number(order.discountCents||0)/100,labels[order.status]||order.status,order.paymentProvider||'',order.createdAt,order.paidAt||''])];
    const blob = new Blob([`\uFEFF${lines.map(line => line.map(safe).join(';')).join('\r\n')}`], { type:'text/csv;charset=utf-8' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `paxinbot-pedidos-${new Date().toISOString().slice(0,10)}.csv`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  async function loadAll() {
    const [overview, users, products, coupons] = await Promise.all([call('?action=overview'), call('?action=users'), call('?action=products'), call('?action=coupons')]);
    renderOverview(overview); renderUsers(users); renderProducts(products); renderCoupons(coupons);
    const [orders, tickets, audit] = await Promise.all([call('?action=orders').catch(() => []), call('?action=tickets').catch(() => []), call('?action=audit').catch(() => [])]);
    renderOrders(orders); renderTickets(tickets); renderAudit(audit);
  }

  function configureProductForm(product = null) {
    const form = document.getElementById('admin-product-form'); form.reset();
    form.elements.id.value = product?.id || ''; form.elements.name.value = product?.name || ''; form.elements.code.value = product?.code || ''; form.elements.accessKind.value = product?.access_kind || 'duration'; form.elements.durationMinutes.value = product?.duration_minutes || ''; form.elements.price.value = product ? (Number(product.price_cents) / 100).toFixed(2) : ''; form.elements.description.value = product?.description || ''; form.elements.active.checked = product ? Boolean(product.active) : true;
    document.getElementById('product-dialog-title').textContent = product ? 'Editar produto' : 'Novo produto'; updateDurationField(); document.getElementById('product-dialog').showModal();
  }

  function configureCouponForm(coupon = null) {
    const form = document.getElementById('admin-coupon-form'); form.reset();
    form.elements.id.value = coupon?.id || ''; form.elements.code.value = coupon?.code || ''; form.elements.description.value = coupon?.description || ''; form.elements.discountType.value = coupon?.discount_type || 'percent'; form.elements.discountValue.value = coupon ? (coupon.discount_type === 'fixed' ? Number(coupon.discount_value) / 100 : coupon.discount_value) : ''; form.elements.maxRedemptions.value = coupon?.max_redemptions || ''; form.elements.expiresAt.value = coupon?.expires_at ? coupon.expires_at.slice(0,10) : ''; form.elements.active.checked = coupon ? Boolean(coupon.active) : true;
    document.getElementById('coupon-dialog-title').textContent = coupon ? 'Editar cupom' : 'Novo cupom'; document.getElementById('coupon-dialog').showModal();
  }

  function updateDurationField() {
    const form = document.getElementById('admin-product-form'); const lifetime = form.elements.accessKind.value === 'lifetime'; const field = form.querySelector('[data-duration-field]'); field.hidden = lifetime; form.elements.durationMinutes.required = !lifetime; if (lifetime) form.elements.durationMinutes.value = '';
  }

  function updateAccessExpiry() {
    const form = document.getElementById('admin-access-form'); const lifetime = form.elements.kind.value === 'lifetime'; form.querySelector('[data-access-expiry]').hidden = lifetime; form.elements.expiresAt.required = !lifetime; if (lifetime) form.elements.expiresAt.value = '';
  }

  async function submitAction(form, body, after) {
    const button = form.querySelector('[type="submit"]'); button.disabled = true;
    try { await call('', { method:'POST', body }); window.showToast?.('Alterações salvas.'); await after(); }
    catch (error) { window.showToast?.(error.message); }
    finally { button.disabled = false; }
  }

  function bind() {
    document.querySelectorAll('[data-admin-view]').forEach(button => button.addEventListener('click', () => setView(button.dataset.adminView)));
    document.querySelectorAll('[data-admin-open]').forEach(button => button.addEventListener('click', () => setView(button.dataset.adminOpen)));
    window.addEventListener('popstate', () => setView(viewFromPath(), false));
    document.querySelectorAll('[data-close-dialog]').forEach(button => button.addEventListener('click', () => document.getElementById(button.dataset.closeDialog).close()));
    document.getElementById('new-product').addEventListener('click', () => configureProductForm());
    document.getElementById('new-coupon').addEventListener('click', () => configureCouponForm());
    document.getElementById('admin-product-form').elements.accessKind.addEventListener('change', updateDurationField);
    document.getElementById('admin-access-form').elements.kind.addEventListener('change', updateAccessExpiry); updateAccessExpiry();
    document.getElementById('admin-user-search').addEventListener('submit', async event => { event.preventDefault(); try { renderUsers(await call(`?action=users&q=${encodeURIComponent(new FormData(event.currentTarget).get('query') || '')}`)); } catch (error) { window.showToast?.(error.message); } });
    document.getElementById('admin-product-form').addEventListener('submit', event => { event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); submitAction(form, { action:'product', id:data.get('id') || null, code:data.get('code'), name:data.get('name'), description:data.get('description'), accessKind:data.get('accessKind'), durationMinutes:data.get('accessKind') === 'lifetime' ? null : Number(data.get('durationMinutes')), priceCents:Math.round(Number(data.get('price')) * 100), active:data.get('active') === 'on' }, async () => { document.getElementById('product-dialog').close(); renderProducts(await call('?action=products')); renderOverview(await call('?action=overview')); }); });
    document.getElementById('admin-coupon-form').addEventListener('submit', event => { event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); submitAction(form, { action:'coupon', id:data.get('id') || null, code:data.get('code'), description:data.get('description'), discountType:data.get('discountType'), discountValue:data.get('discountType') === 'percent' ? Number(data.get('discountValue')) : Math.round(Number(data.get('discountValue')) * 100), maxRedemptions:data.get('maxRedemptions') || null, expiresAt:data.get('expiresAt') ? new Date(`${data.get('expiresAt')}T23:59:59`).toISOString() : null, active:data.get('active') === 'on' }, async () => { document.getElementById('coupon-dialog').close(); renderCoupons(await call('?action=coupons')); }); });
    document.getElementById('admin-access-form').addEventListener('submit', event => { event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); submitAction(form, { action:'access', email:data.get('email'), kind:data.get('kind'), expiresAt:data.get('kind') === 'lifetime' ? null : new Date(data.get('expiresAt')).toISOString() }, async () => { form.reset(); updateAccessExpiry(); renderUsers(await call('?action=users')); renderOverview(await call('?action=overview')); }); });
    document.getElementById('admin-products-list').addEventListener('click', async event => { const edit = event.target.closest('[data-edit-product]'); const toggle = event.target.closest('[data-toggle-product]'); if (edit) configureProductForm(state.products.find(item => item.id === edit.dataset.editProduct)); if (toggle) { const product = state.products.find(item => item.id === toggle.dataset.toggleProduct); if (!product) return; toggle.disabled = true; try { await call('', { method:'POST', body:{ action:'product', id:product.id, code:product.code, name:product.name, description:product.description, accessKind:product.access_kind, durationMinutes:product.duration_minutes, priceCents:product.price_cents, active:!product.active } }); renderProducts(await call('?action=products')); renderOverview(await call('?action=overview')); } catch (error) { toggle.disabled = false; window.showToast?.(error.message); } } });
    document.getElementById('admin-coupons-list').addEventListener('click', async event => { const edit = event.target.closest('[data-edit-coupon]'); const toggle = event.target.closest('[data-toggle-coupon]'); if (edit) configureCouponForm(state.coupons.find(item => item.id === edit.dataset.editCoupon)); if (toggle) { const coupon = state.coupons.find(item => item.id === toggle.dataset.toggleCoupon); if (!coupon) return; toggle.disabled = true; try { await call('', { method:'POST', body:{ action:'coupon', id:coupon.id, code:coupon.code, description:coupon.description, discountType:coupon.discount_type, discountValue:coupon.discount_value, maxRedemptions:coupon.max_redemptions, expiresAt:coupon.expires_at, active:!coupon.active } }); renderCoupons(await call('?action=coupons')); } catch (error) { toggle.disabled = false; window.showToast?.(error.message); } } });
    document.getElementById('admin-users-list').addEventListener('click', async event => { const grant = event.target.closest('[data-grant-email]'); const revoke = event.target.closest('[data-revoke-access]'); if (grant) { setView('access'); document.getElementById('admin-access-form').elements.email.value = grant.dataset.grantEmail; } if (revoke && confirm('Revogar o acesso e as sessões deste cliente?')) { revoke.disabled = true; try { await call('', { method:'POST', body:{ action:'revokeAccess', userId:revoke.dataset.revokeAccess } }); renderUsers(await call('?action=users')); renderOverview(await call('?action=overview')); window.showToast?.('Acesso revogado.'); } catch (error) { revoke.disabled = false; window.showToast?.(error.message); } } });
    document.getElementById('admin-export-orders').addEventListener('click', exportOrders);
    document.getElementById('admin-ticket-list').addEventListener('click', event => { const button = event.target.closest('[data-open-ticket]'); if (button) openTicket(state.tickets.find(ticket => ticket.id === button.dataset.openTicket)); });
    document.getElementById('admin-ticket-status').addEventListener('change', async event => { if (!state.currentTicket) return; event.currentTarget.disabled = true; try { await call('', { method:'POST', body:{ action:'ticketStatus', ticketId:state.currentTicket.id, status:event.currentTarget.value } }); renderTickets(await call('?action=tickets')); renderOverview(await call('?action=overview')); document.getElementById('admin-ticket-dialog').close(); window.showToast?.('Status atualizado.'); } catch (error) { event.currentTarget.disabled = false; window.showToast?.(error.message); } });
    document.getElementById('admin-ticket-reply-form').addEventListener('submit', async event => { event.preventDefault(); if (!state.currentTicket) return; const form = event.currentTarget; const button = form.querySelector('[type="submit"]'); const message = new FormData(form).get('message'); button.disabled = true; try { await call('', { method:'POST', body:{ action:'ticketReply', ticketId:state.currentTicket.id, message } }); form.reset(); const id = state.currentTicket.id; renderTickets(await call('?action=tickets')); renderOverview(await call('?action=overview')); openTicket(state.tickets.find(ticket => ticket.id === id)); window.showToast?.('Resposta enviada.'); } catch (error) { window.showToast?.(error.message); } finally { button.disabled = false; } });
  }

  async function init() {
    const content = document.getElementById('admin-content'); const gate = document.getElementById('admin-gate'); content.setAttribute('aria-busy', 'true');
    try { await loadAll(); bind(); setView(viewFromPath(), false); content.hidden = false; gate.hidden = true; }
    catch (error) { content.hidden = true; gate.hidden = false; document.getElementById('admin-gate-message').textContent = error.message || 'Não foi possível validar o acesso ao painel.'; }
    finally { content.removeAttribute('aria-busy'); }
  }
  return { init };
})();

void Admin.init();
