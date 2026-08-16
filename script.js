'use strict';

const header = document.querySelector('.site-header');
const menuButton = document.querySelector('.menu-button');
const navigation = document.querySelector('.main-nav');
const modal = document.getElementById('login-modal');
const toast = document.querySelector('.toast');
const PUBLIC_CHECKOUT_INTENT_KEY = 'paxinbot_checkout_intent';
let toastTimer = null;

function setHeaderState() {
  header?.classList.toggle('scrolled', window.scrollY > 12);
}

function closeMenu() {
  navigation?.classList.remove('open');
  menuButton?.setAttribute('aria-expanded', 'false');
}

function openModal() {
  if (!modal) return;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.body.classList.add('modal-open');
  window.setTimeout(() => modal.querySelector('input')?.focus(), 120);
}

function closeModal() {
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('modal-open');
}

function showToast(message) {
  if (!toast) return;
  toast.querySelector('span').textContent = message;
  toast.classList.add('show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3200);
}
window.showToast = showToast;

window.addEventListener('scroll', setHeaderState, { passive: true });
setHeaderState();

menuButton?.addEventListener('click', () => {
  const isOpen = navigation?.classList.toggle('open') === true;
  menuButton.setAttribute('aria-expanded', String(isOpen));
});

navigation?.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
document.querySelectorAll('.js-open-login').forEach(button => button.addEventListener('click', openModal));
document.querySelectorAll('.js-close-modal').forEach(button => button.addEventListener('click', closeModal));

document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    closeModal();
    closeMenu();
  }
});

document.querySelector('.js-preview')?.addEventListener('click', () => {
  window.location.href = '/conta';
});

document.querySelector('.js-download')?.addEventListener('click', () => {
  window.location.href = '/api/account?action=download&redirect=1';
});

document.querySelector('.js-support')?.addEventListener('click', () => { window.location.href = '/ajuda'; });

function searchHelp() {
  const input = document.getElementById('help-search-input');
  const status = document.getElementById('help-search-status');
  if (!input || !status) return;
  const query = input.value.trim().toLocaleLowerCase('pt-BR');
  const articles = [...document.querySelectorAll('.faq-list details')];
  let matches = 0;
  articles.forEach(article => {
    const found = !query || article.textContent.toLocaleLowerCase('pt-BR').includes(query);
    article.hidden = !found;
    if (found) { matches += 1; article.open = Boolean(query); }
  });
  status.textContent = query ? (matches ? `${matches} resultado${matches === 1 ? '' : 's'} encontrado${matches === 1 ? '' : 's'}.` : 'Nenhuma resposta encontrada. Tente outro termo.') : 'Digite um termo para pesquisar.';
  if (matches && query) document.querySelector('.faq-list details:not([hidden])')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}
document.querySelector('.js-help-search')?.addEventListener('click', searchHelp);
document.getElementById('help-search-input')?.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); searchHelp(); } });

document.querySelector('.js-forgot')?.addEventListener('click', async () => {
  const email = document.getElementById('client-email')?.value?.trim();
  if (!email) return showToast('Informe seu e-mail para receber as instruções.');
  try {
    await window.PaxinbotAuth?.request('/api/auth/recover', { method: 'POST', body: { email } });
    showToast('Se houver uma conta, enviaremos as instruções para o e-mail informado.');
  } catch { showToast('Não foi possível iniciar a recuperação agora.'); }
});

document.querySelector('.js-create-account')?.addEventListener('click', () => { window.location.href = '/planos'; });

document.querySelectorAll('[data-password-toggle]').forEach(button => {
  button.addEventListener('click', () => {
    const field = document.querySelector(button.dataset.passwordToggle || '');
    if (!(field instanceof HTMLInputElement)) return;
    const willShow = field.type === 'password';
    field.type = willShow ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(willShow));
    button.setAttribute('aria-label', willShow ? 'Ocultar senha' : 'Mostrar senha');
    button.querySelector('use')?.setAttribute('href', willShow ? '#i-eye-off' : '#i-eye');
    button.classList.remove('is-animating');
    void button.offsetWidth;
    button.classList.add('is-animating');
  });
  button.addEventListener('animationend', () => button.classList.remove('is-animating'));
});


document.querySelectorAll('.billing-switch button').forEach(button => button.addEventListener('click', () => document.querySelectorAll('.billing-switch button').forEach(item => item.classList.toggle('active', item === button))));

function catalogEscape(value) { return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]); }
function catalogMoney(cents) { return new Intl.NumberFormat('pt-BR', { style:'currency', currency:'BRL' }).format((Number(cents) || 0) / 100); }
function catalogDuration(product) {
  if (product.accessKind === 'lifetime') return 'SEM EXPIRAÇÃO';
  const minutes = Number(product.durationMinutes) || 0;
  if (minutes >= 1440 && minutes % 1440 === 0) { const days = minutes / 1440; return `${days} ${days === 1 ? 'DIA' : 'DIAS'}`; }
  if (minutes >= 60 && minutes % 60 === 0) { const hours = minutes / 60; return `${hours} ${hours === 1 ? 'HORA' : 'HORAS'}`; }
  return `${minutes} MINUTOS`;
}
async function loadPublicCatalog() {
  const root = document.getElementById('public-products-list'); if (!root) return;
  try {
    const response = await fetch('/api/catalog'); const payload = await response.json();
    if (!response.ok || payload?.ok === false) throw new Error(payload?.error || 'Não foi possível carregar as modalidades.');
    const products = payload.data || [];
    if (!products.length) { root.innerHTML = '<div class="catalog-message">Nenhuma modalidade está disponível neste momento.</div>'; return; }
    const featured = products.length === 1 ? 0 : Math.min(1, products.length - 1);
    root.innerHTML = products.map((product, index) => `<article class="plan-card ${index === featured ? 'featured' : ''}">${index === featured ? '<div class="plan-label">DESTAQUE</div>' : ''}<div class="plan-head"><span>${catalogEscape(catalogDuration(product))}</span><h3>${catalogEscape(product.name)}</h3><p>${catalogEscape(product.description || 'Acesso completo ao Paxinbot durante o período contratado.')}</p></div><div class="price"><b>${catalogMoney(product.priceCents)}</b><small>valor da modalidade</small></div><ul><li><svg><use href="#i-check"></use></svg> Todos os recursos disponíveis</li><li><svg><use href="#i-check"></use></svg> Acesso vinculado à sua conta</li><li><svg><use href="#i-check"></use></svg> ${product.accessKind === 'lifetime' ? 'Acesso sem expiração' : 'Saldo consumido somente com o app conectado'}</li><li><svg><use href="#i-check"></use></svg> Gestão pela Área do Cliente</li></ul><a class="button ${index === featured ? 'button-primary' : 'button-secondary'} button-full" data-select-product="${catalogEscape(product.id)}" href="/conta/checkout?product=${encodeURIComponent(product.id)}">Escolher modalidade</a></article>`).join('');
    root.querySelectorAll('[data-select-product]').forEach(link => link.addEventListener('click', () => {
      try { sessionStorage.setItem(PUBLIC_CHECKOUT_INTENT_KEY, JSON.stringify({ productId:link.dataset.selectProduct, selectedAt:Date.now() })); } catch {}
    }));
  } catch (error) { root.innerHTML = `<div class="catalog-message is-error">${catalogEscape(error.message)}</div>`; }
}
loadPublicCatalog();

document.querySelectorAll('a[href="/conta"]').forEach(link => link.addEventListener('click', () => {
  try { sessionStorage.removeItem(PUBLIC_CHECKOUT_INTENT_KEY); } catch {}
}));

document.querySelectorAll('a[href="#"]').forEach(link => link.addEventListener('click', event => event.preventDefault()));

const revealObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -35px' });

document.querySelectorAll('.reveal').forEach(element => revealObserver.observe(element));
if (document.getElementById('year')) document.getElementById('year').textContent = String(new Date().getFullYear());
