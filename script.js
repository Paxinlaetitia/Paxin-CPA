'use strict';

const header = document.querySelector('.site-header');
const menuButton = document.querySelector('.menu-button');
const navigation = document.querySelector('.main-nav');
const modal = document.getElementById('login-modal');
const toast = document.querySelector('.toast');
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
  window.location.href = 'cliente.html';
});

document.querySelector('.js-download')?.addEventListener('click', () => {
  window.location.href = 'cliente.html';
});

document.querySelector('.js-support')?.addEventListener('click', () => { window.location.href = 'ajuda.html'; });

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

document.querySelector('.js-create-account')?.addEventListener('click', () => { window.location.href = 'planos.html'; });

const passwordField = document.getElementById('client-password');
document.querySelector('.auth-eye')?.addEventListener('click', event => {
  if (!passwordField) return;
  const showing = passwordField.type === 'text';
  passwordField.type = showing ? 'password' : 'text';
  event.currentTarget.textContent = showing ? 'Mostrar' : 'Ocultar';
});


document.querySelectorAll('.billing-switch button').forEach(button => button.addEventListener('click', () => document.querySelectorAll('.billing-switch button').forEach(item => item.classList.toggle('active', item === button))));

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
