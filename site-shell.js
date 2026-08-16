'use strict';

(function buildSiteShell() {
  const page = document.body.dataset.page || 'inicio';
  const nav = [
    ['produto', 'Produto', '/produto'],
    ['recursos', 'Recursos', '/recursos'],
    ['planos', 'Planos', '/planos'],
    ['seguranca', 'Segurança', '/seguranca'],
    ['ajuda', 'Ajuda', '/ajuda']
  ];

  const icons = `
    <svg class="icon-library" aria-hidden="true">
      <symbol id="i-arrow" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6" /></symbol>
      <symbol id="i-play" viewBox="0 0 24 24"><path d="m8 5 11 7-11 7V5Z" /></symbol>
      <symbol id="i-grid" viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></symbol>
      <symbol id="i-flow" viewBox="0 0 24 24"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 6h8M7.5 7.5l3.4 8.4M16.5 7.5l-3.4 8.4"/></symbol>
      <symbol id="i-sliders" viewBox="0 0 24 24"><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></symbol>
      <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6l8-3Z"/><path d="m9 12 2 2 4-4"/></symbol>
      <symbol id="i-bolt" viewBox="0 0 24 24"><path d="m13 2-8 12h7l-1 8 8-12h-7l1-8Z"/></symbol>
      <symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 12 20l1.1-1.1"/></symbol>
      <symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></symbol>
      <symbol id="i-device" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></symbol>
      <symbol id="i-check" viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></symbol>
      <symbol id="i-close" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></symbol>
      <symbol id="i-menu" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></symbol>
      <symbol id="i-chevron" viewBox="0 0 24 24"><path d="m8 10 4 4 4-4"/></symbol>
      <symbol id="i-lock" viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></symbol>
      <symbol id="i-eye" viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></symbol>
      <symbol id="i-eye-off" viewBox="0 0 24 24"><path d="m3 3 18 18"/><path d="M10.6 6.1A10.8 10.8 0 0 1 12 6c6 0 9.5 6 9.5 6a17 17 0 0 1-2.1 2.8M6.2 6.2C3.8 7.8 2.5 12 2.5 12s3.5 6 9.5 6a9 9 0 0 0 3.2-.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></symbol>
      <symbol id="i-download" viewBox="0 0 24 24"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></symbol>
      <symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></symbol>
      <symbol id="i-mail" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m4 7 8 6 8-6"/></symbol>
      <symbol id="i-card" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18M7 15h3"/></symbol>
      <symbol id="i-help" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.7 9a2.5 2.5 0 1 1 3.8 2.1c-.9.5-1.5 1-1.5 2.4M12 17h.01"/></symbol>
      <symbol id="i-file" viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6zM14 3v5h5"/><path d="M9 13h6M9 17h6"/></symbol>
    </svg>`;

  document.body.insertAdjacentHTML('afterbegin', icons);

  const header = document.querySelector('[data-site-header]');
  if (header) {
    header.outerHTML = `
      <header class="site-header" id="top">
        <div class="container header-inner">
          <a class="brand" href="/" aria-label="Paxinbot, início">
            <span class="brand-mark"><img src="/assets/paxinbot-mark.svg" alt="" /></span>
            <span class="brand-name">Paxinbot</span>
          </a>
          <button class="menu-button" type="button" aria-label="Abrir menu" aria-expanded="false" aria-controls="main-nav"><svg><use href="#i-menu"></use></svg></button>
          <nav class="main-nav" id="main-nav" aria-label="Navegação principal">
            ${nav.map(([key, label, href]) => `<a class="${page === key ? 'active' : ''}" href="${href}">${label}</a>`).join('')}
          </nav>
          <div class="header-actions">
            <a class="button button-ghost ${page === 'cliente' ? 'is-current' : ''}" href="/conta">Área do cliente</a>
            <a class="button button-primary ${page === 'download' ? 'is-current' : ''}" href="/api/account?action=download&amp;redirect=1">Baixar aplicativo</a>
          </div>
        </div>
      </header>`;
  }

  const footer = document.querySelector('[data-site-footer]');
  if (footer) {
    footer.outerHTML = `
      <footer class="site-footer">
        <div class="container footer-main">
          <div><a class="brand" href="/"><span class="brand-mark"><img src="/assets/paxinbot-mark.svg" alt="" /></span><span class="brand-name">Paxinbot</span></a><p>Ambiente de trabalho para organizar sessões, rotinas e acompanhamento operacional.</p></div>
          <div class="footer-links">
            <div><b>PRODUTO</b><a href="/produto">Visão geral</a><a href="/recursos">Recursos</a><a href="/planos">Planos</a></div>
            <div><b>CLIENTE</b><a href="/conta">Área do cliente</a><a href="/download">Download</a><a href="/ajuda">Central de ajuda</a></div>
            <div><b>LEGAL</b><a href="/seguranca">Segurança</a><a href="/termos">Termos de uso</a><a href="/privacidade">Privacidade</a><a href="/reembolso">Reembolso</a></div>
          </div>
        </div>
        <div class="container footer-bottom"><span>© <span id="year"></span> Paxinbot. Todos os direitos reservados.</span><span class="prototype-badge">CANAL OFICIAL</span></div>
      </footer>`;
  }
})();
