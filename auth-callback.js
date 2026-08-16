'use strict';

(async () => {
  const status = document.getElementById('callback-status');
  const hash = new URLSearchParams(location.hash.slice(1));
  const params = new URLSearchParams(location.search);
  const error = hash.get('error_description') || params.get('error_description') || hash.get('error');
  if (error) { status.textContent = `Não foi possível concluir: ${error}.`; return; }
  const accessToken = hash.get('access_token');
  const refreshToken = hash.get('refresh_token');
  if (!accessToken) { status.textContent = 'A confirmação foi concluída. Entre na sua conta para continuar.'; return; }
  try {
    const csrfResponse = await fetch('/api/auth/csrf', { credentials:'include', headers:{ accept:'application/json' } });
    const csrfPayload = await csrfResponse.json().catch(() => null);
    if (!csrfResponse.ok || !csrfPayload?.token) throw new Error('csrf_unavailable');
    const response = await fetch('/api/auth/session', {
      method:'POST', credentials:'include',
      headers:{ 'content-type':'application/json', 'x-paxinbot-csrf':csrfPayload.token },
      body:JSON.stringify({ accessToken, refreshToken:refreshToken || '' })
    });
    if (!response.ok) throw new Error('session_unavailable');
    if (params.get('flow') === 'passkey') sessionStorage.setItem('paxinbot_passkey_session', JSON.stringify({ accessToken, refreshToken:refreshToken || '' }));
    let safeReturn = '/conta';
    try {
      const candidate = sessionStorage.getItem('paxinbot_auth_return') || '';
      sessionStorage.removeItem('paxinbot_auth_return');
      const parsed = new URL(candidate, location.origin);
      const productId = parsed.searchParams.get('product') || '';
      if (parsed.origin === location.origin && parsed.pathname === '/conta/checkout' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(productId) && parsed.searchParams.size === 1) safeReturn = `/conta/checkout?product=${encodeURIComponent(productId)}`;
      else if (parsed.origin === location.origin && parsed.pathname === '/conta/downloads' && parsed.searchParams.size === 0) safeReturn = '/conta/downloads';
    } catch {}
    location.replace(params.get('flow') === 'recovery' || hash.get('type') === 'recovery' ? '/redefinir-senha' : params.get('flow') === 'passkey' ? '/conta/seguranca' : safeReturn);
  } catch { status.textContent = 'Não foi possível salvar sua sessão. Volte e entre novamente.'; }
})();
