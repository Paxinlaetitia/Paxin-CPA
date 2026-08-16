'use strict';

document.getElementById('password-reset-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.getElementById('password-reset-status');
  const data = new FormData(form);
  if (data.get('password') !== data.get('confirm')) { status.textContent = 'As senhas precisam ser iguais.'; return; }
  const button = form.querySelector('button'); button.disabled = true;
  try {
    const csrfResponse = await fetch('/api/auth/csrf', { credentials:'include', headers:{ accept:'application/json' } });
    const csrfPayload = await csrfResponse.json().catch(() => null);
    if (!csrfResponse.ok || !csrfPayload?.token) throw new Error('Não foi possível preparar a solicitação segura.');
    const response = await fetch('/api/auth/password', {
      method:'POST', credentials:'include',
      headers:{ 'content-type':'application/json', 'x-paxinbot-csrf':csrfPayload.token },
      body:JSON.stringify({ password:data.get('password') })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error);
    status.textContent = 'Senha atualizada. Redirecionando para sua conta…';
    setTimeout(() => location.replace('/conta'), 900);
  } catch (error) { status.textContent = error.message || 'Não foi possível atualizar a senha.'; }
  finally { button.disabled = false; }
});
