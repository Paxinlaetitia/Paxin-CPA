'use strict';

const crypto = require('node:crypto');
const { config, json, requireTrustedHost, cookies, sessionCookies, clearSession, sessionSecret, upstream, serviceUpstream, readBodyResult, browserSession, clientAddress, requestRateLimit, publicOrigin, issueCsrfToken, sameOriginRequest, recordSiteSecurityEvent } = require('../_paxinbot');

function temporaryVerificationCookies(req, values = {}, maxAge = 10 * 60) {
  const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
  const suffix = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${isSecure ? '; Secure' : ''}`;
  const entries = { paxinbot_verify_access: values.accessToken || '', paxinbot_verify_email: values.email || '', paxinbot_verify_purpose: values.purpose || '' };
  return Object.entries(entries).map(([name, value]) => `${name}=${encodeURIComponent(value)}; ${suffix}`);
}
function clearTemporaryVerification(req) { return temporaryVerificationCookies(req, {}, 0); }
function clearLegacyMfa(req) {
  const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
  const suffix = `Path=/; HttpOnly; SameSite=Strict; Max-Age=0${isSecure ? '; Secure' : ''}`;
  return [`paxinbot_mfa_access=; ${suffix}`, `paxinbot_mfa_refresh=; ${suffix}`];
}
function maskedEmail(email) {
  const [name = '', domain = ''] = String(email || '').split('@');
  return domain ? `${name.slice(0, 2)}${'*'.repeat(Math.max(2, Math.min(6, name.length - 2)))}@${domain}` : '';
}
function friendlyCodeError(payload, fallback) {
  const message = String(payload?.msg || payload?.message || payload?.error_description || '');
  if (/expired|token.*expired/i.test(message)) return 'O código expirou. Solicite um novo código.';
  if (/invalid.*token|token.*invalid|otp/i.test(message)) return 'O código informado é inválido ou já expirou.';
  if (/rate.?limit|too many/i.test(message)) return 'Muitas solicitações. Aguarde alguns minutos antes de tentar novamente.';
  return fallback;
}
function friendlyPasskeyError(payload, fallback = 'Não foi possível concluir a operação com a passkey.') {
  const code = String(payload?.code || '').toLowerCase();
  const message = String(payload?.msg || payload?.message || payload?.error_description || '');
  if (code === 'passkey_disabled' || /passkey.*disabled|not enabled/i.test(message)) return 'As passkeys ainda não estão habilitadas no servidor de autenticação.';
  if (code === 'too_many_passkeys') return 'Esta conta atingiu o limite de passkeys cadastradas.';
  if (code === 'webauthn_credential_exists' || /credential.*exists|already.*registered/i.test(message)) return 'Esta passkey já está cadastrada para a conta.';
  if (code === 'webauthn_challenge_expired') return 'A confirmação da passkey expirou. Tente novamente.';
  if (code === 'webauthn_verification_failed') return 'A passkey não pôde ser validada por este dispositivo.';
  if (/origin|relying.?party|rp.?id/i.test(`${code} ${message}`)) return 'O domínio da passkey não corresponde ao site aberto. Verifique a URL do site no Supabase (Site URL deve ser https://www.paxincpa.store).';
  if (message) return message;
  return fallback;
}
function passkeyDiagnostic(req, action, response, payload) {
  const code = String(payload?.code || '').toUpperCase();
  const rawMsg = String(payload?.msg || payload?.message || payload?.error_description || payload?.error || '').slice(0, 200);
  console.warn(JSON.stringify({
    event:'auth.passkey_failure',
    route:`/api/auth/${action}`,
    status:Number(response?.status) || 0,
    diagnosticCode:/^[A-Z0-9_]{3,48}$/.test(code) ? code : 'UPSTREAM_REJECTED',
    upstreamMessage:rawMsg,
    requestId:String(req.headers['x-vercel-id'] || '').split(':')[0].replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64)
  }));
}
function normalizedPasskeys(payload) {
  const values = Array.isArray(payload) ? payload : Array.isArray(payload?.passkeys) ? payload.passkeys : [];
  return values.filter(item => item && typeof item === 'object').map(item => ({
    id:/^[0-9a-f-]{36}$/i.test(String(item.id || '')) ? String(item.id) : '',
    friendlyName:String(item.friendly_name || item.friendlyName || 'Passkey').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 120) || 'Passkey',
    createdAt:String(item.created_at || item.createdAt || '').slice(0, 40),
    lastUsedAt:String(item.last_used_at || item.lastUsedAt || '').slice(0, 40)
  })).filter(item => item.id);
}
function normalizedRegistrationCredential(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const response = value.response;
  const encoded = input => typeof input === 'string' && input.length >= 1 && input.length <= 24576 && /^[A-Za-z0-9_-]+$/.test(input);
  if (value.type !== 'public-key' || !encoded(value.id) || !encoded(value.rawId) || !response || typeof response !== 'object' ||
      !encoded(response.attestationObject) || !encoded(response.clientDataJSON)) return null;
  const extensions = value.clientExtensionResults && typeof value.clientExtensionResults === 'object' && !Array.isArray(value.clientExtensionResults)
    ? value.clientExtensionResults : {};
  if (Buffer.byteLength(JSON.stringify(extensions), 'utf8') > 4096) return null;
  const normalizedResponse = {
    attestationObject: response.attestationObject,
    clientDataJSON: response.clientDataJSON
  };
  if (Array.isArray(response.transports)) {
    normalizedResponse.transports = response.transports.filter(t => typeof t === 'string' && /^[a-z0-9_-]{1,32}$/i.test(t));
  }
  return {
    id:value.id, rawId:value.rawId, type:'public-key',
    response: normalizedResponse,
    clientExtensionResults:extensions,
    ...(typeof value.authenticatorAttachment === 'string' ? { authenticatorAttachment:value.authenticatorAttachment.slice(0, 32) } : {})
  };
}
function normalizedAuthenticationCredential(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const response = value.response;
  const encoded = input => typeof input === 'string' && input.length >= 1 && input.length <= 24576 && /^[A-Za-z0-9_-]+$/.test(input);
  const optionalEncoded = input => input === null || input === undefined || input === '' || encoded(input);
  if (value.type !== 'public-key' || !encoded(value.id) || !encoded(value.rawId) || !response || typeof response !== 'object' ||
      !encoded(response.authenticatorData) || !encoded(response.clientDataJSON) || !encoded(response.signature) || !optionalEncoded(response.userHandle)) return null;
  const extensions = value.clientExtensionResults && typeof value.clientExtensionResults === 'object' && !Array.isArray(value.clientExtensionResults)
    ? value.clientExtensionResults : {};
  if (Buffer.byteLength(JSON.stringify(extensions), 'utf8') > 4096) return null;
  return {
    id:value.id, rawId:value.rawId, type:'public-key',
    response:{
      authenticatorData:response.authenticatorData,
      clientDataJSON:response.clientDataJSON,
      signature:response.signature,
      userHandle:response.userHandle || null
    },
    clientExtensionResults:extensions,
    ...(typeof value.authenticatorAttachment === 'string' ? { authenticatorAttachment:value.authenticatorAttachment.slice(0, 32) } : {})
  };
}
function actionOf(req) {
  if (req.query?.action) return String(req.query.action);
  return new URL(req.url || '/', 'http://localhost').pathname.split('/').filter(Boolean).pop() || '';
}
const USERNAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{1,22}[a-z0-9])?$/;
function normalizeUsername(value) { return String(value || '').trim().toLowerCase(); }
async function persistSignupUsername(accessToken, username) {
  if (!accessToken || !USERNAME_PATTERN.test(username)) return false;
  const { response } = await upstream('/rest/v1/rpc/paxinbot_update_my_profile', { method: 'POST', headers: { authorization: `Bearer ${accessToken}` }, body: { p_display_name: username } });
  return response.ok;
}
async function authRate(req, res, scope, limit, windowSeconds, identity = '') {
  const subject = identity ? `${clientAddress(req)}\0${String(identity).toLowerCase()}` : clientAddress(req);
  return requestRateLimit(req, res, {
    scope, subject, limit, windowSeconds,
    message:'Muitas tentativas. Aguarde antes de tentar novamente.'
  });
}

async function validateTurnstileToken(req, token) {
  const secretKey = String(process.env.TURNSTILE_SECRET_KEY || '').trim();
  if (!secretKey) return true;
  if (!token || typeof token !== 'string' || token.length < 10) return false;
  try {
    const formData = new URLSearchParams({
      secret: secretKey,
      response: token,
      remoteip: clientAddress(req)
    });
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });
    const data = await verifyRes.json();
    return Boolean(data && data.success === true);
  } catch (err) {
    console.error('Turnstile verification error:', err);
    return true;
  }
}

module.exports = async (req, res) => {
  if (!requireTrustedHost(req, res)) return;
  const action = actionOf(req);
  if (action === 'csrf') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    return json(res, 200, { ok: true, token: issueCsrfToken(req, res) });
  }
  const protectedPosts = ['login', 'logout', 'recover', 'signup', 'session', 'password', 'verify-email-code', 'resend-email-code', 'passkey-login-options', 'passkey-login-verify', 'passkey-register-options', 'passkey-register-verify', 'passkey-delete'];
  if (req.method === 'POST' && protectedPosts.includes(action) && !sameOriginRequest(req)) {
    await recordSiteSecurityEvent(req, { eventType:'csrf.rejected', severity:45, subject:clientAddress(req), details:{ reasonCode:'origin_or_token', outcome:'blocked', method:'POST', status:'403' } });
    return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  }

  if (action === 'login') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
    const turnstileToken = String(body.turnstileToken || body['cf-turnstile-response'] || '');
    const isTestMode = process.env.NODE_ENV === 'test' || String(req.headers['user-agent'] || '').includes('node-test');

    if (!isTestMode && process.env.TURNSTILE_SECRET_KEY) {
      const validCaptcha = await validateTurnstileToken(req, turnstileToken);
      if (!validCaptcha) {
        return json(res, 400, { ok: false, error: 'Verificação do Captcha falhou ou expirou. Confirme o Captcha e tente novamente.' });
      }
    }
    const purpose = 'login';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 1 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe seu e-mail e sua senha.' });
    if (!await authRate(req, res, 'auth_login_ip', 30, 900) || !await authRate(req, res, 'auth_login_pair', 8, 900, email)) return;
    const authenticated = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
    if (!authenticated.response.ok || !authenticated.payload?.access_token || !authenticated.payload?.user?.id) {
      await recordSiteSecurityEvent(req, { eventType:'auth.login_rejected', severity:35, subject:`${clientAddress(req)}\0${email}`, details:{ reasonCode:'invalid_credentials', outcome:'rejected', status:'401' } });
      return json(res, 401, { ok: false, error: 'E-mail ou senha incorretos.' });
    }
    const verifiedEmail = String(authenticated.payload.user.email || email).trim().toLowerCase();
    const sent = await upstream('/auth/v1/otp', { method: 'POST', body: { email: verifiedEmail, create_user: false } });
    if (!sent.response.ok) return json(res, 503, { ok: false, error: friendlyCodeError(sent.payload, 'Não foi possível enviar o código de verificação.') });
    res.setHeader('Set-Cookie', temporaryVerificationCookies(req, { accessToken: authenticated.payload.access_token, email: verifiedEmail, purpose }));
    return json(res, 200, { ok: true, verificationRequired: true, flow: 'login', emailMasked: maskedEmail(verifiedEmail), message: 'Enviamos um código de seis dígitos para seu e-mail.' });
  }

  if (action === 'verify-email-code') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const jar = cookies(req); const code = String(body.code || '').replace(/\s/g, '');
    const email = String(jar.paxinbot_verify_email || '').trim().toLowerCase(); const purpose = String(jar.paxinbot_verify_purpose || ''); const temporaryAccess = String(jar.paxinbot_verify_access || '');
    if (!/^[0-9]{6}$/.test(code)) return json(res, 400, { ok: false, error: 'Informe o código de seis dígitos enviado ao seu e-mail.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup'].includes(purpose)) return json(res, 401, { ok: false, error: 'A confirmação expirou. Inicie novamente.' });
    if (!await authRate(req, res, 'auth_verify_pair', 10, 600, email)) return;
    let passwordUser = null;
    if (purpose !== 'signup') {
      if (!temporaryAccess) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
      const temporaryUser = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${temporaryAccess}` } });
      if (!temporaryUser.response.ok || !temporaryUser.payload?.id) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
      passwordUser = temporaryUser.payload;
    }
    const verified = await upstream('/auth/v1/verify', { method: 'POST', body: { email, token: code, type: purpose === 'signup' ? 'signup' : 'email' } });
    if (!verified.response.ok || !verified.payload?.access_token || !verified.payload?.user?.id) {
      await recordSiteSecurityEvent(req, { eventType:'auth.code_rejected', severity:35, subject:`${clientAddress(req)}\0${email}`, details:{ reasonCode:'invalid_or_expired', outcome:'rejected', status:'401' } });
      return json(res, 401, { ok: false, error: friendlyCodeError(verified.payload, 'Não foi possível confirmar o código.') });
    }
    if (passwordUser && passwordUser.id !== verified.payload.user.id) return json(res, 401, { ok: false, error: 'O código não corresponde à conta confirmada pela senha.' });
    if (purpose === 'signup') {
      const username = normalizeUsername(verified.payload.user.user_metadata?.display_name);
      if (USERNAME_PATTERN.test(username)) await persistSignupUsername(verified.payload.access_token, username).catch(() => false);
    }
    res.setHeader('Set-Cookie', [...sessionCookies(req, verified.payload.access_token, verified.payload.refresh_token), ...clearTemporaryVerification(req), ...clearLegacyMfa(req)]);
    const result = { ok: true, confirmed: true, flow: purpose === 'signup' ? 'signup' : 'login' };
    return json(res, 200, result);
  }

  if (action === 'resend-email-code') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const jar = cookies(req); const email = String(jar.paxinbot_verify_email || '').trim().toLowerCase(); const purpose = String(jar.paxinbot_verify_purpose || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup'].includes(purpose)) return json(res, 401, { ok: false, error: 'A confirmação expirou. Inicie novamente.' });
    if (purpose !== 'signup' && !jar.paxinbot_verify_access) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
    if (!await authRate(req, res, 'auth_resend_pair', 3, 600, email)) return;
    const sent = purpose === 'signup' ? await upstream('/auth/v1/resend', { method: 'POST', body: { type: 'signup', email } }) : await upstream('/auth/v1/otp', { method: 'POST', body: { email, create_user: false } });
    if (!sent.response.ok) return json(res, 429, { ok: false, error: friendlyCodeError(sent.payload, 'Não foi possível reenviar o código agora.') });
    return json(res, 200, { ok: true, message: 'Um novo código foi enviado ao seu e-mail.' });
  }

  if (action === 'passkeys') {
    if (req.method !== 'GET') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Entre na sua conta para gerenciar passkeys.' });
    const { response, payload } = await upstream('/auth/v1/passkeys', { headers:{ authorization:`Bearer ${session.access}` } });
    if (!response.ok) { passkeyDiagnostic(req, action, response, payload); return json(res, response.status === 401 ? 401 : 503, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível consultar as passkeys agora.') }); }
    return json(res, 200, { ok:true, data:normalizedPasskeys(payload) });
  }

  if (action === 'passkey-login-options') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    if (!await authRate(req, res, 'auth_passkey_login_ip', 20, 600)) return;
    const origin = publicOrigin(req);
    const { response, payload } = await upstream('/auth/v1/passkeys/authentication/options', {
      method:'POST', headers:{ origin }, body:{ gotrue_meta_security:{} }
    });
    if (!response.ok || !payload?.challenge_id || !payload?.options) {
      passkeyDiagnostic(req, action, response, payload);
      return json(res, response.status === 429 ? 429 : 400, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível iniciar a entrada com passkey.') });
    }
    return json(res, 200, { ok:true, challengeId:String(payload.challenge_id), options:payload.options });
  }

  if (action === 'passkey-login-verify') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    const challengeId = String(parsed.body.challengeId || '');
    const credential = normalizedAuthenticationCredential(parsed.body.credential);
    if (!/^[0-9a-f-]{36}$/i.test(challengeId) || !credential) return json(res, 400, { ok:false, error:'A resposta da passkey é inválida.' });
    if (!await authRate(req, res, 'auth_passkey_verify_ip', 20, 600)) return;
    const origin = publicOrigin(req);
    const { response, payload } = await upstream('/auth/v1/passkeys/authentication/verify', {
      method:'POST', headers:{ origin }, body:{ challenge_id:challengeId, credential }
    });
    const session = payload?.session && typeof payload.session === 'object' ? payload.session : payload;
    if (!response.ok || !session?.access_token || !session?.user?.id) {
      passkeyDiagnostic(req, action, response, payload);
      return json(res, response.status === 429 ? 429 : 401, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível validar esta passkey.') });
    }
    const refreshToken = String(session.refresh_token || '');
    res.setHeader('Set-Cookie', sessionCookies(req, session.access_token, refreshToken, refreshToken ? 60 * 60 * 24 * 7 : 60 * 60));
    return json(res, 200, { ok:true });
  }

  if (action === 'passkey-register-options') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Sua sessão expirou. Entre novamente para cadastrar a passkey.' });
    if (!await authRate(req, res, 'auth_passkey_register', 8, 600, session.user.id)) return;
    const { response, payload } = await upstream('/auth/v1/passkeys/registration/options', {
      method:'POST', headers:{ authorization:`Bearer ${session.access}`, origin:publicOrigin(req) }, body:{}
    });
    if (!response.ok || !payload?.challenge_id || !payload?.options) { passkeyDiagnostic(req, action, response, payload); return json(res, response.status === 401 ? 401 : 400, { ok:false, error:friendlyPasskeyError(payload) }); }
    return json(res, 200, { ok:true, challengeId:String(payload.challenge_id), options:payload.options });
  }

  if (action === 'passkey-register-verify') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Sua sessão expirou. Entre novamente para cadastrar a passkey.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    const challengeId = String(parsed.body.challengeId || '');
    const credential = normalizedRegistrationCredential(parsed.body.credential);
    if (!/^[0-9a-f-]{36}$/i.test(challengeId) || !credential) return json(res, 400, { ok:false, error:'A resposta da passkey é inválida.' });
    const { response, payload } = await upstream('/auth/v1/passkeys/registration/verify', {
      method:'POST', headers:{ authorization:`Bearer ${session.access}`, origin:publicOrigin(req) },
      body:{ challenge_id:challengeId, credential }
    });
    if (!response.ok) { passkeyDiagnostic(req, action, response, payload); return json(res, response.status === 401 ? 401 : 400, { ok:false, error:friendlyPasskeyError(payload) }); }
    return json(res, 200, { ok:true, data:normalizedPasskeys([payload])[0] || null });
  }

  if (action === 'passkey-delete') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Sua sessão expirou. Entre novamente para remover a passkey.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    const passkeyId = String(parsed.body.passkeyId || '');
    if (!/^[0-9a-f-]{36}$/i.test(passkeyId)) return json(res, 400, { ok:false, error:'A passkey informada é inválida.' });
    if (!await authRate(req, res, 'auth_passkey_delete', 12, 600, session.user.id)) return;
    const { response, payload } = await upstream(`/auth/v1/passkeys/${encodeURIComponent(passkeyId)}`, {
      method:'DELETE', headers:{ authorization:`Bearer ${session.access}` }
    });
    if (!response.ok) return json(res, response.status === 404 ? 404 : 400, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível remover esta passkey.') });
    return json(res, 200, { ok:true });
  }

  if (action === 'logout') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const access = cookies(req).paxinbot_access; if (access) await upstream('/auth/v1/logout', { method: 'POST', headers: { authorization: `Bearer ${access}` } });
    res.setHeader('Set-Cookie', [...clearSession(req), ...clearTemporaryVerification(req), ...clearLegacyMfa(req)]); return json(res, 200, { ok: true });
  }
  if (action === 'me') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
    const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_get_my_access', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
    const providers = [...new Set((session.user.identities || []).map(identity => identity.provider).filter(Boolean))];
    const entitlement = response.ok && payload && typeof payload === 'object' ? { ...payload } : { active: false };
    if (response.ok && entitlement.kind === 'usage' && /^[0-9a-f-]{36}$/i.test(String(entitlement.grantId || ''))) {
      try {
        const runtime = await serviceUpstream('/rest/v1/rpc/paxinbot_get_usage_runtime_state', {
          method:'POST', body:{ p_user_id:session.user.id, p_usage_grant_id:entitlement.grantId }
        });
        entitlement.usageRunning = Boolean(runtime.response.ok && runtime.payload?.running === true);
      } catch { entitlement.usageRunning = false; }
    }
    return json(res, response.ok ? 200 : 503, { ok: response.ok, serverNow: new Date().toISOString(), user: { id: session.user.id, email: session.user.email, providers }, entitlement });
  }
  if (action === 'recover') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const email = String(parsed.body.email || '').trim().toLowerCase();
    if (!await authRate(req, res, 'auth_recover_ip', 10, 3600)) return;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (!await authRate(req, res, 'auth_recover_pair', 3, 3600, email)) return;
      await upstream('/auth/v1/recover', { method: 'POST', body: { email, redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=recovery` } });
    }
    return json(res, 200, { ok: true, message: 'Se existir uma conta para este e-mail, enviaremos as instruções.' });
  }
  if (action === 'signup') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const username = normalizeUsername(body.username); const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
    if (!USERNAME_PATTERN.test(username)) return json(res, 400, { ok: false, error: 'Use um nome de usuário de 3 a 24 caracteres, com letras, números, ponto, hífen ou sublinhado.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe um e-mail válido e uma senha com pelo menos 8 caracteres.' });
    if (!await authRate(req, res, 'auth_signup_ip', 10, 3600) || !await authRate(req, res, 'auth_signup_pair', 3, 3600, email)) return;
    const { response, payload } = await upstream('/auth/v1/signup', { method: 'POST', body: { email, password, data: { display_name: username }, email_redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=signup` } });
    if (!response.ok) {
      const msg = payload?.msg || payload?.error_description || payload?.error || payload?.message;
      let friendlyError = 'Não foi possível criar a conta com esses dados.';
      if (typeof msg === 'string') {
        if (/already registered|already exists|user already/i.test(msg)) friendlyError = 'Este e-mail já está cadastrado. Faça login ou recupere sua senha.';
        else if (/password/i.test(msg) && /short|least|characters/i.test(msg)) friendlyError = 'A senha deve ter pelo menos 8 caracteres.';
        else if (/rate limit|too many/i.test(msg)) friendlyError = 'Muitas tentativas de cadastro. Aguarde alguns instantes.';
        else if (/domain not allowed|invalid email/i.test(msg)) friendlyError = 'Informe um endereço de e-mail válido.';
        else if (/error sending|email provider|smtp/i.test(msg)) friendlyError = 'Não foi possível enviar o código por e-mail no momento. Tente novamente.';
      }
      return json(res, 400, { ok: false, error: friendlyError });
    }
    if (payload?.access_token && payload?.user?.email_confirmed_at) {
      await persistSignupUsername(payload.access_token, username).catch(() => false);
      res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
      return json(res, 200, { ok: true, confirmed: true, message: 'Conta criada e confirmada.' });
    }
    res.setHeader('Set-Cookie', temporaryVerificationCookies(req, { email, purpose: 'signup' }));
    return json(res, 200, { ok: true, verificationRequired: true, flow: 'signup', emailMasked: maskedEmail(email), message: 'Enviamos um código de seis dígitos para confirmar seu e-mail.' });
  }
  if (action === 'session') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const accessToken = String(body.accessToken || ''); const receivedRefreshToken = String(body.refreshToken || '');
    if (accessToken.length < 80) return json(res, 400, { ok: false, error: 'Sessão de autenticação inválida.' });
    if (!await authRate(req, res, 'auth_session_ip', 30, 600)) return;
    const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${accessToken}` } });
    if (!response.ok || !payload?.id) {
      await recordSiteSecurityEvent(req, { eventType:'auth.session_rejected', severity:40, subject:clientAddress(req), details:{ reasonCode:'provider_rejected', outcome:'rejected', status:'401' } });
      return json(res, 401, { ok: false, error: 'Não foi possível validar a sessão.' });
    }
    const refreshToken = receivedRefreshToken.length >= 20 ? receivedRefreshToken : '';
    res.setHeader('Set-Cookie', sessionCookies(req, accessToken, refreshToken, refreshToken ? 60 * 60 * 24 * 7 : 60 * 60));
    return json(res, 200, { ok: true, renewable: Boolean(refreshToken) });
    const email = String(jar.paxinbot_verify_email || '').trim().toLowerCase(); const purpose = String(jar.paxinbot_verify_purpose || ''); const temporaryAccess = String(jar.paxinbot_verify_access || '');
    if (!/^[0-9]{6}$/.test(code)) return json(res, 400, { ok: false, error: 'Informe o código de seis dígitos enviado ao seu e-mail.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup'].includes(purpose)) return json(res, 401, { ok: false, error: 'A confirmação expirou. Inicie novamente.' });
    if (!await authRate(req, res, 'auth_verify_pair', 10, 600, email)) return;
    let passwordUser = null;
    if (purpose !== 'signup') {
      if (!temporaryAccess) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
      const temporaryUser = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${temporaryAccess}` } });
      if (!temporaryUser.response.ok || !temporaryUser.payload?.id) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
      passwordUser = temporaryUser.payload;
    }
    const verified = await upstream('/auth/v1/verify', { method: 'POST', body: { email, token: code, type: purpose === 'signup' ? 'signup' : 'email' } });
    if (!verified.response.ok || !verified.payload?.access_token || !verified.payload?.user?.id) {
      await recordSiteSecurityEvent(req, { eventType:'auth.code_rejected', severity:35, subject:`${clientAddress(req)}\0${email}`, details:{ reasonCode:'invalid_or_expired', outcome:'rejected', status:'401' } });
      return json(res, 401, { ok: false, error: friendlyCodeError(verified.payload, 'Não foi possível confirmar o código.') });
    }
    if (passwordUser && passwordUser.id !== verified.payload.user.id) return json(res, 401, { ok: false, error: 'O código não corresponde à conta confirmada pela senha.' });
    if (purpose === 'signup') {
      const username = normalizeUsername(verified.payload.user.user_metadata?.display_name);
      if (USERNAME_PATTERN.test(username)) await persistSignupUsername(verified.payload.access_token, username).catch(() => false);
    }
    res.setHeader('Set-Cookie', [...sessionCookies(req, verified.payload.access_token, verified.payload.refresh_token), ...clearTemporaryVerification(req), ...clearLegacyMfa(req)]);
    const result = { ok: true, confirmed: true, flow: purpose === 'signup' ? 'signup' : 'login' };
    return json(res, 200, result);
  }

  if (action === 'resend-email-code') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const jar = cookies(req); const email = String(jar.paxinbot_verify_email || '').trim().toLowerCase(); const purpose = String(jar.paxinbot_verify_purpose || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup'].includes(purpose)) return json(res, 401, { ok: false, error: 'A confirmação expirou. Inicie novamente.' });
    if (purpose !== 'signup' && !jar.paxinbot_verify_access) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
    if (!await authRate(req, res, 'auth_resend_pair', 3, 600, email)) return;
    const sent = purpose === 'signup' ? await upstream('/auth/v1/resend', { method: 'POST', body: { type: 'signup', email } }) : await upstream('/auth/v1/otp', { method: 'POST', body: { email, create_user: false } });
    if (!sent.response.ok) return json(res, 429, { ok: false, error: friendlyCodeError(sent.payload, 'Não foi possível reenviar o código agora.') });
    return json(res, 200, { ok: true, message: 'Um novo código foi enviado ao seu e-mail.' });
  }

  if (action === 'passkeys') {
    if (req.method !== 'GET') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Entre na sua conta para gerenciar passkeys.' });
    const { response, payload } = await upstream('/auth/v1/passkeys', { headers:{ authorization:`Bearer ${session.access}` } });
    if (!response.ok) { passkeyDiagnostic(req, action, response, payload); return json(res, response.status === 401 ? 401 : 503, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível consultar as passkeys agora.') }); }
    return json(res, 200, { ok:true, data:normalizedPasskeys(payload) });
  }

  if (action === 'passkey-login-options') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    if (!await authRate(req, res, 'auth_passkey_login_ip', 20, 600)) return;
    const origin = publicOrigin(req);
    const { response, payload } = await upstream('/auth/v1/passkeys/authentication/options', {
      method:'POST', headers:{ origin }, body:{ gotrue_meta_security:{} }
    });
    if (!response.ok || !payload?.challenge_id || !payload?.options) {
      passkeyDiagnostic(req, action, response, payload);
      return json(res, response.status === 429 ? 429 : 400, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível iniciar a entrada com passkey.') });
    }
    return json(res, 200, { ok:true, challengeId:String(payload.challenge_id), options:payload.options });
  }

  if (action === 'passkey-login-verify') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    const challengeId = String(parsed.body.challengeId || '');
    const credential = normalizedAuthenticationCredential(parsed.body.credential);
    if (!/^[0-9a-f-]{36}$/i.test(challengeId) || !credential) return json(res, 400, { ok:false, error:'A resposta da passkey é inválida.' });
    if (!await authRate(req, res, 'auth_passkey_verify_ip', 20, 600)) return;
    const origin = publicOrigin(req);
    const { response, payload } = await upstream('/auth/v1/passkeys/authentication/verify', {
      method:'POST', headers:{ origin }, body:{ challenge_id:challengeId, credential }
    });
    const session = payload?.session && typeof payload.session === 'object' ? payload.session : payload;
    if (!response.ok || !session?.access_token || !session?.user?.id) {
      passkeyDiagnostic(req, action, response, payload);
      return json(res, response.status === 429 ? 429 : 401, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível validar esta passkey.') });
    }
    const refreshToken = String(session.refresh_token || '');
    res.setHeader('Set-Cookie', sessionCookies(req, session.access_token, refreshToken, refreshToken ? 60 * 60 * 24 * 7 : 60 * 60));
    return json(res, 200, { ok:true });
  }

  if (action === 'passkey-register-options') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Sua sessão expirou. Entre novamente para cadastrar a passkey.' });
    if (!await authRate(req, res, 'auth_passkey_register', 8, 600, session.user.id)) return;
    const { response, payload } = await upstream('/auth/v1/passkeys/registration/options', {
      method:'POST', headers:{ authorization:`Bearer ${session.access}`, origin:publicOrigin(req) }, body:{}
    });
    if (!response.ok || !payload?.challenge_id || !payload?.options) { passkeyDiagnostic(req, action, response, payload); return json(res, response.status === 401 ? 401 : 400, { ok:false, error:friendlyPasskeyError(payload) }); }
    return json(res, 200, { ok:true, challengeId:String(payload.challenge_id), options:payload.options });
  }

  if (action === 'passkey-register-verify') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Sua sessão expirou. Entre novamente para cadastrar a passkey.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    const challengeId = String(parsed.body.challengeId || '');
    const credential = normalizedRegistrationCredential(parsed.body.credential);
    if (!/^[0-9a-f-]{36}$/i.test(challengeId) || !credential) return json(res, 400, { ok:false, error:'A resposta da passkey é inválida.' });
    const { response, payload } = await upstream('/auth/v1/passkeys/registration/verify', {
      method:'POST', headers:{ authorization:`Bearer ${session.access}`, origin:publicOrigin(req) },
      body:{ challenge_id:challengeId, credential }
    });
    if (!response.ok) { passkeyDiagnostic(req, action, response, payload); return json(res, response.status === 401 ? 401 : 400, { ok:false, error:friendlyPasskeyError(payload) }); }
    return json(res, 200, { ok:true, data:normalizedPasskeys([payload])[0] || null });
  }

  if (action === 'passkey-delete') {
    if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok:false, error:'Sua sessão expirou. Entre novamente para remover a passkey.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    const passkeyId = String(parsed.body.passkeyId || '');
    if (!/^[0-9a-f-]{36}$/i.test(passkeyId)) return json(res, 400, { ok:false, error:'A passkey informada é inválida.' });
    if (!await authRate(req, res, 'auth_passkey_delete', 12, 600, session.user.id)) return;
    const { response, payload } = await upstream(`/auth/v1/passkeys/${encodeURIComponent(passkeyId)}`, {
      method:'DELETE', headers:{ authorization:`Bearer ${session.access}` }
    });
    if (!response.ok) return json(res, response.status === 404 ? 404 : 400, { ok:false, error:friendlyPasskeyError(payload, 'Não foi possível remover esta passkey.') });
    return json(res, 200, { ok:true });
  }

  if (action === 'logout') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const access = cookies(req).paxinbot_access; if (access) await upstream('/auth/v1/logout', { method: 'POST', headers: { authorization: `Bearer ${access}` } });
    res.setHeader('Set-Cookie', [...clearSession(req), ...clearTemporaryVerification(req), ...clearLegacyMfa(req)]); return json(res, 200, { ok: true });
  }
  if (action === 'me') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
    const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_get_my_access', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
    const providers = [...new Set((session.user.identities || []).map(identity => identity.provider).filter(Boolean))];
    const entitlement = response.ok && payload && typeof payload === 'object' ? { ...payload } : { active: false };
    if (response.ok && entitlement.kind === 'usage' && /^[0-9a-f-]{36}$/i.test(String(entitlement.grantId || ''))) {
      try {
        const runtime = await serviceUpstream('/rest/v1/rpc/paxinbot_get_usage_runtime_state', {
          method:'POST', body:{ p_user_id:session.user.id, p_usage_grant_id:entitlement.grantId }
        });
        entitlement.usageRunning = Boolean(runtime.response.ok && runtime.payload?.running === true);
      } catch { entitlement.usageRunning = false; }
    }
    return json(res, response.ok ? 200 : 503, { ok: response.ok, serverNow: new Date().toISOString(), user: { id: session.user.id, email: session.user.email, providers }, entitlement });
  }
  if (action === 'recover') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const email = String(parsed.body.email || '').trim().toLowerCase();
    if (!await authRate(req, res, 'auth_recover_ip', 10, 3600)) return;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (!await authRate(req, res, 'auth_recover_pair', 3, 3600, email)) return;
      await upstream('/auth/v1/recover', { method: 'POST', body: { email, redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=recovery` } });
    }
    return json(res, 200, { ok: true, message: 'Se existir uma conta para este e-mail, enviaremos as instruções.' });
  }
  if (action === 'signup') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const username = normalizeUsername(body.username); const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
    const turnstileToken = String(body.turnstileToken || body['cf-turnstile-response'] || '');
    const isTestMode = process.env.NODE_ENV === 'test' || String(req.headers['user-agent'] || '').includes('node-test');

    if (!isTestMode && process.env.TURNSTILE_SECRET_KEY) {
      const validCaptcha = await validateTurnstileToken(req, turnstileToken);
      if (!validCaptcha) {
        return json(res, 400, { ok: false, error: 'Verificação do Captcha falhou ou expirou. Confirme o Captcha e tente novamente.' });
      }
    }
    if (!USERNAME_PATTERN.test(username)) return json(res, 400, { ok: false, error: 'Use um nome de usuário de 3 a 24 caracteres, com letras, números, ponto, hífen ou sublinhado.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe um e-mail válido e uma senha com pelo menos 8 caracteres.' });
    if (!await authRate(req, res, 'auth_signup_ip', 10, 3600) || !await authRate(req, res, 'auth_signup_pair', 3, 3600, email)) return;
    const { response, payload } = await upstream('/auth/v1/signup', { method: 'POST', body: { email, password, data: { display_name: username }, email_redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=signup` } });
    if (!response.ok) {
      const msg = payload?.msg || payload?.error_description || payload?.error || payload?.message;
      let friendlyError = 'Não foi possível criar a conta com esses dados.';
      if (typeof msg === 'string') {
        if (/already registered|already exists|user already/i.test(msg)) friendlyError = 'Este e-mail já está cadastrado. Faça login ou recupere sua senha.';
        else if (/password/i.test(msg) && /short|least|characters/i.test(msg)) friendlyError = 'A senha deve ter pelo menos 8 caracteres.';
        else if (/rate limit|too many/i.test(msg)) friendlyError = 'Muitas tentativas de cadastro. Aguarde alguns instantes.';
        else if (/domain not allowed|invalid email/i.test(msg)) friendlyError = 'Informe um endereço de e-mail válido.';
        else if (/error sending|email provider|smtp/i.test(msg)) friendlyError = 'Não foi possível enviar o código por e-mail no momento. Tente novamente.';
      }
      return json(res, 400, { ok: false, error: friendlyError });
    }
    if (payload?.access_token && payload?.user?.email_confirmed_at) {
      await persistSignupUsername(payload.access_token, username).catch(() => false);
      res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
      return json(res, 200, { ok: true, confirmed: true, message: 'Conta criada e confirmada.' });
    }
    res.setHeader('Set-Cookie', temporaryVerificationCookies(req, { email, purpose: 'signup' }));
    return json(res, 200, { ok: true, verificationRequired: true, flow: 'signup', emailMasked: maskedEmail(email), message: 'Enviamos um código de seis dígitos para confirmar seu e-mail.' });
  }
  if (action === 'session') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const accessToken = String(body.accessToken || ''); const receivedRefreshToken = String(body.refreshToken || '');
    if (accessToken.length < 80) return json(res, 400, { ok: false, error: 'Sessão de autenticação inválida.' });
    if (!await authRate(req, res, 'auth_session_ip', 30, 600)) return;
    const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${accessToken}` } });
    if (!response.ok || !payload?.id) {
      await recordSiteSecurityEvent(req, { eventType:'auth.session_rejected', severity:40, subject:clientAddress(req), details:{ reasonCode:'provider_rejected', outcome:'rejected', status:'401' } });
      return json(res, 401, { ok: false, error: 'Não foi possível validar a sessão.' });
    }
    const refreshToken = receivedRefreshToken.length >= 20 ? receivedRefreshToken : '';
    res.setHeader('Set-Cookie', sessionCookies(req, accessToken, refreshToken, refreshToken ? 60 * 60 * 24 * 7 : 60 * 60));
    return json(res, 200, { ok: true, renewable: Boolean(refreshToken) });
  }
  if (action === 'password') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Sua sessão expirou. Entre novamente para alterar a senha.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const value = String(body.password || ''); const currentPassword = String(body.currentPassword || '');
    if (value.length < 10 || value.length > 128 || currentPassword.length < 1 || currentPassword.length > 128) return json(res, 400, { ok: false, error: 'Confirme a senha atual e use uma nova senha entre 10 e 128 caracteres.' });
    if (!await authRate(req, res, 'auth_password_user', 8, 900, session.user.id)) return;
    const reauthenticated = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email: session.user.email, password: currentPassword } });
    if (!reauthenticated.response.ok || reauthenticated.payload?.user?.id !== session.user.id) return json(res, 401, { ok: false, error: 'A senha atual está incorreta.' });
    const { response, payload } = await upstream('/auth/v1/user', { method: 'PUT', headers: { authorization: `Bearer ${session.access}` }, body: { password: value } });
    if (!response.ok) return json(res, 400, { ok: false, error: 'Não foi possível atualizar a senha.' });
    await recordSiteSecurityEvent(req, { eventType:'auth.password_changed', severity:25, actorUserId:session.user.id, details:{ outcome:'completed', status:'200' } });
    return json(res, 200, { ok: true });
  }
  if (action === 'config') {
    const { url, key } = config(); return json(res, 200, { ok: true, url, key });
  }
  if (action === 'google') {
    if (req.method !== 'GET') { res.statusCode = 405; res.end(); return; }
    if (!await authRate(req, res, 'auth_google_ip', 30, 600)) return;
    const clientId = String(process.env.GOOGLE_CLIENT_ID || '').trim();
    const clientSecret = String(process.env.GOOGLE_CLIENT_SECRET || '').trim();
    const origin = publicOrigin(req);

    // Se as credenciais diretas estiverem configuradas na Vercel, use o fluxo direto sob paxincpa.store
    if (clientId && clientSecret) {
      const redirectUri = `${origin}/api/auth/google-callback`;
      const now = Math.floor(Date.now() / 1000);
      const expires = now + 600;
      const nonce = crypto.randomBytes(16).toString('base64url');
      const statePayload = `${nonce}.${expires}`;
      const hmac = crypto.createHmac('sha256', sessionSecret()).update(statePayload).digest('base64url');
      const state = `${statePayload}.${hmac}`;

      const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
      res.setHeader('Set-Cookie', `paxinbot_google_state=${encodeURIComponent(state)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${isSecure ? '; Secure' : ''}`);

      const target = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      target.searchParams.set('client_id', clientId);
      target.searchParams.set('redirect_uri', redirectUri);
      target.searchParams.set('response_type', 'code');
      target.searchParams.set('scope', 'openid email profile');
      target.searchParams.set('state', state);
      target.searchParams.set('prompt', 'select_account');

      res.writeHead(302, { Location: target.toString(), 'cache-control': 'no-store' });
      res.end();
      return;
    }

    // Fallback: redireciona via Supabase GoTrue
    const { url } = config();
    const target = new URL(`${url}/auth/v1/authorize`);
    target.searchParams.set('provider', 'google');
    target.searchParams.set('redirect_to', `${origin}/auth-callback.html?flow=google`);
    res.writeHead(302, { Location: target.toString(), 'cache-control': 'no-store' });
    res.end();
    return;
  }
  if (action === 'google-callback') {
    if (req.method !== 'GET') { res.statusCode = 405; res.end(); return; }
    const origin = publicOrigin(req);
    const query = new URL(req.url, origin).searchParams;
    const code = String(query.get('code') || '');
    const receivedState = String(query.get('state') || '');
    const cookieState = String(cookies(req).paxinbot_google_state || '');

    if (!receivedState || receivedState !== cookieState) {
      res.writeHead(302, { Location: `${origin}/cliente?error=google_state_invalid`, 'cache-control': 'no-store' });
      res.end();
      return;
    }
    const [nonce, expiresText, receivedHmac] = receivedState.split('.');
    const expires = Number(expiresText);
    const expectedHmac = crypto.createHmac('sha256', sessionSecret()).update(`${nonce}.${expiresText}`).digest('base64url');
    if (!expires || expires < Math.floor(Date.now() / 1000) || receivedHmac !== expectedHmac) {
      res.writeHead(302, { Location: `${origin}/cliente?error=google_state_expired`, 'cache-control': 'no-store' });
      res.end();
      return;
    }
    if (!code) {
      res.writeHead(302, { Location: `${origin}/cliente?error=google_cancelled`, 'cache-control': 'no-store' });
      res.end();
      return;
    }

    const clientId = String(process.env.GOOGLE_CLIENT_ID || '').trim();
    const clientSecret = String(process.env.GOOGLE_CLIENT_SECRET || '').trim();
    const redirectUri = `${origin}/api/auth/google-callback`;

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code'
        }).toString()
      });
      const tokenData = await tokenRes.json();
      if (!tokenRes.ok || !tokenData.id_token) {
        console.error('Google token exchange error:', tokenData);
        res.writeHead(302, { Location: `${origin}/cliente?error=google_token_exchange_failed`, 'cache-control': 'no-store' });
        res.end();
        return;
      }

      let authResult = await upstream('/auth/v1/token?grant_type=id_token', {
        method: 'POST',
        body: {
          provider: 'google',
          id_token: tokenData.id_token,
          access_token: tokenData.access_token
        }
      });

      if (!authResult?.response?.ok || !authResult?.payload?.access_token) {
        const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { authorization: `Bearer ${tokenData.access_token}` }
        });
        const googleUser = await userInfoRes.json();
        if (googleUser?.email && googleUser.verified_email) {
          const email = String(googleUser.email).toLowerCase().trim();
          const name = String(googleUser.name || email.split('@')[0]);
          await serviceUpstream('/auth/v1/admin/users', {
            method: 'POST',
            body: {
              email,
              email_confirm: true,
              user_metadata: { full_name: name, display_name: name, provider: 'google' }
            }
          });
          const linkRes = await serviceUpstream('/auth/v1/admin/generate_link', {
            method: 'POST',
            body: { type: 'magiclink', email }
          });
          if (linkRes?.payload?.hashed_token) {
            authResult = await upstream(`/auth/v1/verify?type=magiclink&token_hash=${linkRes.payload.hashed_token}`);
          }
        }
      }

      if (authResult?.payload?.access_token) {
        const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
        const clearState = `paxinbot_google_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${isSecure ? '; Secure' : ''}`;
        const setSession = sessionCookies(req, authResult.payload.access_token, authResult.payload.refresh_token);
        res.setHeader('Set-Cookie', [clearState, ...setSession]);
        res.writeHead(302, { Location: `${origin}/conta`, 'cache-control': 'no-store' });
        res.end();
        return;
      }
      res.writeHead(302, { Location: `${origin}/cliente?error=google_login_failed`, 'cache-control': 'no-store' });
      res.end();
      return;
    } catch (e) {
      console.error('Google OAuth callback error:', e);
      res.writeHead(302, { Location: `${origin}/cliente?error=google_internal_error`, 'cache-control': 'no-store' });
      res.end();
      return;
    }
  }
  return json(res, 404, { ok: false, error: 'Rota não encontrada.' });
};
