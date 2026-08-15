'use strict';
const { json, serviceUpstream, serviceRateLimit, sha256 } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const match = String(req.headers.authorization || '').match(/^Bearer\s+([a-f0-9]{64})$/i); if (!match) return json(res, 401, { ok: false, error: 'Sessão do aplicativo ausente.' });
  if (!await serviceRateLimit('desktop_session', match[1], 600, 3600)) return json(res, 429, { ok: false, error: 'Muitas validações de sessão. Aguarde e tente novamente.' }, { 'retry-after': '30' });
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_desktop_session_v2', { method: 'POST', body: { p_token_hash: sha256(match[1]) } });
  if (!response.ok || payload?.active === false) return json(res, 401, { ok: false, error: payload?.reason === 'usage_exhausted' ? 'Seu saldo de uso terminou.' : 'Sessão do aplicativo inválida, expirada ou sem acesso ativo.', reason: payload?.reason || 'session_invalid' });
  return json(res, 200, { ok: true, ...payload, minAppVersion: '1.0.0' });
};
