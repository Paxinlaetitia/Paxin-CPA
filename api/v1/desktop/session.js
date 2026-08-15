'use strict';
const { json, upstream, sha256 } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const match = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i); if (!match) return json(res, 401, { ok: false, error: 'Sessão do aplicativo ausente.' });
  const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_desktop_session', { method: 'POST', body: { p_token_hash: sha256(match[1]) } });
  if (!response.ok) return json(res, 401, { ok: false, error: 'Sessão do aplicativo inválida, expirada ou sem acesso ativo.' });
  return json(res, 200, { ok: true, ...payload, minAppVersion: '1.0.0' });
};
