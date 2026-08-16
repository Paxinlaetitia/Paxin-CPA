'use strict';
const { json, requireTrustedHost, upstream, safeUpstreamError } = require('../_paxinbot');

module.exports = async (req, res) => {
  if (!requireTrustedHost(req, res)) return;
  if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_list_active_products', { method: 'POST', body: {} });
  return json(
    res,
    response.ok ? 200 : 503,
    response.ok ? { ok: true, data: payload } : { ok: false, error: safeUpstreamError(payload, 'Não foi possível carregar as modalidades agora.') },
    response.ok ? { 'cache-control': 'public, s-maxage=60, stale-while-revalidate=300' } : {}
  );
};
