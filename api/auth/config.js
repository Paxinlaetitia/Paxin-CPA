'use strict';
const { config, json } = require('../_paxinbot');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const { url, key } = config();
  return json(res, 200, { ok: true, url, key });
};
