'use strict';
const { config, publicOrigin } = require('../_paxinbot');

module.exports = async (req, res) => {
  if (req.method !== 'GET') { res.status(405).end(); return; }
  const { url } = config();
  const target = new URL(`${url}/auth/v1/authorize`);
  target.searchParams.set('provider', 'google');
  target.searchParams.set('redirect_to', `${publicOrigin(req)}/auth-callback.html?flow=google`);
  res.writeHead(302, { Location: target.toString(), 'cache-control': 'no-store' });
  res.end();
};
