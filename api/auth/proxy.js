'use strict';
const https = require('node:https');
const { config, publicOrigin } = require('../_paxinbot');

module.exports = async (req, res) => {
  try {
    const { url: supabaseUrl } = config();
    const parsedSupabase = new URL(supabaseUrl);
    const incomingUrl = new URL(req.url, publicOrigin(req));
    
    // Constrói o caminho para o Supabase
    let subPath = incomingUrl.pathname;
    if (!subPath.startsWith('/auth/v1/')) {
      const qPath = req.query?.path;
      subPath = '/auth/v1/' + (Array.isArray(qPath) ? qPath.join('/') : String(qPath || ''));
    }
    
    const targetUrl = new URL(subPath + incomingUrl.search, parsedSupabase.origin);

    const headers = { ...req.headers };
    delete headers.host;
    delete headers.connection;
    headers['host'] = parsedSupabase.host;
    headers['x-forwarded-host'] = incomingUrl.host;
    headers['x-forwarded-proto'] = 'https';

    const proxyReq = https.request(targetUrl, {
      method: req.method,
      headers: headers
    }, (proxyRes) => {
      // Ajusta cabeçalho de Location se for redirect
      const location = proxyRes.headers['location'];
      const resHeaders = { ...proxyRes.headers };
      
      if (location) {
        try {
          const locUrl = new URL(location, targetUrl);
          if (locUrl.host === parsedSupabase.host) {
            locUrl.host = incomingUrl.host;
            locUrl.protocol = incomingUrl.protocol;
            resHeaders['location'] = locUrl.toString();
          }
        } catch {}
      }

      res.writeHead(proxyRes.statusCode, resHeaders);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error('Supabase auth proxy error:', err);
      res.statusCode = 502;
      res.end('Bad Gateway');
    });

    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      req.pipe(proxyReq);
    } else {
      proxyReq.end();
    }
  } catch (err) {
    console.error('Proxy handler fatal:', err);
    res.statusCode = 500;
    res.end('Internal Server Error');
  }
};
