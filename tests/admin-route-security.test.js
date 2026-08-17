'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const helperPath = require.resolve('../api/_paxinbot');
const handlerPath = require.resolve('../api/admin');

function response() {
  return {
    headers: {},
    statusCode: 0,
    setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
    end(value) { this.body = String(value || ''); }
  };
}

function loadHandler({ authenticated = false, owner = false } = {}) {
  delete require.cache[handlerPath];
  require.cache[helperPath] = {
    id: helperPath,
    filename: helperPath,
    loaded: true,
    exports: {
      requireTrustedHost: () => true,
      browserSession: async () => authenticated ? { user: { id: 'owner' }, access: 'session' } : null,
      upstream: async () => ({ response: { ok: true }, payload: owner }),
      json: (res, status, payload) => { res.statusCode = status; res.end(JSON.stringify(payload)); },
      readBody: async () => ({}), sameOriginRequest: () => true,
      safeUpstreamError: () => 'Erro', sendTransactionalEmail: async () => null, sha256: value => String(value),
      clientAddress: () => 'test-address', recordSiteSecurityEvent: async () => true
    }
  };
  return require('../api/admin');
}

test('admin-specific files are not deployed from the public root', () => {
  assert.equal(fs.existsSync(path.join(root, 'admin.html')), false);
  assert.equal(fs.existsSync(path.join(root, 'admin.css')), false);
  assert.equal(fs.existsSync(path.join(root, 'admin-client.js')), false);
  assert.equal(fs.existsSync(path.join(root, 'api', 'admin', '_assets', 'page.txt')), true);
});

test('unauthenticated visitors are redirected home without admin markup', async () => {
  const handler = loadHandler(); const res = response();
  await handler({ method: 'GET', query: { view: 'page' }, headers: {}, socket: {} }, res);
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.location, '/');
  assert.doesNotMatch(res.body, /Administração|admin-client/i);
  assert.equal(res.headers['cache-control'], 'private, no-store, max-age=0');
});

test('only an authenticated owner receives the protected page and assets', async () => {
  const handler = loadHandler({ authenticated: true, owner: true });
  const page = response();
  await handler({ method: 'GET', query: { view: 'page' }, headers: {}, socket: {} }, page);
  assert.equal(page.statusCode, 200);
  assert.match(page.body, /Administração Paxinbot/);
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);

  const asset = response();
  await handler({ method: 'GET', query: { view: 'asset', name: 'client' }, headers: {}, socket: {} }, asset);
  assert.equal(asset.statusCode, 200);
  assert.match(asset.body, /const Admin/);
  assert.equal(asset.headers['x-content-type-options'], 'nosniff');
});
