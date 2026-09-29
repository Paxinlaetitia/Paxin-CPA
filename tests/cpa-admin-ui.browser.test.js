const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('C:/Users/Guilh/OneDrive/Desktop/PAXINBOT/node_modules/playwright-core');

const root = path.join(__dirname, '..');
const pageAsset = fs.readFileSync(path.join(root, 'api/admin/_assets/page.txt'), 'utf8');
const clientAsset = fs.readFileSync(path.join(root, 'api/admin/_assets/client.txt'), 'utf8');
const styleAsset = fs.readFileSync(path.join(root, 'api/admin/_assets/style.txt'), 'utf8');

function json(response, body, status = 200) {
  response.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
  response.end(JSON.stringify(body));
}

test('Cash Hunters admin UI exercises creation, filtering, revoke, device reset and ban locally', async t => {
  const requests = [];
  let created = false;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    requests.push({ method: req.method, path: url.pathname, query: url.search, csrf: req.headers['x-paxinbot-csrf'] || '' });
    if (url.pathname === '/api/auth/csrf') return json(res, { ok: true, token: 'fixture-csrf' });
    if (url.pathname === '/api/admin' && url.searchParams.get('view') === 'asset' && url.searchParams.get('name') === 'client') return res.end(clientAsset);
    if (url.pathname === '/api/admin' && url.searchParams.get('view') === 'asset' && url.searchParams.get('name') === 'style') { res.writeHead(200, { 'content-type': 'text/css' }); return res.end(styleAsset); }
    if (url.pathname === '/site-shell.js' || url.pathname === '/controls.js' || url.pathname === '/script.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); return res.end(''); }
    if (url.pathname === '/assets/paxinbot-mark.svg') { res.writeHead(200, { 'content-type': 'image/svg+xml' }); return res.end('<svg xmlns="http://www.w3.org/2000/svg"></svg>'); }
    if (url.pathname === '/api/admin') return json(res, { ok: true, data: url.searchParams.get('action') === 'audit' ? [] : url.searchParams.get('action') === 'overview' ? {} : [] });
    if (url.pathname === '/api/licenses-admin') {
      if (req.method === 'GET') {
        if (url.searchParams.get('action') === 'audit') return json(res, { ok: true, data: { events: [{ event: 'fixture', licenseId: 'lic-1', category: 'test', createdAt: '2026-09-29T10:00:00Z' }] } });
        return json(res, { ok: true, data: { licenses: [{ id: 'lic-1', keyPrefix: 'CH-TEST', customerLabel: '<img src=x onerror=alert(1)>', email: 'owner@example.test', status: 'valid', configuredDuration: '1 dia', remainingSeconds: 86400, expiresAt: '2026-10-01T00:00:00Z', createdAt: '2026-09-29T09:00:00Z', activatedAt: '2026-09-29T09:01:00Z', lastAuth: '2026-09-29T09:02:00Z', heartbeatAt: '2026-09-29T09:03:00Z', hwid: 'a'.repeat(64), publicKey: 'old-key', activeSessions: 1, deviceBanned: false }] } });
      }
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const payload = JSON.parse(body || '{}');
        assert.equal(req.headers['x-paxinbot-csrf'], 'fixture-csrf');
        requests[requests.length - 1].body = payload;
        if (payload.action === 'create') { created = true; return json(res, { ok: true, data: { licenseKey: 'CH-ONCE-SECRET', license: { id: 'lic-new' } } }); }
        return json(res, { ok: true, data: {} });
      });
      return;
    }
    if (url.pathname === '/gestao/e7fc8a8f64e6e0aed8e92b6a' || url.pathname === '/gestao/e7fc8a8f64e6e0aed8e92b6a/licencas-cash-hunters') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(pageAsset); }
    res.writeHead(404); res.end('not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
  t.after(async () => { await browser.close(); await new Promise(resolve => server.close(resolve)); });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', dialog => dialog.accept());
  await page.goto(`http://127.0.0.1:${address.port}/gestao/e7fc8a8f64e6e0aed8e92b6a`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('tab', { name: 'Licenças Cash Hunters' }).click();
  await page.locator('#cash-license-create-form [name="unit"]').fill('days');
  await page.locator('#cash-license-create-form [name="value"]').fill('1');
  await page.getByRole('button', { name: 'Gerar chave' }).click();
  await page.locator('#cash-license-created').waitFor({ state: 'visible' });
  await page.locator('[data-license-key]').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('[data-license-key]')?.textContent === 'CH-ONCE-SECRET');
  assert.equal(await page.locator('[data-license-key]').textContent(), 'CH-ONCE-SECRET');
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  assert.equal(created, true);
  const createRequest = requests.find(item => item.body?.action === 'create');
  assert.deepEqual(createRequest.body.duration, { unit: 'days', value: 1 });
  await page.locator('#cash-license-search [name="q"]').fill('CH-TEST');
  await page.locator('#cash-license-search').evaluate(form => form.requestSubmit());
  assert.equal(await page.locator('#cash-licenses-list img').count(), 0);
  assert.match(await page.locator('#cash-licenses-list').textContent(), /<img src=x onerror=alert\(1\)>/);
  await page.locator('#cash-licenses-list [data-license-action="revoke"]').click();
  await page.locator('#cash-licenses-list [data-license-action="reset_device"]').click();
  await page.locator('#cash-licenses-list [data-license-action="replace_device"]').click();
  await page.locator('#cash-license-device-form [name="hwid"]').fill('b'.repeat(64));
  await page.locator('#cash-license-device-form [name="publicKey"]').fill('new-public-key');
  await page.locator('#cash-license-device-form button[type="submit"]').click();
  await page.locator('#cash-licenses-list [data-license-action="device"]').click();
  const actions = requests.filter(item => item.body?.action === 'update' || item.body?.action === 'device').map(item => item.body);
  assert.deepEqual(actions.map(item => item.operation || item.action), ['revoke', 'reset_device', 'replace_device', 'device']);
  assert.equal(actions[2].hwid, 'b'.repeat(64));
  assert.equal(actions[2].publicKey, 'new-public-key');
  assert.equal(actions.at(-1).banned, true);
  assert.match(await page.locator('#cash-licenses-list').textContent(), /owner@example\.test/);
  assert.match(await page.locator('#cash-licenses-list').textContent(), /Criada/);
  assert.match(await page.locator('#cash-licenses-list').textContent(), /Heartbeat/);
  assert.match(await page.locator('#cash-licenses-list').textContent(), /a{12}/);
  assert.equal(errors.length, 0, errors.join('\n'));
  await page.evaluate(() => { const node = document.createElement('div'); node.id = 'fixture'; document.body.append(node); });
  await page.evaluate(() => { const node = document.getElementById('fixture'); node.textContent = '<img src=x onerror=alert(1)>'; });
  assert.equal(await page.locator('#fixture img').count(), 0);
});
