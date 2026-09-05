'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const sharp = require('sharp');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';
process.env.PAXINBOT_SESSION_SECRET = 'test-only-avatar-session-secret-not-deployed';
process.env.PUBLIC_SITE_URL = 'https://www.paxincpa.store';

const handler = require('../api/account');
const accountId = 'a1234567-1234-4234-8234-123456789abc';
const csrfToken = 'x'.repeat(43);

test('photo endpoint reuses the account function through an explicit rewrite', () => {
  const config = JSON.parse(fs.readFileSync(path.join(__dirname, '../vercel.json'), 'utf8'));
  assert.ok(config.rewrites.some(rule => rule.source === '/api/account/avatar' && rule.destination === '/api/account?action=avatar'));
  assert.equal(fs.existsSync(path.join(__dirname, '../api/account/avatar.js')), false);
});

function request(method = 'POST', body = {}, headers = {}) {
  return { method, body, query: { action: 'avatar' }, headers: { 'content-type': 'application/json', origin: 'https://www.paxincpa.store', cookie: `paxinbot_access=test; paxinbot_csrf=${csrfToken}`, 'x-paxinbot-csrf': csrfToken, ...headers }, socket: { remoteAddress: '127.0.0.1' } };
}

function response() {
  return { statusCode: 0, headers: {}, setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(value) { this.body = Buffer.isBuffer(value) ? value : JSON.parse(value); } };
}

function mockBackend(context, options = {}) {
  const calls = [];
  const saved = [];
  context.mock.method(global, 'fetch', async (url, init = {}) => {
    calls.push(String(url));
    const reply = (status, payload) => ({ ok: status >= 200 && status < 300, status, json: async () => payload });
    if (url.endsWith('/auth/v1/user')) return reply(options.anonymous ? 401 : 200, { id: accountId });
    if (url.includes('paxinbot_service_rate_limit')) return options.rateUnavailable ? reply(503, {}) : reply(200, { allowed: !options.limited, remaining: options.limited ? 0 : 9, resetAfter: 60 });
    if (url.includes('paxinbot_record_site_security_event')) return reply(200, { ok: true });
    if (url.endsWith('/paxinbot_service_avatar')) {
      const body = JSON.parse(init.body);
      saved.push(body);
      if (options.unavailable) return reply(500, { message: 'private database error' });
      return reply(200, { ok: true, avatarData: options.avatarData || body.p_avatar_data });
    }
    throw new Error('Unexpected upstream path: ' + url);
  });
  return { calls, saved };
}

test('photos require an authenticated browser account', async context => {
  const backend = mockBackend(context, { anonymous: true });
  const res = response();
  await handler(request('GET'), res);
  assert.equal(res.statusCode, 401);
  assert.equal(backend.saved.length, 0);
});

for (const headers of [{ origin: 'https://attacker.example' }, { 'x-paxinbot-csrf': '' }, { 'x-paxinbot-csrf': 'z'.repeat(43) }]) {
  test('cross-origin or invalid CSRF mutations stop before upstream work ' + JSON.stringify(headers), async context => {
    const backend = mockBackend(context);
    const res = response();
    await handler(request('POST', {}, headers), res);
    assert.equal(res.statusCode, 403);
    assert.equal(backend.calls.length, 0);
  });
}

test('upload and removal respect the per-account rate limit', async context => {
  const backend = mockBackend(context, { limited: true });
  for (const method of ['POST', 'DELETE']) {
    const res = response();
    await handler(request(method), res);
    assert.equal(res.statusCode, 429);
  }
  assert.equal(backend.saved.length, 0);
});

test('oversized bodies are rejected before decoding', async context => {
  const backend = mockBackend(context);
  const res = response();
  await handler(request('POST', { image: 'A'.repeat(3 * 1024 * 1024) }), res);
  assert.equal(res.statusCode, 413);
  assert.equal(backend.saved.length, 0);
});

test('uploads stop when abuse protection is unavailable', async context => {
  const backend = mockBackend(context, { rateUnavailable: true });
  const res = response();
  await handler(request(), res);
  assert.equal(res.statusCode, 503);
  assert.equal(backend.saved.length, 0);
});

test('animated PNG containers cannot be submitted as static photos', async context => {
  const backend = mockBackend(context);
  const png = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#fff' } }).png().toBuffer();
  const animationChunk = Buffer.alloc(20);
  animationChunk.writeUInt32BE(8, 0);
  animationChunk.write('acTL', 4);
  animationChunk.writeUInt32BE(2, 8);
  const image = Buffer.concat([png.subarray(0, 33), animationChunk, png.subarray(33)]);
  const res = response();
  await handler(request('POST', { image: image.toString('base64') }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(backend.saved.length, 0);
});

for (const input of [Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), Buffer.from('<html>not a photo</html>'), Buffer.from([255, 216, 255, 0]), Buffer.from('GIF89a')]) {
  test('invalid or active content never reaches image storage: ' + input.subarray(0, 8).toString('hex'), async context => {
    const backend = mockBackend(context);
    const res = response();
    await handler(request('POST', { image: input.toString('base64') }), res);
    assert.equal(res.statusCode, 400);
    assert.equal(backend.saved.length, 0);
  });
}

test('only the authenticated owner is used and arbitrary fields are rejected', async context => {
  const backend = mockBackend(context);
  const res = response();
  await handler(request('POST', { image: 'abcd', userId: 'another-user', url: 'http://127.0.0.1' }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(backend.saved.length, 0);
});

test('large pixel dimensions cannot bypass the compressed byte limit', async context => {
  const backend = mockBackend(context);
  const image = await sharp({ create: { width: 4100, height: 4100, channels: 3, background: '#ffffff' } }).png().toBuffer();
  assert.ok(image.length < 2 * 1024 * 1024);
  const res = response();
  await handler(request('POST', { image: image.toString('base64') }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(backend.saved.length, 0);
});

for (const format of ['jpeg', 'png', 'webp']) {
  test(`${format} upload is decoded, resized and stripped of metadata before storage`, async context => {
    const backend = mockBackend(context);
    const original = await sharp({ create: { width: 320, height: 180, channels: 3, background: '#f0a500' } }).withMetadata({ orientation: 6 }).toFormat(format).toBuffer();
    const res = response();
    await handler(request('POST', { image: original.toString('base64') }), res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.hasPhoto, true);
    assert.equal(backend.saved[0].p_user_id, accountId);
    assert.equal(backend.saved[0].p_action, 'update');
    const processed = Buffer.from(backend.saved[0].p_avatar_data.slice(23), 'base64');
    const metadata = await sharp(processed).metadata();
    assert.equal(metadata.format, 'jpeg');
    assert.equal(metadata.width, 256);
    assert.equal(metadata.height, 256);
    assert.equal(metadata.exif, undefined);
    assert.equal(metadata.icc, undefined);
    assert.ok(processed.length <= 48 * 1024);
    assert.notDeepEqual(processed, original);
  });
}

test('photo retrieval is private, uncached and serves only the verified owner', async context => {
  const image = await sharp({ create: { width: 16, height: 16, channels: 3, background: '#f0a500' } }).jpeg().toBuffer();
  const backend = mockBackend(context, { avatarData: 'data:image/jpeg;base64,' + image.toString('base64') });
  const res = response();
  const req = request('GET'); req.query.userId = 'another-user';
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(backend.saved[0].p_user_id, accountId);
  assert.deepEqual(res.body, image);
  assert.equal(res.headers['cache-control'], 'private, no-store');
  assert.equal(res.headers['content-type'], 'image/jpeg');
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['cross-origin-resource-policy'], 'same-origin');
});

test('removal only clears the current account photo and confirms persistence', async context => {
  const backend = mockBackend(context);
  const res = response();
  await handler(request('DELETE'), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.hasPhoto, false);
  assert.deepEqual(backend.saved[0], { p_user_id: accountId, p_action: 'delete', p_avatar_data: null });
});

test('backend failure never reports a saved photo or exposes its details', async context => {
  mockBackend(context, { unavailable: true });
  const res = response();
  await handler(request('DELETE'), res);
  assert.equal(res.statusCode, 503);
  assert.equal(res.body.ok, false);
  assert.doesNotMatch(JSON.stringify(res.body), /private database/);
});

test('only service-role image processing can change the private avatar column', () => {
  const migration = fs.readFileSync(path.join(__dirname, '../supabase/migrations/20260905_profile_avatar.sql'), 'utf8');
  assert.match(migration, /auth\.role\(\) is distinct from 'service_role'/);
  assert.match(migration, /revoke update \(avatar_data\) on public\.profiles from public, anon, authenticated/);
  assert.match(migration, /revoke all on function public\.paxinbot_service_avatar\(uuid,text,text\) from public,anon,authenticated/);
  assert.match(migration, /where id=p_user_id and disabled_at is null for update/);
  assert.match(migration, /octet_length\(avatar_data\) <= 65559/);
});
