'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { PUBLIC_FILES, buildPublic } = require('../build-public.cjs');
const root = path.join(__dirname, '..');

test('Vercel serves only the explicit public output, not the source root', () => {
  const config = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json')));
  assert.equal(config.outputDirectory, 'public-site');
  assert.equal(config.buildCommand, 'node build-public.cjs');
  assert.equal(config.public, false);
  assert.ok(config.functions['api/admin/index.js'].includeFiles.includes('_assets'));
  for (const relative of PUBLIC_FILES) {
    assert.doesNotMatch(relative, /^(?:server|api|tests|docs|scripts|supabase|backup|backups|\.git|\.vercel)\//);
    assert.doesNotMatch(relative, /\.map$|\.env|build-public/);
    assert.ok(fs.existsSync(path.join(root, relative)), relative);
  }
});

test('all local page scripts, styles and images remain available', () => {
  const approved = new Set(PUBLIC_FILES);
  for (const file of PUBLIC_FILES.filter(f => f.endsWith('.html'))) {
    const html = fs.readFileSync(path.join(root, file), 'utf8');
    for (const match of html.matchAll(/(?:src|href)=["']([^"']+)["']/g)) {
      const url = match[1].split(/[?#]/)[0].replace(/^\//, '');
      if (/^(?:https?:|data:)/.test(url) || !/\.(?:js|css|svg|png|ico)$/.test(url)) continue;
      assert.ok(approved.has(url), `${file} references missing asset ${url}`);
    }
  }
});

test('build excludes private files even when they exist in the project', t => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'paxin-public-build-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  for (const relative of PUBLIC_FILES) {
    fs.mkdirSync(path.dirname(path.join(fixture, relative)), { recursive: true });
    fs.copyFileSync(path.join(root, relative), path.join(fixture, relative));
  }
  fs.mkdirSync(path.join(fixture, 'server'));
  fs.writeFileSync(path.join(fixture, 'server/private.js'), 'TEST_ONLY');
  fs.writeFileSync(path.join(fixture, '.env'), 'TEST_ONLY');
  const result = buildPublic(fixture);
  assert.equal(fs.existsSync(path.join(result.output, 'server')), false);
  assert.equal(fs.existsSync(path.join(result.output, '.env')), false);
  for (const relative of PUBLIC_FILES) {
    assert.ok(fs.readFileSync(path.join(result.output, relative)).equals(fs.readFileSync(path.join(fixture, relative))));
  }
  assert.equal(buildPublic(fixture).publicFiles, PUBLIC_FILES.length);
  fs.writeFileSync(path.join(result.output, 'unexpected.txt'), 'preserve');
  assert.throws(() => buildPublic(fixture), /Unexpected file/);
  assert.equal(fs.readFileSync(path.join(result.output, 'unexpected.txt'), 'utf8'), 'preserve');
});
