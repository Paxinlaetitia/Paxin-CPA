'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_unique_backend_credential';
process.env.PAXINBOT_SESSION_SECRET = 'unique-session-secret-with-at-least-32-bytes';

const helpers = require('../api/_paxinbot');
const { securityDiagnostic } = require('../server/security-log');

function validEnvironment() {
  process.env.SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
  process.env.SUPABASE_SECRET_KEY = 'sb_secret_unique_backend_credential';
  process.env.PAXINBOT_SESSION_SECRET = 'unique-session-secret-with-at-least-32-bytes';
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  delete process.env.MERCADOPAGO_ACCESS_TOKEN;
  delete process.env.MERCADOPAGO_WEBHOOK_SECRET;
  delete process.env.RESEND_API_KEY;
}

test.beforeEach(validEnvironment);

test('core production configuration is valid only with dedicated secrets', () => {
  assert.equal(helpers.validateCoreEnvironment(), true);
});

test('legacy service-role variable is not accepted as a fallback', () => {
  delete process.env.SUPABASE_SECRET_KEY;
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'legacy.jwt.value';
  assert.throws(() => helpers.serviceConfig(), /Chave secreta do Supabase ausente/);
});

test('session signing never falls back to another provider credential', () => {
  delete process.env.PAXINBOT_SESSION_SECRET;
  assert.throws(() => helpers.sessionSecret(), /Segredo de sessão interno ausente/);
});

test('credentials reused across purposes are rejected', () => {
  process.env.PAXINBOT_SESSION_SECRET = process.env.SUPABASE_SECRET_KEY.padEnd(40, 'x');
  process.env.SUPABASE_SECRET_KEY = process.env.PAXINBOT_SESSION_SECRET;
  assert.throws(() => helpers.validateCoreEnvironment(), /exclusivas por finalidade/);
});

test('security diagnostics allow only non-sensitive fields', () => {
  const original = console.warn;
  let output = '';
  console.warn = value => { output = String(value); };
  try {
    securityDiagnostic('test.event', {
      reason:'invalid_signature', status:401,
      token:'must-not-appear', email:'cliente@example.com', authorization:'Bearer secret'
    });
  } finally {
    console.warn = original;
  }
  assert.match(output, /test\.event/);
  assert.match(output, /invalid_signature/);
  assert.doesNotMatch(output, /must-not-appear|cliente@example|Bearer secret|authorization|token/);
});
