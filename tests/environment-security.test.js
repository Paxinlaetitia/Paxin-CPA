'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_unique_backend_credential';
process.env.PAXINBOT_SESSION_SECRET = 'unique-session-secret-with-at-least-32-bytes';
process.env.PAXINBOT_DOWNLOAD_SIGNING_SECRET = 'unique-download-secret-with-at-least-32-bytes';

const helpers = require('../api/_paxinbot');
const { securityDiagnostic } = require('../server/security-log');

function validEnvironment() {
  process.env.SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
  process.env.SUPABASE_SECRET_KEY = 'sb_secret_unique_backend_credential';
  process.env.PAXINBOT_SESSION_SECRET = 'unique-session-secret-with-at-least-32-bytes';
  process.env.PAXINBOT_DOWNLOAD_SIGNING_SECRET = 'unique-download-secret-with-at-least-32-bytes';
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  delete process.env.MERCADOPAGO_ACCESS_TOKEN;
  delete process.env.MERCADOPAGO_WEBHOOK_SECRET;
  delete process.env.MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS;
  delete process.env.MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS_UNTIL;
  delete process.env.PAXINBOT_ORIGIN_GATE_SECRET;
  delete process.env.PAXINBOT_ORIGIN_GATE_PREVIOUS_SECRET;
  delete process.env.PAXINBOT_ORIGIN_GATE_PREVIOUS_UNTIL;
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

test('private downloads require a distinct signing secret', () => {
  delete process.env.PAXINBOT_DOWNLOAD_SIGNING_SECRET;
  assert.throws(() => helpers.downloadSigningSecret(), /download privado ausente/);
  validEnvironment();
  process.env.PAXINBOT_DOWNLOAD_SIGNING_SECRET = process.env.PAXINBOT_SESSION_SECRET;
  assert.throws(() => helpers.validateCoreEnvironment(), /exclusivas por finalidade/);
});

test('credentials reused across purposes are rejected', () => {
  process.env.PAXINBOT_SESSION_SECRET = process.env.SUPABASE_SECRET_KEY.padEnd(40, 'x');
  process.env.SUPABASE_SECRET_KEY = process.env.PAXINBOT_SESSION_SECRET;
  assert.throws(() => helpers.validateCoreEnvironment(), /exclusivas por finalidade/);
});

test('origin gate rotation is bounded and rejects incomplete configuration', () => {
  process.env.PAXINBOT_ORIGIN_GATE_SECRET = 'current-origin-secret-with-at-least-32-bytes';
  process.env.PAXINBOT_ORIGIN_GATE_PREVIOUS_SECRET = 'previous-origin-secret-with-at-least-32-bytes';
  process.env.PAXINBOT_ORIGIN_GATE_PREVIOUS_UNTIL = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  assert.equal(helpers.originGateConfig().previous.length > 0, true);
  process.env.PAXINBOT_ORIGIN_GATE_PREVIOUS_UNTIL = new Date(Date.now() + 49 * 60 * 60 * 1000).toISOString();
  assert.throws(() => helpers.originGateConfig(), /não pode exceder 48 horas/);
  delete process.env.PAXINBOT_ORIGIN_GATE_SECRET;
  assert.throws(() => helpers.originGateConfig(), /sem o segredo atual/);
});

test('Mercado Pago webhook accepts a previous secret only inside a short rotation window', () => {
  process.env.MERCADOPAGO_WEBHOOK_SECRET = 'current-webhook-secret-value';
  process.env.MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS = 'previous-webhook-secret-value';
  process.env.MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS_UNTIL = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  assert.equal(helpers.mercadoPagoWebhookConfig().active.length, 2);
  process.env.MERCADOPAGO_WEBHOOK_SECRET_PREVIOUS_UNTIL = new Date(Date.now() - 1000).toISOString();
  assert.deepEqual(helpers.mercadoPagoWebhookConfig().active, ['current-webhook-secret-value']);
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
