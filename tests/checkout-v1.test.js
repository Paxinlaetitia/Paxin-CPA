'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('public catalog preserves the selected existing product through authentication', () => {
  const publicClient = read('script.js');
  const accountClient = read('auth-client.js');
  const callback = read('auth-callback.html');
  assert.match(publicClient, /\/conta\/checkout\?product=\$\{encodeURIComponent\(product\.id\)\}/);
  assert.match(accountClient, /sessionStorage\.setItem\('paxinbot_auth_return'/);
  assert.match(callback, /parsed\.origin===location\.origin/);
  assert.match(callback, /parsed\.pathname==='\/conta\/checkout'/);
  assert.match(callback, /parsed\.searchParams\.size===1/);
  assert.match(accountClient, /root\.hidden=true/);
  assert.match(accountClient, /selectedCheckoutIntentMatches\(productId\)/);
  assert.match(publicClient, /data-select-product/);
  assert.match(publicClient, /sessionStorage\.setItem\(PUBLIC_CHECKOUT_INTENT_KEY/);
});

test('checkout collects only the approved customer fields and supports PIX plus card', () => {
  const html = read('cliente.html');
  const css = read('client.css');
  assert.match(html, /id="checkout-payer-name"/);
  assert.match(html, /id="checkout-payer-email"[^>]+readonly/);
  assert.match(html, /name="paymentMethod" value="pix" checked/);
  assert.match(html, /name="paymentMethod" value="checkout_pro"/);
  assert.match(html, /id="checkout-pix-qr"/);
  assert.match(html, /id="checkout-pix-code" readonly/);
  assert.doesNotMatch(html, /checkout[^\n]{0,200}(CPF|endereço de cobrança)/i);
  assert.match(css, /\.auth-purchase-context\[hidden\] \{ display: none !important; \}/);
  assert.match(css, /\.auth-head \{ gap: 16px; margin-bottom: 22px; \}/);
  assert.match(css, /\.auth-purchase-context \{ display: grid; gap: 5px; margin: 0 0 22px;/);
});

test('checkout server keeps private credentials server-side and creates idempotent PIX orders', () => {
  const checkout = read('api/checkout/index.js');
  assert.match(checkout, /https:\/\/api\.mercadopago\.com\/v1\/orders/);
  assert.match(checkout, /'x-idempotency-key':String\(order\.orderId\)/);
  assert.match(checkout, /payment_method:\{ id:'pix', type:'bank_transfer' \}/);
  assert.match(checkout, /expiration_time:'PT30M'/);
  assert.match(checkout, /paxinbot_prepare_checkout_v2/);
  assert.doesNotMatch(read('auth-client.js'), /MERCADOPAGO_ACCESS_TOKEN/);
});

test('database migration makes checkout attempts idempotent and stores no PIX secret in the browser schema', () => {
  const migration = read('supabase/migrations/20260824_checkout_v1.sql');
  assert.match(migration, /orders_user_client_request_unique/);
  assert.match(migration, /pg_advisory_xact_lock/);
  assert.match(migration, /paxinbot_quote_checkout/);
  assert.match(migration, /paxinbot_attach_pix_order/);
  assert.doesNotMatch(migration, /qr_code/i);
});

test('Mercado Pago webhook supports signed Order events without dropping Checkout Pro payments', () => {
  const webhook = read('api/webhooks/mercadopago.js');
  assert.match(webhook, /const isOrder = type === 'order'/);
  assert.match(webhook, /\/v1\/orders\/\$\{encodeURIComponent\(dataId\)\}/);
  assert.match(webhook, /providerStatus === 'processed' \? 'approved'/);
  assert.match(webhook, /\/v1\/payments\/\$\{encodeURIComponent\(dataId\)\}/);
  assert.match(webhook, /crypto\.timingSafeEqual/);
  assert.match(webhook, /code:'invalid_signature'/);
  assert.match(webhook, /code:'provider_lookup_failed'/);
  assert.match(webhook, /code:'finalization_failed'/);
  assert.match(webhook, /isExpandedSimulation\(body\)/);
  assert.match(webhook, /mercadopago_webhook_simulation_acknowledged/);
  assert.match(webhook, /return json\(res, 200, \{ ok:true, simulated:true \}\)/);
  assert.ok(webhook.indexOf('verifySignature(req, dataId)') < webhook.indexOf('isExpandedSimulation(body)'), 'a simulação só pode ser aceita após validar a assinatura');
});

test('client locks the payment action and reuses one request id per attempt', () => {
  const client = read('auth-client.js');
  assert.match(client, /button\.disabled = true; button\.textContent = 'Preparando pagamento/);
  assert.match(client, /checkoutClientRequestId \|\|= newCheckoutRequestId\(\)/);
  assert.match(client, /showPixResult\(result\.orderId,result\.pix\)/);
  assert.match(client, /window\.open\(result\.checkoutUrl,'_blank','noopener,noreferrer'\)/);
});
