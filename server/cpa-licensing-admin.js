'use strict';

const crypto = require('node:crypto');
const {
  json, requireTrustedHost, readBodyResult, browserSession, upstream,
  requestRateLimit, sameOriginRequest, isUuid
} = require('../api/_paxinbot');
const { generateLicense } = require('./cpa-licensing');

const OPERATIONS = new Set([
  'activate', 'deactivate', 'suspend', 'revoke', 'ban', 'unban',
  'reset_device', 'replace_device', 'extend', 'set_expiration', 'terminate_sessions'
]);
const DURATIONS = new Set(['hours', 'days', 'weeks', 'months', 'lifetime', 'custom']);
const STATUSES = new Set(['', 'pending', 'inactive', 'active', 'suspended', 'revoked', 'banned', 'expired']);

function invalid(res) { return json(res, 400, { ok:false, code:'invalid_request' }); }

function duration(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const unit = String(value.unit || '');
  if (!DURATIONS.has(unit)) return null;
  if (unit === 'lifetime') return { unit, value:null, expiresAt:null };
  if (unit === 'custom') {
    const time = Date.parse(String(value.expiresAt || ''));
    return Number.isFinite(time) ? { unit, value:null, expiresAt:new Date(time).toISOString() } : null;
  }
  const amount = Number(value.value);
  return Number.isInteger(amount) && amount >= 1 && amount <= 10000 ? { unit, value:amount, expiresAt:null } : null;
}

function deviceBinding(body) {
  const hwid = String(body.hwid || '').toLowerCase();
  const publicKey = String(body.publicKey || '');
  if (!/^[a-f0-9]{64}$/.test(hwid) || !/^[A-Za-z0-9_-]{40,255}$/.test(publicKey)) return null;
  let key;
  try { key = crypto.createPublicKey({ key:Buffer.from(publicKey, 'base64url'), format:'der', type:'spki' }); }
  catch { return null; }
  if (key.asymmetricKeyType !== 'ed25519') return null;
  const publicKeyHash = crypto.createHash('sha256').update(Buffer.from(publicKey, 'base64url')).digest('hex');
  return { hwid, publicKey, publicKeyHash };
}

async function ownerRpc(session, name, body) {
  return upstream(`/rest/v1/rpc/${name}`, {
    method:'POST', headers:{ authorization:`Bearer ${session.access}` }, body
  });
}

async function ownerSession(req, res) {
  const session = await browserSession(req, res);
  if (!session) { json(res, 401, { ok:false, code:'not_authenticated' }); return null; }
  const check = await ownerRpc(session, 'paxinbot_is_owner', {});
  if (!check.response.ok || check.payload !== true) { json(res, 403, { ok:false, code:'owner_required' }); return null; }
  return session;
}

async function handleGet(req, res, session) {
  if (!await requestRateLimit(req, res, { scope:'cpa_license_admin_read', subject:session.user.id, limit:600, windowSeconds:600 })) return;
  const action = String(req.query?.action || 'list');
  const rpc = action === 'list' ? 'cpa_owner_list_licenses' : action === 'audit' ? 'cpa_owner_list_license_audit' : '';
  if (!rpc) return json(res, 404, { ok:false, code:'invalid_request' });
  const status = String(req.query?.status || '');
  if (action === 'list' && !STATUSES.has(status)) return invalid(res);
  const result = await ownerRpc(session, rpc, action === 'list'
    ? { p_query:String(req.query?.q || '').trim().slice(0,120), p_status:status || null, p_limit:200 }
    : { p_limit:200 });
  if (!result.response.ok) return json(res, 503, { ok:false, code:'server_unavailable' });
  return json(res, 200, { ok:true, data:Array.isArray(result.payload) ? result.payload : [] });
}

async function createLicense(res, session, body) {
  const term = duration(body.duration);
  const activationPolicy = String(body.activationPolicy || '');
  const customerId = body.customerId === undefined || body.customerId === null || body.customerId === '' ? null : String(body.customerId);
  if (!term || !['first','immediate'].includes(activationPolicy) || (customerId !== null && !isUuid(customerId))) return invalid(res);
  let generated;
  try { generated = generateLicense(); }
  catch { return json(res, 503, { ok:false, code:'server_unavailable' }); }
  const result = await ownerRpc(session, 'cpa_owner_create_license', {
    p_key_id:generated.keyId, p_key_prefix:generated.keyPrefix,
    p_key_hmac:generated.keyHash, p_pepper_version:generated.pepperVersion,
    p_duration_unit:term.unit, p_duration_value:term.value,
    p_custom_expires_at:term.expiresAt, p_activation_policy:activationPolicy,
    p_customer_id:customerId
  });
  if (!result.response.ok || !result.payload || typeof result.payload !== 'object') return json(res, 400, { ok:false, code:'invalid_request' });
  return json(res, 201, { ok:true, data:{ licenseKey:generated.licenseKey, license:result.payload } });
}

async function updateLicense(res, session, body) {
  const licenseId = String(body.licenseId || '');
  const operation = String(body.operation || '');
  if (!isUuid(licenseId) || !OPERATIONS.has(operation)) return invalid(res);
  const term = body.duration === undefined ? null : duration(body.duration);
  if (body.duration !== undefined && !term) return invalid(res);
  let expiresAt = body.expiresAt === undefined || body.expiresAt === null || body.expiresAt === '' ? null : new Date(body.expiresAt);
  if (expiresAt && !Number.isFinite(expiresAt.getTime())) return invalid(res);
  expiresAt = expiresAt ? expiresAt.toISOString() : null;
  let binding = null;
  if (operation === 'replace_device') {
    binding = deviceBinding(body);
    if (!binding) return invalid(res);
  }
  const result = await ownerRpc(session, 'cpa_owner_update_license', {
    p_license_id:licenseId, p_operation:operation,
    p_duration_unit:term?.unit || null, p_duration_value:term?.value ?? null,
    p_expires_at:term?.expiresAt || expiresAt,
    p_hwid:binding?.hwid || null, p_public_key:binding?.publicKey || null,
    p_public_key_hash:binding?.publicKeyHash || null
  });
  if (!result.response.ok || !result.payload || typeof result.payload !== 'object') return json(res, 400, { ok:false, code:'invalid_request' });
  return json(res, 200, { ok:true, data:result.payload });
}

async function setDeviceBan(res, session, body) {
  const hwid = String(body.hwid || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hwid) || typeof body.banned !== 'boolean') return invalid(res);
  const result = await ownerRpc(session, 'cpa_owner_set_device_ban', { p_hwid:hwid, p_banned:body.banned });
  if (!result.response.ok) return json(res, 400, { ok:false, code:'invalid_request' });
  return json(res, 200, { ok:true, data:result.payload });
}

async function handle(req, res) {
  if (!requireTrustedHost(req, res)) return;
  const session = await ownerSession(req, res); if (!session) return;
  if (req.method === 'GET') return handleGet(req, res, session);
  if (req.method !== 'POST') return json(res, 405, { ok:false, code:'invalid_request' });
  if (!await requestRateLimit(req, res, { scope:'cpa_license_admin_write', subject:session.user.id, limit:120, windowSeconds:600 })) return;
  if (!sameOriginRequest(req)) return json(res, 403, { ok:false, code:'invalid_request' });
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
  const action = String(parsed.body.action || '');
  if (action === 'create') return createLicense(res, session, parsed.body);
  if (action === 'update') return updateLicense(res, session, parsed.body);
  if (action === 'device') return setDeviceBan(res, session, parsed.body);
  return invalid(res);
}

module.exports = async (req, res) => {
  try { return await handle(req, res); }
  catch { return json(res, 503, { ok:false, code:'server_unavailable' }); }
};

module.exports._test = { handle, duration, deviceBinding };
