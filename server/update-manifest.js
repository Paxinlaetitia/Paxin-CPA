'use strict';

const crypto = require('node:crypto');
const trust = require('./release-public-key.json');
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

// Public, offline-signed metadata only. The signing private key never lives in Vercel.
function readUpdateManifest(raw = process.env.PAXINBOT_UPDATE_MANIFEST) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 32 * 1024) throw new Error('update_manifest_missing');
  const document = JSON.parse(raw);
  const signature = document.signature;
  if (document.schema !== 'paxinbot.update/v1' || document.product !== 'Paxinbot' ||
      document.platform !== 'win32-x64' || document.channel !== 'stable' ||
      !/^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(document.version) ||
      !Number.isSafeInteger(document.sequence) || document.sequence < 1 ||
      signature?.algorithm !== 'Ed25519' || signature.keyId !== trust.keyId ||
      !/^[A-Za-z0-9_-]{86}$/.test(signature.value)) throw new Error('update_manifest_invalid');
  const unsigned = { ...document }; delete unsigned.signature;
  const key = crypto.createPublicKey({ key: Buffer.from(trust.publicKey, 'base64url'), format: 'der', type: 'spki' });
  if (!crypto.verify(null, Buffer.from(canonical(unsigned)), key, Buffer.from(signature.value, 'base64url'))) throw new Error('update_manifest_signature');
  const created = Date.parse(document.createdAt), expires = Date.parse(document.expiresAt), now = Date.now();
  if (!Number.isFinite(created) || !Number.isFinite(expires) || created > now + 300000 ||
      expires <= now || expires <= created || expires - created > 30 * 86400000) throw new Error('update_manifest_expired');
  const installer = document.installer;
  if (!installer || !Number.isSafeInteger(installer.size) || installer.size < 1048576 || installer.size > 1073741824 ||
      !/^[a-f0-9]{64}$/.test(installer.sha256) || !/^[a-f0-9]{64}$/.test(document.integrityDigest)) throw new Error('update_installer_invalid');
  const url = new URL(installer.url);
  if (!['https://paxincpa.store', 'https://www.paxincpa.store'].includes(url.origin) ||
      url.pathname !== '/releases/PaxinbotSetup.exe' || url.search || url.hash || url.username || url.password) throw new Error('update_url_invalid');
  return document;
}
module.exports = { readUpdateManifest };
