'use strict';

const { json, requireTrustedHost, browserSession, sameOriginRequest, requestRateLimit, readBodyResult, serviceUpstream } = require('../api/_paxinbot');

const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_AVATAR_BYTES = 48 * 1024;
let activeImageUploads = 0;

async function normalizeAvatar(encoded) {
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(MAX_IMAGE_BYTES / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error('invalid_image');
  const input = Buffer.from(encoded, 'base64');
  if (!input.length || input.length > MAX_IMAGE_BYTES || input.toString('base64') !== encoded) throw new Error('invalid_image');
  const jpeg = input.subarray(0, 3).equals(Buffer.from([255, 216, 255]));
  const png = input.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  const webp = input.toString('ascii', 0, 4) === 'RIFF' && input.toString('ascii', 8, 12) === 'WEBP';
  if (!jpeg && !png && !webp) throw new Error('invalid_image');
  if (png) {
    for (let offset = 8; offset + 12 <= input.length;) {
      const length = input.readUInt32BE(offset);
      if (length > input.length - offset - 12 || input.toString('ascii', offset + 4, offset + 8) === 'acTL') throw new Error('invalid_image');
      offset += length + 12;
    }
  }
  const sharp = require('sharp');
  const image = sharp(input, { failOn: 'warning', limitInputPixels: 16000000, limitInputChannels: 4, animated: false }).timeout({ seconds: 5 });
  try {
    const metadata = await image.metadata();
    if (!['jpeg', 'png', 'webp'].includes(metadata.format) || (metadata.pages || 1) !== 1 || !metadata.width || !metadata.height || metadata.width > 8192 || metadata.height > 8192) throw new Error('invalid_image');
    const output = await image.rotate().resize(256, 256, { fit: 'cover' }).flatten({ background: '#ffffff' }).jpeg({ quality: 80 }).toBuffer();
    if (output.length > MAX_AVATAR_BYTES) throw new Error('invalid_image');
    return 'data:image/jpeg;base64,' + output.toString('base64');
  } finally { image.destroy(); }
}

module.exports = async (req, res) => {
  try {
    if (!requireTrustedHost(req, res)) return;
    if (!['GET', 'POST', 'DELETE'].includes(req.method)) return json(res, 405, { ok: false, error: 'Método não permitido.' });
    if (req.method !== 'GET' && !sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
    const session = await browserSession(req, res);
    if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
    if (!await requestRateLimit(req, res, { scope: req.method === 'GET' ? 'avatar_read_user' : 'avatar_write_user', subject: session.user.id, limit: req.method === 'GET' ? 120 : 10, windowSeconds: 600, failClosed: true })) return;
    let avatarData = null;
    if (req.method === 'POST') {
      const parsed = await readBodyResult(req, res, { maximumBytes: Math.ceil(MAX_IMAGE_BYTES / 3) * 4 + 100, allowedMediaTypes: ['application/json'] });
      if (!parsed.ok) return;
      if (!parsed.body || typeof parsed.body !== 'object' || Array.isArray(parsed.body) || Object.keys(parsed.body).some(key => key !== 'image')) return json(res, 400, { ok: false, error: 'Solicitação de foto inválida.' });
      if (activeImageUploads >= 2) return json(res, 503, { ok: false, error: 'O processamento de fotos está ocupado. Tente novamente em instantes.' }, { 'retry-after': '5' });
      activeImageUploads += 1;
      try { avatarData = await normalizeAvatar(parsed.body.image); }
      catch { return json(res, 400, { ok: false, error: 'Use uma imagem JPG, PNG ou WebP estática de até 2 MB e 16 megapixels.' }); }
      finally { activeImageUploads -= 1; }
    }
    const action = req.method === 'GET' ? 'read' : req.method === 'POST' ? 'update' : 'delete';
    const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_service_avatar', {
      method: 'POST', body: { p_user_id: session.user.id, p_action: action, p_avatar_data: avatarData }, signal: AbortSignal.timeout(10000)
    });
    if (!response.ok || payload?.ok !== true) return json(res, 503, { ok: false, error: 'Não foi possível acessar sua foto agora. Tente novamente.' });
    if (req.method !== 'GET') return json(res, 200, { ok: true, hasPhoto: action === 'update' });
    const stored = String(payload.avatarData || '');
    if (!stored) return json(res, 404, { ok: false, error: 'Conta sem foto de perfil.' });
    if (stored.length > 65559 || !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(stored)) return json(res, 503, { ok: false, error: 'Foto indisponível.' });
    const output = Buffer.from(stored.slice(23), 'base64');
    res.statusCode = 200;
    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('Content-Length', output.length);
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('Content-Disposition', 'inline; filename="avatar.jpg"');
    return res.end(output);
  } catch { return json(res, 503, { ok: false, error: 'O serviço de fotos está temporariamente indisponível.' }); }
};
