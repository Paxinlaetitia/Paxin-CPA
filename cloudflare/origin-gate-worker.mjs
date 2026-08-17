const ORIGIN_HEADER = 'x-paxinbot-origin-key';
const RELEASE_PATH = '/releases/PaxinbotSetup.exe';
const RELEASE_OBJECT = 'PaxinbotSetup.exe';

function plain(status, message, extra = {}) {
  return new Response(message, { status, headers:{ 'cache-control':'private, no-store, max-age=0', 'content-type':'text/plain; charset=utf-8', 'x-content-type-options':'nosniff', ...extra } });
}

function decodeBase64Url(value) {
  try {
    const normalized=value.replaceAll('-','+').replaceAll('_','/');
    const binary=atob(normalized+'='.repeat((4-normalized.length%4)%4));
    return Uint8Array.from(binary,character=>character.charCodeAt(0));
  } catch { return null; }
}

async function validReleaseToken(url, env) {
  const secret=String(env.PAXINBOT_DOWNLOAD_SIGNING_SECRET || '');
  const secretSize=new TextEncoder().encode(secret).byteLength;
  const expiresText=url.searchParams.get('expires') || '';
  const nonce=url.searchParams.get('nonce') || '';
  const signatureText=url.searchParams.get('signature') || '';
  if (secretSize<32 || secretSize>128 || url.searchParams.size!==3 || !/^\d{10}$/.test(expiresText) || !/^[A-Za-z0-9_-]{24}$/.test(nonce) || !/^[A-Za-z0-9_-]{43}$/.test(signatureText)) return false;
  const now=Math.floor(Date.now()/1000); const expires=Number(expiresText);
  if (!Number.isSafeInteger(expires) || expires<=now || expires>now+180) return false;
  const signature=decodeBase64Url(signatureText); if (!signature || signature.byteLength!==32) return false;
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{ name:'HMAC',hash:'SHA-256' },false,['verify']);
  const canonical=`GET\n${RELEASE_PATH}\n${expires}\n${nonce}`;
  return crypto.subtle.verify('HMAC',key,signature,new TextEncoder().encode(canonical));
}

async function serveRelease(request, env, url) {
  if (request.method!=='GET') return plain(405,'Método não permitido.',{ allow:'GET' });
  if (!env.PAXINBOT_RELEASES || typeof env.PAXINBOT_RELEASES.get!=='function') return plain(503,'Download temporariamente indisponível.');
  if (!await validReleaseToken(url,env)) return plain(403,'Autorização de download inválida ou expirada.');
  let object;
  try { object=await env.PAXINBOT_RELEASES.get(RELEASE_OBJECT,{ range:request.headers }); }
  catch { return request.headers.has('range') ? plain(416,'Intervalo solicitado inválido.') : plain(503,'Download temporariamente indisponível.'); }
  if (!object) return plain(404,'Instalador não encontrado.');
  const headers=new Headers(); object.writeHttpMetadata?.(headers);
  headers.set('cache-control','private, no-store, max-age=0');
  headers.set('content-disposition','attachment; filename="PaxinbotSetup.exe"');
  headers.set('content-type','application/vnd.microsoft.portable-executable');
  headers.set('accept-ranges','bytes'); headers.set('x-content-type-options','nosniff');
  if (object.httpEtag) headers.set('etag',object.httpEtag);
  let status=200;
  if (object.range && Number.isFinite(object.range.offset) && Number.isFinite(object.range.length)) {
    const end=object.range.offset+object.range.length-1; headers.set('content-range',`bytes ${object.range.offset}-${end}/${object.size}`); headers.set('content-length',String(object.range.length)); status=206;
  } else if (Number.isFinite(object.size)) headers.set('content-length',String(object.size));
  return new Response(object.body,{ status,headers });
}

export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    const cf = request.cf || {};
    if (url.pathname.startsWith('/api/auth/')) {
      if (cf.isTor === true || (typeof cf.threatScore === 'number' && cf.threatScore > 85)) {
        return new Response('Acesso bloqueado por segurança (Proxy/Tor detectado).', {
          status: 403,
          headers: { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' }
        });
      }
    }
    if (url.pathname.startsWith('/releases/')) return url.pathname===RELEASE_PATH ? serveRelease(request,env,url) : plain(404,'Arquivo não encontrado.');
    if (url.pathname.startsWith('/auth/v1/')) {
      const supabaseHost = 'drkyjgnctbxmupbfarnj.supabase.co';
      const targetUrl = new URL(url.pathname + url.search, `https://${supabaseHost}`);
      const headers = new Headers(request.headers);
      headers.set('host', supabaseHost);
      headers.set('x-forwarded-host', url.host);
      headers.set('x-forwarded-proto', 'https');
      const response = await fetch(new Request(targetUrl.toString(), {
        method: request.method,
        headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'manual'
      }));
      const resHeaders = new Headers(response.headers);
      const location = resHeaders.get('location');
      if (location) {
        try {
          const locUrl = new URL(location, targetUrl);
          if (locUrl.host === supabaseHost) {
            locUrl.host = url.host;
            locUrl.protocol = url.protocol;
            resHeaders.set('location', locUrl.toString());
          }
        } catch {}
      }
      return new Response(response.body, { status: response.status, headers: resHeaders });
    }
    const secret = String(env.PAXINBOT_ORIGIN_GATE_SECRET || '');
    const secretBytes = new TextEncoder().encode(secret).byteLength;
    if (secretBytes < 32 || secretBytes > 128) {
      return new Response('Origem temporariamente indisponível.', {
        status: 503,
        headers: { 'cache-control':'no-store', 'content-type':'text/plain; charset=utf-8' }
      });
    }
    const headers = new Headers(request.headers);
    headers.delete(ORIGIN_HEADER);
    headers.set(ORIGIN_HEADER, secret);
    return fetch(new Request(request, { headers }));
  }
};
