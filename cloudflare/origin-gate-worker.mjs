const ORIGIN_HEADER = 'x-paxinbot-origin-key';

export default {
  async fetch(request, env) {
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
