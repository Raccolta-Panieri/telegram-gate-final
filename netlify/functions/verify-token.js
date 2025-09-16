// netlify/functions/verify-token.js
// Behavior: verifies Cloudflare Turnstile server-side on every use, returns the saved redirectUrl.
// Token is REUSABLE until its TTL expires (we preserve remaining TTL when updating uses).
export async function handler(event) {
  try {
    if (event.httpMethod !== 'POST') {
      return { statusCode: 405, body: 'method not allowed' };
    }
    const body = JSON.parse(event.body || '{}');
    const token = body.t || body.token;
    const turnstileResp = body['cf-turnstile-response'] || body.turnstile_response;

    if (!token) return { statusCode: 400, body: 'missing token' };
    if (!turnstileResp) return { statusCode: 400, body: 'missing turnstile response' };

    // Verify Turnstile server-side
    const verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    const form = new URLSearchParams();
    form.append('secret', process.env.TURNSTILE_SECRET || '');
    form.append('response', turnstileResp);
    const remoteip = event.headers['x-forwarded-for']?.split(',')[0]?.trim() || event.headers['cf-connecting-ip'];
    if (remoteip) form.append('remoteip', remoteip);

    const vRes = await fetch(verifyUrl, { method: 'POST', body: form });
    const vJson = await vRes.json();
    if (!vJson.success) {
      return { statusCode: 401, body: JSON.stringify({ ok: false, detail: 'turnstile failed', verify: vJson }) };
    }

    // Read metadata from Upstash
    const key = `token:${token}`;
    const upstashGet = `${process.env.UPSTASH_REST_URL}/get/${encodeURIComponent(key)}`;
    const got = await fetch(upstashGet, {
      headers: { 'Authorization': `Bearer ${process.env.UPSTASH_REST_TOKEN}` }
    });
    const gotJson = await got.json();
    if (!gotJson || gotJson.result == null) {
      return { statusCode: 404, body: JSON.stringify({ ok: false, detail: 'token not found or expired' }) };
    }

    let meta;
    try { meta = JSON.parse(gotJson.result); } catch (e) { meta = { redirectUrl: String(gotJson.result), createdAt: Date.now(), ttlSeconds: parseInt(process.env.DEFAULT_TTL_SECONDS || '300',10), uses:0 }; }

    // compute remaining TTL (seconds) from original createdAt + ttlSeconds
    const expiresAt = (meta.createdAt || Date.now()) + ( (meta.ttlSeconds || parseInt(process.env.DEFAULT_TTL_SECONDS || '300',10)) * 1000 );
    const remainingMs = expiresAt - Date.now();
    const remainingSec = Math.max(1, Math.floor(remainingMs / 1000));

    // update uses and lastUsedAt
    meta.uses = (meta.uses || 0) + 1;
    meta.lastUsedAt = Date.now();

    // save back preserving remaining TTL
    const upstashSet = `${process.env.UPSTASH_REST_URL}/set/${encodeURIComponent(key)}?EX=${remainingSec}`;
    await fetch(upstashSet, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.UPSTASH_REST_TOKEN}`, 'Content-Type': 'text/plain' },
      body: JSON.stringify(meta)
    });

    // respond with the redirect URL
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true, url: meta.redirectUrl })
    };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, body: JSON.stringify({ ok: false, error: 'internal error' }) };
  }
}
