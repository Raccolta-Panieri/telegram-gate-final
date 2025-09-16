// netlify/functions/generate-token.js
import crypto from "crypto";

export async function handler(event) {
  const ADMIN_KEY = process.env.ADMIN_KEY;
  const provided = event.headers["x-admin-key"] || (event.queryStringParameters && event.queryStringParameters.admin_key);
  if (!provided || provided !== ADMIN_KEY) {
    return { statusCode: 401, body: "unauthorized" };
  }

  const isPost = event.httpMethod === "POST";
  const body = isPost ? JSON.parse(event.body || "{}") : (event.queryStringParameters || {});
  const redirectUrl = body.url || body.redirect;
  if (!redirectUrl) return { statusCode: 400, body: "missing url" };

  const ttl = parseInt(body.ttl || process.env.DEFAULT_TTL_SECONDS || "300", 10);
  const token = crypto.randomBytes(18).toString("hex");
  const key = `token:${token}`;

  const meta = {
    redirectUrl,
    createdAt: Date.now(),       // ms since epoch
    ttlSeconds: ttl,
    uses: 0
  };

  const upstashUrl = `${process.env.UPSTASH_REST_URL}/set/${encodeURIComponent(key)}?EX=${ttl}`;
  const res = await fetch(upstashUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.UPSTASH_REST_TOKEN}`,
      "Content-Type": "text/plain"
    },
    body: JSON.stringify(meta)
  });
  const json = await res.json();
  if (json.error) return { statusCode: 500, body: JSON.stringify(json) };

  return {
    statusCode: 200,
    body: JSON.stringify({ token, expires_in: ttl }),
    headers: { "content-type": "application/json" }
  };
}
