// Cloudflare Worker: password-protected message mailboxes.
// Uses ONLY default Worker settings - no KV namespace, no secrets, no
// wrangler.toml changes needed. Just paste this into the dashboard editor
// (or wrangler deploy with a plain wrangler.toml) and it works.
//
// Storage: uses the built-in Cache API (caches.default), which every
// Worker has access to with zero setup. Note: this is best-effort edge
// cache, not a guaranteed database - entries can occasionally be evicted,
// and requests can be served from different Cloudflare data centers. For
// a personal low-traffic tool this works fine. If you ever want guaranteed
// durability, swapping this for a KV namespace binding is a quick upgrade.
//
// IMPORTANT: change PEPPER below to your own random string before deploying.
// It's mixed into password hashing so mailbox keys can't be reverse-engineered.
//
// API:
//   POST /send     { "password": "...", "message": "..." }  -> { ok: true }
//   POST /receive  { "password": "..." }                     -> { messages: [{text, ts}, ...] }
//   (receiving clears the mailbox for that password)

const PEPPER = "change-me-to-your-own-random-string-9f8x2q";

const MAX_ATTEMPTS = 5;             // requests allowed per IP...
const WINDOW_SECONDS = 300;         // ...per this many seconds
const MESSAGE_TTL_SECONDS = 604800; // messages auto-expire after 7 days
const MAX_MESSAGES_PER_BOX = 50;    // cap stored messages per password
const MAX_MESSAGE_LENGTH = 2000;
const MIN_PASSWORD_LENGTH = 4;

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const cache = caches.default;

    if (url.pathname === "/send" && request.method === "POST") {
      return handleSend(request, cache, ip);
    }
    if (url.pathname === "/receive" && request.method === "POST") {
      return handleReceive(request, cache, ip);
    }

    return json({ error: "Not found" }, 404);
  },
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

// ---- Cache-backed key/value helpers (no bindings required) ----

function cacheKeyFor(path) {
  // The Cache API keys on Request/URL, so we synthesize an internal URL
  // to use as a key. This URL is never actually fetched anywhere.
  return new Request(`https://cache-key.internal${path}`);
}

async function cacheGet(cache, path) {
  const res = await cache.match(cacheKeyFor(path));
  if (!res) return null;
  return await res.text();
}

async function cachePut(cache, path, value, ttlSeconds) {
  const res = new Response(value, {
    headers: { "Cache-Control": `max-age=${ttlSeconds}` },
  });
  await cache.put(cacheKeyFor(path), res);
}

async function cacheDelete(cache, path) {
  await cache.delete(cacheKeyFor(path));
}

// ---- Rate limiting ----

async function checkRateLimit(cache, ip) {
  const path = `/rl/${encodeURIComponent(ip)}`;
  const raw = await cacheGet(cache, path);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= MAX_ATTEMPTS) {
    return false;
  }

  await cachePut(cache, path, String(count + 1), WINDOW_SECONDS);
  return true;
}

// ---- Password hashing ----

async function hashPassword(password) {
  const enc = new TextEncoder();
  const data = enc.encode(PEPPER + password);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Handlers ----

async function handleSend(request, cache, ip) {
  if (!(await checkRateLimit(cache, ip))) {
    return json({ error: "Too many requests. Try again later." }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { password, message } = body || {};

  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    return json(
      { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` },
      400
    );
  }
  if (typeof message !== "string" || message.length === 0) {
    return json({ error: "Message required" }, 400);
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    return json(
      { error: `Message too long (max ${MAX_MESSAGE_LENGTH} chars)` },
      400
    );
  }

  const hash = await hashPassword(password);
  const path = `/msgs/${hash}`;

  const existingRaw = await cacheGet(cache, path);
  const existing = existingRaw ? JSON.parse(existingRaw) : [];
  existing.push({ text: message, ts: Date.now() });

  const capped = existing.slice(-MAX_MESSAGES_PER_BOX);

  await cachePut(cache, path, JSON.stringify(capped), MESSAGE_TTL_SECONDS);

  return json({ ok: true });
}

async function handleReceive(request, cache, ip) {
  if (!(await checkRateLimit(cache, ip))) {
    return json({ error: "Too many requests. Try again later." }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { password } = body || {};
  if (typeof password !== "string" || password.length === 0) {
    return json({ error: "Password required" }, 400);
  }

  const hash = await hashPassword(password);
  const path = `/msgs/${hash}`;

  const raw = await cacheGet(cache, path);
  const messages = raw ? JSON.parse(raw) : [];

  // Single-use inbox: clear it once read.
  if (messages.length > 0) {
    await cacheDelete(cache, path);
  }

  return json({ messages });
}
