// Cloudflare Worker: password-protected message mailboxes (zero-knowledge version).
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
// SECURITY MODEL (changed from the original version):
// The client (messenger.cpp) never sends your password to this Worker.
// Instead it locally derives two independent values from the password
// using PBKDF2:
//   - a "lookup key" (a random-looking hex string) used only to address
//     the mailbox
//   - an "encryption key" (never transmitted at all) used to encrypt the
//     message with AES-256-GCM before it ever leaves the client
// This Worker therefore only ever sees the lookup key and an opaque
// ciphertext blob. It cannot recover your password or read your messages,
// and neither can anyone who gains read access to the cache.
//
// IMPORTANT: change PEPPER below to your own random string before deploying.
// It adds a second hashing step server-side as defense in depth (it does
// NOT protect the plaintext password/message - the client-side design
// above is what does that).
//
// API:
//   POST /send     { "key": "<64 hex chars>", "message": "<base64 ciphertext>" } -> { ok: true }
//   POST /receive  { "key": "<64 hex chars>" }  -> { messages: [{text, ts}, ...] }
//   (receiving clears the mailbox for that key; "text" is ciphertext, decrypt client-side)

const PEPPER = "change-me-to-your-own-random-string-9f8x2q";

const MAX_ATTEMPTS = 5;             // requests allowed per IP...
const WINDOW_SECONDS = 300;         // ...per this many seconds
const MESSAGE_TTL_SECONDS = 604800; // messages auto-expire after 7 days
const MAX_MESSAGES_PER_BOX = 50;    // cap stored messages per mailbox
const MAX_MESSAGE_LENGTH = 4000;    // base64 ciphertext is bigger than the
                                     // original plaintext (iv + tag + b64
                                     // overhead), so this is larger than
                                     // the old MAX_MESSAGE_LENGTH of 2000
const LOOKUP_KEY_LENGTH = 64;       // hex-encoded 32-byte PBKDF2 output

const LOOKUP_KEY_RE = /^[0-9a-f]{64}$/;

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

// ---- Storage-path hashing ----
// This hashes the already-derived lookup key with a server-side pepper
// before using it as a cache path. It's defense in depth (obscures the
// raw lookup key even from someone reading cache keys directly) - it is
// NOT what keeps your password/messages private. That protection comes
// from the client never sending the password or plaintext message at all.

async function hashKey(lookupKey) {
  const enc = new TextEncoder();
  const data = enc.encode(PEPPER + lookupKey);
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

  const { key, message } = body || {};

  if (typeof key !== "string" || !LOOKUP_KEY_RE.test(key)) {
    return json(
      { error: `key must be a ${LOOKUP_KEY_LENGTH}-character hex string` },
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

  const hashed = await hashKey(key);
  const path = `/msgs/${hashed}`;

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

  const { key } = body || {};
  if (typeof key !== "string" || !LOOKUP_KEY_RE.test(key)) {
    return json(
      { error: `key must be a ${LOOKUP_KEY_LENGTH}-character hex string` },
      400
    );
  }

  const hashed = await hashKey(key);
  const path = `/msgs/${hashed}`;

  const raw = await cacheGet(cache, path);
  const messages = raw ? JSON.parse(raw) : [];

  // Single-use inbox: clear it once read.
  if (messages.length > 0) {
    await cacheDelete(cache, path);
  }

  return json({ messages });
}
