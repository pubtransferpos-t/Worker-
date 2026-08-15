// Cloudflare Worker: password-protected message mailboxes (zero-knowledge version).
//
// SECURITY MODEL (unchanged from before):
// The client (messenger.cpp) never sends your password to this Worker.
// It locally derives, via PBKDF2:
//   - a "lookup key" (64 hex chars) used only to address the mailbox
//   - an "encryption key" (never transmitted) used to AES-256-GCM encrypt
//     the message client-side before it ever leaves the client
// This Worker only ever sees the lookup key and an opaque ciphertext blob.
// It cannot recover your password or read your messages.
//
// STORAGE (changed from the Cache-API version):
// Mailboxes and rate limits are now backed by Durable Objects instead of
// caches.default. This fixes two real bugs the Cache API version had:
//   1. Rate limiting was bypassable via a read-then-write race (two
//      concurrent requests could both read the same stale counter).
//   2. Concurrent /send calls could race and silently drop a message
//      (last write wins on a read-modify-write over JSON).
// A Durable Object serializes all operations against a given instance
// (Cloudflare automatically gates new requests behind in-flight storage
// operations for the same DO id), and this code additionally wraps the
// read-modify-write in state.storage.transaction() for defense in depth.
// This also fixes the durability/locality problems the Cache API had:
// caches.default is best-effort, per-datacenter, and can evict early.
// Durable Object storage is durable and has a single global home per id.
//
// DEPLOYMENT: this file is still the only *code* file, but Durable
// Objects require a binding + migration in wrangler.toml (unavoidable on
// this platform - it's config, not code). See wrangler.toml alongside
// this file, or bind two Durable Object classes named MAILBOX and
// RATE_LIMITER to the classes below via the dashboard's Durable Objects
// UI if you're not using wrangler.
//
// SECRETS: PEPPER should be set as a Worker secret, not hardcoded:
//   wrangler secret put PEPPER
// The DEFAULT_PEPPER below is only a fallback so this still runs if you
// forget - change it or (better) set the real secret before relying on
// this for anything sensitive. The pepper is defense-in-depth only; it
// does not protect the plaintext password or message (the client-side
// design does that).
//
// CORS: intentionally not set. This API is called from a native client
// (messenger.cpp), not from browser JS on other sites, so there's no
// reason to allow cross-origin browser requests. If you later build a
// web client on a specific origin, add
// "Access-Control-Allow-Origin": "https://your-web-client.example"
// to the json() helper below - do not set it back to "*".
//
// API (unchanged):
//   POST /send     { "key": "<64 hex chars>", "message": "<base64 ciphertext>" } -> { ok: true }
//   POST /receive  { "key": "<64 hex chars>" }  -> { messages: [{text, ts}, ...] }
//   (receiving clears the mailbox for that key; "text" is ciphertext, decrypt client-side)

const DEFAULT_PEPPER = "change-me-to-your-own-random-string-9f8x2q";

const MAX_ATTEMPTS = 5;             // requests allowed per IP...
const WINDOW_SECONDS = 300;         // ...per this many seconds
const MESSAGE_TTL_SECONDS = 604800; // messages auto-expire after 7 days
const MAX_MESSAGES_PER_BOX = 50;    // cap stored messages per mailbox
const MAX_MESSAGE_LENGTH = 4000;    // base64 ciphertext is bigger than the
                                     // original plaintext (iv + tag + b64
                                     // overhead)
const LOOKUP_KEY_LENGTH = 64;       // hex-encoded 32-byte PBKDF2 output

const LOOKUP_KEY_RE = /^[0-9a-f]{64}$/;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function hashKey(pepper, lookupKey) {
  const enc = new TextEncoder();
  const data = enc.encode(pepper + lookupKey);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Main Worker entrypoint ----

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pepper = env.PEPPER || DEFAULT_PEPPER;
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    if (url.pathname === "/send" && request.method === "POST") {
      return handleSend(request, env, ip, pepper);
    }
    if (url.pathname === "/receive" && request.method === "POST") {
      return handleReceive(request, env, ip, pepper);
    }

    return json({ error: "Not found" }, 404);
  },
};

async function checkRateLimit(env, ip) {
  const id = env.RATE_LIMITER.idFromName(ip);
  const stub = env.RATE_LIMITER.get(id);
  const res = await stub.fetch("https://rate-limiter.internal/hit");
  const { allowed } = await res.json();
  return allowed;
}

async function handleSend(request, env, ip, pepper) {
  if (!(await checkRateLimit(env, ip))) {
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

  const hashed = await hashKey(pepper, key);
  const id = env.MAILBOX.idFromName(hashed);
  const stub = env.MAILBOX.get(id);

  const res = await stub.fetch("https://mailbox.internal/push", {
    method: "POST",
    body: JSON.stringify({ text: message }),
  });

  if (!res.ok) {
    return json({ error: "Failed to store message" }, 500);
  }

  return json({ ok: true });
}

async function handleReceive(request, env, ip, pepper) {
  if (!(await checkRateLimit(env, ip))) {
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

  const hashed = await hashKey(pepper, key);
  const id = env.MAILBOX.idFromName(hashed);
  const stub = env.MAILBOX.get(id);

  const res = await stub.fetch("https://mailbox.internal/drain", {
    method: "POST",
  });
  const { messages } = await res.json();

  return json({ messages });
}

// ---- Durable Object: Mailbox ----
// One instance per (peppered, hashed) lookup key. All operations against
// a given instance are serialized by the runtime, so push/drain can't
// race each other the way they could with the old cache-based
// read-modify-write.

export class Mailbox {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/push" && request.method === "POST") {
      return this.push(request);
    }
    if (url.pathname === "/drain" && request.method === "POST") {
      return this.drain();
    }
    return new Response("Not found", { status: 404 });
  }

  async push(request) {
    const { text } = await request.json();
    const now = Date.now();

    await this.state.storage.transaction(async (txn) => {
      let messages = (await txn.get("messages")) || [];
      // Drop anything already past its TTL before appending.
      messages = messages.filter(
        (m) => now - m.ts < MESSAGE_TTL_SECONDS * 1000
      );
      messages.push({ text, ts: now });
      if (messages.length > MAX_MESSAGES_PER_BOX) {
        messages = messages.slice(-MAX_MESSAGES_PER_BOX);
      }
      await txn.put("messages", messages);
    });

    // Make sure this object eventually cleans itself up even if nobody
    // ever calls /drain (e.g. sender sends but recipient never checks).
    const existingAlarm = await this.state.storage.getAlarm();
    if (existingAlarm === null) {
      await this.state.storage.setAlarm(now + MESSAGE_TTL_SECONDS * 1000);
    }

    return json({ ok: true });
  }

  async drain() {
    let messages = [];
    await this.state.storage.transaction(async (txn) => {
      messages = (await txn.get("messages")) || [];
      if (messages.length > 0) {
        await txn.delete("messages");
      }
    });
    return json({ messages });
  }

  // Runs if a mailbox is never drained before its TTL - clears storage
  // so this Durable Object doesn't hold stale ciphertext forever.
  async alarm() {
    await this.state.storage.deleteAll();
  }
}

// ---- Durable Object: RateLimiter ----
// One instance per client IP. Fixed-window counter. Serialized per
// instance by the runtime, so the "read count, then write count+1" race
// that existed in the Cache API version can't happen here.

export class RateLimiter {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/hit") {
      return new Response("Not found", { status: 404 });
    }

    const now = Date.now();
    let allowed = false;

    await this.state.storage.transaction(async (txn) => {
      const record = (await txn.get("window")) || {
        count: 0,
        windowStart: now,
      };

      const windowExpired =
        now - record.windowStart > WINDOW_SECONDS * 1000;

      const count = windowExpired ? 0 : record.count;
      const windowStart = windowExpired ? now : record.windowStart;

      if (count >= MAX_ATTEMPTS) {
        allowed = false;
        await txn.put("window", { count, windowStart });
        return;
      }

      allowed = true;
      await txn.put("window", { count: count + 1, windowStart });
    });

    // Self-cleanup once the window is clearly over, so idle IPs don't
    // hold storage forever.
    await this.state.storage.setAlarm(now + WINDOW_SECONDS * 1000 * 2);

    return json({ allowed });
  }

  async alarm() {
    await this.state.storage.deleteAll();
  }
}
