'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/ratelimit.js
//
// Tiny fixed-window rate limiter, no dependency. Used on POST /api/attest so a
// laptop (or a script) cannot hammer proof verification.
// Good enough for a demo on a private network; a real deployment would sit
// behind a reverse proxy with shared limits.
// ---------------------------------------------------------------------------

class RateLimiter {
  constructor({ limit = 30, windowMs = 60000, now = () => Date.now() } = {}) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
    this.hits = new Map();
  }

  check(key) {
    const now = this.now();
    const windowStart = Math.floor(now / this.windowMs) * this.windowMs;
    const entry = this.hits.get(key);
    if (!entry || entry.windowStart !== windowStart) {
      this.hits.set(key, { windowStart, count: 1 });
      return { ok: true, remaining: this.limit - 1 };
    }
    if (entry.count >= this.limit) {
      return { ok: false, remaining: 0, retryAfterMs: windowStart + this.windowMs - now };
    }
    entry.count += 1;
    return { ok: true, remaining: this.limit - entry.count };
  }

  reset() {
    this.hits.clear();
  }
}

module.exports = { RateLimiter };
