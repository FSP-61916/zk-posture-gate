'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/challenges.js
//
// Single-use challenges. The verifier's clock is the only clock that matters.
//
// A challenge is:
//   * random (8 bytes = ~20 decimal digits)
//   * bound to one deviceId
//   * valid for 60 seconds
//   * consumed the moment it is presented (so a failed proof also burns it)
//
// Challenges are held in memory. A verifier restart makes outstanding
// challenges invalid, which is safe: the agent simply asks for a new one.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');

function randomDecimal(bytes = 8) {
  // Clear the top bit so the value is always positive and ~19-20 digits.
  const buf = crypto.randomBytes(bytes);
  buf[0] &= 0x7f;
  let value = 0n;
  for (const byte of buf) value = (value << 8n) | BigInt(byte);
  return value.toString();
}

class ChallengeStore {
  constructor({ ttlSeconds = 60, now = () => Date.now() } = {}) {
    this.ttlMs = ttlSeconds * 1000;
    this.now = now;
    this.map = new Map();
  }

  issue(deviceId) {
    this.prune();
    const challenge = randomDecimal(8);
    const createdAt = this.now();
    this.map.set(challenge, {
      deviceId,
      createdAt,
      expiresAt: createdAt + this.ttlMs,
      used: false,
    });
    return { challenge, expiresAt: new Date(createdAt + this.ttlMs).toISOString() };
  }

  /**
   * Checks in the documented order: exists (else expired/unknown), belongs to
   * this device, not already used, not expired. Marks it used when accepted.
   */
  consume(challenge, deviceId) {
    const key = String(challenge);
    const rec = this.map.get(key);
    if (!rec) return { ok: false, reason: 'EXPIRED' }; // never issued, or pruned
    if (rec.deviceId !== deviceId) return { ok: false, reason: 'CHALLENGE_DEVICE_MISMATCH' };
    if (rec.used) return { ok: false, reason: 'REPLAY' };
    if (rec.expiresAt <= this.now()) return { ok: false, reason: 'EXPIRED' };
    rec.used = true;
    return { ok: true };
  }

  prune() {
    const cutoff = this.now();
    for (const [key, rec] of this.map) {
      if (rec.expiresAt + 10 * 60 * 1000 < cutoff) this.map.delete(key);
    }
  }

  get size() {
    return this.map.size;
  }
}

module.exports = { ChallengeStore, randomDecimal };
