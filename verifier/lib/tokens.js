'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/tokens.js
//
// Short-lived signed tokens (gate access) and admin sessions.
// Format: <type>.<base64url(payload)>.<base64url(hmac-sha256)>
// The HMAC covers the type and the payload, so a token for one purpose can
// never be replayed as another, and tampering with the payload breaks the MAC.
// Comparisons use timingSafeEqual.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');

function toBase64Url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

class SignedTokenService {
  constructor(key, { now = () => Date.now() } = {}) {
    if (!Buffer.isBuffer(key) || key.length < 16) {
      throw new Error('signing key must be a Buffer of at least 16 bytes');
    }
    this.key = key;
    this.now = now;
  }

  mac(type, body) {
    return crypto.createHmac('sha256', this.key).update(`${type}.${body}`).digest();
  }

  sign(type, payload) {
    const body = toBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
    return `${type}.${body}.${toBase64Url(this.mac(type, body))}`;
  }

  /** Returns the payload, or null for any problem (never throws). */
  verify(type, token) {
    if (typeof token !== 'string' || token.length > 4096) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [tokenType, body, macPart] = parts;
    if (tokenType !== type) return null;

    let given;
    try {
      given = Buffer.from(macPart, 'base64url');
    } catch {
      return null;
    }
    const expected = this.mac(type, body);
    if (given.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(given, expected)) return null;

    let payload;
    try {
      payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    if (!payload || typeof payload !== 'object') return null;
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= this.now()) return null;
    return payload;
  }
}

module.exports = { SignedTokenService };
