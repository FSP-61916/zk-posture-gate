'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/session.js
//
// Admin login, session cookie and CSRF token.
//   * password compared in constant time (hash both sides first)
//   * session is an HMAC-signed cookie: httpOnly, SameSite=Strict, path=/
//   * every admin POST must also send x-csrf-token equal to the session's CSRF
//     value, so a cross-site form post cannot change policy
// Plain HTTP is for the demo only; over HTTP the cookie cannot be Secure.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');

const COOKIE_NAME = 'zkpg_admin';
const CSRF_HEADER = 'x-csrf-token';

function sha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest();
}

function safeEqual(a, b) {
  const left = sha256(a);
  const right = sha256(b);
  return crypto.timingSafeEqual(left, right);
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

function cookieHeader(name, value, { maxAgeSeconds, secure = false } = {}) {
  const bits = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
  ];
  if (secure) bits.push('Secure');
  if (typeof maxAgeSeconds === 'number') bits.push(`Max-Age=${maxAgeSeconds}`);
  return bits.join('; ');
}

class AdminAuth {
  constructor(tokens, { adminPassword, ttlSeconds, now = () => Date.now() }) {
    this.tokens = tokens;
    this.adminPassword = adminPassword;
    this.ttlSeconds = ttlSeconds;
    this.now = now;
  }

  /** Returns a token + CSRF secret, or null for a wrong password. */
  login(password) {
    if (typeof password !== 'string' || !safeEqual(password, this.adminPassword)) return null;
    const csrf = crypto.randomBytes(24).toString('base64url');
    const exp = Math.floor(this.now() / 1000) + this.ttlSeconds;
    const token = this.tokens.sign('admin', { sub: 'admin', csrf, exp });
    return { token, csrf, expiresAt: new Date(exp * 1000).toISOString() };
  }

  /** Reads the session from the request. Returns null when not signed in. */
  sessionFrom(req) {
    const cookies = parseCookies(req.headers.cookie);
    const payload = this.tokens.verify('admin', cookies[COOKIE_NAME]);
    if (!payload || payload.sub !== 'admin') return null;
    return payload;
  }

  requireAdmin(req, res, next) {
    const session = this.sessionFrom(req);
    if (!session) {
      return res.status(401).json({ error: 'Not signed in', code: 'UNAUTHORIZED' });
    }
    req.admin = session;
    next();
  }

  requireCsrf(req, res, next) {
    const session = req.admin;
    const provided = req.get(CSRF_HEADER);
    if (!session || typeof provided !== 'string' || !safeEqual(provided, session.csrf)) {
      return res.status(403).json({ error: 'Invalid CSRF token', code: 'CSRF' });
    }
    next();
  }

  setCookie(res, token, { secure = false } = {}) {
    res.setHeader(
      'Set-Cookie',
      cookieHeader(COOKIE_NAME, token, { maxAgeSeconds: this.ttlSeconds, secure })
    );
  }

  clearCookie(res, { secure = false } = {}) {
    res.setHeader('Set-Cookie', cookieHeader(COOKIE_NAME, '', { maxAgeSeconds: 0, secure }));
  }
}

module.exports = { AdminAuth, parseCookies, cookieHeader, safeEqual, COOKIE_NAME, CSRF_HEADER };
