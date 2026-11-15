'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/gate.js
//
// The reverse proxy behind the attestation. A browser shows the gate at
// GATE_PORT; the gate checks a signed token and forwards the request to
// GATE_UPSTREAM (a real app, e.g. `python -m http.server 8080`).
//
// Rules that matter:
//   * The upstream comes from configuration only. Nothing in the request can
//     change host, port or scheme, so the gate is not an open proxy.
//   * The token is accepted once from ?t=, then moved into an HttpOnly cookie
//     and removed from the URL, so it does not sit in browser history.
//   * The gate never stores posture values; it only knows a device id and an
//     expiry time.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');

const { parseCookies } = require('./session');

const GATE_COOKIE = 'zkpg_gate';
const TOKEN_TYPE = 'gate';
const UPSTREAM_TIMEOUT_MS = 15000;

// Headers that describe a single connection, not an end-to-end message.
// Forwarding them breaks the proxy (chunked encoding double-applied, etc.).
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

/** Removes one cookie from a Cookie header and returns what is left. */
function withoutCookie(header, name) {
  return String(header || '')
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part && part.split('=')[0].trim() !== name)
    .join('; ');
}

function createGate({ config, tokens }) {
  const upstream = config.gateUpstreamUrl;
  const transport = upstream.protocol === 'https:' ? https : http;
  const prefix = upstream.pathname.replace(/\/+$/, '');
  const deniedTemplate = fs.readFileSync(
    path.join(config.dashboardDir, 'gate-denied.html'),
    'utf8'
  );

  function deny(res, status, reason) {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      // The page is a single static file with its own inline styles. No
      // scripts, no external resources, no framing.
      'content-security-policy':
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'",
    });
    res.end(deniedTemplate.replace(/\{\{REASON\}\}/g, escapeHtml(reason)));
  }

  return function gateHandler(req, res) {
    // Node gives origin-form paths ("/x") for proxy requests. Anything else is
    // not something this gate should forward.
    if (typeof req.url !== 'string' || req.url[0] !== '/') {
      return deny(res, 400, 'Bad request path.');
    }

    let url;
    try {
      // Parsing against a fixed base lets us reject protocol-relative paths
      // ("//host/path") instead of letting them choose a host.
      url = new URL(req.url, 'http://gate.invalid');
    } catch {
      return deny(res, 400, 'Bad request path.');
    }
    if (url.host !== 'gate.invalid') {
      return deny(res, 400, 'Bad request path.');
    }

    const fromQuery = url.searchParams.get('t');
    const cookies = parseCookies(req.headers.cookie);
    const presented = fromQuery || cookies[GATE_COOKIE] || null;
    const payload = tokens.verify(TOKEN_TYPE, presented);
    if (!payload) {
      return deny(res, 401, 'A valid, unexpired attestation token is required.');
    }

    if (fromQuery) {
      url.searchParams.delete('t');
      const remaining = Math.max(1, payload.exp - Math.floor(config.now() / 1000));
      res.writeHead(302, {
        location: url.pathname + url.search,
        'set-cookie':
          `${GATE_COOKIE}=${fromQuery}; Path=/; HttpOnly; SameSite=Strict; ` +
          `Max-Age=${remaining}${req.socket.encrypted ? '; Secure' : ''}`,
        'cache-control': 'no-store',
      });
      return res.end();
    }

    // ---- proxy -------------------------------------------------------------
    const headers = {};
    for (const [name, value] of Object.entries(req.headers)) {
      const key = name.toLowerCase();
      if (HOP_BY_HOP.has(key) || key === 'host' || value === undefined) continue;
      if (key === 'cookie') {
        const rest = withoutCookie(value, GATE_COOKIE);
        if (rest) headers.cookie = rest;
        continue;
      }
      headers[key] = value;
    }
    headers.host = upstream.host;
    headers['x-forwarded-for'] = req.socket.remoteAddress || '';
    headers['x-forwarded-proto'] = req.socket.encrypted ? 'https' : 'http';
    headers['x-forwarded-host'] = req.headers.host || '';

    const proxyReq = transport.request({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port || undefined,
      method: req.method,
      path: prefix + url.pathname + url.search,
      headers,
      // One socket per request: nothing is left pooled when the server stops.
      agent: false,
    });

    proxyReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
      const err = new Error('upstream timeout');
      err.code = 'ETIMEDOUT';
      proxyReq.destroy(err);
    });

    proxyReq.on('response', (upstreamRes) => {
      const responseHeaders = {};
      for (const [name, value] of Object.entries(upstreamRes.headers)) {
        if (HOP_BY_HOP.has(name.toLowerCase()) || value === undefined) continue;
        responseHeaders[name] = value;
      }
      res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
      upstreamRes.pipe(res);
    });

    proxyReq.on('error', () => {
      // No upstream detail on screen; the admin console already knows where it
      // points, and a visitor should not learn the internal network layout.
      deny(res, 502, 'The internal app is not reachable. Ask the admin to start it.');
    });

    req.on('aborted', () => proxyReq.destroy());
    req.pipe(proxyReq);
  };
}

module.exports = { createGate, GATE_COOKIE, TOKEN_TYPE, withoutCookie };
