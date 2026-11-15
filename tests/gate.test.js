'use strict';
// ---------------------------------------------------------------------------
// tests/gate.test.js
//
// The reverse proxy is tested against a REAL upstream HTTP server on a random
// port: real sockets, real streaming, real cookies. Nothing is stubbed.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');

const {
  posture,
  startVerifier,
  agentConfig,
  enroll,
  attestBody,
  submit,
  cookieFrom,
} = require('./helpers');
const { normalizeUpstream } = require('../verifier/lib/config');
const { gateUrlFor } = require('../agent/lib/gate-url');

async function startUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      if (req.url.startsWith('/boom')) {
        res.writeHead(500, { 'content-type': 'text/plain' });
        return res.end('upstream exploded');
      }
      if (req.url.startsWith('/cookie')) {
        res.setHeader('set-cookie', 'app_session=xyz; Path=/; HttpOnly');
      }
      res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'real' });
      res.end(JSON.stringify({ method: req.method, url: req.url, body }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    server,
    base: `http://127.0.0.1:${server.address().port}`,
    seen,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

async function grantedToken(ctx) {
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());
  const res = await submit(ctx, body);
  assert.equal(res.data.decision, 'GRANTED');
  return res.data;
}

/** Follows the token redirect and returns the cookie the gate set. */
async function enterGate(ctx, data) {
  const redirect = await fetch(ctx.gateBase + data.gatePath, { redirect: 'manual' });
  assert.equal(redirect.status, 302);
  return cookieFrom(redirect);
}

test('gate: no token is 401, token moves to a cookie and the app is proxied', async (t) => {
  const upstream = await startUpstream();
  t.after(() => upstream.close());
  const ctx = await startVerifier({ gateUpstream: upstream.base });
  t.after(() => ctx.close());

  const denied = await fetch(ctx.gateBase + '/admin');
  assert.equal(denied.status, 401);
  assert.match(await denied.text(), /No valid attestation/);

  const data = await grantedToken(ctx);
  const cookie = await enterGate(ctx, data);

  const res = await fetch(ctx.gateBase + '/admin?tab=users', { headers: { cookie } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-upstream'), 'real');
  const echoed = await res.json();
  assert.equal(echoed.url, '/admin?tab=users');

  const last = upstream.seen[upstream.seen.length - 1];
  assert.equal(last.method, 'GET');
  // The gate's own cookie must not leak to the app.
  assert.doesNotMatch(last.headers.cookie || '', /zkpg_gate/);
  assert.ok(last.headers['x-forwarded-for']);
});

test('gate: POST bodies stream through and app cookies come back', async (t) => {
  const upstream = await startUpstream();
  t.after(() => upstream.close());
  const ctx = await startVerifier({ gateUpstream: upstream.base });
  t.after(() => ctx.close());

  const cookie = await enterGate(ctx, await grantedToken(ctx));
  const payload = JSON.stringify({ action: 'create', name: 'laptop-42' });
  const res = await fetch(ctx.gateBase + '/api/items', {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', 'x-app-header': 'kept' },
    body: payload,
  });
  assert.equal(res.status, 200);
  const echoed = await res.json();
  assert.equal(echoed.method, 'POST');
  assert.equal(echoed.body, payload);

  const last = upstream.seen[upstream.seen.length - 1];
  assert.equal(last.headers['x-app-header'], 'kept');

  // Upstream status and headers are passed through, not replaced.
  const boom = await fetch(ctx.gateBase + '/boom', { headers: { cookie } });
  assert.equal(boom.status, 500);
  assert.equal(await boom.text(), 'upstream exploded');

  const withCookie = await fetch(ctx.gateBase + '/cookie', { headers: { cookie } });
  assert.equal(withCookie.status, 200);
  assert.match(withCookie.headers.get('set-cookie'), /app_session=xyz/);
});

test('gate: expired or tampered tokens are 401', async (t) => {
  let clock = Date.now();
  const upstream = await startUpstream();
  t.after(() => upstream.close());
  const ctx = await startVerifier({ gateUpstream: upstream.base, now: () => clock });
  t.after(() => ctx.close());

  const data = await grantedToken(ctx);
  const cookie = await enterGate(ctx, data);

  const tampered = cookie.slice(0, -2) + (cookie.endsWith('aa') ? 'bb' : 'aa');
  const bad = await fetch(ctx.gateBase + '/', { headers: { cookie: tampered } });
  assert.equal(bad.status, 401);

  clock += (data.tokenTtlSeconds + 1) * 1000;
  const expired = await fetch(ctx.gateBase + '/', { headers: { cookie } });
  assert.equal(expired.status, 401);
});

test('gate: unreachable upstream is 502, never a redirect loop', async (t) => {
  const ctx = await startVerifier({ gateUpstream: 'http://127.0.0.1:9' });
  t.after(() => ctx.close());

  const cookie = await enterGate(ctx, await grantedToken(ctx));
  const res = await fetch(ctx.gateBase + '/', { headers: { cookie } });
  assert.equal(res.status, 502);
  assert.match(await res.text(), /not reachable/);
});

test('gate: a protocol-relative path cannot choose the upstream', async (t) => {
  const upstream = await startUpstream();
  t.after(() => upstream.close());
  const ctx = await startVerifier({ gateUpstream: upstream.base });
  t.after(() => ctx.close());

  const cookie = await enterGate(ctx, await grantedToken(ctx));
  const before = upstream.seen.length;

  const port = ctx.config.gatePort;
  const status = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: '//127.0.0.1:9/steal',
        headers: { cookie },
      },
      (res) => {
        res.resume();
        resolve(res.statusCode);
      }
    );
    req.on('error', reject);
    req.end();
  });

  assert.equal(status, 400);
  assert.equal(upstream.seen.length, before);
});

test('gate: GATE_UPSTREAM is validated at startup', () => {
  assert.throws(() => normalizeUpstream('ftp://127.0.0.1:21'), /http/);
  assert.throws(() => normalizeUpstream('http://user:pass@127.0.0.1:8080'), /credentials/);
  assert.throws(() => normalizeUpstream('http://127.0.0.1:8080/?x=1'), /query/);
  assert.throws(() => normalizeUpstream('not a url'), /valid URL/);
  assert.equal(normalizeUpstream('http://127.0.0.1:8080/').toString(), 'http://127.0.0.1:8080/');
});

test('gate: default access lifetime is 10 minutes', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  assert.equal(ctx.config.tokenTtlSeconds, 600);
});

test('agent: gate URL uses the reported port and accepts GATE_URL', () => {
  assert.equal(
    gateUrlFor({
      verifierUrl: 'http://127.0.0.1:3000',
      gatePort: 8081,
      gatePath: '/?t=gate.abc.def',
    }),
    'http://127.0.0.1:8081/?t=gate.abc.def'
  );
  assert.equal(
    gateUrlFor({
      verifierUrl: 'http://10.0.0.5:3000',
      gatePort: 8081,
      gatePath: '/x?t=gate.abc.def',
      gateUrl: 'https://gate.corp.example/',
    }),
    'https://gate.corp.example/x?t=gate.abc.def'
  );
  assert.throws(
    () => gateUrlFor({ verifierUrl: 'http://x:1', gatePort: 2, gatePath: 'no-slash' }),
    /must start with \//
  );
});
