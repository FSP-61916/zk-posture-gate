'use strict';
// ---------------------------------------------------------------------------
// tests/tls.test.js
//
// The local CA and the agent's pinning are real: certificates are generated,
// an HTTPS server presents them, and the agent client refuses or accepts based
// on the CA SPKI SHA-256. No system trust store and no test-only bypass is used
// except DEMO_INSECURE, which is part of the product.
// ---------------------------------------------------------------------------

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { once } = require('node:events');

const { ensureTls, regenerateLeaf } = require('../verifier/lib/tls');
const { request, closeClient } = require('../agent/lib/client');
const { parseInterval } = require('../agent/lib/interval');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-test-tls-'));
}

test('tls: local CA and leaf are generated, chained and stable across restarts', () => {
  const dir = tempDir();
  const first = ensureTls({ dataDir: dir });
  assert.equal(first.created, true);
  assert.match(first.caSpkiSha256, /^[0-9a-f]{64}$/);
  assert.match(first.leafSha256, /^[0-9a-f]{64}$/);

  const leaf = new crypto.X509Certificate(first.cert);
  const ca = new crypto.X509Certificate(fs.readFileSync(first.caCertFile));
  assert.equal(leaf.verify(ca.publicKey), true, 'leaf is signed by the CA');
  assert.equal(ca.verify(ca.publicKey), true, 'CA is self-signed');
  assert.equal(leaf.checkHost('localhost'), 'localhost');
  assert.equal(leaf.checkIP('127.0.0.1'), '127.0.0.1');
  assert.match(leaf.subjectAltName, /DNS:/);

  const keyMode = fs.statSync(first.keyFile).mode & 0o777;
  if (process.platform !== 'win32') assert.equal(keyMode, 0o600);

  const second = ensureTls({ dataDir: dir });
  assert.equal(second.created, false, 'restart reuses the existing material');
  assert.equal(second.caSpkiSha256, first.caSpkiSha256);
  assert.equal(second.leafSha256, first.leafSha256);
});

test('tls: regenerating the leaf keeps the CA pin agents rely on', () => {
  const dir = tempDir();
  const first = ensureTls({ dataDir: dir });
  const renewed = regenerateLeaf({ dataDir: dir });
  assert.notEqual(renewed.leafSha256, first.leafSha256, 'leaf really changed');
  assert.equal(renewed.caSpkiSha256, first.caSpkiSha256, 'CA pin did not change');

  const leaf = new crypto.X509Certificate(renewed.cert);
  const ca = new crypto.X509Certificate(fs.readFileSync(renewed.caCertFile));
  assert.equal(leaf.verify(ca.publicKey), true);
});

test('tls: existing cert/key paths are used instead of generating anything', () => {
  const dir = tempDir();
  const generated = ensureTls({ dataDir: dir });
  const custom = ensureTls({ dataDir: tempDir(), certPath: generated.certFile, keyPath: generated.keyFile });
  assert.equal(custom.custom, true);
  assert.equal(custom.key, fs.readFileSync(generated.keyFile, 'utf8'));
  assert.equal(custom.caSpkiSha256, null, 'a lone leaf has no CA pin to print');
});

test('tls: agent accepts the pinned CA, refuses a wrong pin, and refuses no pin', async (t) => {
  const dir = tempDir();
  const material = ensureTls({ dataDir: dir });
  const server = https.createServer(
    { key: material.key, cert: material.cert, minVersion: 'TLSv1.2' },
    (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    }
  );
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(
    () =>
      new Promise((resolve) => {
        closeClient();
        server.closeAllConnections?.();
        server.close(() => resolve());
      })
  );
  const port = server.address().port;

  const good = await request(
    {
      verifierUrl: `https://127.0.0.1:${port}`,
      tlsCaFingerprint: material.caSpkiSha256,
      requestTimeoutMs: 5000,
    },
    '/api/health'
  );
  assert.equal(good.status, 200);
  assert.equal(good.data.ok, true);

  await assert.rejects(
    () =>
      request(
        {
          verifierUrl: `https://127.0.0.1:${port}`,
          tlsCaFingerprint: '00'.repeat(32),
          requestTimeoutMs: 5000,
        },
        '/api/health'
      ),
    /CA fingerprint does not match/
  );

  await assert.rejects(
    () => request({ verifierUrl: `https://127.0.0.1:${port}`, requestTimeoutMs: 5000 }, '/api/health'),
    /no valid CA fingerprint/
  );

  // The one deliberate bypass. It still has to be asked for explicitly.
  const insecure = await request(
    {
      verifierUrl: `https://127.0.0.1:${port}`,
      insecureTls: true,
      requestTimeoutMs: 5000,
    },
    '/api/health'
  );
  assert.equal(insecure.status, 200);
});

test('interval: 5 is the default, 1 is allowed, nonsense is refused', () => {
  assert.equal(parseInterval(undefined), null, 'no flag means one-shot');
  assert.equal(parseInterval(true), 5);
  assert.equal(parseInterval('1'), 1);
  assert.equal(parseInterval('15'), 15);
  assert.throws(() => parseInterval('0'), />= 1/);
  assert.throws(() => parseInterval('-3'), />= 1/);
  assert.throws(() => parseInterval('abc'), />= 1/);
});
