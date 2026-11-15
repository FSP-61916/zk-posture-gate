'use strict';
// ---------------------------------------------------------------------------
// agent/lib/client.js
//
// Thin HTTP client for the verifier. Every call has a timeout and a clear
// error message. Nothing here ever sends posture values.
//
// Why node:http instead of the global fetch():
//   fetch() keeps keep-alive sockets in a dispatcher pool that we cannot close
//   without depending on undici. Calling process.exit() while those sockets are
//   tearing down crashes Node 24 on Windows (libuv: assertion failed,
//   !(handle->flags & UV_HANDLE_CLOSING), src\win\async.c). With node:http and
//   `agent: false` each request owns exactly one socket and closes it, so the
//   event loop drains on its own. closeClient() is the belt-and-braces cleanup
//   for a request that was cut short.
// ---------------------------------------------------------------------------

const http = require('node:http');
const https = require('node:https');
const { verifySocket, isValidPin } = require('./tls-verify');

const liveSockets = new Set();

/** Destroy any socket that is still open. Safe to call more than once. */
function closeClient() {
  for (const socket of liveSockets) {
    if (!socket.destroyed) socket.destroy();
  }
  liveSockets.clear();
}

function request(config, pathname, { method = 'GET', body, headers = {} } = {}) {
  let url;
  try {
    url = new URL(config.verifierUrl + pathname);
  } catch {
    return Promise.reject(new Error(`invalid verifier URL: ${config.verifierUrl}`));
  }

  const payload = body === undefined ? undefined : JSON.stringify(body);
  const isHttps = url.protocol === 'https:';
  const transport = isHttps ? https : http;

  // TLS is on unless DEMO_INSECURE=1. With TLS we insist on a pinned CA: there
  // is no silent fallback to the system trust store.
  if (isHttps && !config.insecureTls && !isValidPin(config.tlsCaFingerprint)) {
    return Promise.reject(
      new Error(
        'TLS is enabled but no valid CA fingerprint is configured. Set tlsCaFingerprint in ' +
          'agent/agent.config.json (the verifier prints it at startup) or ZKPG_CA_FINGERPRINT.'
      )
    );
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err, value) => {
      if (settled) return;
      settled = true;
      if (err) reject(err);
      else resolve(value);
    };

    const req = transport.request(
      url,
      {
        method,
        // One socket per request: nothing is pooled, nothing outlives the call.
        agent: false,
        // Verification is done explicitly in verifySocket so the pinned CA is
        // the only trust anchor. DEMO_INSECURE=1 is the sole bypass.
        ...(isHttps ? { rejectUnauthorized: false } : {}),
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          connection: 'close',
          ...(payload === undefined ? {} : { 'content-length': Buffer.byteLength(payload) }),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let data = null;
          try {
            data = text ? JSON.parse(text) : null;
          } catch {
            data = { raw: text };
          }
          done(null, {
            status: res.statusCode,
            ok: res.statusCode >= 200 && res.statusCode < 300,
            data,
            headers: res.headers,
          });
        });
        res.on('error', (err) => {
          done(new Error(`cannot read verifier response (${err.message})`));
        });
      }
    );

    req.on('socket', (socket) => {
      liveSockets.add(socket);
      socket.once('close', () => liveSockets.delete(socket));
      if (isHttps && !config.insecureTls) {
        socket.once('secureConnect', () => {
          const problem = verifySocket(socket, url.hostname, config.tlsCaFingerprint);
          if (problem) {
            const err = new Error(`TLS refused: ${problem}`);
            err.code = 'TLS_PIN_MISMATCH';
            req.destroy(err);
          }
        });
      }
    });

    req.setTimeout(config.requestTimeoutMs, () => {
      const err = new Error('timed out');
      err.code = 'ETIMEDOUT';
      req.destroy(err);
    });

    req.on('error', (err) => {
      const reason = err && err.code === 'ETIMEDOUT' ? 'timed out' : err.message;
      done(new Error(`cannot reach verifier at ${config.verifierUrl} (${reason})`));
    });

    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const api = {
  policy: (config) => request(config, '/api/policy'),
  checkHealth: (config) => request(config, '/api/health'),
  challenge: (config, deviceId) =>
    request(config, '/api/challenge', { method: 'POST', body: { deviceId } }),
  attest: (config, body) => request(config, '/api/attest', { method: 'POST', body }),
  enroll: (config, body) => request(config, '/api/enroll', { method: 'POST', body }),
};

module.exports = { request, api, closeClient };
