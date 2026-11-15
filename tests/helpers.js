'use strict';
// ---------------------------------------------------------------------------
// tests/helpers.js
//
// Shared test scaffolding: start a real verifier on a random port with a
// temporary data directory, create a real agent identity, enroll it, and build
// real Groth16 attestations through the same code the agent uses.
//
// Nothing is mocked except the posture *provider*: tests pass a posture object
// directly, because a Linux CI machine cannot read Windows registry values.
// The proof, the signature, the HTTP calls and the verifier are all real.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');

const { createApp } = require('../verifier/server');
const { loadConfig } = require('../verifier/lib/config');
const { loadOrCreateIdentity, signText } = require('../agent/lib/keys');
const { generateProof } = require('../agent/lib/prover');
const { toPosture } = require('../agent/lib/posture');
const { attestMessage } = require('../shared/canonical');

const ROOT = path.resolve(__dirname, '..');

function posture(overrides = {}) {
  return toPosture({
    build: 22631,
    ubr: 3803,
    updateAgeDays: 4,
    updateSource: 'test provider',
    firewallAllProfiles: true,
    defenderRealTime: true,
    bitlocker: null,
    ...overrides,
  });
}

async function startVerifier(overrides = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-test-verifier-'));
  const config = loadConfig({
    dataDir,
    adminPassword: 'test-admin-password-123',
    host: '127.0.0.1',
    // The HTTP tests assert proxy/API behaviour, not TLS. TLS has its own test
    // file that starts an HTTPS server with a generated leaf.
    tls: false,
    // A closed port by default, so a test that proxies without starting an
    // upstream gets a deterministic 502 instead of reaching a real server.
    gateUpstream: 'http://127.0.0.1:9',
    ...overrides,
  });
  const { app, gate, services } = createApp({ config });
  const server = app.listen(0, '127.0.0.1');
  const gateServer = http.createServer(gate);
  gateServer.listen(0, '127.0.0.1');
  await Promise.all([once(server, 'listening'), once(gateServer, 'listening')]);
  // The attestation response reports this port; tests know it before use.
  config.gatePort = gateServer.address().port;
  const base = `http://127.0.0.1:${server.address().port}`;
  const gateBase = `http://127.0.0.1:${config.gatePort}`;
  return {
    config,
    services,
    server,
    gateServer,
    base,
    gateBase,
    dataDir,
    close: () =>
      new Promise((resolve) => {
        // Undici's global fetch keeps sockets alive; without this, server.close()
        // waits forever and the test runner hangs instead of reporting.
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
        if (typeof gateServer.closeAllConnections === 'function') gateServer.closeAllConnections();
        server.close();
        gateServer.close(() => resolve());
      }),
  };
}

function agentConfig(base) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-test-agent-'));
  return {
    dataDir,
    keyFile: path.join(dataDir, 'device.key'),
    wasmPath: path.join(ROOT, 'circuits', 'build', 'posture_js', 'posture.wasm'),
    zkeyPath: path.join(ROOT, 'circuits', 'build', 'posture_final.zkey'),
    verifierUrl: base,
    requestTimeoutMs: 20000,
  };
}

async function jsonFetch(base, pathname, { method = 'GET', body, headers = {} } = {}) {
  const finalHeaders = { ...headers };
  if (body !== undefined) finalHeaders['content-type'] = 'application/json';
  const res = await fetch(base + pathname, {
    method,
    headers: finalHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  return { status: res.status, ok: res.ok, data, headers: res.headers };
}

async function enroll(ctx, agent, label = 'Test laptop') {
  const { code } = ctx.services.enrollment.issue();
  const identity = loadOrCreateIdentity(agent);
  const res = await jsonFetch(ctx.base, '/api/enroll', {
    method: 'POST',
    body: {
      code,
      deviceId: identity.deviceId,
      publicKey: identity.publicKeySpkiB64,
      label,
    },
  });
  if (res.status !== 201) throw new Error('enroll failed: ' + JSON.stringify(res.data));
  return identity;
}

async function attestBody(ctx, agent, identity, postureValues, policyOverride) {
  const policy = policyOverride || (await jsonFetch(ctx.base, '/api/policy')).data;
  const challengeRes = await jsonFetch(ctx.base, '/api/challenge', {
    method: 'POST',
    body: { deviceId: identity.deviceId },
  });
  if (challengeRes.status !== 200) {
    throw new Error('challenge failed: ' + JSON.stringify(challengeRes.data));
  }
  const challenge = challengeRes.data.challenge;
  const { proof, publicSignals } = await generateProof(agent, {
    posture: postureValues,
    policy,
    challenge,
  });
  const body = {
    deviceId: identity.deviceId,
    policyVersion: policy.version,
    challenge,
    publicSignals,
    proof,
  };
  // Sign exactly as the agent does, so the happy path exercises check 2.
  resign(identity, body);
  return { body, proof, publicSignals };
}

/** Re-sign a (possibly tampered) body so the signature check is not the reason it fails. */
function resign(identity, body) {
  body.signature = signText(
    identity.privateKey,
    attestMessage({
      deviceId: body.deviceId,
      challenge: body.challenge,
      policyVersion: body.policyVersion,
      publicSignals: body.publicSignals,
      proof: body.proof,
    })
  );
  return body;
}

function submit(ctx, body) {
  return jsonFetch(ctx.base, '/api/attest', { method: 'POST', body });
}

function cookieFrom(res) {
  return (res.headers.get('set-cookie') || '').split(';')[0];
}

module.exports = {
  ROOT,
  posture,
  startVerifier,
  agentConfig,
  jsonFetch,
  enroll,
  attestBody,
  resign,
  submit,
  cookieFrom,
};
