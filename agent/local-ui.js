'use strict';
// ---------------------------------------------------------------------------
// agent/local-ui.js
//
// Optional local UI, bound to 127.0.0.1 ONLY (never 0.0.0.0).
// It calls the same agent functions as the CLI. It never returns or displays a
// posture value: the browser gets step labels, a decision and a reason code.
//
// Endpoints:
//   GET  /              local page
//   GET  /theme.css     the dashboard's theme file (single source of truth)
//   GET  /ui.js         local page script
//   GET  /api/status    identity + enrollment state (no posture)
//   POST /api/check     verifier reachability + policy version (sends no posture)
//   POST /api/enroll    { code, label }
//   POST /api/attest    full flow; returns steps + decision
// ---------------------------------------------------------------------------

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const { loadAgentConfig } = require('./lib/config');
const { loadOrCreateIdentity, signText } = require('./lib/keys');
const { readPosture } = require('./lib/posture');
const { generateProof } = require('./lib/prover');
const { api } = require('./lib/client');
const { gateUrlFor } = require('./lib/gate-url');
const { loadState, saveState } = require('./lib/state');
const { attestMessage } = require('../shared/canonical');

const config = loadAgentConfig();
const HOST = '127.0.0.1'; // hard-coded: this UI must never be reachable from the LAN
const MAX_BODY_BYTES = 8 * 1024;

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function sendFile(res, file, type) {
  try {
    const body = fs.readFileSync(file);
    res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
    res.end(body);
  } catch {
    sendJson(res, 404, { error: 'Not found' });
  }
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

async function runAttest() {
  const steps = [];
  const roll = (label, status) => steps.push({ label, status });

  const policyRes = await api.policy(config);
  if (!policyRes.ok) throw new Error(`Verifier returned HTTP ${policyRes.status}`);
  const policy = policyRes.data;
  roll('Checking verifier', `OK (policy v${policy.version})`);

  const identity = loadOrCreateIdentity(config);
  const state = loadState(config);
  if (!state.enrolledAt) throw new Error('This laptop is not enrolled yet.');

  const posture = readPosture(); // stays in this process
  roll('Reading posture', 'done (values stay on this device)');

  const challengeRes = await api.challenge(config, identity.deviceId);
  if (!challengeRes.ok) throw new Error(challengeRes.data.error || 'Challenge refused');
  const challenge = challengeRes.data.challenge;
  roll('Fetching challenge', 'OK');

  const proofStarted = Date.now();
  const { proof, publicSignals } = await generateProof(config, { posture, policy, challenge });
  roll('Generating proof', `done (${((Date.now() - proofStarted) / 1000).toFixed(1)} s)`);

  const signature = signText(
    identity.privateKey,
    attestMessage({
      deviceId: identity.deviceId,
      challenge,
      policyVersion: policy.version,
      publicSignals,
      proof,
    })
  );
  roll('Signing submission', 'done');

  const attestRes = await api.attest(config, {
    deviceId: identity.deviceId,
    policyVersion: policy.version,
    challenge,
    publicSignals,
    proof,
    signature,
  });
  const result = attestRes.data || {};
  roll('Sending attestation', result.decision || 'ERROR');

  saveState(config, {
    ...state,
    lastResult: result.decision || 'ERROR',
    lastAttestAt: new Date().toISOString(),
  });

  return {
    steps,
    decision: result.decision || 'ERROR',
    reasonCode: result.reasonCode || null,
    message: result.message || null,
    gateUrl: result.gatePath
      ? gateUrlFor({
          verifierUrl: config.verifierUrl,
          gatePort: result.gatePort,
          gatePath: result.gatePath,
          gateUrl: config.gateUrl || result.gatePublicUrl,
        })
      : null,
    tokenTtlSeconds: result.tokenTtlSeconds || 600,
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${config.uiPort}`);

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      return sendFile(res, path.join(__dirname, 'ui.html'), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/ui.js') {
      return sendFile(res, path.join(__dirname, 'ui.js'), 'text/javascript; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/theme.css') {
      return sendFile(res, path.join(config.root, 'dashboard', 'theme.css'), 'text/css; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/favicon.svg') {
      return sendFile(res, path.join(config.root, 'dashboard', 'favicon.svg'), 'image/svg+xml');
    }

    if (req.method === 'GET' && url.pathname === '/api/status') {
      const identity = loadOrCreateIdentity(config);
      const state = loadState(config);
      return sendJson(res, 200, {
        deviceId: identity.deviceId,
        enrolled: Boolean(state.enrolledAt),
        enrolledAt: state.enrolledAt || null,
        lastResult: state.lastResult || null,
        verifierUrl: config.verifierUrl,
        platform: process.platform,
        canReadPosture: process.platform === 'win32',
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/check') {
      const policyRes = await api.policy(config);
      if (!policyRes.ok) return sendJson(res, 502, { error: `Verifier returned HTTP ${policyRes.status}` });
      return sendJson(res, 200, {
        ok: true,
        policyVersion: policyRes.data.version,
        minBuild: policyRes.data.minBuild,
        maxUpdateAge: policyRes.data.maxUpdateAge,
        requireFirewall: policyRes.data.requireFirewall,
        requireDefender: policyRes.data.requireDefender,
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/enroll') {
      const body = await readJsonBody(req);
      const code = typeof body.code === 'string' ? body.code.toUpperCase().trim() : '';
      if (!code) return sendJson(res, 400, { error: 'Enter the enrollment code from the dashboard.' });
      const identity = loadOrCreateIdentity(config);
      const enrollRes = await api.enroll(config, {
        code,
        deviceId: identity.deviceId,
        publicKey: identity.publicKeySpkiB64,
        label: typeof body.label === 'string' ? body.label.slice(0, 40) : undefined,
      });
      if (enrollRes.status !== 201) {
        return sendJson(res, 400, { error: enrollRes.data.error || 'Enrollment failed' });
      }
      saveState(config, {
        ...loadState(config),
        deviceId: identity.deviceId,
        enrolledAt: enrollRes.data.enrolledAt,
        label: enrollRes.data.label,
      });
      return sendJson(res, 200, { ok: true, deviceId: identity.deviceId, label: enrollRes.data.label });
    }

    if (req.method === 'POST' && url.pathname === '/api/attest') {
      const result = await runAttest();
      return sendJson(res, 200, result);
    }

    return sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }
});

if (process.platform !== 'win32') {
  console.warn('Warning: posture cannot be read on this platform; /api/attest will refuse.');
}

server.listen(config.uiPort, HOST, () => {
  console.log('');
  console.log('  ZK Posture Gate - agent UI');
  console.log(`  http://${HOST}:${config.uiPort}  (this laptop only)`);
  console.log('  Nothing on this page is sent anywhere except the proof and public signals.');
  console.log('');
});
