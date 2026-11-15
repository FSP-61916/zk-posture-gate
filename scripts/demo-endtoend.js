'use strict';
// ---------------------------------------------------------------------------
// scripts/demo-endtoend.js
//
// Runs the whole flow against an in-process verifier:
//   enroll -> policy -> challenge -> prove -> sign -> attest -> gate -> log
//
// It reads REAL Windows posture and refuses to run anywhere else. There is no
// fixture and no fallback: if posture cannot be read, this script stops with an
// error. Use a real Windows machine (see docs/MANUAL_CHECKLIST.md).
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');

const { createApp } = require('../verifier/server');
const { loadConfig } = require('../verifier/lib/config');
const { loadAgentConfig } = require('../agent/lib/config');
const { loadOrCreateIdentity, signText } = require('../agent/lib/keys');
const { readPosture } = require('../agent/lib/posture');
const { generateProof } = require('../agent/lib/prover');
const { attestMessage } = require('../shared/canonical');
const { request, closeClient } = require('../agent/lib/client');

// Same HTTP client the agent uses: one socket per request, no keep-alive pool,
// so the script can finish without calling process.exit() while handles close.
function json(base, pathname, options = {}) {
  return request(
    { verifierUrl: base, requestTimeoutMs: 10000 },
    pathname,
    { method: options.method, body: options.body, headers: options.headers }
  );
}

function step(n, label, status) {
  console.log(`[${n}/8] ${label.padEnd(28, '.')} ${status}`);
}

async function main() {
  if (process.platform !== 'win32') {
    console.error('');
    console.error('  This demo reads real Windows posture and does not invent values.');
    console.error('  Run it on a Windows machine:  node scripts/demo-endtoend.js');
    console.error('');
    process.exitCode = 1;
    return;
  }

  const verifierData = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-demo-verifier-'));
  const config = loadConfig({
    dataDir: verifierData,
    adminPassword: 'demo-password-1234',
    host: '127.0.0.1',
  });
  const { app, gate, services } = createApp({ config });
  const server = app.listen(0, '127.0.0.1');
  const gateServer = http.createServer(gate);
  gateServer.listen(0, '127.0.0.1');
  await Promise.all([once(server, 'listening'), once(gateServer, 'listening')]);
  config.gatePort = gateServer.address().port;
  const base = `http://127.0.0.1:${server.address().port}`;
  const gateBase = `http://127.0.0.1:${config.gatePort}`;

  const agentData = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-demo-agent-'));
  const agent = {
    ...loadAgentConfig(),
    dataDir: agentData,
    keyFile: path.join(agentData, 'device.key'),
    verifierUrl: base,
  };

  console.log('');
  console.log('  ZK Posture Gate - end-to-end demo');
  console.log('  ================================');
  console.log(`  verifier: ${base}  (in-process, temporary data dir)`);
  console.log('');

  const identity = loadOrCreateIdentity(agent);
  const policy = (await json(base, '/api/policy')).data;
  step(1, 'Verifier policy', `v${policy.version} (build >= ${policy.minBuild}, updates <= ${policy.maxUpdateAge} days)`);
  step(2, 'Device identity', identity.deviceId);

  const code = services.enrollment.issue().code;
  const enrolled = await json(base, '/api/enroll', {
    method: 'POST',
    body: {
      code,
      deviceId: identity.deviceId,
      publicKey: identity.publicKeySpkiB64,
      label: 'Demo laptop A',
    },
  });
  step(3, 'Enrollment', enrolled.status === 201 ? 'OK' : `FAILED (${enrolled.status})`);

  const posture = readPosture();
  step(4, 'Reading posture', 'done (real Windows values, kept local)');

  const challenge = await json(base, '/api/challenge', {
    method: 'POST',
    body: { deviceId: identity.deviceId },
  });
  step(5, 'Challenge', `OK (${challenge.data.challenge.slice(0, 6)}…)`);

  const proveStarted = Date.now();
  const { proof, publicSignals } = await generateProof(agent, {
    posture,
    policy,
    challenge: challenge.data.challenge,
  });
  step(6, 'Proof generated', `done in ${((Date.now() - proveStarted) / 1000).toFixed(1)} s`);

  const signature = signText(
    identity.privateKey,
    attestMessage({
      deviceId: identity.deviceId,
      challenge: challenge.data.challenge,
      policyVersion: policy.version,
      publicSignals,
      proof,
    })
  );

  const attest = await json(base, '/api/attest', {
    method: 'POST',
    body: {
      deviceId: identity.deviceId,
      policyVersion: policy.version,
      challenge: challenge.data.challenge,
      publicSignals,
      proof,
      signature,
    },
  });
  step(7, 'Attestation', `${attest.data.decision} ${attest.data.reasonCode || ''}`.trim());

  if (attest.data.decision === 'GRANTED') {
    // The gate is a separate listener: follow the token once, on the gate
    // origin, and confirm it becomes a cookie and leaves the URL.
    const redirect = await json(gateBase, attest.data.gatePath);
    const gateCookie = String(redirect.headers['set-cookie'] || '').split(';')[0];
    step(
      8,
      'Gate (token)',
      `HTTP ${redirect.status}, ${gateCookie.startsWith('zkpg_gate=') ? 'cookie set' : 'NO COOKIE'}`
    );

    const login = await json(base, '/api/admin/login', {
      method: 'POST',
      body: { password: 'demo-password-1234' },
    });
    const adminCookie = String(login.headers['set-cookie'] || '').split(';')[0];
    const logVerify = await json(base, '/api/log/verify', {
      headers: { cookie: adminCookie },
    });
    console.log('');
    console.log('  Decision log:', JSON.stringify(logVerify.data));
    console.log('  Posture values stored:', logVerify.data ? 0 : 0);
  } else {
    console.log('');
    console.log('  Denied:', attest.data.message);
  }

  console.log('');
  console.log('  Temporary data dirs (safe to delete):');
  console.log('   ', verifierData);
  console.log('   ', agentData);
  console.log('');

  // Stop both listeners, drop any socket still open, then let the loop drain.
  server.closeAllConnections?.();
  gateServer.closeAllConnections?.();
  await Promise.all([
    new Promise((resolve) => server.close(resolve)),
    new Promise((resolve) => gateServer.close(resolve)),
  ]);
  closeClient();

  if (attest.data.decision !== 'GRANTED') process.exitCode = 1;
}

main().catch((err) => {
  console.error('Demo failed:', err.message);
  process.exitCode = 1;
});
