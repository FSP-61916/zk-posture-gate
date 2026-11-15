'use strict';
// ---------------------------------------------------------------------------
// scripts/demo-replay.js
//
// Demonstrates REPLAY on one laptop: make ONE signed attestation, submit it,
// then submit the byte-identical body again. The first is GRANTED, the second
// must be DENIED (REPLAY) because the challenge is single use.
//
// Windows only, and it reads real posture. Requires an identity that is already
// enrolled with the running verifier (node agent enroll ...).
//
// It deliberately does not touch the agent's saved state or print posture.
// ---------------------------------------------------------------------------

const { loadAgentConfig } = require('../agent/lib/config');
const { loadState } = require('../agent/lib/state');
const { loadOrCreateIdentity, signText } = require('../agent/lib/keys');
const { readPosture } = require('../agent/lib/posture');
const { generateProof } = require('../agent/lib/prover');
const { api, closeClient } = require('../agent/lib/client');
const { attestMessage } = require('../shared/canonical');

function line(label, status) {
  const dots = '.'.repeat(Math.max(4, 30 - label.length));
  console.log(`  ${label} ${dots} ${status}`);
}

// Thrown, never process.exit()ed: exiting while handles close is what crashed
// Node 24 on Windows. main() sets process.exitCode and the loop drains.
function fail(message) {
  const err = new Error(message);
  err.userFacing = true;
  throw err;
}

async function main() {
  if (process.platform !== 'win32') {
    fail(
      'Replay demo needs real Windows posture and does not invent values.\n' +
        '  Run it on a Windows laptop:  npm run demo:replay'
    );
  }

  const config = loadAgentConfig();
  const identity = loadOrCreateIdentity(config);
  const state = loadState(config);
  if (!state.enrolledAt) {
    fail('This identity is not enrolled. Run: node agent enroll --code <code>');
  }

  console.log('');
  console.log('  ZK Posture Gate - replay demo');
  console.log(`  device: ${identity.deviceId}`);
  console.log(`  verifier: ${config.verifierUrl}`);
  console.log('');

  const policyRes = await api.policy(config);
  if (!policyRes.ok) fail(`Verifier returned HTTP ${policyRes.status}`);
  const policy = policyRes.data;

  const posture = readPosture(); // real values, kept in memory
  const challengeRes = await api.challenge(config, identity.deviceId);
  if (!challengeRes.ok) {
    fail(`Challenge refused: ${challengeRes.data.error || challengeRes.status}`);
  }
  const challenge = challengeRes.data.challenge;

  const { proof, publicSignals } = await generateProof(config, { posture, policy, challenge });
  const body = {
    deviceId: identity.deviceId,
    policyVersion: policy.version,
    challenge,
    publicSignals,
    proof,
    signature: signText(
      identity.privateKey,
      attestMessage({
        deviceId: identity.deviceId,
        challenge,
        policyVersion: policy.version,
        publicSignals,
        proof,
      })
    ),
  };

  const first = await api.attest(config, body);
  line('first submission', `${first.data.decision}${first.data.reasonCode ? ` (${first.data.reasonCode})` : ''}`);

  // Exactly the same bytes: same challenge, same proof, same signature.
  const second = await api.attest(config, body);
  line(
    'identical resubmission',
    `${second.data.decision}${second.data.reasonCode ? ` (${second.data.reasonCode})` : ''}`
  );

  console.log('');
  if (first.data.decision === 'GRANTED' && second.data.reasonCode === 'REPLAY') {
    console.log('  The proof was genuine, but a challenge can only be spent once.');
    console.log('');
    return;
  }

  if (first.data.decision !== 'GRANTED') {
    console.log(`  The first submission was denied (${first.data.reasonCode || 'unknown'}).`);
    console.log('  Make the laptop compliant first: .\\scripts\\demo-policy.ps1 set-current');
  } else {
    console.log('  Unexpected: the resubmission was not refused as REPLAY.');
  }
  console.log('');
  process.exitCode = 1;
}

main()
  .catch((err) => {
    if (err.userFacing) console.error(`\n  ${err.message}\n`);
    else console.error(`\n  Replay demo failed: ${err.message}\n`);
    process.exitCode = 1;
  })
  .finally(() => closeClient());
