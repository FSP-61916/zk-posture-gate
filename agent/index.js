#!/usr/bin/env node
'use strict';
// ---------------------------------------------------------------------------
// agent/index.js
//
// Usage:
//   node agent enroll --code ABCD-EFGH [--label "Laptop A"]
//   node agent check        (connectivity + policy version only, sends no posture)
//   node agent attest [--open] [--interval [minutes]]
//       one-shot, or repeat every 5 minutes (default) until Ctrl+C
//
// The step output never prints posture values. They exist only inside this
// process, as private circuit inputs.
//
// This process never calls process.exit(). Proving runs single-threaded (no
// worker handles) and the HTTP client closes its own socket after every call,
// so the event loop drains by itself and the shell gets the real exit code.
// process.exit() while handles were closing used to crash Node 24 on Windows
// with a libuv assertion in src\win\async.c.
// ---------------------------------------------------------------------------

const { loadAgentConfig } = require('./lib/config');
const { loadOrCreateIdentity, signText } = require('./lib/keys');
const { readPosture } = require('./lib/posture');
const { generateProof } = require('./lib/prover');
const { api, closeClient } = require('./lib/client');
const { gateUrlFor } = require('./lib/gate-url');
const { openBrowser } = require('./lib/open-browser');
const { attestMessage } = require('../shared/canonical');
const { loadState, saveState } = require('./lib/state');
const { parseInterval } = require('./lib/interval');

const config = loadAgentConfig();

// One clean line per step, printed when the step finishes. No in-place
// redrawing: captured output has to be readable in the demo recording.
function line(step, text, status) {
  const dots = '.'.repeat(Math.max(4, 28 - text.length));
  console.log(`[${step}/6] ${text} ${dots} ${status}`);
}

function fail(message) {
  console.error(`\n  ${message}\n`);
  process.exitCode = 1;
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const value = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      args[key] = value;
    } else {
      args._.push(token);
    }
  }
  return args;
}

async function commandEnroll(args) {
  const code = typeof args.code === 'string' ? args.code.toUpperCase() : '';
  if (!code) {
    fail('Missing --code. Ask the admin to generate an enrollment code on the Devices page.');
    return;
  }

  const identity = loadOrCreateIdentity(config);
  if (identity.created) {
    console.log('  Generated a new ed25519 device key (private key stays on this laptop).');
  }
  console.log(`  Device id: ${identity.deviceId}`);

  const res = await api.enroll(config, {
    code,
    deviceId: identity.deviceId,
    publicKey: identity.publicKeySpkiB64,
    label: typeof args.label === 'string' ? args.label : undefined,
  });

  if (res.status === 201) {
    saveState(config, {
      ...loadState(config),
      deviceId: identity.deviceId,
      enrolledAt: res.data.enrolledAt,
      label: res.data.label,
    });
    console.log(`  Enrolled. ${res.data.label} is registered with the verifier.`);
    return;
  }
  fail(`Enrollment failed: ${res.data.error || res.status}`);
}

async function commandCheck() {
  const res = await api.policy(config);
  if (!res.ok) {
    fail(`Verifier did not answer correctly (HTTP ${res.status}).`);
    return;
  }
  const identity = loadOrCreateIdentity(config);
  const state = loadState(config);
  console.log('');
  console.log('  Verifier ............ OK');
  console.log(`  Policy version ...... v${res.data.version}`);
  console.log(`  Policy requires ..... build >= ${res.data.minBuild}, updates <= ${res.data.maxUpdateAge} days,`);
  console.log(`                         firewall ${res.data.requireFirewall ? 'required' : 'optional'}, Defender ${res.data.requireDefender ? 'required' : 'optional'}`);
  console.log(`  Device id ........... ${identity.deviceId}`);
  console.log(`  Enrolled ............ ${state.enrolledAt ? 'yes' : 'not yet (run: node agent enroll --code ...)'}`);
  console.log('  Note: this command reads no posture values and sends none.');
  console.log('');
}

async function commandAttest(args) {
  const startedAt = Date.now();
  // Wall-clock per step, in milliseconds. These are durations only: no posture
  // value ever reaches this object or the screen.
  const timings = { policy: 0, posture: 0, challenge: 0, proof: 0, submit: 0 };
  console.log('');

  let stepStart = Date.now();
  const policyRes = await api.policy(config);
  timings.policy = Date.now() - stepStart;
  if (!policyRes.ok) throw new Error(`verifier returned HTTP ${policyRes.status}`);
  const policy = policyRes.data;
  line(1, 'Checking verifier', `OK (policy v${policy.version})`);

  const identity = loadOrCreateIdentity(config);
  const state = loadState(config);
  if (!state.enrolledAt) {
    throw new Error('This laptop is not enrolled. Run: node agent enroll --code <code>');
  }

  stepStart = Date.now();
  const posture = readPosture(); // stays in memory
  timings.posture = Date.now() - stepStart;
  line(2, 'Reading posture', 'done (values stay on this device)');

  stepStart = Date.now();
  const challengeRes = await api.challenge(config, identity.deviceId);
  timings.challenge = Date.now() - stepStart;
  if (!challengeRes.ok) {
    throw new Error(`challenge refused: ${challengeRes.data.error || challengeRes.status}`);
  }
  const { challenge } = challengeRes.data;
  line(3, 'Fetching challenge', 'OK');

  const { proof, publicSignals, ms } = await generateProof(config, {
    posture,
    policy,
    challenge,
  });
  timings.proof = Math.round(ms);
  line(4, 'Generating proof', `done (${(ms / 1000).toFixed(1)} s)`);

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
  line(5, 'Signing submission', 'done');

  stepStart = Date.now();
  const attestRes = await api.attest(config, {
    deviceId: identity.deviceId,
    policyVersion: policy.version,
    challenge,
    publicSignals,
    proof,
    signature,
  });
  timings.submit = Date.now() - stepStart;
  const result = attestRes.data || {};
  line(
    6,
    'Sending attestation',
    `${result.decision || 'ERROR'}${result.reasonCode ? ` (${result.reasonCode})` : ''}`
  );

  saveState(config, {
    ...loadState(config),
    lastResult: result.decision || 'ERROR',
    lastAttestAt: new Date().toISOString(),
  });

  console.log('');
  if (result.decision === 'GRANTED') {
    console.log(`  ${result.message || 'Access granted for policy v' + result.policyVersion}.`);
    const gateLink = gateUrlFor({
      verifierUrl: config.verifierUrl,
      gatePort: result.gatePort,
      gatePath: result.gatePath,
      // The verifier's GATE_PUBLIC_URL (if set) is the admin's declared gate
      // origin; this laptop's GATE_URL wins when both exist.
      gateUrl: config.gateUrl || result.gatePublicUrl,
    });
    console.log(`  Gate URL (valid ${Math.round((result.tokenTtlSeconds || 600) / 60)} min):`);
    console.log(`  ${gateLink}`);
    if (args.open) {
      const opened = await openBrowser(gateLink);
      console.log(
        opened
          ? '  Opened in your browser.'
          : '  Could not open a browser automatically. Copy the URL above.'
      );
    } else {
      console.log('  Tip: add --open to attest to launch it in your browser.');
    }
  } else {
    console.log(`  Reason: ${result.message || result.reasonCode || 'unknown'}`);
    console.log('  Which value failed is not revealed - that is the point.');
  }
  const network = timings.policy + timings.challenge + timings.submit;
  console.log('');
  console.log(
    `  Timings: posture ${timings.posture} ms | proof ${timings.proof} ms | network ${network} ms` +
      ` (policy ${timings.policy}, challenge ${timings.challenge}, submit ${timings.submit})`
  );
  console.log(`  Total: ${((Date.now() - startedAt) / 1000).toFixed(1)} s`);
  console.log('');
}

// Loop mode exists for the real check-in cadence. Five minutes is the default;
// one minute is allowed for a rehearsal. Every attempt is logged by the
// verifier on purpose: the audit trail is the record, not a side effect.
async function commandAttestLoop(args) {
  const minutes = parseInterval(args.interval);
  console.log('');
  console.log(`  Scheduled attestation every ${minutes} minute${minutes === 1 ? '' : 's'}. Ctrl+C to stop.`);
  for (;;) {
    process.exitCode = 0;
    console.log(`\n  ${new Date().toLocaleString()} - attestation`);
    try {
      // --open is ignored in loop mode: a browser tab every five minutes is
      // noise. The gate URL is printed on every GRANTED instead.
      await commandAttest({ ...args, interval: undefined, open: false });
    } catch (err) {
      fail(err.message);
    }
    console.log(`  Next attestation in ${minutes} minute${minutes === 1 ? '' : 's'}.`);
    await new Promise((resolve) => setTimeout(resolve, minutes * 60 * 1000));
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  try {
    if (command === 'enroll') await commandEnroll(args);
    else if (command === 'check') await commandCheck();
    else if (command === 'attest') {
      if (args.interval !== undefined) await commandAttestLoop(args);
      else await commandAttest(args);
    }
    else {
      console.log('');
      console.log('  ZK Posture Gate agent');
      console.log('  ---------------------');
      console.log('  node agent enroll --code ABCD-EFGH [--label "Laptop A"]');
      console.log('  node agent check     (connectivity + policy version, no posture)');
      console.log('  node agent attest [--open]  (prove compliance, then open the gate)');
      console.log('  node agent attest --interval [5]  (repeat every 5 min; 1 min for rehearsals)');
      console.log('');
    }
  } catch (err) {
    fail(err.message);
  }
}

main()
  .catch((err) => fail(err.message))
  // Release anything a cut-short request left behind, then let the loop drain.
  .finally(() => closeClient());
