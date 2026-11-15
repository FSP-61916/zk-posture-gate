'use strict';
// ---------------------------------------------------------------------------
// agent/lib/prover.js
//
// Generates the Groth16 proof ON THIS LAPTOP. Only the proof and the public
// signals are returned; the private inputs stay in this process's memory.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const snarkjs = require('snarkjs');

function assertArtifacts(config) {
  for (const [label, file] of [
    ['witness generator (.wasm)', config.wasmPath],
    ['proving key (.zkey)', config.zkeyPath],
  ]) {
    if (!fs.existsSync(file)) {
      throw new Error(`${label} not found at ${file}. Run "npm run setup:circuit" or copy the agent bundle.`);
    }
  }
}

/** Circuit inputs: private posture values plus the verifier's public policy. */
function buildCircuitInput({ posture, policy, challenge }) {
  return {
    build: String(posture.build),
    updateAgeDays: String(posture.updateAgeDays),
    firewallOn: String(posture.firewallOn),
    defenderOn: String(posture.defenderOn),
    minBuild: String(policy.minBuild),
    maxUpdateAge: String(policy.maxUpdateAge),
    requireFirewall: policy.requireFirewall ? '1' : '0',
    requireDefender: policy.requireDefender ? '1' : '0',
    challenge: String(challenge),
  };
}

async function generateProof(config, { posture, policy, challenge }) {
  assertArtifacts(config);
  const input = buildCircuitInput({ posture, policy, challenge });

  const started = process.hrtime.bigint();
  // singleThread: true keeps snarkjs from spawning worker threads for the
  // witness calculator and curve code. Those workers leave MessagePort handles
  // open after the proof, which forces scripts to call process.exit() while
  // handles are still closing - that is the libuv crash on Windows Node 24
  // (src\win\async.c, !(handle->flags & UV_HANDLE_CLOSING)). In-process proving
  // leaves nothing behind, so the process exits on its own.
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    config.wasmPath,
    config.zkeyPath,
    undefined,
    { singleThread: true },
    { singleThread: true }
  );
  const ms = Number(process.hrtime.bigint() - started) / 1e6;

  // The private input object is not returned, logged or stored.
  return { proof, publicSignals, ms };
}

module.exports = { generateProof, buildCircuitInput, assertArtifacts };
