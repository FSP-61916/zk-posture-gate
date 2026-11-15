'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/verify-proof.js
//
// Loads the Groth16 verification key once and verifies proofs with snarkjs.
// The public signals are the exact strings the client sent; the route has
// already checked that every one of the 7 signals matches policy + challenge.
// ---------------------------------------------------------------------------

const fs = require('node:fs');

// snarkjs builds the BN128 curve on worker threads unless it is told not to,
// and `groth16.verify()` exposes no option for it. Those workers keep their
// MessagePort handles alive after the proof is checked, so the verifier could
// not shut down on Ctrl+C without calling process.exit() - and exiting while
// handles close is the Node 24 Windows crash (libuv src\win\async.c).
//
// Forcing the in-process curve build here keeps verification single-threaded.
// Checked on Node 24.13.0: after a verification the process reports no worker
// handles and exits by itself. Pinned in package.json so this cannot silently
// drift with snarkjs's dependency tree.
const ffjavascript = require('ffjavascript');
const buildBn128 = ffjavascript.buildBn128;
ffjavascript.buildBn128 = (singleThread) => buildBn128(singleThread ?? true);

const snarkjs = require('snarkjs');

function loadVerificationKey(vkPath) {
  if (!fs.existsSync(vkPath)) {
    throw new Error(
      `verification key not found at ${vkPath}. Run "npm run setup:circuit" first.`
    );
  }
  return JSON.parse(fs.readFileSync(vkPath, 'utf8'));
}

class ProofVerifier {
  constructor(vkPath) {
    this.vk = loadVerificationKey(vkPath);
  }

  /** true only if the proof is valid for these public signals. */
  async verify(publicSignals, proof) {
    try {
      return await snarkjs.groth16.verify(this.vk, publicSignals, proof);
    } catch {
      // An off-curve point or a malformed group element throws inside snarkjs.
      // That is a failed proof, not a server error.
      return false;
    }
  }
}

module.exports = { ProofVerifier, loadVerificationKey };
