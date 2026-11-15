'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/public-signals.js
//
// The exact public-signal order, read from the circuit's own output rather
// than assumed. `snarkjs groth16 fullprove ... proof.json public.json` produced:
//
//   [ "1", "152415787532388367501905199875019052100" ]
//        ^ index 0 = compliant (output)      ^ index 1 = challengeSq (output)
//
// ... and after declaring the inputs public in `component main {public [...]}`
// the full list is (outputs first, then public inputs in declaration order):
//
//   index 0  compliant
//   index 1  challengeSq
//   index 2  minBuild
//   index 3  maxUpdateAge
//   index 4  requireFirewall
//   index 5  requireDefender
//   index 6  challenge
//
// That is 7 signals. tests/circuit.test.js fails loudly if this ever changes.
// ---------------------------------------------------------------------------

const PUBLIC_SIGNAL_ORDER = [
  'compliant',
  'challengeSq',
  'minBuild',
  'maxUpdateAge',
  'requireFirewall',
  'requireDefender',
  'challenge',
];

const IDX = Object.freeze(
  PUBLIC_SIGNAL_ORDER.reduce((acc, name, i) => {
    acc[name] = i;
    return acc;
  }, {})
);

const PUBLIC_SIGNAL_COUNT = PUBLIC_SIGNAL_ORDER.length;

/**
 * The public signals the verifier expects for a challenge + its own policy.
 * `compliant` is not part of this because the prover decides it; the verifier
 * reads it separately at index IDX.compliant.
 */
function expectedPublicSignals({ policy, challenge }) {
  const out = new Array(PUBLIC_SIGNAL_COUNT).fill(null);
  out[IDX.minBuild] = String(policy.minBuild);
  out[IDX.maxUpdateAge] = String(policy.maxUpdateAge);
  out[IDX.requireFirewall] = policy.requireFirewall ? '1' : '0';
  out[IDX.requireDefender] = policy.requireDefender ? '1' : '0';
  out[IDX.challenge] = String(challenge);
  return out;
}

// BN128 scalar field prime. challengeSq is challenge^2 reduced modulo this.
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** The challengeSq public signal the circuit must produce. Null if unparsable. */
function expectedChallengeSq(challenge) {
  try {
    const value = BigInt(String(challenge));
    if (value < 0n) return null;
    return ((value * value) % BN128_PRIME).toString();
  } catch {
    return null;
  }
}

/** Parse an array of decimal strings into a map keyed by signal name. */
function parsePublicSignals(signals) {
  if (!Array.isArray(signals) || signals.length !== PUBLIC_SIGNAL_COUNT) return null;
  const map = {};
  PUBLIC_SIGNAL_ORDER.forEach((name, i) => {
    map[name] = signals[i];
  });
  return map;
}

module.exports = {
  PUBLIC_SIGNAL_ORDER,
  PUBLIC_SIGNAL_COUNT,
  IDX,
  expectedPublicSignals,
  expectedChallengeSq,
  parsePublicSignals,
  BN128_PRIME,
};
