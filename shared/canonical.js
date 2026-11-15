'use strict';
// ---------------------------------------------------------------------------
// shared/canonical.js
//
// Two things must be byte-identical on the laptop and on the verifier:
//   1. the text the device signs
//   2. the text that is hashed into the decision log
//
// So the rule lives in one file that both sides require(). Keep it small.
//
// Canonical JSON = JSON.stringify with object keys sorted (A-Z) at every level,
// arrays kept in order, no whitespace, no trailing newline, UTF-8 bytes.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');

/** Recursively sort object keys, then stringify. Arrays keep their order. */
function canonicalJson(value) {
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// Plain-language decode of what the proof covers, used by the dashboard panel.
const ATTEST_MESSAGE_HEADER = 'zkpg-attest-v1';

/**
 * The exact bytes the laptop signs with its ed25519 key.
 *
 * Digests are used for publicSignals and proof so the signed text stays short
 * and cannot be re-ordered by a middlebox. Format is newline separated and
 * documented in docs/ARCHITECTURE.md.
 */
function attestMessage({ deviceId, challenge, policyVersion, publicSignals, proof }) {
  return [
    ATTEST_MESSAGE_HEADER,
    `deviceId:${deviceId}`,
    `challenge:${challenge}`,
    `policyVersion:${policyVersion}`,
    `publicSignals:${sha256Hex(canonicalJson(publicSignals))}`,
    `proof:${sha256Hex(canonicalJson(proof))}`,
  ].join('\n');
}

module.exports = { canonicalJson, sha256Hex, attestMessage, ATTEST_MESSAGE_HEADER };
