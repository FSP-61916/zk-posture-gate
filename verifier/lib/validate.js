'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/validate.js
//
// Strict request validation. Every endpoint uses these helpers before doing any
// work, so malformed input never reaches the proof verifier or the disk.
// We do not accept extra fields on /api/attest: the body shape is fixed.
// ---------------------------------------------------------------------------

const { PUBLIC_SIGNAL_COUNT } = require('./public-signals');

const DEVICE_ID_RE = /^dev_[0-9a-f]{24}$/;
const DECIMAL_RE = /^[0-9]{1,80}$/;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{64,128}$/;

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDecimalString(value, maxLength = 80) {
  return typeof value === 'string' && value.length <= maxLength && DECIMAL_RE.test(value);
}

function isFieldElementArray(value, length) {
  return Array.isArray(value) && value.length === length && value.every((v) => isDecimalString(v));
}

/** Structural check of the proof object produced by snarkjs groth16. */
function isGroth16Proof(proof) {
  if (!isPlainObject(proof)) return false;
  if (proof.protocol !== 'groth16' || proof.curve !== 'bn128') return false;
  if (!isFieldElementArray(proof.pi_a, 3)) return false;
  if (!Array.isArray(proof.pi_b) || proof.pi_b.length !== 3) return false;
  for (const pair of proof.pi_b) {
    if (!isFieldElementArray(pair, 2)) return false;
  }
  return isFieldElementArray(proof.pi_c, 3);
}

const ALLOWED_ATTEST_FIELDS = new Set([
  'deviceId',
  'policyVersion',
  'challenge',
  'publicSignals',
  'proof',
  'signature',
]);

/**
 * Returns { ok: true } or { ok: false, error }.
 * Deliberately strict: additional properties are rejected, so a client cannot
 * smuggle extra data (for example raw posture values) into the verifier.
 */
function validateAttestBody(body) {
  if (!isPlainObject(body)) return { ok: false, error: 'body must be a JSON object' };

  for (const key of Object.keys(body)) {
    if (!ALLOWED_ATTEST_FIELDS.has(key)) {
      return { ok: false, error: `unexpected field: ${key}` };
    }
  }

  if (typeof body.deviceId !== 'string' || !DEVICE_ID_RE.test(body.deviceId)) {
    return { ok: false, error: 'deviceId is malformed' };
  }
  if (!Number.isInteger(body.policyVersion) || body.policyVersion < 1) {
    return { ok: false, error: 'policyVersion must be a positive integer' };
  }
  if (!isDecimalString(body.challenge, 40)) {
    return { ok: false, error: 'challenge must be a decimal string' };
  }
  if (!Array.isArray(body.publicSignals) || body.publicSignals.length !== PUBLIC_SIGNAL_COUNT) {
    return { ok: false, error: `publicSignals must contain exactly ${PUBLIC_SIGNAL_COUNT} decimal strings` };
  }
  if (!body.publicSignals.every((s) => isDecimalString(s, 80))) {
    return { ok: false, error: 'publicSignals must be decimal strings' };
  }
  if (!isGroth16Proof(body.proof)) {
    return { ok: false, error: 'proof is not a Groth16 proof' };
  }
  if (typeof body.signature !== 'string' || !SIGNATURE_RE.test(body.signature)) {
    return { ok: false, error: 'signature is malformed' };
  }
  return { ok: true };
}

function validateEnrollBody(body) {
  if (!isPlainObject(body)) return { ok: false, error: 'body must be a JSON object' };
  const allowed = new Set(['code', 'deviceId', 'publicKey', 'label']);
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) return { ok: false, error: `unexpected field: ${key}` };
  }
  if (typeof body.code !== 'string' || !/^[A-Z0-9-]{4,20}$/.test(body.code)) {
    return { ok: false, error: 'code is malformed' };
  }
  if (typeof body.deviceId !== 'string' || !DEVICE_ID_RE.test(body.deviceId)) {
    return { ok: false, error: 'deviceId is malformed' };
  }
  if (typeof body.publicKey !== 'string' || body.publicKey.length > 400) {
    return { ok: false, error: 'publicKey is malformed' };
  }
  if (body.label !== undefined && (typeof body.label !== 'string' || body.label.length > 40)) {
    return { ok: false, error: 'label must be a short string' };
  }
  return { ok: true };
}

function validateChallengeBody(body) {
  if (!isPlainObject(body)) return { ok: false, error: 'body must be a JSON object' };
  if (typeof body.deviceId !== 'string' || !DEVICE_ID_RE.test(body.deviceId)) {
    return { ok: false, error: 'deviceId is malformed' };
  }
  return { ok: true };
}

module.exports = {
  isPlainObject,
  isDecimalString,
  isGroth16Proof,
  validateAttestBody,
  validateEnrollBody,
  validateChallengeBody,
  DEVICE_ID_RE,
};
