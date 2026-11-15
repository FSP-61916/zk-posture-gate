'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/policy.js
//
// The verifier OWNS the policy. A laptop can read it, but a laptop can never
// set it: only the admin endpoint can change it, and every change bumps the
// version number that proofs are checked against.
// ---------------------------------------------------------------------------

const { JsonFile } = require('./store');

// A sane starting policy: Windows 11 22H2-level builds, updates within 30 days,
// firewall and Defender required.
const DEFAULT_POLICY = {
  version: 1,
  minBuild: 2262100000, // 22621 (Windows 11 22H2) with UBR 0
  maxUpdateAge: 30,
  requireFirewall: true,
  requireDefender: true,
  updatedAt: new Date('2026-01-01T00:00:00.000Z').toISOString(),
};

const LIMITS = {
  minBuild: 2 ** 40 - 1,
  maxUpdateAge: 65535,
};

function validatePolicyFields(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return ['body must be a JSON object'];

  if (!Number.isInteger(input.minBuild) || input.minBuild < 0 || input.minBuild > LIMITS.minBuild) {
    errors.push(`minBuild must be an integer between 0 and ${LIMITS.minBuild}`);
  }
  if (
    !Number.isInteger(input.maxUpdateAge) ||
    input.maxUpdateAge < 0 ||
    input.maxUpdateAge > LIMITS.maxUpdateAge
  ) {
    errors.push(`maxUpdateAge must be an integer between 0 and ${LIMITS.maxUpdateAge}`);
  }
  if (typeof input.requireFirewall !== 'boolean') errors.push('requireFirewall must be true or false');
  if (typeof input.requireDefender !== 'boolean') errors.push('requireDefender must be true or false');
  return errors;
}

class PolicyStore {
  constructor(file, { now = () => Date.now() } = {}) {
    this.file = new JsonFile(file, { ...DEFAULT_POLICY });
    this.now = now;
  }

  get() {
    return this.file.get();
  }

  /** Replace the four parameters, bump the version and stamp updatedAt. */
  update(fields) {
    const errors = validatePolicyFields(fields);
    if (errors.length) {
      const err = new Error(errors.join('; '));
      err.code = 'INVALID_POLICY';
      throw err;
    }
    const current = this.get();
    const next = {
      version: current.version + 1,
      minBuild: fields.minBuild,
      maxUpdateAge: fields.maxUpdateAge,
      requireFirewall: fields.requireFirewall,
      requireDefender: fields.requireDefender,
      updatedAt: new Date(this.now()).toISOString(),
    };
    return this.file.set(next);
  }
}

module.exports = { PolicyStore, DEFAULT_POLICY, validatePolicyFields, LIMITS };
