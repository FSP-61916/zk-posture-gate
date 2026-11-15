'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/log.js
//
// Tamper-evident decision log: append-only JSON Lines, one record per line.
//
// Why JSON Lines and not SQLite?
//   * It is the simplest thing that can be reviewed line by line by hand.
//   * Append-only by construction: fs.appendFileSync, no UPDATE statements.
//   * No native dependency to install on the demo machine.
//
// Canonical form (documented in docs/ARCHITECTURE.md):
//   fields, in this object, hashed as
//     canonicalJson({ id, timestamp, deviceId, policyVersion, result, reasonCode, latencyMs, prevHash })
//   where canonicalJson sorts keys A-Z, has no whitespace, and is UTF-8.
//   hash = sha256_hex(prevHash + canonicalJson(fields))
//   prevHash of record 1 is 64 zeros.
//
// NEVER logged: posture values. Only pass/fail and a reason code leave the PC.
//
// Honest limit: a hash chain is tamper-EVIDENT, not tamper-PROOF. Anyone who
// rewrites every record consistently, including all hashes, is not detected
// without an external anchor.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson } = require('../../shared/canonical');

const GENESIS_HASH = '0'.repeat(64);

const HASHED_FIELDS = [
  'id',
  'timestamp',
  'deviceId',
  'policyVersion',
  'result',
  'reasonCode',
  'latencyMs',
  'prevHash',
];

function hashRecord(fields) {
  const subset = {};
  for (const key of HASHED_FIELDS) subset[key] = fields[key];
  return crypto
    .createHash('sha256')
    .update(String(fields.prevHash) + canonicalJson(subset), 'utf8')
    .digest('hex');
}

class DecisionLog {
  constructor(file, { now = () => Date.now() } = {}) {
    this.file = file;
    this.now = now;
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    if (!fs.existsSync(file)) fs.writeFileSync(file, '', { mode: 0o600 });
    const summary = this.summarise();
    this.count = summary.count;
    this.lastHash = summary.lastHash;
  }

  lines() {
    const raw = fs.readFileSync(this.file, 'utf8');
    return raw.length ? raw.split('\n').filter((l) => l.trim().length > 0) : [];
  }

  /** Read every record, keeping malformed lines visible to verify(). */
  records() {
    return this.lines().map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { __malformed: line };
      }
    });
  }

  summarise() {
    const recs = this.records();
    const valid = recs.filter((r) => !r.__malformed);
    return {
      count: recs.length,
      lastHash: valid.length ? valid[valid.length - 1].hash || GENESIS_HASH : GENESIS_HASH,
    };
  }

  /**
   * Append one decision. Only non-sensitive fields are allowed in:
   * no posture values can reach this function because the route never has them.
   */
  append({ deviceId, policyVersion, result, reasonCode, latencyMs }) {
    const id = this.count + 1;
    const fields = {
      id,
      timestamp: new Date(this.now()).toISOString(),
      deviceId,
      policyVersion,
      result,
      reasonCode: reasonCode || null,
      latencyMs: Math.max(0, Math.round(Number(latencyMs) || 0)),
      prevHash: this.count === 0 ? GENESIS_HASH : this.lastHash,
    };
    const record = { ...fields, hash: hashRecord(fields) };
    fs.appendFileSync(this.file, JSON.stringify(record) + '\n', { mode: 0o600 });
    this.count = id;
    this.lastHash = record.hash;
    return record;
  }

  /**
   * Recompute the whole chain from disk.
   * Returns the FIRST broken record and why, or "intact".
   */
  verify() {
    const recs = this.records();
    let prev = GENESIS_HASH;
    for (let i = 0; i < recs.length; i++) {
      const rec = recs[i];
      const position = i + 1;
      if (rec.__malformed) {
        return {
          status: 'broken',
          brokenAt: position,
          reason: 'record is not valid JSON',
          count: recs.length,
          checkedAt: new Date(this.now()).toISOString(),
        };
      }
      if (rec.id !== position) {
        return {
          status: 'broken',
          brokenAt: position,
          reason: `record id is ${rec.id}, expected ${position}`,
          count: recs.length,
          checkedAt: new Date(this.now()).toISOString(),
        };
      }
      if (rec.prevHash !== prev) {
        return {
          status: 'broken',
          brokenAt: position,
          reason: 'prevHash does not match the previous record hash',
          count: recs.length,
          checkedAt: new Date(this.now()).toISOString(),
        };
      }
      const expected = hashRecord(rec);
      if (rec.hash !== expected) {
        return {
          status: 'broken',
          brokenAt: position,
          reason: 'record hash does not match its contents',
          count: recs.length,
          checkedAt: new Date(this.now()).toISOString(),
        };
      }
      prev = rec.hash;
    }
    return {
      status: 'intact',
      brokenAt: null,
      reason: null,
      count: recs.length,
      latestHash: prev,
      checkedAt: new Date(this.now()).toISOString(),
    };
  }
}

module.exports = { DecisionLog, hashRecord, GENESIS_HASH, HASHED_FIELDS };
