'use strict';
// ---------------------------------------------------------------------------
// tests/log.test.js
//
// The decision log must survive restarts, keep its chain, and report the FIRST
// broken record when someone edits it by hand.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { DecisionLog, hashRecord, GENESIS_HASH, HASHED_FIELDS } = require('../verifier/lib/log');
const { canonicalJson } = require('../shared/canonical');

function tempLog() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-test-log-'));
  return path.join(dir, 'decisions.jsonl');
}

function sampleLog(file) {
  const log = new DecisionLog(file, { now: () => Date.parse('2026-11-08T10:00:00.000Z') });
  log.append({ deviceId: 'dev_' + 'a'.repeat(24), policyVersion: 1, result: 'GRANTED', reasonCode: null, latencyMs: 700 });
  log.append({ deviceId: 'dev_' + 'b'.repeat(24), policyVersion: 1, result: 'DENIED', reasonCode: 'NON_COMPLIANT', latencyMs: 690 });
  log.append({ deviceId: 'dev_' + 'c'.repeat(24), policyVersion: 2, result: 'DENIED', reasonCode: 'PROOF_INVALID', latencyMs: 5 });
  return log;
}

test('chain links records and verifies as intact', () => {
  const file = tempLog();
  sampleLog(file);
  const recs = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);

  assert.equal(recs.length, 3);
  assert.equal(recs[0].prevHash, GENESIS_HASH);
  assert.equal(recs[1].prevHash, recs[0].hash);
  assert.equal(recs[2].prevHash, recs[1].hash);

  const verdict = new DecisionLog(file).verify();
  assert.equal(verdict.status, 'intact');
  assert.equal(verdict.count, 3);
  assert.equal(verdict.latestHash, recs[2].hash);
});

test('hash is reproducible from the documented canonical form', () => {
  const file = tempLog();
  sampleLog(file);
  const rec = JSON.parse(fs.readFileSync(file, 'utf8').split('\n')[0]);

  const fields = {};
  for (const key of HASHED_FIELDS) fields[key] = rec[key];
  const recomputed = require('node:crypto')
    .createHash('sha256')
    .update(rec.prevHash + canonicalJson(fields), 'utf8')
    .digest('hex');

  assert.equal(recomputed, rec.hash);
  assert.equal(hashRecord(rec), rec.hash);
  // canonical JSON is key-sorted and whitespace free
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test('editing one record reports that record as broken', () => {
  const file = tempLog();
  sampleLog(file);
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  const rec = JSON.parse(lines[1]);
  rec.result = 'GRANTED'; // hand edit: hide a denial
  lines[1] = JSON.stringify(rec);
  fs.writeFileSync(file, lines.join('\n') + '\n');

  const verdict = new DecisionLog(file).verify();
  assert.equal(verdict.status, 'broken');
  assert.equal(verdict.brokenAt, 2);
  assert.match(verdict.reason, /hash/);
});

test('deleting a record breaks the id sequence at that position', () => {
  const file = tempLog();
  sampleLog(file);
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  fs.writeFileSync(file, [lines[0], lines[2]].join('\n') + '\n');

  const verdict = new DecisionLog(file).verify();
  assert.equal(verdict.status, 'broken');
  assert.equal(verdict.brokenAt, 2);
});

test('history persists across a restart and new records continue the chain', () => {
  const file = tempLog();
  sampleLog(file);

  const reopened = new DecisionLog(file);
  assert.equal(reopened.count, 3);
  reopened.append({
    deviceId: 'dev_' + 'd'.repeat(24),
    policyVersion: 2,
    result: 'GRANTED',
    reasonCode: null,
    latencyMs: 800,
  });

  const recs = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(recs.length, 4);
  assert.equal(recs[3].id, 4);
  assert.equal(recs[3].prevHash, recs[2].hash);
  assert.equal(new DecisionLog(file).verify().status, 'intact');
});

test('records contain no posture fields, only the agreed metadata', () => {
  const file = tempLog();
  sampleLog(file);
  const rec = JSON.parse(fs.readFileSync(file, 'utf8').split('\n')[0]);
  assert.deepEqual(
    Object.keys(rec).sort(),
    ['deviceId', 'hash', 'id', 'latencyMs', 'policyVersion', 'prevHash', 'reasonCode', 'result', 'timestamp'].sort()
  );
});
