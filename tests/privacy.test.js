'use strict';
// ---------------------------------------------------------------------------
// tests/privacy.test.js
//
// The headline claim, tested mechanically:
// after a full GRANTED attestation from a laptop whose real build encodes to
// 2263103803, that number must not appear anywhere in the verifier's files.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { posture, startVerifier, agentConfig, enroll, attestBody, submit, ROOT } = require('./helpers');

const REAL_BUILD = 2263103803; // 22631 * 100000 + 3803
const REAL_UBR = 3803;
const REAL_AGE = 4;

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

test('the real build number never reaches the verifier', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);

  const laptop = posture({ build: 22631, ubr: 3803, updateAgeDays: REAL_AGE });
  const { body } = await attestBody(ctx, agent, identity, laptop);
  const res = await submit(ctx, body);
  assert.equal(res.data.decision, 'GRANTED');

  // 1. every file the verifier wrote
  const verifierFiles = walk(ctx.dataDir);
  assert.ok(verifierFiles.length > 0);
  for (const file of verifierFiles) {
    const content = fs.readFileSync(file, 'latin1');
    assert.ok(
      !content.includes(String(REAL_BUILD)),
      `${file} contains the encoded OS build`
    );
    assert.ok(!content.includes('"build"'), `${file} contains a build field`);
  }

  // 2. every verifier source file
  for (const file of walk(path.join(ROOT, 'verifier')).filter((f) => f.endsWith('.js'))) {
    const content = fs.readFileSync(file, 'utf8');
    assert.ok(!content.includes(String(REAL_BUILD)), `${file} contains the encoded OS build`);
  }

  // 3. the log record has exactly the agreed metadata and nothing else
  const record = ctx.services.log.records()[0];
  assert.deepEqual(
    Object.keys(record).sort(),
    ['deviceId', 'hash', 'id', 'latencyMs', 'policyVersion', 'prevHash', 'reasonCode', 'result', 'timestamp'].sort()
  );
  const serialised = JSON.stringify(record);
  assert.ok(!serialised.includes(String(REAL_BUILD)));
  assert.ok(!serialised.includes('firewall'));
  assert.ok(!serialised.includes('defender'));
});

test('a posture value is not recoverable from the public signals either', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { publicSignals, body } = await attestBody(
    ctx,
    agent,
    identity,
    posture({ build: 22631, ubr: 3803 })
  );
  await submit(ctx, body);

  // Public signals are: compliant, challengeSq, and the FOUR POLICY NUMBERS,
  // plus the challenge. The private build/age/booleans are not among them.
  assert.equal(publicSignals.length, 7);
  assert.ok(!publicSignals.includes(String(REAL_BUILD)));
  // 2200000000-style policy values are the verifier's own numbers, not posture.
  for (const signal of publicSignals) {
    assert.ok(signal !== String(22631) && signal !== String(REAL_UBR));
  }
});
