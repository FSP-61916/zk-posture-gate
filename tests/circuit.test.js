'use strict';
// ---------------------------------------------------------------------------
// tests/circuit.test.js
//
// Proves the circuit does what the verifier assumes:
//   * the real public-signal ORDER (read from the artifact, asserted here)
//   * exact-boundary values pass
//   * a failing value produces compliant = 0 (and the proof still verifies,
//     which is what makes NON_COMPLIANT a separate check)
//   * constraint count is recorded
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const snarkjs = require('snarkjs');

const { generateProof } = require('../agent/lib/prover');
const { toPosture } = require('../agent/lib/posture');
const {
  PUBLIC_SIGNAL_ORDER,
  IDX,
  expectedChallengeSq,
} = require('../verifier/lib/public-signals');
const { ROOT, posture } = require('./helpers');

const agent = {
  wasmPath: path.join(ROOT, 'circuits', 'build', 'posture_js', 'posture.wasm'),
  zkeyPath: path.join(ROOT, 'circuits', 'build', 'posture_final.zkey'),
};

const POLICY = {
  minBuild: 2262100000,
  maxUpdateAge: 30,
  requireFirewall: true,
  requireDefender: true,
};

test('public signals are exactly the documented seven, in order', async () => {
  const challenge = '12345678901234567890';
  const { publicSignals } = await generateProof(agent, {
    posture: posture(),
    policy: POLICY,
    challenge,
  });

  assert.deepEqual(PUBLIC_SIGNAL_ORDER, [
    'compliant',
    'challengeSq',
    'minBuild',
    'maxUpdateAge',
    'requireFirewall',
    'requireDefender',
    'challenge',
  ]);
  assert.equal(publicSignals.length, 7);
  assert.equal(publicSignals[0], '1'); // compliant
  assert.equal(publicSignals[1], expectedChallengeSq(challenge));
  assert.equal(publicSignals[2], String(POLICY.minBuild));
  assert.equal(publicSignals[3], String(POLICY.maxUpdateAge));
  assert.equal(publicSignals[4], '1');
  assert.equal(publicSignals[5], '1');
  assert.equal(publicSignals[6], challenge);
});

test('values exactly at the policy minimum are compliant', async () => {
  const boundary = posture({
    build: 22621, // encoded 2262100000 = the policy minimum
    ubr: 0,
    updateAgeDays: 30,
  });
  const { publicSignals } = await generateProof(agent, {
    posture: boundary,
    policy: POLICY,
    challenge: '55555555555555555555',
  });
  assert.equal(publicSignals[IDX.compliant], '1');
});

test('one failed check produces compliant = 0, and the proof still verifies', async () => {
  const challenge = '77777777777777777777';
  const { proof, publicSignals } = await generateProof(agent, {
    posture: posture({ defenderRealTime: false }),
    policy: POLICY,
    challenge,
  });

  assert.equal(publicSignals[IDX.compliant], '0');

  const vk = JSON.parse(
    require('node:fs').readFileSync(path.join(ROOT, 'circuits', 'build', 'verification_key.json'), 'utf8')
  );
  const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  assert.equal(valid, true, 'a non-compliant proof is still a valid proof');
});

test('boolean requirement is enforced: firewall off with requirement on fails', async () => {
  const { publicSignals } = await generateProof(agent, {
    posture: posture({ firewallAllProfiles: false }),
    policy: POLICY,
    challenge: '88888888888888888888',
  });
  assert.equal(publicSignals[IDX.compliant], '0');
});

test('encoded build fits in 40 bits and is reversible', () => {
  const { encodeBuild, decodeBuild } = require('../agent/lib/posture');
  const encoded = encodeBuild(22631, 3803);
  assert.equal(encoded, 2263103803);
  assert.ok(encoded < 2 ** 40, 'must fit in 40 bits');
  assert.equal(encoded, 22631 * 100000 + 3803);
  assert.deepEqual(decodeBuild(encoded), { build: 22631, ubr: 3803 });
});

test('constraint count is recorded in the report', () => {
  // Run the snarkjs CLI through the current Node binary. Spawning
  // node_modules/.bin/snarkjs.cmd directly fails on current Windows Node
  // releases (EINVAL, CVE-2024-27980 hardening), and the extensionless .bin
  // file is a shell script, not an executable.
  const cli = path.join(ROOT, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
  const out = execFileSync(
    process.execPath,
    [cli, 'r1cs', 'info', path.join(ROOT, 'circuits', 'build', 'posture.r1cs')],
    { encoding: 'utf8' }
  );
  const constraints = Number((out.match(/# of Constraints:\s*(\d+)/) || [])[1]);
  assert.equal(constraints, 125);
});
