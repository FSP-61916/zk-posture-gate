'use strict';
// ---------------------------------------------------------------------------
// scripts/measure.js
//
// Measurements for the report. N = 10 runs by default.
//   * proof generation time (mean and spread)
//   * verification time
//   * artifact sizes
//   * constraint count
//
// Every step of the mean/spread working is printed, so the numbers in
// docs/MEASUREMENTS.md can be checked by hand.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const snarkjs = require('snarkjs');

const { buildCircuitInput } = require('../agent/lib/prover');
const { readPosture } = require('../agent/lib/posture');

const ROOT = path.resolve(__dirname, '..');
const N = Number(process.argv[2] || 10);
const wasmPath = path.join(ROOT, 'circuits', 'build', 'posture_js', 'posture.wasm');
const zkeyPath = path.join(ROOT, 'circuits', 'build', 'posture_final.zkey');
const vkPath = path.join(ROOT, 'circuits', 'build', 'verification_key.json');

const policy = {
  minBuild: 2262100000,
  maxUpdateAge: 30,
  requireFirewall: true,
  requireDefender: true,
};

function sizes() {
  const kb = (p) => fs.statSync(p).size;
  return {
    'posture.wasm': kb(wasmPath),
    'posture_final.zkey': kb(zkeyPath),
    'verification_key.json': kb(vkPath),
  };
}

function mean(values) {
  const sum = values.reduce((a, b) => a + b, 0);
  return sum / values.length;
}

function stdev(values) {
  const m = mean(values);
  const squared = values.map((v) => (v - m) ** 2);
  const variance = squared.reduce((a, b) => a + b, 0) / (values.length - 1 || 1);
  return { m, squared, variance, stdev: Math.sqrt(variance) };
}

async function main() {
  // Real posture only. This script contains no sample values and never invents
  // them: on a non-Windows machine it stops with an error instead.
  let posture;
  try {
    posture = readPosture();
  } catch (err) {
    console.error('');
    console.error('  Measurements need real Windows posture:', err.message);
    console.error('  Run this on a Windows machine:  node scripts/measure.js 10');
    console.error('');
    process.exitCode = 1;
    return;
  }

  const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));
  const proveMs = [];
  const verifyMs = [];
  let proofBytes = 0;
  let allValid = true;

  for (let i = 0; i < N; i++) {
    const challenge = String(1000000000000000000n + BigInt(Date.now() % 100000) + BigInt(i));
    const input = buildCircuitInput({ posture, policy, challenge });

    const t0 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath,
      undefined,
      { singleThread: true },
      { singleThread: true }
    );
    const t1 = process.hrtime.bigint();

    const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const t2 = process.hrtime.bigint();

    proveMs.push(Number(t1 - t0) / 1e6);
    verifyMs.push(Number(t2 - t1) / 1e6);
    proofBytes = Buffer.byteLength(JSON.stringify(proof));
    if (!valid) allValid = false;
  }

  const info = execFileSync(
    path.join(ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'snarkjs.cmd' : 'snarkjs'),
    ['r1cs', 'info', path.join(ROOT, 'circuits', 'build', 'posture.r1cs')],
    { encoding: 'utf8' }
  );
  const constraints = Number((info.match(/# of Constraints:\s*(\d+)/) || [])[1]);
  const wires = Number((info.match(/# of Wires:\s*(\d+)/) || [])[1]);

  const prove = stdev(proveMs);
  const verify = stdev(verifyMs);

  console.log('');
  console.log(`Measurements, N = ${N}, all proofs valid: ${allValid}`);
  console.log('='.repeat(64));
  console.log('Proof generation (ms):', proveMs.map((v) => v.toFixed(1)).join(', '));
  console.log('Verification (ms):    ', verifyMs.map((v) => v.toFixed(2)).join(', '));
  console.log('');
  console.log('WORKING - proof generation mean');
  console.log('  sum =', proveMs.map((v) => v.toFixed(1)).join(' + '));
  console.log('      =', proveMs.reduce((a, b) => a + b, 0).toFixed(1), 'ms');
  console.log('  mean = sum / N =', proveMs.reduce((a, b) => a + b, 0).toFixed(1), '/', N, '=', prove.m.toFixed(1), 'ms');
  console.log('');
  console.log('WORKING - sample standard deviation (spread)');
  console.log('  deviations squared:', prove.squared.map((v) => v.toFixed(1)).join(', '));
  console.log('  sum of squared deviations =', prove.squared.reduce((a, b) => a + b, 0).toFixed(1));
  console.log('  variance = sum / (N-1) =', prove.squared.reduce((a, b) => a + b, 0).toFixed(1), '/', N - 1, '=', prove.variance.toFixed(1));
  console.log('  stddev = sqrt(variance) =', prove.stdev.toFixed(1), 'ms');
  console.log('  range =', Math.min(...proveMs).toFixed(1), 'to', Math.max(...proveMs).toFixed(1), 'ms');
  console.log('');
  console.log('Verification: mean =', verify.m.toFixed(2), 'ms, stddev =', verify.stdev.toFixed(2), 'ms');
  console.log('Proof JSON size:', proofBytes, 'bytes');
  console.log('Constraint count:', constraints, '| wires:', wires);
  console.log('Artifact sizes (bytes):', JSON.stringify(sizes()));
  console.log('');

  if (!allValid) process.exitCode = 1;
}

main().catch((err) => {
  console.error('Measurement failed:', err.message);
  process.exitCode = 1;
});
