#!/usr/bin/env node
'use strict';
// ---------------------------------------------------------------------------
// scripts/tls-info.js
//
// Prints the gate certificate information a laptop needs, and creates the local
// CA/leaf if this is the first run. It never prints, writes or returns private
// keys; only fingerprints, SANs and file paths.
//
//   node scripts/tls-info.js
// ---------------------------------------------------------------------------

const path = require('node:path');

const { ensureTls, formatFingerprint } = require('../verifier/lib/tls');

function dataDir() {
  return process.env.ZKPG_DATA_DIR || path.resolve(__dirname, '..', 'verifier', 'data');
}

try {
  const tls = ensureTls({
    dataDir: dataDir(),
    certPath: process.env.TLS_CERT_PATH || '',
    keyPath: process.env.TLS_KEY_PATH || '',
  });
  console.log('');
  console.log('  ZK Posture Gate - TLS');
  console.log('  ---------------------');
  console.log(`  mode:                  ${tls.custom ? 'existing certificate (TLS_CERT_PATH)' : 'local CA'}`);
  console.log(`  certificate:           ${tls.certFile}`);
  console.log(`  private key:           ${tls.keyFile}  (not printed, mode 600)`);
  if (tls.caCertFile) console.log(`  issuing CA:            ${tls.caCertFile}`);
  console.log(`  leaf SHA-256:          ${formatFingerprint(tls.leafSha256)}`);
  if (tls.caSpkiSha256) {
    console.log(`  CA pin (SPKI SHA-256): ${formatFingerprint(tls.caSpkiSha256)}`);
    console.log('');
    console.log('  Put the CA pin in agent/agent.config.json on each laptop:');
    console.log(`    { "tlsCaFingerprint": "${tls.caSpkiSha256}" }`);
    console.log('  or set ZKPG_CA_FINGERPRINT. Colons and spaces are accepted.');
    if (!tls.custom) {
      console.log('');
      console.log('  Windows browser trust (CurrentUser, no admin):');
      console.log('    .\\scripts\\trust-ca.ps1');
    }
  } else {
    console.log('');
    console.log('  No issuing CA was found beside the custom certificate, so there is');
    console.log('  no CA pin to copy. Include the CA PEM after the leaf in TLS_CERT_PATH.');
  }
  if (tls.sans) console.log(`  SANs:                  ${tls.sans.map((s) => s.value).join(', ')}`);
  console.log('');
} catch (err) {
  console.error(`\n  ${err.message}\n`);
  process.exitCode = 1;
}
