#!/usr/bin/env node
'use strict';
// ---------------------------------------------------------------------------
// scripts/set-agent-pin.js        (npm run pin)
//
// SINGLE-LAPTOP CONVENIENCE. Creates the local CA if it does not exist yet,
// then copies the CA's public-key fingerprint (SPKI SHA-256) into
// agent/agent.config.json as "tlsCaFingerprint", so you do not have to copy it
// by hand. Only the fingerprint is written. No private key is read or printed.
//
// For a different laptop, copy the pin by hand (or set ZKPG_CA_FINGERPRINT);
// that is the point of pinning: each laptop is told once which CA to trust.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');

const { ensureTls, formatFingerprint } = require('../verifier/lib/tls');

try {
  const dataDir = process.env.ZKPG_DATA_DIR || path.resolve(__dirname, '..', 'verifier', 'data');
  const tls = ensureTls({
    dataDir,
    certPath: process.env.TLS_CERT_PATH || '',
    keyPath: process.env.TLS_KEY_PATH || '',
  });
  if (!tls.caSpkiSha256) {
    throw new Error('No issuing CA found, so there is no CA pin to write.');
  }

  const configPath = path.resolve(__dirname, '..', 'agent', 'agent.config.json');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  config.tlsCaFingerprint = tls.caSpkiSha256;
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  console.log('');
  console.log('  CA pin written to agent/agent.config.json');
  console.log(`  ${formatFingerprint(tls.caSpkiSha256)}`);
  console.log('');
  console.log('  Next (once): .\\scripts\\trust-ca.ps1   so the browser trusts the demo certificate.');
  console.log('');
} catch (err) {
  console.error(`\n  ${err.message}\n`);
  process.exitCode = 1;
}
