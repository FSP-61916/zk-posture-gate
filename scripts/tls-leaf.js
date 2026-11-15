#!/usr/bin/env node
'use strict';
// ---------------------------------------------------------------------------
// scripts/tls-leaf.js
//
// Regenerates ONLY the server certificate, keeping the CA and therefore every
// agent's CA pin. Run this after the machine's IP address or hostname changes;
// the verifier also does it automatically on startup when the SANs change.
//
//   node scripts/tls-leaf.js
// ---------------------------------------------------------------------------

const path = require('node:path');

const { regenerateLeaf, formatFingerprint } = require('../verifier/lib/tls');

try {
  const dataDir = process.env.ZKPG_DATA_DIR || path.resolve(__dirname, '..', 'verifier', 'data');
  const tls = regenerateLeaf({ dataDir });
  console.log('');
  console.log('  Replaced the leaf certificate. The CA is unchanged, so existing');
  console.log('  agents keep working without editing their pin.');
  console.log(`  leaf SHA-256:          ${formatFingerprint(tls.leafSha256)}`);
  console.log(`  CA pin (unchanged):    ${formatFingerprint(tls.caSpkiSha256)}`);
  console.log(`  SANs:                  ${tls.sans.map((s) => s.value).join(', ')}`);
  console.log('  Restart the verifier to serve the new leaf.');
  console.log('');
} catch (err) {
  console.error(`\n  ${err.message}\n`);
  process.exitCode = 1;
}
