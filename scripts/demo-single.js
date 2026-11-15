'use strict';
// ---------------------------------------------------------------------------
// scripts/demo-single.js
//
// SINGLE-LAPTOP MODE.
// Starts the verifier + dashboard on 127.0.0.1 only (never the LAN), issues one
// enrollment code, and prints the exact agent commands to run in a second
// terminal on the same machine.
//
// Multi-device mode is still available (DEMO_LAN=1 + the firewall script), but
// it is optional and not used here.
//
// This script itself never reads posture. `node agent attest` does, and it only
// works on Windows. On other platforms the dashboard still runs so the UI can
// be reviewed, and attestation refuses instead of inventing values.
// ---------------------------------------------------------------------------

const http = require('node:http');
const https = require('node:https');

const { loadConfig } = require('../verifier/lib/config');
const { createApp } = require('../verifier/server');
const { ensureTls, formatFingerprint } = require('../verifier/lib/tls');

// No process.exit() anywhere in this script: the server is closed and its
// sockets are destroyed, then the loop drains and the shell gets the code.
function fail(message) {
  const err = new Error(message);
  err.userFacing = true;
  throw err;
}

function main() {
  // demoLan:false forces the loopback binding even if DEMO_LAN=1 is set.
  const config = loadConfig({
    demoLan: false,
    host: '127.0.0.1',
    port: Number(process.env.PORT || 3000),
  });

  const { app, gate, services } = createApp({ config });
  const tls = config.tlsEnabled
    ? ensureTls({ dataDir: config.dataDir, certPath: config.tlsCertPath, keyPath: config.tlsKeyPath })
    : null;
  const scheme = tls ? 'https' : 'http';
  const server = tls
    ? https.createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, app)
    : http.createServer(app);
  const gateServer = tls
    ? https.createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, gate)
    : http.createServer(gate);
  server.listen(config.port, '127.0.0.1');

  server.on('error', (err) => {
    const message =
      err.code === 'EADDRINUSE'
        ? `Port ${config.port} is already in use. Stop the other verifier, or set $env:PORT to a free port.`
        : `Could not start the verifier: ${err.message}`;
    console.error(`\n  ${message}\n`);
    process.exitCode = 1;
  });

  server.on('listening', () => {
    const url = `${scheme}://127.0.0.1:${config.port}`;
    const code = services.enrollment.issue();
    const policy = services.policy.get();
    const expires = new Date(code.expiresAt).toLocaleTimeString();

    console.log('');
    console.log('  ZK Posture Gate - SINGLE LAPTOP DEMO');
    console.log('  ====================================');
    console.log(`  verifier + dashboard: ${url}`);
    console.log(`  gate:                 ${scheme}://127.0.0.1:${config.gatePort}`);
    console.log(`  gate forwards to:     ${config.gateUpstreamUrl.href}`);
    console.log('  binding: 127.0.0.1 (this machine only, never the LAN)');
    console.log(`  policy: v${policy.version}  (build >= ${policy.minBuild}, updates <= ${policy.maxUpdateAge} days)`);
    console.log(`  access token lasts:  ${Math.round(config.tokenTtlSeconds / 60)} min`);
    if (tls) {
      console.log(`  TLS:                 local CA (data/tls), leaf ${formatFingerprint(tls.leafSha256).slice(0, 23)}...`);
      console.log(`  CA pin:              ${tls.caSpkiSha256 ? formatFingerprint(tls.caSpkiSha256) : 'not available'}`);
      console.log('  first run on Windows: .\\scripts\\trust-ca.ps1   (CurrentUser, no admin)');
    } else {
      console.log('  DEMO_INSECURE=1:     plain HTTP, no TLS');
    }
    console.log('');
    console.log('  Start the protected app first (second terminal):');
    console.log('    npm run app');
    console.log('    (or: cd internal-app ; python -m http.server 8080)');
    console.log('');
    console.log(`  one-time enrollment code: ${code.code}   (expires ${expires})`);
    console.log('');
    console.log('  In a SECOND terminal on this same laptop:');
    console.log('');
    console.log(`    node agent enroll --code ${code.code} --label "This laptop"`);
    console.log('    node agent attest --open');
    console.log('');
    console.log('  Then open the dashboard and sign in with $env:ADMIN_PASSWORD:');
    console.log(`    ${url}`);
    console.log('');
    console.log('  Optional second identity on the SAME machine (multi-device stays optional):');
    console.log('    $env:AGENT_DATA_DIR = "$PWD\\agent\\data-second"');
    console.log(`    node agent enroll --code <new code> --label "same machine, 2nd identity"`);
    console.log('    node agent attest');
    console.log('');
    console.log('  Demo helpers (see docs/DEMO_SCRIPT.md):');
    console.log('    .\\scripts\\demo-policy.ps1 set-current   |  raise  |  reset');
    console.log('    .\\scripts\\demo-firewall.ps1 off-public  |  restore');
    console.log('    npm run demo:replay');
    console.log('');
    if (process.platform !== 'win32') {
      console.log('  NOTE: this machine is not Windows. The dashboard works, but');
      console.log('  "node agent attest" will refuse: posture is read for real, never invented.');
      console.log('');
    }
    console.log('  Ctrl+C to stop.');
    console.log('');
  });

  gateServer.on('error', (err) => {
    console.error(`\n  Could not start the gate on port ${config.gatePort}: ${err.message}\n`);
    process.exitCode = 1;
    server.close();
  });
  gateServer.listen(config.gatePort, '127.0.0.1');

  const shutdown = () => {
    process.exitCode = 0;
    server.close();
    server.closeAllConnections?.();
    gateServer.close();
    gateServer.closeAllConnections?.();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

try {
  main();
} catch (err) {
  console.error(`\n  ${err.userFacing ? err.message : `Could not start the demo: ${err.message}`}\n`);
  process.exitCode = 1;
}
