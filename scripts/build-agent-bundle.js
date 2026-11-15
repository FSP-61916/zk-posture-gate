'use strict';
// ---------------------------------------------------------------------------
// scripts/build-agent-bundle.js
//
// Builds a folder that can be copied to a laptop by USB. The laptop needs
// Node.js and the pinned snarkjs package - it does NOT need the circom compiler.
//
//   node scripts/build-agent-bundle.js                    (needs internet once)
//   node scripts/build-agent-bundle.js --with-node-modules (fully offline copy)
//
// Output: bundle/agent-bundle/
//   agent/            agent code (no data/ folder, no private keys)
//   shared/           canonical JSON used by both sides
//   circuits/build/   posture.wasm + posture_final.zkey (needed to prove)
//   package.json      exact pinned versions
//   package-lock.json generated with npm (when internet is available)
//   README.txt        what to run on the laptop
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'bundle', 'agent-bundle');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const withNodeModules = process.argv.includes('--with-node-modules');

const wasm = path.join(ROOT, 'circuits', 'build', 'posture_js', 'posture.wasm');
const zkey = path.join(ROOT, 'circuits', 'build', 'posture_final.zkey');

if (!fs.existsSync(wasm) || !fs.existsSync(zkey)) {
  console.error('Circuit artifacts missing. Run "npm run setup:circuit" first.');
  process.exitCode = 1;
  // Top-level return in a CommonJS module: stop here, let the process exit on
  // its own instead of calling process.exit() while handles are closing.
  return;
}

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

// 1. code
fs.cpSync(path.join(ROOT, 'agent'), path.join(OUT, 'agent'), {
  recursive: true,
  filter: (src) => {
    const rel = path.relative(path.join(ROOT, 'agent'), src);
    return !rel.startsWith('data' + path.sep) && rel !== 'data';
  },
});
fs.cpSync(path.join(ROOT, 'shared'), path.join(OUT, 'shared'), { recursive: true });

// 2. proving artifacts, same relative layout the agent expects
fs.mkdirSync(path.join(OUT, 'circuits', 'build', 'posture_js'), { recursive: true });
fs.copyFileSync(wasm, path.join(OUT, 'circuits', 'build', 'posture_js', 'posture.wasm'));
fs.copyFileSync(zkey, path.join(OUT, 'circuits', 'build', 'posture_final.zkey'));

// 3. package.json with pinned versions only
const bundlePkg = {
  name: 'zk-posture-gate-agent',
  version: pkg.version,
  private: true,
  description: 'ZK Posture Gate agent - runs on the laptop, proves locally',
  scripts: {
    enroll: 'node agent/index.js enroll',
    check: 'node agent/index.js check',
    attest: 'node agent/index.js attest',
    ui: 'node agent/local-ui.js',
  },
  dependencies: { snarkjs: pkg.dependencies.snarkjs },
};
fs.writeFileSync(path.join(OUT, 'package.json'), JSON.stringify(bundlePkg, null, 2) + '\n');

// 4. lockfile so the laptop can use `npm ci` (best effort: needs network)
try {
  execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: OUT,
    stdio: 'ignore',
  });
  console.log('Generated package-lock.json');
} catch {
  console.warn('Could not generate package-lock.json (offline). Use --with-node-modules instead.');
}

// 5. optional fully-offline node_modules
if (withNodeModules) {
  console.log('Copying node_modules (this takes a moment)...');
  fs.cpSync(path.join(ROOT, 'node_modules'), path.join(OUT, 'node_modules'), { recursive: true });
}

// 6. instructions
fs.writeFileSync(
  path.join(OUT, 'README.txt'),
  [
    'ZK Posture Gate - agent bundle',
    '',
    'What this is',
    '  Everything a Windows laptop needs to prove its posture in zero knowledge.',
    '  The laptop does NOT need the circom compiler. It does need Node.js 20+.',
    '',
    'Setup on the laptop',
    '  1. Copy this folder anywhere, e.g. C:\\zk-posture-gate',
    '  2. Open PowerShell in that folder',
    '  3. Install the exact pinned dependency:',
    '       npm ci',
    '     (offline bundle: node_modules is already included, skip this step)',
    '  4. Point at the main computer (no secrets in this file):',
    '       $env:VERIFIER_URL = "https://<MAIN-PC-IP>:3000"',
    '     or edit agent\\agent.config.json',
    '',
    '  5. Copy the CA pin printed by the verifier at startup (one time):',
    '       $env:ZKPG_CA_FINGERPRINT = "AA:BB:..."',
    '     or set "tlsCaFingerprint" in agent\\agent.config.json.',
    '     The agent refuses TLS without it; there is no fallback to the',
    '     system trust store. DEMO_INSECURE=1 is the only way to use HTTP.',
    '',
    'Use it',
    '  node agent enroll --code ABCD-EFGH --label "Laptop A"',
    '  node agent check',
    '  node agent attest --open',
    '  node agent attest --interval     (repeat every 5 minutes; 1 for rehearsal)',
    '  node agent\\local-ui.js      (optional local page on 127.0.0.1:4000)',
    '',
    'Privacy',
    '  Posture values are read on this machine, used as private circuit inputs,',
    '  and never written to disk or sent over the network. Only the proof and',
    '  seven public signals are submitted.',
    '',
    `snarkjs pinned version: ${pkg.dependencies.snarkjs}`,
    `bundle built: ${new Date().toISOString()}`,
    '',
  ].join('\n')
);

const bytes = (file) => (fs.statSync(file).size / 1024 / 1024).toFixed(2) + ' MB';
console.log('');
console.log('Bundle ready:', OUT);
console.log('  posture.wasm:', bytes(path.join(OUT, 'circuits', 'build', 'posture_js', 'posture.wasm')));
console.log('  posture_final.zkey:', bytes(path.join(OUT, 'circuits', 'build', 'posture_final.zkey')));
console.log('  node_modules included:', withNodeModules ? 'yes' : 'no (run npm ci on the laptop)');
