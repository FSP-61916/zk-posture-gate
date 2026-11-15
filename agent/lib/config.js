'use strict';
// ---------------------------------------------------------------------------
// agent/lib/config.js
//
// Where the agent looks for things. No secrets live in agent.config.json.
// Precedence: environment variable, then agent/agent.config.json, then default.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const AGENT_DIR = path.join(ROOT, 'agent');
const CONFIG_FILE = path.join(AGENT_DIR, 'agent.config.json');

function readConfigFile() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {}; // missing or unreadable config is fine, defaults are used
  }
}

function loadAgentConfig() {
  const file = readConfigFile();

  // VERIFIER_URL wins over the file so the same USB bundle can be pointed at
  // any main computer without editing files.
  const verifierUrl =
    process.env.VERIFIER_URL ||
    (typeof file.verifierUrl === 'string' && file.verifierUrl) ||
    'http://127.0.0.1:3000';

  // AGENT_DATA_DIR lets a second identity live on the same laptop (demo only).
  // ZKPG_AGENT_DATA_DIR is kept as an alias so existing instructions still work.
  const dataDir =
    process.env.AGENT_DATA_DIR || process.env.ZKPG_AGENT_DATA_DIR || path.join(AGENT_DIR, 'data');

  // One-time pin of the verifier's CA public key (SPKI SHA-256, hex). Colons
  // and spaces are accepted so a copied fingerprint works as-is. This is the
  // only TLS setting a laptop needs; leaf renewals do not change it.
  const tlsCaFingerprint =
    process.env.ZKPG_CA_FINGERPRINT ||
    (typeof file.tlsCaFingerprint === 'string' ? file.tlsCaFingerprint : '');

  // DEMO_INSECURE=1 is the only way to skip TLS verification. It must be set
  // deliberately on both the verifier (plain HTTP) and the agent.
  const insecureTls = process.env.DEMO_INSECURE === '1';

  return {
    root: ROOT,
    dataDir,
    // identity + local state (git-ignored)
    keyFile: path.join(dataDir, 'device.key'),
    stateFile: path.join(dataDir, 'state.json'),
    // circuit artifacts produced by `npm run setup:circuit`
    wasmPath: process.env.ZKPG_WASM || path.join(ROOT, 'circuits', 'build', 'posture_js', 'posture.wasm'),
    zkeyPath: process.env.ZKPG_ZKEY || path.join(ROOT, 'circuits', 'build', 'posture_final.zkey'),
    verifierUrl: verifierUrl.replace(/\/+$/, ''),
    // Optional full gate origin, e.g. https://gate.corp.example or
    // http://main-pc:8081. When empty the gate is assumed to be on the same
    // host as the verifier, on the port the verifier reports.
    gateUrl: process.env.GATE_URL || (typeof file.gateUrl === 'string' ? file.gateUrl : ''),
    tlsCaFingerprint: tlsCaFingerprint.trim(),
    insecureTls,
    uiPort: Number(process.env.AGENT_UI_PORT || 4000),
    requestTimeoutMs: 20000,
  };
}

module.exports = { loadAgentConfig };
