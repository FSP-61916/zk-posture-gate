'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/config.js
//
// All configuration comes from environment variables (see .env.example).
// One exception, by design: if TOKEN_SIGNING_KEY is not set, a random key is
// generated once into verifier/data/token-signing.key (git-ignored, mode 600)
// so a demo machine keeps working across restarts without a committed secret.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..', '..');

function loadSigningKey(file) {
  const fromEnv = process.env.TOKEN_SIGNING_KEY;
  if (fromEnv && fromEnv.trim()) {
    if (fromEnv.trim().length < 32) {
      throw new Error('TOKEN_SIGNING_KEY must be at least 32 characters long');
    }
    return Buffer.from(fromEnv.trim(), 'utf8');
  }

  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  if (fs.existsSync(file)) return fs.readFileSync(file);

  const key = crypto.randomBytes(32);
  fs.writeFileSync(file, key, { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* Windows may ignore POSIX modes; the file is still per-user */
  }
  return key;
}

/**
 * The upstream is configuration only. It must never be taken from a request
 * header, query parameter or body, otherwise the gate becomes an open proxy.
 * Returns a URL with no credentials, query or fragment; a path prefix is allowed.
 */
function normalizeUpstream(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error(`GATE_UPSTREAM is not a valid URL: ${value}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('GATE_UPSTREAM must use http:// or https://');
  }
  if (!url.hostname) throw new Error('GATE_UPSTREAM must include a host name');
  if (url.username || url.password) {
    throw new Error('GATE_UPSTREAM must not contain credentials; use the environment for those');
  }
  if (url.search || url.hash) {
    throw new Error('GATE_UPSTREAM must not contain a query string or fragment');
  }
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

function loadConfig(overrides = {}) {
  const env = process.env;
  const dataDir = overrides.dataDir || env.ZKPG_DATA_DIR || path.join(ROOT, 'verifier', 'data');
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  const adminPassword =
    overrides.adminPassword !== undefined ? overrides.adminPassword : env.ADMIN_PASSWORD || '';

  const demoLan = overrides.demoLan !== undefined ? overrides.demoLan : env.DEMO_LAN === '1';

  const gatePublicUrl = overrides.gatePublicUrl ?? env.GATE_PUBLIC_URL ?? '';
  if (gatePublicUrl) {
    parsePublicUrl(gatePublicUrl);
  }

  // TLS is on by default with a local CA. DEMO_INSECURE=1 is the only switch
  // that turns it off (and the agent needs the same switch to speak HTTP).
  const tlsEnabled =
    overrides.tls !== undefined ? Boolean(overrides.tls) : env.DEMO_INSECURE !== '1';

  const config = {
    root: ROOT,
    dataDir,
    adminPassword,
    demoLan,
    tlsEnabled,
    tlsCertPath: overrides.tlsCertPath ?? env.TLS_CERT_PATH ?? '',
    tlsKeyPath: overrides.tlsKeyPath ?? env.TLS_KEY_PATH ?? '',
    host: overrides.host || (demoLan ? '0.0.0.0' : '127.0.0.1'),
    port: Number(overrides.port !== undefined ? overrides.port : env.PORT || 3000),
    // policy / challenge / token lifetimes
    enrollCodeTtlSeconds: Number(overrides.enrollCodeTtlSeconds ?? env.ENROLL_CODE_TTL ?? 600),
    challengeTtlSeconds: Number(overrides.challengeTtlSeconds ?? 60),
    // How long a gate token / browser session lasts. 10 minutes by default so
    // access does not lapse between 5-minute agent check-ins. See README
    // "Access does not end when compliance does" for the trade-off.
    tokenTtlSeconds: Number(
      overrides.tokenTtlSeconds ?? env.GATE_TOKEN_TTL_SECONDS ?? 600
    ),
    sessionTtlSeconds: Number(overrides.sessionTtlSeconds ?? env.SESSION_TTL_SECONDS ?? 8 * 3600),
    // Reverse proxy gate: browser traffic enters gatePort and is forwarded to
    // gateUpstream. The upstream comes from configuration, never a request.
    gateUpstream: overrides.gateUpstream ?? env.GATE_UPSTREAM ?? 'http://127.0.0.1:8080',
    gatePort: Number(overrides.gatePort ?? env.GATE_PORT ?? 8081),
    gateHost: overrides.gateHost || (demoLan ? '0.0.0.0' : '127.0.0.1'),
    gatePublicUrl, // optional, e.g. https://gate.corp.example; used in printed links
    // abuse control on /api/attest
    attestRateLimitPerMinute: Number(overrides.attestRateLimitPerMinute ?? 30),
    // circuit artifacts
    vkPath: overrides.vkPath || env.ZKPG_VK || path.join(ROOT, 'circuits', 'build', 'verification_key.json'),
    dashboardDir: path.join(ROOT, 'dashboard'),
    // threat-intel
    kevUrl:
      env.KEV_URL ||
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    kevCacheFile: path.join(dataDir, 'kev-cache.json'),
    // secrets
    tokenKeyFile: path.join(dataDir, 'token-signing.key'),
    // files
    policyFile: path.join(dataDir, 'policy.json'),
    devicesFile: path.join(dataDir, 'devices.json'),
    enrollmentFile: path.join(dataDir, 'enrollment-codes.json'),
    logFile: path.join(dataDir, 'decisions.jsonl'),
    // injectable clock so tests can simulate expiry
    now: overrides.now || (() => Date.now()),
  };

  if (!config.adminPassword) {
    throw new Error(
      'ADMIN_PASSWORD is not set. Set it in the environment before starting the verifier (see .env.example).'
    );
  }
  if (config.adminPassword.length < 12) {
    throw new Error('ADMIN_PASSWORD must be at least 12 characters long');
  }
  if (Boolean(config.tlsCertPath) !== Boolean(config.tlsKeyPath)) {
    throw new Error('Set both TLS_CERT_PATH and TLS_KEY_PATH, or neither.');
  }

  config.gateUpstreamUrl = normalizeUpstream(config.gateUpstream);

  return config;
}

/** Public-facing gate origin used only to print links; not trusted for routing. */
function parsePublicUrl(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error(`GATE_PUBLIC_URL is not a valid URL: ${value}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('GATE_PUBLIC_URL must use http:// or https://');
  }
  return url;
}

module.exports = { loadConfig, loadSigningKey, normalizeUpstream, ROOT };
