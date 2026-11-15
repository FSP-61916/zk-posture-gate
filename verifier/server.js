'use strict';
// ---------------------------------------------------------------------------
// verifier/server.js
//
// The verifier. Express serves the API and the dashboard; the reverse proxy
// gate (verifier/lib/gate.js) serves the real internal app on GATE_PORT.
//
// POST /api/attest checks, in this exact order, stopping at the first failure:
//   1. input validation          -> BAD_REQUEST            (HTTP 400)
//   2. device signature (ed25519)-> BAD_SIGNATURE
//   3. policy match              -> POLICY_MISMATCH
//   4. challenge unused/unexpired-> REPLAY / EXPIRED / CHALLENGE_DEVICE_MISMATCH
//   5. Groth16 proof             -> PROOF_INVALID
//   6. compliant == 1            -> NON_COMPLIANT
// On success: a signed gate token (10 minutes by default), and one line in the
// hash-chained log.
//
// The verifier NEVER receives posture values. The request schema is strict and
// only proof + the seven public signals are accepted (see lib/validate.js).
// ---------------------------------------------------------------------------

const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const os = require('node:os');

const { loadConfig, loadSigningKey } = require('./lib/config');
const { createGate } = require('./lib/gate');
const { ensureTls, formatFingerprint } = require('./lib/tls');
const { PolicyStore, validatePolicyFields } = require('./lib/policy');
const { DecisionLog } = require('./lib/log');
const { ChallengeStore } = require('./lib/challenges');
const { SignedTokenService } = require('./lib/tokens');
const { AdminAuth } = require('./lib/session');
const { RateLimiter } = require('./lib/ratelimit');
const { ProofVerifier } = require('./lib/verify-proof');
const { DeviceStore, EnrollmentStore } = require('./lib/devices');
const { KevAdvisory, windowSince } = require('./lib/kev');
const { validateAttestBody, validateEnrollBody, validateChallengeBody } = require('./lib/validate');
const { IDX, expectedPublicSignals, expectedChallengeSq } = require('./lib/public-signals');
const { attestMessage } = require('../shared/canonical');

// Plain-language microcopy. Never reveals WHICH value failed.
const REASON_COPY = {
  POLICY_MISMATCH: 'Device used an outdated policy',
  REPLAY: 'This proof was already used',
  EXPIRED: 'Challenge expired, please retry',
  PROOF_INVALID: 'Proof could not be verified',
  BAD_SIGNATURE: 'Device identity could not be verified',
  NON_COMPLIANT: 'Device does not meet policy',
  BAD_REQUEST: 'Request was malformed',
  CHALLENGE_DEVICE_MISMATCH: 'Challenge was issued to a different device',
  RATE_LIMITED: 'Too many attempts, please wait a moment',
};

function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
      "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
  );
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
}

function publicKeyFromSpki(b64) {
  return crypto.createPublicKey({
    key: Buffer.from(b64, 'base64'),
    format: 'der',
    type: 'spki',
  });
}

function signatureIsValid(device, message, signature) {
  if (!device) return false;
  try {
    const key = publicKeyFromSpki(device.publicKey);
    const sig = Buffer.from(String(signature), 'base64url');
    if (sig.length !== 64) return false;
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, sig);
  } catch {
    return false;
  }
}

function computeStats(records, deviceCount, policy, now) {
  const today = new Date(now).toISOString().slice(0, 10);
  const todayRecords = records.filter((r) => String(r.timestamp).startsWith(today));
  const grantedToday = todayRecords.filter((r) => r.result === 'GRANTED').length;
  const deniedToday = todayRecords.filter((r) => r.result === 'DENIED').length;
  const grantedAll = records.filter((r) => r.result === 'GRANTED').length;
  const compliancePct =
    records.length === 0 ? null : Math.round((grantedAll / records.length) * 1000) / 10;

  const denialsByReason = {};
  for (const r of records) {
    if (r.result !== 'DENIED' || !r.reasonCode) continue;
    denialsByReason[r.reasonCode] = (denialsByReason[r.reasonCode] || 0) + 1;
  }

  return {
    compliancePct,
    grantedToday,
    deniedToday,
    totalDecisions: records.length,
    devicesSeen: new Set(records.map((r) => r.deviceId)).size,
    enrolledDevices: deviceCount,
    policyVersion: policy.version,
    postureValuesStored: 0, // and this is not a slogan: there is no field for them
    denialsByReason,
    lastDecisionAt: records.length ? records[records.length - 1].timestamp : null,
    updatedAt: new Date(now).toISOString(),
  };
}

function createApp({ config, fetchImpl = fetch }) {
  const signingKey = loadSigningKey(config.tokenKeyFile);
  const tokens = new SignedTokenService(signingKey, { now: config.now });
  const adminAuth = new AdminAuth(tokens, {
    adminPassword: config.adminPassword,
    ttlSeconds: config.sessionTtlSeconds,
    now: config.now,
  });

  const policy = new PolicyStore(config.policyFile, { now: config.now });
  const log = new DecisionLog(config.logFile, { now: config.now });
  const challenges = new ChallengeStore({ ttlSeconds: config.challengeTtlSeconds, now: config.now });
  const devices = new DeviceStore(config.devicesFile, { now: config.now });
  const enrollment = new EnrollmentStore(config.enrollmentFile, {
    ttlSeconds: config.enrollCodeTtlSeconds,
    now: config.now,
  });
  const proofs = new ProofVerifier(config.vkPath);
  const attestLimiter = new RateLimiter({
    limit: config.attestRateLimitPerMinute,
    windowMs: 60000,
    now: config.now,
  });
  const enrollLimiter = new RateLimiter({ limit: 10, windowMs: 60000, now: config.now });
  const loginLimiter = new RateLimiter({ limit: 10, windowMs: 60000, now: config.now });
  const kev = new KevAdvisory({
    cacheFile: config.kevCacheFile,
    url: config.kevUrl,
    fetchImpl,
    now: config.now,
  });

  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(express.json({ limit: '256kb' }));
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  // -------------------------------------------------------------------------
  // public API
  // -------------------------------------------------------------------------

  app.get('/api/health', (req, res) => {
    res.json({
      ok: true,
      service: 'zk-posture-gate-verifier',
      policyVersion: policy.get().version,
      demoLan: config.demoLan,
      tlsEnabled: config.tlsEnabled,
      host: config.host,
      lanIps: lanIps(),
      postureValuesStored: 0,
      now: new Date(config.now()).toISOString(),
    });
  });

  app.get('/api/policy', (req, res) => {
    res.json(policy.get());
  });

  app.post('/api/challenge', (req, res) => {
    const check = validateChallengeBody(req.body);
    if (!check.ok) return res.status(400).json({ error: check.error, code: 'BAD_REQUEST' });
    if (!devices.find(req.body.deviceId)) {
      return res.status(403).json({ error: 'Unknown device', code: 'BAD_SIGNATURE' });
    }
    const issued = challenges.issue(req.body.deviceId);
    res.json({
      challenge: issued.challenge,
      expiresAt: issued.expiresAt,
      ttlSeconds: config.challengeTtlSeconds,
      policyVersion: policy.get().version,
    });
  });

  app.post('/api/enroll', (req, res) => {
    const limit = enrollLimiter.check(req.ip);
    if (!limit.ok) {
      return res.status(429).json({ error: 'Too many attempts', code: 'RATE_LIMITED' });
    }
    const check = validateEnrollBody(req.body);
    if (!check.ok) return res.status(400).json({ error: check.error, code: 'BAD_REQUEST' });

    if (devices.find(req.body.deviceId)) {
      return res.status(409).json({ error: 'Device already enrolled', code: 'ALREADY_ENROLLED' });
    }

    // Public key must parse, and the deviceId must be derived from it, so one
    // laptop cannot enroll another laptop's id.
    let deviceIdFromKey;
    try {
      const key = publicKeyFromSpki(req.body.publicKey);
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('not ed25519');
      const spki = key.export({ type: 'spki', format: 'der' });
      deviceIdFromKey =
        'dev_' + crypto.createHash('sha256').update(spki).digest('hex').slice(0, 24);
    } catch {
      return res.status(400).json({ error: 'publicKey is not an ed25519 SPKI key', code: 'BAD_REQUEST' });
    }
    if (deviceIdFromKey !== req.body.deviceId) {
      return res.status(400).json({ error: 'deviceId does not match the public key', code: 'BAD_REQUEST' });
    }

    const redeemed = enrollment.redeem(req.body.code);
    if (!redeemed.ok) {
      return res.status(403).json({ error: 'Enrollment code is not valid', code: redeemed.reason });
    }

    const device = devices.add({
      deviceId: req.body.deviceId,
      publicKey: req.body.publicKey,
      label: req.body.label,
    });
    res.status(201).json({
      deviceId: device.deviceId,
      enrolledAt: device.enrolledAt,
      label: device.label,
    });
  });

  // -------------------------------------------------------------------------
  // the gate
  // -------------------------------------------------------------------------

  app.post('/api/attest', async (req, res) => {
    const startedAt = config.now();
    const body = req.body;

    const record = ({ deviceId, policyVersion, result, reasonCode }) => {
      try {
        log.append({
          deviceId,
          policyVersion,
          result,
          reasonCode,
          latencyMs: config.now() - startedAt,
        });
      } catch (err) {
        console.error('[log] could not append decision:', err.message);
      }
      if (deviceId && devices.find(deviceId)) devices.touch(deviceId, result);
    };

    const deny = (deviceId, policyVersion, reasonCode, status = 200, extra = {}) => {
      record({ deviceId, policyVersion, result: 'DENIED', reasonCode });
      return res.status(status).json({
        decision: 'DENIED',
        reasonCode,
        message: REASON_COPY[reasonCode] || 'Denied',
        ...extra,
      });
    };

    const limit = attestLimiter.check(req.ip);
    if (!limit.ok) {
      res.setHeader('Retry-After', Math.ceil((limit.retryAfterMs || 1000) / 1000));
      return deny('unknown', 0, 'RATE_LIMITED', 429);
    }

    // --- 1. input validation ------------------------------------------------
    const validation = validateAttestBody(body);
    if (!validation.ok) {
      record({ deviceId: 'unknown', policyVersion: 0, result: 'DENIED', reasonCode: 'BAD_REQUEST' });
      return res.status(400).json({
        decision: 'DENIED',
        reasonCode: 'BAD_REQUEST',
        message: REASON_COPY.BAD_REQUEST,
        detail: validation.error,
      });
    }

    const currentPolicy = policy.get();

    // --- 2. device signature ------------------------------------------------
    const device = devices.find(body.deviceId);
    const message = attestMessage({
      deviceId: body.deviceId,
      challenge: body.challenge,
      policyVersion: body.policyVersion,
      publicSignals: body.publicSignals,
      proof: body.proof,
    });
    if (!signatureIsValid(device, message, body.signature)) {
      return deny(body.deviceId, body.policyVersion, 'BAD_SIGNATURE');
    }

    // --- 3. policy match on the public signals -----------------------------
    const expected = expectedPublicSignals({ policy: currentPolicy, challenge: body.challenge });
    let policyMismatch = body.policyVersion !== currentPolicy.version;
    for (let i = IDX.minBuild; i <= IDX.challenge; i++) {
      if (body.publicSignals[i] !== expected[i]) policyMismatch = true;
    }
    if (policyMismatch) {
      return deny(body.deviceId, body.policyVersion, 'POLICY_MISMATCH', 200, {
        currentPolicyVersion: currentPolicy.version,
      });
    }

    // --- 4. challenge: unused and unexpired --------------------------------
    const consumed = challenges.consume(body.challenge, body.deviceId);
    if (!consumed.ok) {
      return deny(body.deviceId, body.policyVersion, consumed.reason);
    }

    // --- 5. proof verification ---------------------------------------------
    const proofOk = await proofs.verify(body.publicSignals, body.proof);
    if (!proofOk) {
      return deny(body.deviceId, body.policyVersion, 'PROOF_INVALID');
    }
    // Belt and braces: the circuit binds the challenge, so a proof carrying a
    // different challengeSq must not be accepted.
    if (body.publicSignals[IDX.challengeSq] !== expectedChallengeSq(body.challenge)) {
      return deny(body.deviceId, body.policyVersion, 'PROOF_INVALID');
    }

    // --- 6. did the circuit say compliant? --------------------------------
    if (body.publicSignals[IDX.compliant] !== '1') {
      return deny(body.deviceId, body.policyVersion, 'NON_COMPLIANT');
    }

    // --- success -----------------------------------------------------------
    const exp = Math.floor(config.now() / 1000) + config.tokenTtlSeconds;
    const token = tokens.sign('gate', {
      sub: body.deviceId,
      pv: currentPolicy.version,
      exp,
      jti: crypto.randomBytes(8).toString('hex'),
    });
    record({ deviceId: body.deviceId, policyVersion: currentPolicy.version, result: 'GRANTED', reasonCode: null });

    return res.json({
      decision: 'GRANTED',
      reasonCode: null,
      policyVersion: currentPolicy.version,
      token,
      // The agent turns this into a full URL on the gate port. The verifier
      // does not trust a request Host header to decide where the gate lives.
      gatePath: `/?t=${token}`,
      gatePort: config.gatePort,
      gatePublicUrl: config.gatePublicUrl || null,
      expiresAt: new Date(exp * 1000).toISOString(),
      tokenTtlSeconds: config.tokenTtlSeconds,
    });
  });

  // -------------------------------------------------------------------------
  // admin session
  // -------------------------------------------------------------------------

  app.post('/api/admin/login', async (req, res) => {
    const limit = loginLimiter.check(req.ip);
    if (!limit.ok) return res.status(429).json({ error: 'Too many attempts', code: 'RATE_LIMITED' });
    const password = req.body && req.body.password;
    if (typeof password !== 'string' || password.length > 512) {
      return res.status(400).json({ error: 'password is required', code: 'BAD_REQUEST' });
    }
    const session = adminAuth.login(password);
    if (!session) {
      // Small constant delay slows password guessing without leaking anything.
      await new Promise((r) => setTimeout(r, 200));
      return res.status(401).json({ error: 'Incorrect password', code: 'UNAUTHORIZED' });
    }
    const secure = Boolean(req.socket.encrypted);
    adminAuth.setCookie(res, session.token, { secure });
    res.json({ ok: true, csrfToken: session.csrf, expiresAt: session.expiresAt });
  });

  app.post('/api/admin/logout', (req, res) => {
    adminAuth.clearCookie(res, { secure: Boolean(req.socket.encrypted) });
    res.json({ ok: true });
  });

  // Deliberately public: the dashboard uses this to decide between the login
  // card and the app. Answering 200 with authenticated:false keeps a fresh
  // visit free of scary 401s; every real admin endpoint still returns 401.
  app.get('/api/admin/me', (req, res) => {
    const session = adminAuth.sessionFrom(req);
    if (!session) return res.json({ ok: true, authenticated: false });
    res.json({
      ok: true,
      authenticated: true,
      csrfToken: session.csrf,
      expiresAt: new Date(session.exp * 1000).toISOString(),
      policyVersion: policy.get().version,
    });
  });

  // -------------------------------------------------------------------------
  // admin API (session + CSRF)
  // -------------------------------------------------------------------------

  const adminWrite = [adminAuth.requireAdmin.bind(adminAuth), adminAuth.requireCsrf.bind(adminAuth)];

  app.post('/api/admin/policy', adminWrite, (req, res) => {
    const errors = validatePolicyFields(req.body);
    if (errors.length) return res.status(400).json({ error: errors.join('; '), code: 'INVALID_POLICY' });
    try {
      const updated = policy.update(req.body);
      res.json({ ok: true, policy: updated });
    } catch (err) {
      res.status(400).json({ error: err.message, code: err.code || 'INVALID_POLICY' });
    }
  });

  app.post('/api/admin/enrollment-code', adminWrite, (req, res) => {
    res.json({ ok: true, ...enrollment.issue() });
  });

  // A code is only "active" while it is unused and unexpired. The store
  // computes the state (see EnrollmentStore.listWithState) so the dashboard
  // can never present a spent or stale code as usable.
  app.get('/api/admin/enrollment-codes', adminAuth.requireAdmin.bind(adminAuth), (req, res) => {
    res.json({ codes: enrollment.listWithState() });
  });

  app.get('/api/devices', adminAuth.requireAdmin.bind(adminAuth), (req, res) => {
    // Auditing every attestation is intentional: the count per device is the
    // visible proof that scheduled check-ins are landing, not a hidden cost.
    const counts = new Map();
    for (const r of log.records()) {
      if (r.__malformed || !r.deviceId) continue;
      const c = counts.get(r.deviceId) || { total: 0, granted: 0, denied: 0 };
      c.total += 1;
      if (r.result === 'GRANTED') c.granted += 1;
      else if (r.result === 'DENIED') c.denied += 1;
      counts.set(r.deviceId, c);
    }
    res.json({
      devices: devices.list().map((d) => ({
        deviceId: d.deviceId,
        label: d.label,
        enrolledAt: d.enrolledAt,
        lastSeen: d.lastSeen,
        lastResult: d.lastResult,
        records: counts.get(d.deviceId) || { total: 0, granted: 0, denied: 0 },
        keyFingerprint: crypto
          .createHash('sha256')
          .update(Buffer.from(d.publicKey, 'base64'))
          .digest('hex')
          .slice(0, 16),
      })),
    });
  });

  app.get('/api/decisions', adminAuth.requireAdmin.bind(adminAuth), (req, res) => {
    const all = log.records().filter((r) => !r.__malformed).reverse();

    const { result, reason, from, to } = req.query;
    const filtered = all.filter((r) => {
      if (result && r.result !== result) return false;
      if (reason && r.reasonCode !== reason) return false;
      if (from && String(r.timestamp).slice(0, 10) < String(from)) return false;
      if (to && String(r.timestamp).slice(0, 10) > String(to)) return false;
      return true;
    });

    const pageSizeRaw = Number(req.query.pageSize || 25);
    const pageSize = Math.min(Math.max(Number.isFinite(pageSizeRaw) ? pageSizeRaw : 25, 1), 100);
    const pageRaw = Number(req.query.page || 1);
    const page = Math.max(Number.isFinite(pageRaw) ? Math.floor(pageRaw) : 1, 1);
    const start = (page - 1) * pageSize;

    res.json({
      total: filtered.length,
      page,
      pageSize,
      records: filtered.slice(start, start + pageSize),
    });
  });

  app.get('/api/stats', adminAuth.requireAdmin.bind(adminAuth), (req, res) => {
    const records = log.records().filter((r) => !r.__malformed);
    res.json(computeStats(records, devices.list().length, policy.get(), config.now()));
  });

  app.get('/api/log/verify', adminAuth.requireAdmin.bind(adminAuth), (req, res) => {
    res.json(log.verify());
  });

  app.get('/api/advisory', adminAuth.requireAdmin.bind(adminAuth), async (req, res) => {
    // window=policy (default, since the policy last changed) | 30d | 90d.
    const requested = req.query.window;
    const window = requested === '30d' || requested === '90d' ? requested : 'policy';
    const sinceIso = windowSince(window, policy.get().updatedAt, config.now());
    try {
      const advisory = await kev.advisory({ sinceIso });
      res.json({ ...advisory, window });
    } catch (err) {
      res.status(503).json({ error: err.message, code: 'KEV_UNAVAILABLE' });
    }
  });

  // -------------------------------------------------------------------------
  // static dashboard + errors
  // -------------------------------------------------------------------------

  app.use(express.static(config.dashboardDir, { index: 'index.html' }));

  app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Not found', code: 'NOT_FOUND' });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request body too large', code: 'TOO_LARGE' });
    }
    if (err && (err.status === 400 || err instanceof SyntaxError)) {
      return res.status(400).json({ error: 'Invalid JSON body', code: 'BAD_REQUEST' });
    }
    // Never send stack traces to clients.
    console.error('[error]', err && err.message ? err.message : err);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  });

  return {
    app,
    gate: createGate({ config, tokens }),
    services: { policy, log, challenges, devices, enrollment, kev, proofs },
  };
}

function lanIps() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const entry of list || []) {
      if (entry.family === 'IPv4' && !entry.internal) out.push(entry.address);
    }
  }
  return out;
}

function start() {
  const config = loadConfig();
  const { app, gate } = createApp({ config });

  // TLS is the default. The local CA lives in the git-ignored data folder; only
  // fingerprints are printed, never key material.
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

  server.on('listening', () => {
    const urls =
      config.host === '0.0.0.0'
        ? [
            `${scheme}://127.0.0.1:${config.port}`,
            ...lanIps().map((ip) => `${scheme}://${ip}:${config.port}`),
          ]
        : [`${scheme}://127.0.0.1:${config.port}`];

    console.log('');
    console.log('  ZK Posture Gate - verifier + dashboard');
    console.log('  --------------------------------------');
    console.log(`  listening on ${config.host}:${config.port}`);
    for (const url of urls) console.log(`  dashboard: ${url}`);
    console.log(`  policy version: ${JSON.parse(fs.readFileSync(config.policyFile, 'utf8')).version}`);
    console.log(`  decision log: ${config.logFile}`);
    if (tls) {
      console.log(`  TLS: ${tls.custom ? 'certificate from TLS_CERT_PATH' : 'local CA (data/tls)'}`);
      console.log(`  leaf SHA-256: ${formatFingerprint(tls.leafSha256)}`);
      if (tls.caSpkiSha256) {
        console.log(`  CA pin (SPKI SHA-256): ${formatFingerprint(tls.caSpkiSha256)}`);
        if (!tls.custom) {
          console.log('  trust it (Windows, current user): .\\scripts\\trust-ca.ps1');
        }
      } else {
        console.log('  CA pin: not available (custom cert did not include its issuer)');
      }
    } else {
      console.log('  DEMO_INSECURE=1: plain HTTP, no TLS. Do not use this on an untrusted network.');
    }
    console.log('');
  });
  server.listen(config.port, config.host);

  gateServer.on('error', (err) => {
    console.error(
      err.code === 'EADDRINUSE'
        ? `Cannot start the gate: port ${config.gatePort} is already in use.`
        : `Cannot start the gate: ${err.message}`
    );
    process.exitCode = 1;
    server.close();
  });

  gateServer.listen(config.gatePort, config.gateHost, () => {
    const gateUrls = config.gatePublicUrl
      ? [config.gatePublicUrl]
      : config.gateHost === '0.0.0.0'
        ? [
            `${scheme}://127.0.0.1:${config.gatePort}`,
            ...lanIps().map((ip) => `${scheme}://${ip}:${config.gatePort}`),
          ]
        : [`${scheme}://127.0.0.1:${config.gatePort}`];
    console.log(`  gate: ${gateUrls.join('  ')}`);
    console.log(`  gate forwards to: ${config.gateUpstreamUrl.origin}${config.gateUpstreamUrl.pathname}`);
    console.log(`  gate token lifetime: ${Math.round(config.tokenTtlSeconds / 60)} min`);
    console.log('');
  });

  // Close both listeners and destroy open sockets, then let the loop drain.
  // No process.exit() while handles are closing: that is the Node 24 Windows
  // libuv assertion (src\win\async.c). The shell still gets exit code 0.
  const shutdown = () => {
    process.exitCode = 0;
    server.close();
    server.closeAllConnections?.();
    gateServer.close();
    gateServer.closeAllConnections?.();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return server;
}

if (require.main === module) {
  try {
    start();
  } catch (err) {
    console.error('Cannot start verifier:', err.message);
    process.exitCode = 1;
  }
}

module.exports = { createApp, computeStats, REASON_COPY, lanIps };
