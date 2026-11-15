'use strict';
// ---------------------------------------------------------------------------
// tests/verifier.test.js
//
// Each of the six gate checks is exercised with a REAL proof and a REAL
// signature, so a failure here means the gate is wrong, not the fixture.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  posture,
  startVerifier,
  agentConfig,
  jsonFetch,
  enroll,
  attestBody,
  resign,
  submit,
  cookieFrom,
} = require('./helpers');

test('compliant laptop: GRANTED, gate accepts the token and 401 without it', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  const res = await submit(ctx, body);
  assert.equal(res.status, 200);
  assert.equal(res.data.decision, 'GRANTED');
  assert.equal(res.data.reasonCode, null);
  assert.ok(res.data.token);

  // Any device, even with the right token, is separate from the app's own
  // auth; here we only prove the gate moved the token into a cookie.
  assert.equal(res.data.gatePort, ctx.config.gatePort);
  assert.match(res.data.gatePath, /^\/\?t=gate\./);

  const noToken = await fetch(ctx.gateBase + '/');
  assert.equal(noToken.status, 401);

  const redirect = await fetch(ctx.gateBase + res.data.gatePath, { redirect: 'manual' });
  assert.equal(redirect.status, 302);
  assert.equal(redirect.headers.get('location'), '/');
  const cookie = cookieFrom(redirect);
  assert.match(cookie, /^zkpg_gate=/);

  // No upstream is running in this helper, so a valid cookie must reach the
  // proxy and fail there with 502, not with the gate's 401.
  const proxied = await fetch(ctx.gateBase + '/', { headers: { cookie } });
  assert.equal(proxied.status, 502);

  const records = ctx.services.log.records();
  assert.equal(records.length, 1);
  assert.equal(records[0].result, 'GRANTED');
});

test('replaying the same proof is refused with REPLAY', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  assert.equal((await submit(ctx, body)).data.decision, 'GRANTED');
  const again = await submit(ctx, body);
  assert.equal(again.data.decision, 'DENIED');
  assert.equal(again.data.reasonCode, 'REPLAY');
});

test('challenge expires after 60 seconds of verifier time', async (t) => {
  let clock = Date.now();
  const ctx = await startVerifier({ now: () => clock });
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  clock += 61 * 1000;
  const res = await submit(ctx, body);
  assert.equal(res.data.decision, 'DENIED');
  assert.equal(res.data.reasonCode, 'EXPIRED');
});

test('a policy change invalidates proofs made for the old policy', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  ctx.services.policy.update({
    ...ctx.services.policy.get(),
    minBuild: 2263100000, // raised above the laptop's real build
  });

  const res = await submit(ctx, body);
  assert.equal(res.data.decision, 'DENIED');
  assert.equal(res.data.reasonCode, 'POLICY_MISMATCH');
  assert.equal(res.data.currentPolicyVersion, 2);
});

test('an outdated policyVersion field is POLICY_MISMATCH', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  body.policyVersion = 99;
  const res = await submit(ctx, resign(identity, body));
  assert.equal(res.data.reasonCode, 'POLICY_MISMATCH');
});

test('tampered policy signal is POLICY_MISMATCH', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  body.publicSignals[2] = '1'; // minBuild changed after signing
  const res = await submit(ctx, resign(identity, body));
  assert.equal(res.data.reasonCode, 'POLICY_MISMATCH');
});

test('bad device signature is BAD_SIGNATURE', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  const sig = Buffer.from(body.signature, 'base64url');
  sig[0] ^= 0xff;
  body.signature = sig.toString('base64url');

  const res = await submit(ctx, body);
  assert.equal(res.data.reasonCode, 'BAD_SIGNATURE');
});

test('unsigned device (unknown id) is BAD_SIGNATURE', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  body.deviceId = 'dev_' + 'a'.repeat(24);
  const res = await submit(ctx, resign(identity, body));
  assert.equal(res.data.reasonCode, 'BAD_SIGNATURE');
});

test('a device cannot borrow another device’s challenge', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agentA = agentConfig(ctx.base);
  const agentB = agentConfig(ctx.base);
  const idA = await enroll(ctx, agentA, 'Laptop A');
  const idB = await enroll(ctx, agentB, 'Laptop B');

  const { body } = await attestBody(ctx, agentA, idA, posture());
  // B signs A's challenge for its own id
  const stolen = { ...body, deviceId: idB.deviceId };
  const res = await submit(ctx, resign(idB, stolen));
  assert.equal(res.data.reasonCode, 'CHALLENGE_DEVICE_MISMATCH');
});

test('off-curve proof point is PROOF_INVALID', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  body.proof = { ...body.proof, pi_a: ['1', '3', '1'] }; // 3^2 != 1^3 + 3: not on the curve
  const res = await submit(ctx, resign(identity, body));
  assert.equal(res.data.decision, 'DENIED');
  assert.equal(res.data.reasonCode, 'PROOF_INVALID');
});

test('on-curve but wrong proof point is PROOF_INVALID', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  body.proof = { ...body.proof, pi_a: ['1', '2', '1'] }; // generator point, valid curve point
  const res = await submit(ctx, resign(identity, body));
  assert.equal(res.data.decision, 'DENIED');
  assert.equal(res.data.reasonCode, 'PROOF_INVALID');
});

test('a real proof of a non-compliant laptop is NON_COMPLIANT', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body, publicSignals } = await attestBody(
    ctx,
    agent,
    identity,
    posture({ defenderRealTime: false })
  );
  assert.equal(publicSignals[0], '0');

  const res = await submit(ctx, body);
  assert.equal(res.data.decision, 'DENIED');
  assert.equal(res.data.reasonCode, 'NON_COMPLIANT');
});

test('strict schema rejects extra fields with 400 BAD_REQUEST', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);
  const { body } = await attestBody(ctx, agent, identity, posture());

  const withExtra = { ...body, osBuild: 2263103803 };
  const res = await submit(ctx, resign(identity, withExtra));
  assert.equal(res.status, 400);
  assert.equal(res.data.reasonCode, 'BAD_REQUEST');
});

test('challenge is refused for an unknown device', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const res = await jsonFetch(ctx.base, '/api/challenge', {
    method: 'POST',
    body: { deviceId: 'dev_' + 'b'.repeat(24) },
  });
  assert.equal(res.status, 403);
});

test('enrollment code is single use', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());

  const { loadOrCreateIdentity } = require('../agent/lib/keys');
  const { code } = ctx.services.enrollment.issue();

  // First laptop redeems the code.
  const first = agentConfig(ctx.base);
  const identityA = loadOrCreateIdentity(first);
  const firstRes = await jsonFetch(ctx.base, '/api/enroll', {
    method: 'POST',
    body: {
      code,
      deviceId: identityA.deviceId,
      publicKey: identityA.publicKeySpkiB64,
      label: 'A',
    },
  });
  assert.equal(firstRes.status, 201);

  // Second laptop tries the same code.
  const second = agentConfig(ctx.base);
  const identityB = loadOrCreateIdentity(second);
  const res = await jsonFetch(ctx.base, '/api/enroll', {
    method: 'POST',
    body: {
      code,
      deviceId: identityB.deviceId,
      publicKey: identityB.publicKeySpkiB64,
      label: 'B',
    },
  });
  assert.equal(res.status, 403);
  assert.equal(res.data.code, 'CODE_USED');
});

test('enrollment rejects a deviceId that does not match the public key', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const { loadOrCreateIdentity } = require('../agent/lib/keys');
  const identity = loadOrCreateIdentity(agent);
  const { code } = ctx.services.enrollment.issue();

  const res = await jsonFetch(ctx.base, '/api/enroll', {
    method: 'POST',
    body: {
      code,
      deviceId: 'dev_' + 'c'.repeat(24),
      publicKey: identity.publicKeySpkiB64,
    },
  });
  assert.equal(res.status, 400);
});

test('admin: password, session cookie, CSRF and policy version bump', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());

  const bad = await jsonFetch(ctx.base, '/api/admin/login', {
    method: 'POST',
    body: { password: 'definitely-wrong-password' },
  });
  assert.equal(bad.status, 401);

  const good = await jsonFetch(ctx.base, '/api/admin/login', {
    method: 'POST',
    body: { password: 'test-admin-password-123' },
  });
  assert.equal(good.status, 200);
  assert.ok(good.data.csrfToken);

  const cookie = cookieFrom(good);
  const payload = {
    minBuild: 2263100000,
    maxUpdateAge: 14,
    requireFirewall: true,
    requireDefender: true,
  };

  const noCsrf = await jsonFetch(ctx.base, '/api/admin/policy', {
    method: 'POST',
    body: payload,
    headers: { cookie },
  });
  assert.equal(noCsrf.status, 403);

  const withCsrf = await jsonFetch(ctx.base, '/api/admin/policy', {
    method: 'POST',
    body: payload,
    headers: { cookie, 'x-csrf-token': good.data.csrfToken },
  });
  assert.equal(withCsrf.status, 200);
  assert.equal(withCsrf.data.policy.version, 2);
  assert.equal(withCsrf.data.policy.minBuild, 2263100000);

  const stats = await jsonFetch(ctx.base, '/api/stats', { headers: { cookie } });
  assert.equal(stats.data.policyVersion, 2);
  assert.equal(stats.data.postureValuesStored, 0);
});

test('admin endpoints reject requests without a session', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());
  for (const pathname of ['/api/stats', '/api/decisions', '/api/devices', '/api/log/verify', '/api/advisory']) {
    const res = await jsonFetch(ctx.base, pathname);
    assert.equal(res.status, 401, pathname + ' should be 401');
  }
});

test('attest is rate limited', async (t) => {
  const ctx = await startVerifier({ attestRateLimitPerMinute: 2 });
  t.after(() => ctx.close());
  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);

  // Two malformed bodies are enough to exhaust a limit of 2.
  for (let i = 0; i < 2; i++) await submit(ctx, { deviceId: 'nope' });
  const third = await submit(ctx, { deviceId: 'nope' });
  assert.equal(third.status, 429);
  assert.equal(third.data.reasonCode, 'RATE_LIMITED');
});
