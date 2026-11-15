'use strict';
// ---------------------------------------------------------------------------
// tests/records.test.js
//
// Every attestation is logged on purpose. The Devices page exposes that count
// per device, so this test proves the number is real: one GRANTED, one replay
// denial, two records for the same device, and nothing invented for others.
// ---------------------------------------------------------------------------

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  startVerifier,
  agentConfig,
  enroll,
  posture,
  attestBody,
  submit,
  jsonFetch,
  cookieFrom,
} = require('./helpers');

test('devices: records column counts granted and denied attestations', async (t) => {
  const ctx = await startVerifier();
  t.after(() => ctx.close());

  const login = await jsonFetch(ctx.base, '/api/admin/login', {
    method: 'POST',
    body: { password: 'test-admin-password-123' },
  });
  assert.equal(login.status, 200);
  const cookie = cookieFrom(login);

  const agent = agentConfig(ctx.base);
  const identity = await enroll(ctx, agent);

  const { body } = await attestBody(ctx, agent, identity, posture());
  const granted = await submit(ctx, body);
  assert.equal(granted.data.decision, 'GRANTED');

  // Same proof again: refused, but it is still an auditable attempt.
  const replay = await submit(ctx, body);
  assert.equal(replay.data.reasonCode, 'REPLAY');

  const res = await jsonFetch(ctx.base, '/api/devices', { headers: { cookie } });
  assert.equal(res.status, 200);
  const device = res.data.devices.find((d) => d.deviceId === identity.deviceId);
  assert.ok(device);
  assert.deepEqual(device.records, { total: 2, granted: 1, denied: 1 });
});
