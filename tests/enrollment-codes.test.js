'use strict';
// ---------------------------------------------------------------------------
// tests/enrollment-codes.test.js
//
// Enrollment codes are single use and time limited, and the dashboard must be
// told the truth about their state. These tests drive EnrollmentStore directly
// with a controllable clock, so expiry needs no sleeping.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { EnrollmentStore, enrollmentCodeState } = require('../verifier/lib/devices');

function makeStore(clock, ttlSeconds = 600) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkpg-codes-'));
  return new EnrollmentStore(path.join(dir, 'enrollment-codes.json'), {
    ttlSeconds,
    now: () => clock.value,
  });
}

test('a fresh code is active', () => {
  const clock = { value: Date.parse('2026-11-10T09:00:00.000Z') };
  const store = makeStore(clock);
  const { code } = store.issue();

  const [entry] = store.listWithState();
  assert.equal(entry.code, code);
  assert.equal(entry.state, 'active');
  assert.equal(entry.usedAt, null);
});

test('a used code is rejected and reported as used, never active', () => {
  const clock = { value: Date.parse('2026-11-10T09:00:00.000Z') };
  const store = makeStore(clock);
  const { code } = store.issue();

  assert.deepEqual(store.redeem(code), { ok: true });
  assert.deepEqual(store.redeem(code), { ok: false, reason: 'CODE_USED' });

  const [entry] = store.listWithState();
  assert.equal(entry.state, 'used');
  assert.ok(entry.usedAt);
});

test('an expired code is rejected and reported as expired, never active', () => {
  const clock = { value: Date.parse('2026-11-10T09:00:00.000Z') };
  const store = makeStore(clock, 600);
  const { code } = store.issue();

  clock.value += 601 * 1000; // one second past the TTL

  assert.deepEqual(store.redeem(code), { ok: false, reason: 'CODE_EXPIRED' });
  assert.equal(store.listWithState()[0].state, 'expired');
});

test('state is computed from usedAt before expiry', () => {
  const now = Date.parse('2026-11-10T09:00:00.000Z');
  const entry = { code: 'AAAA-BBBB', createdAt: now, expiresAt: now - 1000, usedAt: null };
  assert.equal(enrollmentCodeState(entry, now), 'expired');
  assert.equal(enrollmentCodeState({ ...entry, usedAt: new Date(now).toISOString() }, now), 'used');
  assert.equal(enrollmentCodeState({ ...entry, expiresAt: now + 1 }, now), 'active');
});
