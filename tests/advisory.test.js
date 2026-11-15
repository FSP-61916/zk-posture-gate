'use strict';
// ---------------------------------------------------------------------------
// tests/advisory.test.js
//
// The advisory page offers three windows. The dates they produce are the only
// thing that decides which CVEs appear, so they are tested directly: policy
// change (default), rolling 30 days, rolling 90 days. No network is used.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');

const { windowSince } = require('../verifier/lib/kev');

const NOW = Date.parse('2026-11-10T12:00:00.000Z');
const POLICY_UPDATED = '2026-01-02T03:04:05.000Z';

test('advisory window: since the policy change is the default', () => {
  assert.equal(windowSince('policy', POLICY_UPDATED, NOW), POLICY_UPDATED);
});

test('advisory window: last 30 days is counted back from now', () => {
  assert.equal(windowSince('30d', POLICY_UPDATED, NOW), '2026-10-11T12:00:00.000Z');
});

test('advisory window: last 90 days is counted back from now', () => {
  assert.equal(windowSince('90d', POLICY_UPDATED, NOW), '2026-08-12T12:00:00.000Z');
});

test('advisory window: an unknown value falls back to the policy change', () => {
  assert.equal(windowSince('all', POLICY_UPDATED, NOW), POLICY_UPDATED);
  assert.equal(windowSince(undefined, POLICY_UPDATED, NOW), POLICY_UPDATED);
});
