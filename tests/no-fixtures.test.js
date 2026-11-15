'use strict';
// ---------------------------------------------------------------------------
// tests/no-fixtures.test.js
//
// Honesty guard for the product code. agent/, verifier/ and shared/ must not
// import test code, and must not assign a literal to a posture field: posture
// values may only come from the Windows reader, never from a default, fixture
// or fallback.
//
// This is a static check, not a proof. It catches the obvious mistake (someone
// pasting a sample posture object into product code) and deliberately allows
// comparisons and conversions like `firewallOn: raw.firewallAllProfiles ? 1 : 0`.
// ---------------------------------------------------------------------------

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT } = require('./helpers');

const PRODUCT_DIRS = ['agent', 'verifier', 'shared'];
const SOURCE_EXTENSIONS = /\.(js|ps1)$/;

// Field names the circuit takes. A literal on the right-hand side of one of
// these is a made-up posture value.
const POSTURE_FIELDS = [
  'buildNumber',
  'updateAgeDays',
  'firewallOn',
  'defenderOn',
  'firewallAllProfiles',
  'defenderRealTime',
];
const LITERAL_ASSIGNMENT = new RegExp(
  `\\b(?:${POSTURE_FIELDS.join('|')})\\s*[:=]\\s*(?:true|false|\\d+)\\b`,
  'i'
);

function walk(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walk(full));
    else if (SOURCE_EXTENSIONS.test(entry.name)) files.push(full);
  }
  return files;
}

function productFiles() {
  const files = [];
  for (const dir of PRODUCT_DIRS) files.push(...walk(path.join(ROOT, dir)));
  return files;
}

test('product code never imports test code', () => {
  for (const file of productFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    const imported = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
    let match;
    while ((match = imported.exec(src)) !== null) {
      assert.ok(
        !/(^|\/)tests?\//.test(match[1]),
        `${path.relative(ROOT, file)} imports test code: ${match[1]}`
      );
    }
  }
});

test('product code has no hard-coded posture values', () => {
  for (const file of productFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    const hit = LITERAL_ASSIGNMENT.exec(src);
    assert.equal(
      hit,
      null,
      `${path.relative(ROOT, file)} assigns a literal posture value: ${hit && hit[0]}`
    );
  }
});
