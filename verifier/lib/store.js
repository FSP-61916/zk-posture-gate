'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/store.js
//
// Tiny JSON-file store. We deliberately avoid a database dependency: the demo
// serves one admin and three laptops, and plain files are easy to audit.
// Writes are atomic (write temp file, then rename) so a crash cannot leave a
// half-written policy or device list.
//
// The decision log is NOT stored here - it is append-only JSON Lines, see
// verifier/lib/log.js.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** A JSON document with simple read/update helpers. */
class JsonFile {
  constructor(file, fallback) {
    this.file = file;
    this.value = readJson(file, fallback);
    if (!fs.existsSync(file)) writeJsonAtomic(file, this.value);
  }

  get() {
    return this.value;
  }

  set(next) {
    this.value = next;
    writeJsonAtomic(this.file, next);
    return next;
  }

  update(mutator) {
    const next = mutator(this.value);
    return this.set(next === undefined ? this.value : next);
  }
}

module.exports = { JsonFile, readJson, writeJsonAtomic };
