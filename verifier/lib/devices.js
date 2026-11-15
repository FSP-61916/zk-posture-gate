'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/devices.js
//
// Enrolled devices and one-time enrollment codes.
// The verifier stores ONLY: device id, public key, label, timestamps.
// No posture values, ever.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');
const { JsonFile } = require('./store');

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I/O/0/1 confusion

function makeEnrollmentCode() {
  const bytes = crypto.randomBytes(8);
  let raw = '';
  for (const byte of bytes) raw += CODE_ALPHABET[byte % CODE_ALPHABET.length];
  return `${raw.slice(0, 4)}-${raw.slice(4)}`;
}

/** A code is active only while it is unused and unexpired. */
function enrollmentCodeState(entry, now) {
  if (entry.usedAt) return 'used';
  if (entry.expiresAt <= now) return 'expired';
  return 'active';
}

class DeviceStore {
  constructor(file, { now = () => Date.now() } = {}) {
    this.file = new JsonFile(file, { devices: [] });
    this.now = now;
  }

  list() {
    return this.file.get().devices;
  }

  find(deviceId) {
    return this.list().find((d) => d.deviceId === deviceId) || null;
  }

  add({ deviceId, publicKey, label }) {
    if (this.find(deviceId)) {
      const err = new Error('device already enrolled');
      err.code = 'ALREADY_ENROLLED';
      throw err;
    }
    const device = {
      deviceId,
      publicKey,
      label: label || 'unlabelled laptop',
      enrolledAt: new Date(this.now()).toISOString(),
      lastSeen: null,
      lastResult: null,
    };
    this.file.update((state) => ({ devices: [...state.devices, device] }));
    return device;
  }

  touch(deviceId, result) {
    this.file.update((state) => ({
      devices: state.devices.map((d) =>
        d.deviceId === deviceId
          ? { ...d, lastSeen: new Date(this.now()).toISOString(), lastResult: result }
          : d
      ),
    }));
  }
}

class EnrollmentStore {
  constructor(file, { ttlSeconds = 600, now = () => Date.now() } = {}) {
    this.file = new JsonFile(file, { codes: [] });
    this.ttlSeconds = ttlSeconds;
    this.now = now;
  }

  issue() {
    const code = makeEnrollmentCode();
    const createdAt = this.now();
    const expiresAt = createdAt + this.ttlSeconds * 1000;
    this.file.update((state) => ({
      codes: [
        ...state.codes.filter((c) => c.expiresAt > this.now() - 24 * 3600 * 1000),
        { code, createdAt, expiresAt, usedAt: null },
      ],
    }));
    return { code, expiresAt: new Date(expiresAt).toISOString(), ttlSeconds: this.ttlSeconds };
  }

  /** Single use and time limited. Unknown, used and expired are all refused. */
  redeem(code) {
    const entry = this.file.get().codes.find((c) => c.code === code);
    if (!entry) return { ok: false, reason: 'UNKNOWN_CODE' };
    if (entry.usedAt) return { ok: false, reason: 'CODE_USED' };
    if (entry.expiresAt <= this.now()) return { ok: false, reason: 'CODE_EXPIRED' };
    // Burn the code immediately, even if enrollment fails later.
    this.file.update((state) => ({
      codes: state.codes.map((c) =>
        c.code === code ? { ...c, usedAt: new Date(this.now()).toISOString() } : c
      ),
    }));
    return { ok: true };
  }

  list() {
    return this.file.get().codes;
  }

  /** Newest first, with the state computed here so every caller agrees. */
  listWithState() {
    const now = this.now();
    return this.list()
      .slice()
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((c) => ({
        code: c.code,
        createdAt: new Date(c.createdAt).toISOString(),
        expiresAt: new Date(c.expiresAt).toISOString(),
        usedAt: c.usedAt || null,
        state: enrollmentCodeState(c, now),
      }));
  }
}

module.exports = { DeviceStore, EnrollmentStore, makeEnrollmentCode, enrollmentCodeState };
