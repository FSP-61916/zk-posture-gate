'use strict';
// ---------------------------------------------------------------------------
// agent/lib/posture.js
//
// Reads REAL posture values from Windows and encodes them for the circuit.
//
// Everything this module returns is PRIVATE. It is used only as circuit input
// and must never be logged, printed, or sent anywhere. The verifier only ever
// receives the proof plus public signals.
//
// Windows is read by running one fixed PowerShell script (agent/lib/posture.ps1)
// with a fixed argument list: no untrusted text is ever concatenated into a
// command line, there is a hard timeout, and failures are handled.
// ---------------------------------------------------------------------------

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, 'posture.ps1');
const TIMEOUT_MS = 30000;

/**
 * Encode OS build as ONE integer, as required:
 *   build * 100000 + UBR
 * Example: Windows 11 23H2 = CurrentBuild 22631, UBR 3803
 *   22631 * 100000 + 3803 = 2263103803
 * Fits in 40 bits? 2^40 = 1,099,511,627,776. 2263103803 < 1099511627776 (yes).
 * Even an absurd build 99999 with UBR 99999 gives 9,999,999,999 < 2^40.
 */
function encodeBuild(build, ubr) {
  const b = Number(build);
  const u = Number(ubr);
  if (!Number.isInteger(b) || b < 0 || !Number.isInteger(u) || u < 0) {
    throw new Error('build and UBR must be non-negative integers');
  }
  if (u >= 100000) throw new Error('UBR must be below 100000 so the encoding stays reversible');
  const encoded = b * 100000 + u;
  if (encoded >= 2 ** 40) throw new Error('encoded build does not fit in 40 bits');
  return encoded;
}

function decodeBuild(encoded) {
  return { build: Math.floor(encoded / 100000), ubr: encoded % 100000 };
}

/** Run the fixed PowerShell collector. Windows only. */
function runWindowsCollector() {
  if (process.platform !== 'win32') {
    const err = new Error(
      'Posture can only be read on Windows. This build refuses to invent posture values.'
    );
    err.code = 'NOT_WINDOWS';
    throw err;
  }
  const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', SCRIPT];
  const run = spawnSync('powershell.exe', args, {
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });
  if (run.error) throw new Error(`Could not run PowerShell: ${run.error.message}`);
  if (run.status !== 0) {
    throw new Error(`Posture script failed (exit ${run.status})`);
  }
  let data;
  try {
    data = JSON.parse(String(run.stdout).trim());
  } catch {
    throw new Error('Posture script did not return JSON');
  }
  if (!data.ok) throw new Error(`Posture script reported: ${data.error || 'unknown error'}`);
  return data;
}

/**
 * Turn collector output into circuit inputs.
 * Anything missing or malformed becomes a hard error: we never guess.
 */
function toPosture(raw) {
  if (typeof raw.build !== 'number' || typeof raw.ubr !== 'number') {
    throw new Error('collector did not report OS build');
  }
  if (typeof raw.updateAgeDays !== 'number' || raw.updateAgeDays < 0) {
    throw new Error('collector did not report a usable update age');
  }
  if (typeof raw.firewallAllProfiles !== 'boolean') {
    throw new Error('collector did not report firewall state');
  }
  if (typeof raw.defenderRealTime !== 'boolean') {
    throw new Error('collector did not report Defender state');
  }

  return {
    // private circuit inputs
    build: encodeBuild(raw.build, raw.ubr),
    updateAgeDays: Math.floor(raw.updateAgeDays),
    firewallOn: raw.firewallAllProfiles ? 1 : 0,
    defenderOn: raw.defenderRealTime ? 1 : 0,
    // local display only (still private, never leaves the device)
    detail: {
      buildNumber: raw.build,
      ubr: raw.ubr,
      updateAgeDays: Math.floor(raw.updateAgeDays),
      updateSource: raw.updateSource || 'unknown',
      firewallAllProfiles: raw.firewallAllProfiles,
      defenderRealTime: raw.defenderRealTime,
      bitlocker: raw.bitlocker, // null when not elevated / not available
    },
  };
}

/** Default provider: the real Windows collector. Injectable for tests. */
function readPosture({ provider = runWindowsCollector } = {}) {
  return toPosture(provider());
}

module.exports = { readPosture, runWindowsCollector, toPosture, encodeBuild, decodeBuild };
