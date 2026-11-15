'use strict';
// ---------------------------------------------------------------------------
// agent/lib/interval.js
//
// Parses the scheduled-attestation interval. Five minutes is the default when
// --interval is given without a value; one minute is the floor and exists for
// rehearsals, not for production. There is no fractional or zero interval
// because that would turn the audit log into a flood.
// ---------------------------------------------------------------------------

const DEFAULT_MINUTES = 5;
const MIN_MINUTES = 1;

function parseInterval(value) {
  if (value === undefined) return null; // no --interval: one-shot attestation
  if (value === true) return DEFAULT_MINUTES; // bare --interval
  const minutes = Number(value);
  if (!Number.isFinite(minutes) || minutes < MIN_MINUTES) {
    throw new Error(`--interval must be a number of minutes >= ${MIN_MINUTES} (got "${value}")`);
  }
  return Math.floor(minutes);
}

module.exports = { parseInterval, DEFAULT_MINUTES, MIN_MINUTES };
