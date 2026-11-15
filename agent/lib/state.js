'use strict';
// ---------------------------------------------------------------------------
// agent/lib/state.js
//
// Local, non-secret agent state: enrolled device id, when it enrolled, last
// result. Contains nothing sensitive: no posture values, no private key.
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');

function loadState(config) {
  try {
    return JSON.parse(fs.readFileSync(config.stateFile, 'utf8'));
  } catch {
    return {};
  }
}

function saveState(config, state) {
  fs.mkdirSync(path.dirname(config.stateFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(config.stateFile, JSON.stringify(state, null, 2), { mode: 0o600 });
  return state;
}

module.exports = { loadState, saveState };
