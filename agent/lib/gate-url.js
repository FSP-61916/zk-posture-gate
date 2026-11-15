'use strict';
// ---------------------------------------------------------------------------
// agent/lib/gate-url.js
//
// Turns the verifier's gatePath into a URL on the gate port. The verifier does
// not send an absolute URL (it does not trust a request Host header), and the
// gate may live somewhere else again (GATE_URL), so the agent is the one place
// that decides what to print and open.
// ---------------------------------------------------------------------------

/** @returns {string} e.g. http://127.0.0.1:8081/?t=gate... */
function gateUrlFor({ verifierUrl, gatePort, gatePath, gateUrl }) {
  if (typeof gatePath !== 'string' || gatePath[0] !== '/') {
    throw new Error('gatePath must start with /');
  }

  if (gateUrl) {
    const base = new URL(gateUrl);
    assertWebUrl(base);
    const path = base.pathname.replace(/\/+$/, '');
    return base.origin + path + gatePath;
  }

  const base = new URL(verifierUrl);
  assertWebUrl(base);
  if (gatePort) base.port = String(gatePort);
  return base.origin + gatePath;
}

function assertWebUrl(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('gate URL must use http:// or https://');
  }
}

module.exports = { gateUrlFor };
