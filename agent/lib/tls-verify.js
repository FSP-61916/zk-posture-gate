'use strict';
// ---------------------------------------------------------------------------
// agent/lib/tls-verify.js
//
// The agent does not trust the system store for the verifier. It pins the CA's
// public key (SPKI SHA-256) from its own config and verifies the certificate
// chain and hostname itself on every TLS connection.
//
// Pinning the CA (not the leaf) means a renewed leaf, a new IP or a new
// hostname does not require editing agent config, as long as the CA is the
// same. A different CA is refused even if it is otherwise valid.
//
// This module sees certificates only. It never receives, prints or stores
// posture values or private keys.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');
const { isIP } = require('node:net');

function normalizeFingerprint(value) {
  return String(value || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
}

function isValidPin(value) {
  return /^[0-9a-f]{64}$/.test(normalizeFingerprint(value));
}

/**
 * Inspect a connected TLS socket. Returns null when everything checks out, or
 * a human-readable reason (fingerprints only; no key material).
 */
function verifySocket(socket, hostname, pin) {
  let peer;
  try {
    peer = socket.getPeerCertificate(true);
  } catch {
    return 'the server did not present a usable certificate';
  }
  if (!peer || !peer.raw) return 'the server did not present a certificate';

  let leaf;
  let ca;
  try {
    leaf = new crypto.X509Certificate(peer.raw);
    if (!peer.issuerCertificate || !peer.issuerCertificate.raw) {
      return 'the server did not send its issuing CA certificate';
    }
    ca = new crypto.X509Certificate(peer.issuerCertificate.raw);
    if (ca.raw.equals(leaf.raw)) return 'the server certificate is self-signed; the local CA chain is missing';
  } catch (err) {
    return `the server certificate could not be parsed (${err.message})`;
  }

  // 1. Chain: CA is self-signed, and it really signed the leaf.
  try {
    if (!ca.verify(ca.publicKey)) return 'the issuing CA is not self-signed as expected';
    if (!leaf.verify(ca.publicKey)) return 'the server certificate is not signed by its stated CA';
  } catch {
    return 'the certificate chain signature check failed';
  }

  // 2. Pin: the CA public key must equal the one written into agent config.
  const actual = crypto
    .createHash('sha256')
    .update(ca.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  if (actual !== normalizeFingerprint(pin)) {
    return 'the CA fingerprint does not match the pinned value';
  }

  // 3. Validity of both certificates, right now.
  const now = Date.now();
  for (const cert of [leaf, ca]) {
    if (now < Date.parse(cert.validFrom) || now > Date.parse(cert.validTo)) {
      return 'a certificate in the chain is expired or not yet valid';
    }
  }

  // 4. Hostname, against the SANs only (CN fallback is not used).
  const host = String(hostname || '').replace(/^\[|\]$/g, '');
  let matched = null;
  try {
    matched = isIP(host) ? leaf.checkIP(host) : leaf.checkHost(host);
  } catch {
    matched = null;
  }
  if (!matched) return `the certificate is not valid for ${host}`;

  return null;
}

module.exports = { verifySocket, normalizeFingerprint, isValidPin };
