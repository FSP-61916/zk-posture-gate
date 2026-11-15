'use strict';
// ---------------------------------------------------------------------------
// agent/lib/keys.js
//
// Device identity: an ed25519 keypair generated ON THIS LAPTOP.
// The private key never leaves the machine; only the public key is enrolled.
//
// deviceId = "dev_" + first 24 hex chars of sha256(public key SPKI DER)
// Deriving the id from the key stops a device claiming somebody else's id:
// the verifier looks up the public key by id and checks the signature with it.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function deviceIdFromPublicKey(publicKey) {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return 'dev_' + crypto.createHash('sha256').update(spki).digest('hex').slice(0, 24);
}

/** Load the device keypair, creating it on first run with restrictive perms. */
function loadOrCreateIdentity(config) {
  ensurePrivateDir(config.dataDir);

  if (fs.existsSync(config.keyFile)) {
    const pem = fs.readFileSync(config.keyFile, 'utf8');
    const privateKey = crypto.createPrivateKey(pem);
    const publicKey = crypto.createPublicKey(privateKey);
    return identityOf(privateKey, publicKey, false);
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  // mode 0600: only this user can read it. writeFileSync's mode is ignored if
  // the file already exists, hence the explicit chmod below.
  fs.writeFileSync(config.keyFile, pem, { mode: 0o600 });
  try {
    fs.chmodSync(config.keyFile, 0o600);
  } catch {
    /* Windows may not support POSIX modes; the file is still per-user */
  }
  return identityOf(privateKey, publicKey, true);
}

function identityOf(privateKey, publicKey, created) {
  return {
    created,
    deviceId: deviceIdFromPublicKey(publicKey),
    privateKey,
    publicKey,
    publicKeySpkiB64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

function signText(privateKey, text) {
  return crypto.sign(null, Buffer.from(text, 'utf8'), privateKey).toString('base64url');
}

function verifyText(publicKey, text, signatureB64url) {
  try {
    const sig = Buffer.from(String(signatureB64url), 'base64url');
    if (sig.length !== 64) return false;
    return crypto.verify(null, Buffer.from(text, 'utf8'), publicKey, sig);
  } catch {
    return false;
  }
}

module.exports = { loadOrCreateIdentity, signText, verifyText, deviceIdFromPublicKey, ensurePrivateDir };
