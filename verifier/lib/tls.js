'use strict';
// ---------------------------------------------------------------------------
// verifier/lib/tls.js
//
// A tiny, dependency-free local PKI for the demo:
//   data/tls/ca.key.pem      CA private key   (mode 600, never printed)
//   data/tls/ca.crt.pem      CA certificate
//   data/tls/leaf.key.pem    server key       (mode 600, never printed)
//   data/tls/leaf.crt.pem    server certificate, SANs: localhost, hostname,
//                            127.0.0.1 and every current LAN IPv4
//
// The CA is generated once. The leaf is generated when missing or when the
// machine's addresses changed; `node scripts/tls-leaf.js` regenerates only the
// leaf on demand. Agents pin the CA's SPKI SHA-256, so a new leaf or a new IP
// does not require touching agent config.
//
// TLS_CERT_PATH / TLS_KEY_PATH load an existing cert/key instead, in which case
// nothing is generated. The cert file must include the issuing CA as a second
// PEM block so agents can verify the chain.
//
// This module never logs or returns private key material. Callers print only
// fingerprints and file paths.
// ---------------------------------------------------------------------------

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// --- minimal DER encoding --------------------------------------------------

function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let value = n;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const set = (...parts) => tlv(0x31, Buffer.concat(parts));

function integer(buffer) {
  let value = Buffer.from(buffer);
  while (value.length > 1 && value[0] === 0 && !(value[1] & 0x80)) value = value.subarray(1);
  if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0]), value]);
  return tlv(0x02, value);
}

function oid(value) {
  const parts = String(value).split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const bytes = [];
    let n = part;
    do {
      bytes.unshift(n & 0x7f);
      n = Math.floor(n / 128);
    } while (n > 0);
    for (let i = 0; i < bytes.length - 1; i++) bytes[i] |= 0x80;
    out.push(...bytes);
  }
  return tlv(0x06, Buffer.from(out));
}

const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const ia5 = (s) => tlv(0x16, Buffer.from(s, 'ascii'));
const octetString = (b) => tlv(0x04, b);
const boolean = (b) => tlv(0x01, Buffer.from([b ? 0xff : 0x00]));
const nullValue = Buffer.from([0x05, 0x00]);
const bitString = (bytes, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), bytes]));

function utcTime(date) {
  const iso = date.toISOString().replace(/[-:T]/g, '').slice(2, 14);
  return tlv(0x17, Buffer.from(`${iso}Z`, 'ascii'));
}

function name(cn) {
  return seq(
    set(seq(oid('2.5.4.10'), utf8('ZK Posture Gate'))),
    set(seq(oid('2.5.4.3'), utf8(cn)))
  );
}

const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), nullValue);

function extension(oidValue, critical, value) {
  return seq(oid(oidValue), ...(critical ? [boolean(true)] : []), octetString(value));
}

function serialNumber() {
  const bytes = crypto.randomBytes(16);
  bytes[0] &= 0x7f;
  if (bytes[0] === 0) bytes[0] = 1;
  return integer(bytes);
}

function pem(der, label) {
  const body = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function spkiFingerprint(certificate) {
  return crypto
    .createHash('sha256')
    .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

function certificateFingerprint(certificate) {
  return crypto.createHash('sha256').update(certificate.raw).digest('hex');
}

function collectSans() {
  const dns = new Set(['localhost', os.hostname().toLowerCase()]);
  const ips = new Set(['127.0.0.1']);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const entry of list || []) {
      if (entry.family === 'IPv4' && !entry.internal) ips.add(entry.address);
    }
  }
  const entries = [
    ...[...dns].filter(Boolean).map((value) => ({ type: 'dns', value })),
    ...[...ips].map((value) => ({ type: 'ip', value })),
  ];
  entries.sort((a, b) => (a.type + a.value).localeCompare(b.type + b.value));
  return entries;
}

function sanExtension(entries) {
  const names = entries.map((entry) =>
    entry.type === 'dns'
      ? tlv(0x82, Buffer.from(entry.value, 'ascii'))
      : tlv(0x87, Buffer.from(entry.value.split('.').map(Number)))
  );
  return extension('2.5.29.17', false, seq(...names));
}

function keyUsage(value) {
  // value is a Buffer of KeyUsage bits already shifted for BIT STRING.
  return extension('2.5.29.15', true, bitString(value.bytes, value.unused));
}

function signCertificate({ subject, issuer, publicKey, signingKey, isCa, sans, notBefore, notAfter, issuerCertificate }) {
  const extensions = [
    extension(
      '2.5.29.19',
      true,
      seq(...(isCa ? [boolean(true)] : []))
    ),
    isCa
      ? keyUsage({ bytes: Buffer.from([0x06]), unused: 1 }) // keyCertSign, cRLSign
      : keyUsage({ bytes: Buffer.from([0xa0]), unused: 5 }), // digitalSignature, keyEncipherment
  ];
  if (!isCa) {
    extensions.push(
      extension('2.5.29.37', false, seq(oid('1.3.6.1.5.5.7.3.1'))), // serverAuth
      sanExtension(sans)
    );
  }
  // Subject key identifier: SHA-1 of the subjectPublicKey BIT STRING value,
  // approximated by SHA-1 of the full SPKI DER, which is what most tools show.
  const ski = crypto.createHash('sha1').update(publicKey).digest();
  extensions.push(extension('2.5.29.14', false, octetString(ski)));
  if (issuerCertificate) {
    extensions.push(extension('2.5.29.35', false, seq(tlv(0x80, issuerKeyId(issuerCertificate)))));
  }

  const tbs = seq(
    tlv(0xa0, integer(Buffer.from([2]))), // v3
    serialNumber(),
    SHA256_RSA,
    issuer,
    seq(utcTime(notBefore), utcTime(notAfter)),
    subject,
    publicKey,
    tlv(0xa3, seq(...extensions))
  );
  const signature = crypto.sign('sha256', tbs, signingKey);
  return seq(tbs, SHA256_RSA, bitString(signature));
}

function issuerKeyId(certificate) {
  return crypto
    .createHash('sha1')
    .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
    .digest();
}

function readOrNull(file) {
  try {
    return fs.readFileSync(file);
  } catch {
    return null;
  }
}

function writeKey(file, value) {
  fs.writeFileSync(file, value, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function writeFile(file, value, mode) {
  fs.writeFileSync(file, value, { mode });
  fs.chmodSync(file, mode);
}

function generateCa(tlsDir) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const caPublicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const subject = name('ZK Posture Gate Local CA');
  const now = Date.now();
  const der = signCertificate({
    subject,
    issuer: subject,
    publicKey: caPublicKeyDer,
    signingKey: privateKey,
    isCa: true,
    sans: [],
    notBefore: new Date(now - 60 * 1000),
    notAfter: new Date(now + 10 * 365 * 24 * 60 * 60 * 1000),
  });
  writeKey(path.join(tlsDir, 'ca.key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFile(path.join(tlsDir, 'ca.crt.pem'), pem(der, 'CERTIFICATE'), 0o644);
}

function generateLeaf(tlsDir, sans) {
  const caKey = crypto.createPrivateKey(fs.readFileSync(path.join(tlsDir, 'ca.key.pem')));
  const caCert = new crypto.X509Certificate(fs.readFileSync(path.join(tlsDir, 'ca.crt.pem')));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const subject = name(`ZK Posture Gate (${os.hostname()})`);
  const issuer = new crypto.X509Certificate(caCert.raw).subject;
  const now = Date.now();
  const der = signCertificate({
    subject,
    issuer: parseName(issuer),
    publicKey: publicKeyDer,
    signingKey: caKey,
    isCa: false,
    sans,
    notBefore: new Date(now - 60 * 1000),
    notAfter: new Date(now + 397 * 24 * 60 * 60 * 1000),
    issuerCertificate: caCert,
  });
  writeKey(path.join(tlsDir, 'leaf.key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFile(path.join(tlsDir, 'leaf.crt.pem'), pem(der, 'CERTIFICATE') + fs.readFileSync(path.join(tlsDir, 'ca.crt.pem')), 0o644);
  writeFile(
    path.join(tlsDir, 'leaf-sans.json'),
    JSON.stringify({ sans, hostname: os.hostname(), generatedAt: new Date(now).toISOString() }, null, 2) + '\n',
    0o644
  );
  return der;
}

// X509Certificate.subject is a display string ("CN=...\nO=..."). Rebuild the
// same DER Name from the two fields we always set, rather than parsing it.
function parseName(display) {
  const cn = /CN=([^\n]+)/.exec(display || '');
  return name(cn ? cn[1] : 'ZK Posture Gate');
}

function loadMaterial({ keyFile, certFile, caCertFile }) {
  const key = fs.readFileSync(keyFile, 'utf8');
  const certPem = fs.readFileSync(certFile, 'utf8');
  const leaf = new crypto.X509Certificate(certPem);
  let caSpkiSha256 = null;
  let caSha256 = null;
  if (caCertFile && fs.existsSync(caCertFile)) {
    const ca = new crypto.X509Certificate(fs.readFileSync(caCertFile));
    caSpkiSha256 = spkiFingerprint(ca);
    caSha256 = certificateFingerprint(ca);
  }
  return {
    enabled: true,
    key,
    cert: certPem,
    keyFile,
    certFile,
    caCertFile: caCertFile || null,
    leafSha256: certificateFingerprint(leaf),
    caSpkiSha256,
    caSha256,
  };
}

/**
 * Ensure a usable certificate exists. With TLS_CERT_PATH/TLS_KEY_PATH those
 * files are used exactly as supplied; otherwise the local CA and leaf are
 * generated into <dataDir>/tls on first run.
 */
function ensureTls({ dataDir, certPath, keyPath } = {}) {
  if (certPath || keyPath) {
    if (!certPath || !keyPath) {
      throw new Error('Set both TLS_CERT_PATH and TLS_KEY_PATH, or neither.');
    }
    if (!fs.existsSync(certPath)) throw new Error(`TLS_CERT_PATH does not exist: ${certPath}`);
    if (!fs.existsSync(keyPath)) throw new Error(`TLS_KEY_PATH does not exist: ${keyPath}`);
    return { ...loadMaterial({ keyFile: keyPath, certFile: certPath }), custom: true, created: false };
  }

  const tlsDir = path.join(dataDir, 'tls');
  fs.mkdirSync(tlsDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(tlsDir, 0o700);
  } catch {
    /* Windows may ignore POSIX modes */
  }

  const caKeyFile = path.join(tlsDir, 'ca.key.pem');
  const caCertFile = path.join(tlsDir, 'ca.crt.pem');
  const leafKeyFile = path.join(tlsDir, 'leaf.key.pem');
  const leafCertFile = path.join(tlsDir, 'leaf.crt.pem');
  const sansFile = path.join(tlsDir, 'leaf-sans.json');

  let created = false;
  if (!readOrNull(caKeyFile) || !readOrNull(caCertFile)) {
    generateCa(tlsDir);
    created = true;
  }

  const sans = collectSans();
  const savedSans = readOrNull(sansFile);
  const sameSans = savedSans && JSON.stringify(JSON.parse(savedSans.toString('utf8')).sans) === JSON.stringify(sans);
  if (!readOrNull(leafKeyFile) || !readOrNull(leafCertFile) || !sameSans) {
    generateLeaf(tlsDir, sans);
    created = true;
  }

  const material = loadMaterial({ keyFile: leafKeyFile, certFile: leafCertFile, caCertFile });
  return { ...material, custom: false, created, sans };
}

/** Regenerate only the leaf, keeping the CA (and therefore every agent pin). */
function regenerateLeaf({ dataDir } = {}) {
  const tlsDir = path.join(dataDir, 'tls');
  if (!fs.existsSync(path.join(tlsDir, 'ca.key.pem')) || !fs.existsSync(path.join(tlsDir, 'ca.crt.pem'))) {
    throw new Error('No local CA yet. Start the verifier once, or run scripts/tls-info.js, first.');
  }
  const sans = collectSans();
  generateLeaf(tlsDir, sans);
  return { ...loadMaterial({
    keyFile: path.join(tlsDir, 'leaf.key.pem'),
    certFile: path.join(tlsDir, 'leaf.crt.pem'),
    caCertFile: path.join(tlsDir, 'ca.crt.pem'),
  }), custom: false, created: true, sans };
}

/** Human-readable, colon-separated form of a stored hex fingerprint. */
function formatFingerprint(hex) {
  if (!hex) return '(none)';
  return (hex.match(/.{2}/g) || []).join(':').toUpperCase();
}

module.exports = {
  ensureTls,
  regenerateLeaf,
  collectSans,
  spkiFingerprint,
  certificateFingerprint,
  formatFingerprint,
};
