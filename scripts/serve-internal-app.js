#!/usr/bin/env node
'use strict';
// ---------------------------------------------------------------------------
// scripts/serve-internal-app.js        (npm run app)
//
// A tiny static file server for the protected app in internal-app/, so the demo
// does not depend on Python being installed. It binds 127.0.0.1 only, serves
// files strictly inside internal-app/, and is reached by browsers only through
// the gate. It is the same job as `python -m http.server 8080`.
//
//   $env:APP_PORT = "8080"     (default 8080; must match GATE_UPSTREAM)
// ---------------------------------------------------------------------------

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', 'internal-app');
const PORT = Number(process.env.APP_PORT || 8080);
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

const server = http.createServer((req, res) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  } catch {
    res.writeHead(400).end('Bad request');
    return;
  }
  if (pathname.endsWith('/')) pathname += 'index.html';
  const file = path.resolve(ROOT, '.' + pathname);
  // Never leave internal-app/ (blocks ../ and encoded variants).
  if (file !== ROOT && !file.startsWith(ROOT + path.sep)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
});

server.on('error', (err) => {
  console.error(
    err.code === 'EADDRINUSE'
      ? `\n  Port ${PORT} is already in use (another app server, or python -m http.server?). Close it first.\n`
      : `\n  Could not start the app server: ${err.message}\n`
  );
  process.exitCode = 1;
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log(`  Protected app (internal-app/) on http://127.0.0.1:${PORT}`);
  console.log('  Reach it through the gate only. Ctrl+C to stop.');
  console.log('');
});
process.on('SIGINT', () => {
  server.close();
  server.closeAllConnections?.();
});
