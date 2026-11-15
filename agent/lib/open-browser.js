'use strict';
// ---------------------------------------------------------------------------
// agent/lib/open-browser.js
//
// `--open` convenience for node agent attest. Only ever called with a URL this
// process built from the verifier's gatePath, and the URL is passed as a single
// spawn argument (no shell string), so a crafted URL cannot become a command.
// ---------------------------------------------------------------------------

const { spawn } = require('node:child_process');

function openBrowser(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return Promise.resolve(false);
  }

  const isWindows = process.platform === 'win32';
  const command = isWindows ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  // Windows: "start" treats the first quoted token as a window title, hence "".
  const args = isWindows ? ['/c', 'start', '', url] : [url];

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    } catch {
      return resolve(false);
    }
    child.once('error', () => resolve(false));
    child.once('spawn', () => {
      child.unref();
      resolve(true);
    });
  });
}

module.exports = { openBrowser };
