'use strict';
// Local page logic for the agent UI. No posture values exist in any response
// this script can receive, so there is nothing sensitive it could display.

(function () {
  const $ = (sel) => document.querySelector(sel);

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
  }

  let toastTimer = null;
  function toast(message, kind) {
    const el = $('#toast');
    el.textContent = message;
    el.className = 'toast' + (kind === 'error' ? ' toast-error' : '');
    el.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 4000);
  }

  function showBanner(message) {
    $('#banner-text').textContent = message;
    $('#banner').hidden = false;
  }

  async function call(pathname, body) {
    const res = await fetch(pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({ error: 'Unreadable response' }));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function renderSteps(steps) {
    const list = $('#steps');
    list.innerHTML = steps
      .map(
        (step, index) =>
          `<li class="lock-row"><span>${index + 1}. ${esc(step.label)}</span><span class="kv-val mono">${esc(step.status)}</span></li>`
      )
      .join('');
  }

  async function refreshStatus() {
    try {
      const status = await fetch('/api/status').then((r) => r.json());
      $('#device-id').textContent = status.deviceId;
      $('#verifier-url').textContent = status.verifierUrl;
      $('#last-result').textContent = status.lastResult || '—';
      const badge = $('#enrolled-badge');
      if (status.enrolled) {
        badge.textContent = '✔ enrolled';
        badge.className = 'badge badge-ok';
      } else {
        badge.textContent = '✖ not enrolled';
        badge.className = 'badge badge-bad';
      }
      if (!status.canReadPosture) {
        showBanner('Posture can only be read on Windows. This machine will refuse to invent values.');
      }
    } catch (err) {
      showBanner(err.message);
    }
  }

  $('#enroll-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const data = await call('/api/enroll', {
        code: $('#enroll-code').value,
        label: $('#enroll-label').value,
      });
      toast('Enrolled as ' + data.label);
      await refreshStatus();
    } catch (err) {
      toast(err.message, 'error');
    }
  });

  $('#check-btn').addEventListener('click', async () => {
    try {
      const data = await call('/api/check', {});
      $('#steps').innerHTML = `<li class="lock-row"><span>Verifier reachable</span><span class="kv-val mono">OK (policy v${esc(data.policyVersion)})</span></li>`;
      toast('Verifier OK, policy v' + data.policyVersion);
    } catch (err) {
      toast(err.message, 'error');
    }
  });

  $('#attest-btn').addEventListener('click', async () => {
    const button = $('#attest-btn');
    button.disabled = true;
    $('#result').hidden = true;
    $('#steps').innerHTML = '<li class="lock-row"><span>Working… reading posture and generating the proof</span><span class="mono">…</span></li>';
    try {
      const data = await call('/api/attest', {});
      renderSteps(data.steps || []);
      const result = $('#result');
      result.hidden = false;
      if (data.decision === 'GRANTED') {
        result.className = 'banner banner-info';
        const minutes = Math.round((data.tokenTtlSeconds || 600) / 60);
        result.innerHTML =
          '<strong class="status-granted">&#10004; GRANTED</strong>' +
          `<span>Policy satisfied. <a href="${esc(data.gateUrl)}" target="_blank" rel="noreferrer">Open the internal app</a> (link expires in ${minutes} minutes).</span>`;
      } else {
        result.className = 'banner banner-error';
        result.innerHTML =
          '<strong class="status-denied">&#10006; DENIED</strong>' +
          `<span>${esc(data.message || data.reasonCode || 'Denied')}</span>`;
      }
      toast(data.decision === 'GRANTED' ? 'Access granted.' : 'Access denied.', data.decision === 'GRANTED' ? 'ok' : 'error');
      await refreshStatus();
    } catch (err) {
      toast(err.message, 'error');
      $('#steps').innerHTML = '';
    } finally {
      button.disabled = false;
    }
  });

  refreshStatus();
})();
