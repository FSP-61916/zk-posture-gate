'use strict';
// ---------------------------------------------------------------------------
// dashboard/app.js
//
// One small SPA: hash-free view switching, fetch polling every 2s, plain DOM.
// No framework, no CDN, no inline styles or scripts (the CSP forbids them).
//
// Rules this file follows:
//   * Status is icon + text, never colour alone.
//   * Every row comes from the verifier's real decision log. There is no
//     simulated or sample data anywhere in this file.
//   * Posture values are never displayed as values: the right-hand side of the
//     decision panel says "never leaves the device".
// ---------------------------------------------------------------------------

(function () {
  const REASON_TEXT = {
    POLICY_MISMATCH: 'Device used an outdated policy',
    REPLAY: 'This proof was already used',
    EXPIRED: 'Challenge expired, please retry',
    PROOF_INVALID: 'Proof could not be verified',
    BAD_SIGNATURE: 'Device identity could not be verified',
    NON_COMPLIANT: 'Device does not meet policy',
    BAD_REQUEST: 'Request was malformed',
    CHALLENGE_DEVICE_MISMATCH: 'Challenge was issued to a different device',
    RATE_LIMITED: 'Too many attempts, please wait',
  };

  const state = {
    csrf: null,
    view: 'overview',
    policy: null,
    stats: null,
    recent: null,
    decisions: { records: [], total: 0, page: 1, pageSize: 15 },
    page: 1,
    filters: { result: '', reason: '', from: '', to: '' },
    selected: null,
    devices: null,
    enrollmentCode: null,
    enrollmentCodes: null,
    logStatus: null,
    advisory: null,
    advisoryWindow: 'policy',
    error: null,
    pendingConfirm: null,
    busy: false,
    lastSync: null,
  };

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function esc(value) {
    return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, (c) => {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmtDateTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  function shortHash(hash) {
    return hash ? String(hash).slice(0, 12) + '…' : '—';
  }

  /** "1 record" / "2 records" — never "1 records". */
  function plural(count, singular, pluralForm) {
    const n = Number(count) || 0;
    return `${n} ${n === 1 ? singular : pluralForm || singular + 's'}`;
  }

  // --------------------------------------------------------------- network

  async function apiFetch(pathname, opts) {
    const options = opts || {};
    const headers = { accept: 'application/json' };
    if (options.body !== undefined) headers['content-type'] = 'application/json';
    if (options.method && options.method !== 'GET' && state.csrf) {
      headers['x-csrf-token'] = state.csrf;
    }

    const res = await fetch(pathname, {
      method: options.method || 'GET',
      headers,
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });

    if (res.status === 401 && pathname !== '/api/admin/login') {
      showLogin('Session expired. Please sign in again.');
      const err = new Error('Not signed in');
      err.code = 'UNAUTHORIZED';
      throw err;
    }

    let data = null;
    try {
      data = await res.json();
    } catch {
      data = { error: 'The verifier returned an unreadable response' };
    }

    if (!res.ok) {
      const err = new Error(data.error || 'Request failed (HTTP ' + res.status + ')');
      err.code = data.code;
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // ------------------------------------------------------------- feedback

  let toastTimer = null;
  function showToast(message, kind) {
    const el = $('#toast');
    el.textContent = message;
    el.className = 'toast' + (kind === 'error' ? ' toast-error' : '');
    el.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.hidden = true;
    }, 4000);
  }

  function showError(message) {
    state.error = message;
    const banner = $('#error-banner');
    $('#error-text').textContent = message;
    banner.hidden = false;
  }

  function clearError() {
    state.error = null;
    $('#error-banner').hidden = true;
  }

  // -------------------------------------------------------------- session

  function showLogin(message) {
    state.csrf = null;
    $('#app-view').hidden = true;
    $('#login-view').hidden = false;
    $('#login-error').textContent = message || '';
    const input = $('#login-password');
    input.value = '';
    input.focus();
  }

  function showApp() {
    $('#login-view').hidden = true;
    $('#app-view').hidden = false;
  }

  async function boot() {
    wireEvents();
    try {
      const me = await apiFetch('/api/admin/me');
      if (!me.authenticated) {
        showLogin('');
        return;
      }
      state.csrf = me.csrfToken;
      showApp();
      await Promise.all([loadStats(), loadPolicy(), loadRecent(), loadHealth()]);
      render();
      startPolling();
    } catch (err) {
      // A fresh visit is simply "not signed in": no scary error text.
      if (err.code === 'UNAUTHORIZED') showLogin('');
      else showLogin(err.message);
    }
  }

  // --------------------------------------------------------------- loaders

  async function loadStats() {
    state.stats = await apiFetch('/api/stats');
    state.lastSync = new Date().toISOString();
  }

  async function loadPolicy() {
    state.policy = await apiFetch('/api/policy');
  }

  async function loadRecent() {
    state.recent = await apiFetch('/api/decisions?page=1&pageSize=8');
  }

  async function loadHealth() {
    const health = await apiFetch('/api/health');
    state.health = health;
    const el = $('#verifier-address');
    if (!el) return;
    // Show the LAN address the laptops use, not just localhost.
    const host =
      health.demoLan && Array.isArray(health.lanIps) && health.lanIps.length
        ? health.lanIps[0]
        : location.hostname;
    el.textContent = host + ':' + (location.port || '3000');
  }

  async function loadDecisions() {
    const params = new URLSearchParams({ page: String(state.page), pageSize: String(state.decisions.pageSize) });
    if (state.filters.result) params.set('result', state.filters.result);
    if (state.filters.reason) params.set('reason', state.filters.reason);
    if (state.filters.from) params.set('from', state.filters.from);
    if (state.filters.to) params.set('to', state.filters.to);
    state.decisions = await apiFetch('/api/decisions?' + params.toString());
  }

  async function loadDevices() {
    const [devicesRes, codesRes] = await Promise.all([
      apiFetch('/api/devices'),
      apiFetch('/api/admin/enrollment-codes'),
    ]);
    state.devices = devicesRes.devices;
    state.enrollmentCodes = codesRes.codes;
  }

  async function loadLog() {
    state.logStatus = await apiFetch('/api/log/verify');
  }

  async function loadAdvisory() {
    state.advisory = await apiFetch('/api/advisory?window=' + encodeURIComponent(state.advisoryWindow));
  }

  // ---------------------------------------------------------------- render

  function codeStateCell(state) {
    if (state === 'active') return '<span class="status status-granted">&#10004; active</span>';
    if (state === 'used') return '<span class="status status-muted">used</span>';
    if (state === 'expired') return '<span class="status status-warn">expired</span>';
    return '<span class="status status-muted">—</span>';
  }

  function statusCell(result) {
    if (result === 'GRANTED') return '<span class="status status-granted">&#10004; GRANTED</span>';
    if (result === 'DENIED') return '<span class="status status-denied">&#10006; DENIED</span>';
    return '<span class="status status-muted">—</span>';
  }

  function decisionRow(rec) {
    const viewButton = `<button class="btn btn-sm" type="button" data-action="open-decision" data-id="${rec.id}">View</button>`;
    return `
      <tr>
        <td class="mono nowrap">${esc(fmtTime(rec.timestamp))}</td>
        <td class="mono">${esc(rec.deviceId)}</td>
        <td class="nowrap">v${esc(rec.policyVersion)}</td>
        <td>${statusCell(rec.result)}</td>
        <td>${esc(rec.reasonCode ? REASON_TEXT[rec.reasonCode] || rec.reasonCode : '—')}</td>
        <td class="mono nowrap">${esc(rec.latencyMs)} ms</td>
        <td class="hash nowrap">${esc(shortHash(rec.hash))}</td>
        <td class="nowrap">${viewButton}</td>
      </tr>`;
  }

  function tableHead() {
    return `<thead><tr>
      <th scope="col">Time</th><th scope="col">Device</th><th scope="col">Policy</th>
      <th scope="col">Result</th><th scope="col">Reason</th><th scope="col">Latency</th>
      <th scope="col">Hash</th><th scope="col"><span class="muted">Detail</span></th>
    </tr></thead>`;
  }

  function skeletonRows(count) {
    let out = '';
    for (let i = 0; i < count; i++) out += '<tr><td colspan="8"><div class="skeleton"></div></td></tr>';
    return out;
  }

  function viewOverview() {
    const s = state.stats;
    const head = `
      <div class="page-head">
        <div>
          <h1>Overview</h1>
          <p class="lede">Are we safe? Real decisions only. Simulated data is never mixed in.</p>
        </div>
        <span class="pill">Updated ${esc(fmtTime(state.lastSync))}</span>
      </div>`;

    if (!s) {
      let cards = '';
      for (let i = 0; i < 6; i++) cards += '<div class="card skeleton skeleton-card"></div>';
      return head + `<div class="cards">${cards}</div>`;
    }

    const pct = s.compliancePct === null ? '—' : s.compliancePct + '%';
    const cards = `
      <div class="cards">
        <div class="card"><span class="label">Compliance</span><span class="value">${esc(pct)}</span>
          <span class="foot">${esc(plural(s.totalDecisions, 'decision'))} recorded</span></div>
        <div class="card"><span class="label">Granted today</span><span class="value">${esc(s.grantedToday)}</span>
          <span class="foot">✔ pass/fail only</span></div>
        <div class="card"><span class="label">Denied today</span><span class="value">${esc(s.deniedToday)}</span>
          <span class="foot">✖ reason code only</span></div>
        <div class="card"><span class="label">Devices seen</span><span class="value">${esc(s.devicesSeen)}</span>
          <span class="foot">${esc(s.enrolledDevices)} enrolled</span></div>
        <div class="card"><span class="label">Policy version</span><span class="value">v${esc(s.policyVersion)}</span>
          <span class="foot">owned by the verifier</span></div>
        <div class="card"><span class="label">Posture values stored</span><span class="value">0</span>
          <span class="foot">no such field exists</span></div>
      </div>`;

    const reasons = Object.entries(s.denialsByReason || {}).sort((a, b) => b[1] - a[1]);
    const maxCount = reasons.reduce((m, r) => Math.max(m, r[1]), 0);
    const chart = reasons.length
      ? `<div class="chart">${reasons
          .map(([code, count]) => {
            const width = maxCount ? Math.max(2, Math.round((count / maxCount) * 100)) : 0;
            return `<div class="chart-row">
              <span class="chart-label" title="${esc(code)}">${esc(REASON_TEXT[code] || code)}</span>
              <span class="chart-track"><span class="chart-bar" data-width="${width}"></span></span>
              <span class="chart-value">${esc(count)}</span>
            </div>`;
          })
          .join('')}</div>`
      : '<p class="empty">No denials yet. Every attestation so far met the policy.</p>';

    const rows = (state.recent ? state.recent.records : []).slice();

    const recentTable = `
      <div class="panel">
        <div class="panel-head">
          <h2>Recent decisions</h2>
          <button class="btn btn-sm" type="button" data-nav="decisions">All decisions</button>
        </div>
        <div class="table-wrap">
          <table>
            ${tableHead()}
            <tbody>
              ${rows.length ? rows.map(decisionRow).join('') : '<tr><td colspan="8" class="empty">No attestations yet. Run <span class="mono">node agent attest</span> on a laptop.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;

    const privacy = `
      <div class="panel">
        <div class="panel-head">
          <h2>What the server never saw</h2>
          <span class="badge badge-ok">stored: 0 values</span>
        </div>
        <div class="split">
          <div class="locks">
            <div class="lock-row"><span>OS build number</span><span class="lock-tag">never leaves the device</span></div>
            <div class="lock-row"><span>Days since last update</span><span class="lock-tag">never leaves the device</span></div>
            <div class="lock-row"><span>Firewall profile state</span><span class="lock-tag">never leaves the device</span></div>
            <div class="lock-row"><span>Defender real-time state</span><span class="lock-tag">never leaves the device</span></div>
          </div>
          <div class="kv">
            <div class="kv-row"><span class="kv-key">What is uploaded</span><span class="kv-val">A zero-knowledge proof + 7 public signals</span></div>
            <div class="kv-row"><span class="kv-key">What is learned</span><span class="kv-val">pass/fail and a reason code</span></div>
            <div class="kv-row"><span class="kv-key">Why a database isn't used</span><span class="kv-val">an inventory is a map of who is vulnerable</span></div>
          </div>
        </div>
      </div>`;

    return head + cards + `<div class="panel"><div class="panel-head"><h2>Denied by reason</h2><span class="pill">real decisions</span></div>${chart}</div>` + recentTable + privacy;
  }

  function viewDecisions() {
    const d = state.decisions;
    const f = state.filters;

    const reasonOptions = ['', ...Object.keys(REASON_TEXT)]
      .map(
        (code) =>
          `<option value="${esc(code)}" ${f.reason === code ? 'selected' : ''}>${esc(code ? REASON_TEXT[code] : 'All reasons')}</option>`
      )
      .join('');

    const rows = d.records;
    const total = d.total;
    const first = total === 0 ? 0 : (d.page - 1) * d.pageSize + 1;
    const last = Math.min(d.page * d.pageSize, total);

    const detail = state.selected ? decisionDetail(state.selected) : '';

    return `
      <div class="page-head">
        <div><h1>Decisions</h1><p class="lede">Every attestation, including refusals. Stored without posture values.</p></div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h2>Filters</h2>
          <button class="btn btn-sm" type="button" data-action="clear-filters">Clear</button>
        </div>
        <div class="cards">
          <label class="field">Result
            <select data-filter="result">
              <option value="">All results</option>
              <option value="GRANTED" ${f.result === 'GRANTED' ? 'selected' : ''}>GRANTED</option>
              <option value="DENIED" ${f.result === 'DENIED' ? 'selected' : ''}>DENIED</option>
            </select>
          </label>
          <label class="field">Reason
            <select data-filter="reason">${reasonOptions}</select>
          </label>
          <label class="field">From date
            <input type="date" data-filter="from" value="${esc(f.from)}">
          </label>
          <label class="field">To date
            <input type="date" data-filter="to" value="${esc(f.to)}">
          </label>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h2>${esc(plural(total, 'decision'))}</h2>
          <span class="pill">Showing ${esc(first)}–${esc(last)}</span>
        </div>
        <div class="table-wrap">
          <table>
            ${tableHead()}
            <tbody>
              ${rows.length ? rows.map(decisionRow).join('') : '<tr><td colspan="8" class="empty">No decisions match these filters. Try clearing them.</td></tr>'}
            </tbody>
          </table>
        </div>
        <div class="panel-head">
          <span class="muted small">Page ${esc(d.page)}</span>
          <span>
            <button class="btn btn-sm" type="button" data-action="page-prev" ${d.page <= 1 ? 'disabled' : ''}>Previous</button>
            <button class="btn btn-sm" type="button" data-action="page-next" ${last >= total ? 'disabled' : ''}>Next</button>
          </span>
        </div>
      </div>

      ${detail}`;
  }

  function decisionDetail(rec) {
    const badge = '<span class="badge badge-ok">real record</span>';
    return `
      <div class="panel">
        <div class="panel-head">
          <h2>Decision detail</h2>
          <span>${badge} <button class="btn btn-sm" type="button" data-action="close-detail">Close</button></span>
        </div>
        <p class="muted small">What the server saw vs. what stayed on the laptop.</p>
        <div class="split">
          <div>
            <h3 class="small muted">What the server saw</h3>
            <div class="kv mt-8">
              <div class="kv-row"><span class="kv-key">Result</span><span class="kv-val">${statusCell(rec.result)}</span></div>
              <div class="kv-row"><span class="kv-key">Reason</span><span class="kv-val">${esc(rec.reasonCode ? REASON_TEXT[rec.reasonCode] || rec.reasonCode : '—')}</span></div>
              <div class="kv-row"><span class="kv-key">Policy version</span><span class="kv-val">v${esc(rec.policyVersion)}</span></div>
              <div class="kv-row"><span class="kv-key">Device</span><span class="kv-val mono">${esc(rec.deviceId)}</span></div>
              <div class="kv-row"><span class="kv-key">Latency</span><span class="kv-val mono">${esc(rec.latencyMs)} ms</span></div>
              <div class="kv-row"><span class="kv-key">Proof size</span><span class="kv-val">verified in memory, not retained</span></div>
              <div class="kv-row"><span class="kv-key">Record hash</span><span class="kv-val hash">${esc(shortHash(rec.hash))}</span></div>
            </div>
          </div>
          <div>
            <h3 class="small muted">What stayed on the laptop</h3>
            <div class="locks mt-8">
              <div class="lock-row"><span>OS build</span><span class="lock-tag">never leaves the device</span></div>
              <div class="lock-row"><span>Days since update</span><span class="lock-tag">never leaves the device</span></div>
              <div class="lock-row"><span>Firewall state</span><span class="lock-tag">never leaves the device</span></div>
              <div class="lock-row"><span>Defender state</span><span class="lock-tag">never leaves the device</span></div>
            </div>
            <p class="muted small mt-8">The server cannot show these numbers because it never received them. That is the product, not a limitation of the display.</p>
          </div>
        </div>
      </div>`;
  }

  function viewPolicy() {
    const p = state.policy;
    if (!p) return '<div class="panel"><div class="skeleton skeleton-card"></div></div>';

    return `
      <div class="page-head">
        <div><h1>Policy</h1><p class="lede">The verifier owns this policy. Laptops can read it but never set it.</p></div>
        <span class="pill">Current version v${esc(p.version)}</span>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h2>Current vs. new</h2>
          <span class="muted small">Last changed ${esc(fmtDateTime(p.updatedAt))}</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th scope="col">Parameter</th><th scope="col">Current</th><th scope="col">New</th></tr></thead>
            <tbody>
              <tr><td>Minimum build (encoded)</td><td class="mono">${esc(p.minBuild)}</td>
                <td><input id="policy-minBuild" data-policy="minBuild" type="number" min="0" step="100000" value="${esc(p.minBuild)}"></td></tr>
              <tr><td>Maximum update age (days)</td><td class="mono">${esc(p.maxUpdateAge)}</td>
                <td><input id="policy-maxUpdateAge" data-policy="maxUpdateAge" type="number" min="0" max="65535" value="${esc(p.maxUpdateAge)}"></td></tr>
              <tr><td>Require firewall on all profiles</td><td class="mono">${p.requireFirewall ? 'true' : 'false'}</td>
                <td><label class="switch"><input data-policy="requireFirewall" type="checkbox" ${p.requireFirewall ? 'checked' : ''}> required</label></td></tr>
              <tr><td>Require Defender real-time</td><td class="mono">${p.requireDefender ? 'true' : 'false'}</td>
                <td><label class="switch"><input data-policy="requireDefender" type="checkbox" ${p.requireDefender ? 'checked' : ''}> required</label></td></tr>
            </tbody>
          </table>
        </div>
        <div id="policy-preview" class="banner banner-info">Change a value to see what will happen.</div>
        <div class="panel-head">
          <span class="muted small">Saving bumps the policy to v${esc(p.version + 1)}. Devices proving the old policy get POLICY_MISMATCH until they refetch.</span>
          <button class="btn btn-primary" type="button" data-action="save-policy">Save policy</button>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head"><h2>Why this matters</h2></div>
        <p class="muted small">A proof is only valid for one policy version. Raising the bar instantly invalidates proofs made under the old bar, which is what makes the gate respond to a new threat.</p>
      </div>`;
  }

  function viewDevices() {
    const devices = state.devices;
    const codes = state.enrollmentCodes;
    const fresh = state.enrollmentCode;
    // The banner may only offer a code the server still reports as active.
    const freshActive =
      fresh && codes ? codes.some((c) => c.code === fresh.code && c.state === 'active') : false;

    const codePanel = freshActive
      ? `<div class="banner banner-info">
          <strong>Enrollment code</strong>
          <span class="mono" id="enrollment-code">${esc(fresh.code)}</span>
          <button class="btn btn-sm" type="button" data-action="copy" data-copy="${esc(fresh.code)}">Copy</button>
          <span class="muted small">single use, expires ${esc(fmtDateTime(fresh.expiresAt))}</span>
        </div>`
      : fresh
      ? '<p class="muted small">The last code is no longer active. Generate a new one for the next laptop.</p>'
      : '<p class="muted small">Codes are single use and expire. Generate one per laptop.</p>';

    const codeRows = !codes
      ? skeletonRows(2)
      : codes.length
      ? codes
          .map(
            (c) => `<tr>
              <td class="mono">${esc(c.code)}</td>
              <td class="mono nowrap">${esc(fmtDateTime(c.createdAt))}</td>
              <td class="mono nowrap">${esc(fmtDateTime(c.expiresAt))}</td>
              <td>${codeStateCell(c.state)}</td>
            </tr>`
          )
          .join('')
      : '<tr><td colspan="4" class="empty">No codes yet. Generate one per laptop.</td></tr>';

    const codesPanel = `
      <div class="panel">
        <div class="panel-head"><h2>Enrollment codes</h2><span class="pill">${codes ? plural(codes.length, 'code') : '—'}</span></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th scope="col">Code</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">State</th></tr></thead>
            <tbody>${codeRows}</tbody>
          </table>
        </div>
        <p class="muted small">A code works once. Used and expired codes are refused even if someone still has the text.</p>
      </div>`;

    return `
      <div class="page-head">
        <div><h1>Devices</h1><p class="lede">Only a device id and a public key are stored. Nothing about the machine's configuration.</p></div>
        <button class="btn btn-primary" type="button" data-action="new-code">Generate enrollment code</button>
      </div>

      <div class="panel">
        <div class="panel-head"><h2>Enrollment</h2></div>
        ${codePanel}
      </div>

      ${codesPanel}

      <div class="panel">
        <div class="panel-head"><h2>Enrolled devices</h2><span class="pill">${devices ? plural(devices.length, 'device') : '—'}</span></div>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th scope="col">Device id</th><th scope="col">Label</th><th scope="col">Enrolled</th>
              <th scope="col">Last seen</th><th scope="col">Last result</th><th scope="col">Records</th><th scope="col">Key fingerprint</th>
            </tr></thead>
            <tbody>
              ${
                !devices
                  ? skeletonRows(3)
                  : devices.length
                  ? devices
                      .map(
                        (d) => `<tr>
                          <td class="mono">${esc(d.deviceId)}</td>
                          <td>${esc(d.label)}</td>
                          <td class="mono nowrap">${esc(fmtDateTime(d.enrolledAt))}</td>
                          <td class="mono nowrap">${esc(d.lastSeen ? fmtDateTime(d.lastSeen) : 'never')}</td>
                          <td>${d.lastResult ? statusCell(d.lastResult) : '<span class="status status-muted">—</span>'}</td>
                          <td class="mono" title="${esc(d.records ? `${d.records.granted} granted, ${d.records.denied} denied` : '')}">${esc(d.records ? d.records.total : 0)}</td>
                          <td class="hash">${esc(d.keyFingerprint)}</td>
                        </tr>`
                      )
                      .join('')
                  : '<tr><td colspan="7" class="empty">No devices yet. Generate an enrollment code, then run <span class="mono">node agent enroll</span> on a laptop.</td></tr>'
              }
            </tbody>
          </table>
        </div>
      </div>`;
  }

  function viewLog() {
    const s = state.logStatus;
    const status = !s
      ? '<span class="skeleton" data-block="1"></span>'
      : s.status === 'intact'
      ? '<span class="status status-granted">&#10004; Chain intact</span>'
      : `<span class="status status-denied">&#10006; Broken at record ${esc(s.brokenAt)}</span>`;

    return `
      <div class="page-head">
        <div><h1>Log Integrity</h1><p class="lede">A hash chain makes silent edits visible. It is tamper-evident, not tamper-proof.</p></div>
        <button class="btn" type="button" data-action="verify-log">Verify now</button>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h2>${status}</h2>
          <span class="pill">${s ? plural(s.count, 'record') : 'checking…'}</span>
        </div>
        <div class="kv">
          <div class="kv-row"><span class="kv-key">Last checked</span><span class="kv-val mono">${esc(s ? fmtDateTime(s.checkedAt) : '—')}</span></div>
          <div class="kv-row"><span class="kv-key">First problem</span><span class="kv-val">${esc(s && s.reason ? s.reason : 'none')}</span></div>
          <div class="kv-row"><span class="kv-key">Latest hash</span><span class="kv-val">
            <span class="hash">${esc(s && s.latestHash ? s.latestHash : '—')}</span>
            ${s && s.latestHash ? '<button class="btn btn-sm" type="button" data-action="copy" data-copy="' + esc(s.latestHash) + '">Copy</button>' : ''}
          </span></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head"><h2>How it works</h2></div>
        <p class="muted small">Each record stores the hash of the record before it. Editing one line changes its hash, which breaks every line after it. The verifier recomputes the whole chain and reports the first broken record.</p>
        <p class="muted small">Honest limit: someone who rewrites the entire chain consistently would not be detected without an external anchor. Anchoring the latest hash on a separate chain is listed as future work.</p>
        <p class="muted small">No posture values are in these records, so there is nothing sensitive to leak from the log.</p>
      </div>`;
  }

  function viewAdvisory() {
    const a = state.advisory;
    // ADVISORY ONLY is deliberately permanent: the feed suggests a policy
    // review, it never edits the policy and never maps a CVE to a build.
    const banner = `<div class="banner banner-advisory"><strong>ADVISORY ONLY</strong><span>Not mapped to your builds. It never changes the policy automatically.</span></div>`;
    const windowLabel = state.advisoryWindow === '30d' ? '30' : '90';
    const isPolicyWindow = state.advisoryWindow === 'policy';
    const scope = isPolicyWindow
      ? `added since policy v${esc(state.policy ? state.policy.version : '?')}`
      : `added in the last ${windowLabel} days`;
    const windowOptions = [
      ['policy', 'Since policy change'],
      ['30d', 'Last 30 days'],
      ['90d', 'Last 90 days'],
    ]
      .map(
        ([value, label]) =>
          `<option value="${value}" ${state.advisoryWindow === value ? 'selected' : ''}>${label}</option>`
      )
      .join('');

    if (!a) {
      return `<div class="page-head"><div><h1>Advisory</h1><p class="lede">CISA Known Exploited Vulnerabilities, Microsoft only.</p></div></div>${banner}
        <div class="panel"><div class="skeleton skeleton-card"></div></div>`;
    }

    const rows = a.entries.length
      ? a.entries
          .map(
            (v) => `<tr>
              <td class="mono nowrap">${esc(v.cveID)}</td>
              <td>${esc(v.vulnerabilityName)}</td>
              <td class="nowrap">${esc(v.product)}</td>
              <td class="mono nowrap">${esc(v.dateAdded)}</td>
              <td class="mono nowrap">${esc(v.dueDate)}</td>
              <td class="nowrap">${v.ransomware ? '<span class="status status-warn">⚠ Known</span>' : 'Unknown'}</td>
            </tr>`
          )
          .join('')
      : '<tr><td colspan="6" class="empty">No Microsoft entries in this window. That is good news, not a bug.</td></tr>';

    return `
      <div class="page-head">
        <div><h1>Advisory</h1><p class="lede">CISA Known Exploited Vulnerabilities, filtered to Microsoft, ${scope}.</p></div>
        <label class="field">Window
          <select data-advisory-window>${windowOptions}</select>
        </label>
        <button class="btn" type="button" data-action="review-policy">Review policy</button>
      </div>
      ${banner}
      <div class="panel">
        <div class="panel-head">
          <h2>Microsoft entries ${isPolicyWindow ? 'added since ' + esc(a.since || 'policy start') : 'added in the last ' + windowLabel + ' days'}</h2>
          <span class="pill">fetched ${esc(fmtDateTime(a.fetchedAt))}</span>
        </div>
        ${a.stale ? `<div class="banner banner-error"><strong>OFFLINE</strong><span>Serving the cached feed. Last refresh failed: ${esc(a.error || 'unknown')}</span></div>` : ''}
        <div class="table-wrap">
          <table>
            <thead><tr><th scope="col">CVE</th><th scope="col">Vulnerability</th><th scope="col">Product</th>
              <th scope="col">Added</th><th scope="col">Due</th><th scope="col">Ransomware</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <p class="muted small">${esc(plural(a.microsoftTotal, 'entry', 'entries'))} in the Microsoft catalog (KEV ${esc(a.catalogVersion || 'version unknown')}). Showing up to 60 recent additions. This panel suggests a policy review; it cannot tell you which build fixes which CVE.</p>
      </div>`;
  }

  function viewHtml() {
    switch (state.view) {
      case 'decisions':
        return viewDecisions();
      case 'policy':
        return viewPolicy();
      case 'devices':
        return viewDevices();
      case 'log':
        return viewLog();
      case 'advisory':
        return viewAdvisory();
      default:
        return viewOverview();
    }
  }

  function render() {
    $$('#nav button').forEach((btn) => {
      if (btn.dataset.nav === state.view) btn.setAttribute('aria-current', 'page');
      else btn.removeAttribute('aria-current');
    });
    $('#view-root').innerHTML = viewHtml();

    // Chart bars: widths set through CSSOM (CSP forbids inline style attributes).
    $$('#view-root .chart-bar').forEach((bar) => {
      bar.style.width = String(bar.dataset.width || 0) + '%';
    });
  }

  // ---------------------------------------------------------------- events

  function canAutoRender() {
    // Never re-render while someone is typing into a control inside the view,
    // or focus and half-typed values would be lost. A focused heading or button
    // is fine, which matters because navigating focuses the new heading.
    const active = document.activeElement;
    if (!active || active === document.body) return true;
    const typing = ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName);
    return !(typing && active.closest('#view-root'));
  }

  let polling = false;
  let pollTimer = null;
  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      if (polling || !state.csrf) return;
      polling = true;
      try {
        state.stats = await apiFetch('/api/stats');
        state.lastSync = new Date().toISOString();
        if (state.view === 'overview') state.recent = await apiFetch('/api/decisions?page=1&pageSize=8');
        if (state.view === 'decisions') await loadDecisions();
        if (state.view === 'devices') await loadDevices();
        if (state.view === 'log') await loadLog();
        if (state.error) clearError();
        if (canAutoRender()) render();
      } catch (err) {
        if (err.code !== 'UNAUTHORIZED') showError(err.message);
      } finally {
        polling = false;
      }
    }, 2000);
  }

  async function navigate(view) {
    state.view = view;
    state.selected = null;
    clearError();
    try {
      if (view === 'overview') await Promise.all([loadStats(), loadRecent()]);
      if (view === 'decisions') await loadDecisions();
      if (view === 'policy') await loadPolicy();
      if (view === 'devices') await loadDevices();
      if (view === 'log') await loadLog();
      if (view === 'advisory') await loadAdvisory();
    } catch (err) {
      if (err.code !== 'UNAUTHORIZED') showError(err.message);
    }
    render();
    // Move focus to the new heading for keyboard users.
    const heading = $('#view-root h1');
    if (heading) {
      heading.setAttribute('tabindex', '-1');
      heading.focus({ preventScroll: false });
    }
  }

  function openConfirm(title, body, onConfirm) {
    $('#confirm-title').textContent = title;
    $('#confirm-body').textContent = body;
    state.pendingConfirm = onConfirm;
    const dialog = $('#confirm-dialog');
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else if (window.confirm(title + '\n\n' + body)) onConfirm();
  }

  function updatePolicyPreview() {
    const el = $('#policy-preview');
    if (!el || !state.policy) return;
    const p = state.policy;
    const minBuild = Number($('#policy-minBuild').value);
    const maxAge = Number($('#policy-maxUpdateAge').value);
    const fw = $('[data-policy="requireFirewall"]').checked;
    const df = $('[data-policy="requireDefender"]').checked;

    const changes = [];
    if (minBuild > p.minBuild) changes.push(`minimum build raised ${p.minBuild} → ${minBuild} (stricter)`);
    if (minBuild < p.minBuild) changes.push(`minimum build lowered ${p.minBuild} → ${minBuild} (looser)`);
    if (maxAge < p.maxUpdateAge) changes.push(`update age tightened ${p.maxUpdateAge} → ${maxAge} days (stricter)`);
    if (maxAge > p.maxUpdateAge) changes.push(`update age loosened ${p.maxUpdateAge} → ${maxAge} days (looser)`);
    if (fw !== p.requireFirewall) changes.push(`firewall requirement ${p.requireFirewall ? 'on' : 'off'} → ${fw ? 'on' : 'off'}`);
    if (df !== p.requireDefender) changes.push(`Defender requirement ${p.requireDefender ? 'on' : 'off'} → ${df ? 'on' : 'off'}`);

    el.textContent = changes.length
      ? changes.join(' · ') + ' — saving bumps the version and invalidates old proofs.'
      : 'No change yet. Saving anyway still bumps the version.';
  }

  async function savePolicy() {
    const p = state.policy;
    const payload = {
      minBuild: Number($('#policy-minBuild').value),
      maxUpdateAge: Number($('#policy-maxUpdateAge').value),
      requireFirewall: $('[data-policy="requireFirewall"]').checked,
      requireDefender: $('[data-policy="requireDefender"]').checked,
    };
    if (
      !Number.isInteger(payload.minBuild) ||
      !Number.isInteger(payload.maxUpdateAge) ||
      payload.maxUpdateAge < 0
    ) {
      showToast('Enter whole numbers for build and update age.', 'error');
      return;
    }
    openConfirm(
      'Change policy?',
      `This bumps the policy from v${p.version} to v${p.version + 1}. Proofs made under v${p.version} will be refused as POLICY_MISMATCH until devices refetch.`,
      async () => {
        try {
          state.busy = true;
          const res = await apiFetch('/api/admin/policy', { method: 'POST', body: payload });
          state.policy = res.policy;
          state.stats = await apiFetch('/api/stats');
          state.lastSync = new Date().toISOString();
          showToast(`Policy saved as v${res.policy.version}.`);
          render();
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          state.busy = false;
        }
      }
    );
  }

  async function generateEnrollmentCode() {
    try {
      const res = await apiFetch('/api/admin/enrollment-code', { method: 'POST', body: {} });
      state.enrollmentCode = res;
      state.enrollmentCodes = (await apiFetch('/api/admin/enrollment-codes')).codes;
      showToast('Enrollment code generated.');
      render();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function verifyLog() {
    try {
      state.logStatus = await apiFetch('/api/log/verify');
      if (state.logStatus.status === 'intact') showToast('Chain intact.');
      else showToast(`Chain broken at record ${state.logStatus.brokenAt}.`, 'error');
      render();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function wireEvents() {
    $('#login-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('#login-submit');
      const password = $('#login-password').value;
      $('#login-error').textContent = '';
      button.disabled = true;
      try {
        const res = await apiFetch('/api/admin/login', { method: 'POST', body: { password } });
        state.csrf = res.csrfToken;
        showApp();
        await Promise.all([loadStats(), loadPolicy(), loadRecent(), loadHealth()]);
        state.view = 'overview';
        render();
        startPolling();
      } catch (err) {
        $('#login-error').textContent = err.message;
      } finally {
        button.disabled = false;
      }
    });

    document.addEventListener('click', async (event) => {
      const navTarget = event.target.closest('[data-nav]');
      if (navTarget) {
        await navigate(navTarget.dataset.nav);
        return;
      }

      const el = event.target.closest('[data-action]');
      if (!el) return;
      const action = el.dataset.action;

      if (action === 'logout') {
        try {
          await apiFetch('/api/admin/logout', { method: 'POST', body: {} });
        } catch {
          /* session already gone */
        }
        showLogin('');
        return;
      }
      if (action === 'retry') {
        clearError();
        try {
          await Promise.all([loadStats(), loadRecent()]);
          render();
        } catch (err) {
          showError(err.message);
        }
        return;
      }
      if (action === 'open-decision') {
        const id = Number(el.dataset.id);
        const pool = state.view === 'decisions' ? state.decisions.records : state.recent ? state.recent.records : [];
        state.selected = pool.find((r) => r.id === id) || null;
        render();
        return;
      }
      if (action === 'close-detail') {
        state.selected = null;
        render();
        return;
      }
      if (action === 'page-prev' || action === 'page-next') {
        state.page = Math.max(1, state.page + (action === 'page-next' ? 1 : -1));
        try {
          await loadDecisions();
          render();
        } catch (err) {
          showError(err.message);
        }
        return;
      }
      if (action === 'clear-filters') {
        state.filters = { result: '', reason: '', from: '', to: '' };
        state.page = 1;
        try {
          await loadDecisions();
          render();
        } catch (err) {
          showError(err.message);
        }
        return;
      }
      if (action === 'save-policy') {
        await savePolicy();
        return;
      }
      if (action === 'new-code') {
        await generateEnrollmentCode();
        return;
      }
      if (action === 'verify-log') {
        await verifyLog();
        return;
      }
      if (action === 'review-policy') {
        await navigate('policy');
        return;
      }
      if (action === 'copy') {
        const text = el.dataset.copy || '';
        try {
          await navigator.clipboard.writeText(text);
          showToast('Copied to clipboard.');
        } catch {
          showToast('Copy failed. Select the value and copy it manually.', 'error');
        }
        return;
      }
      if (action === 'dialog-cancel') {
        state.pendingConfirm = null;
        $('#confirm-dialog').close();
        return;
      }
      if (action === 'dialog-confirm') {
        const fn = state.pendingConfirm;
        state.pendingConfirm = null;
        $('#confirm-dialog').close();
        if (typeof fn === 'function') await fn();
      }
    });

    // Filters and policy preview (delegated so re-renders keep working).
    $('#view-root').addEventListener('change', async (event) => {
      const advisoryWindow = event.target.closest('[data-advisory-window]');
      if (advisoryWindow) {
        state.advisoryWindow = advisoryWindow.value;
        try {
          await loadAdvisory();
          render();
        } catch (err) {
          showError(err.message);
        }
        return;
      }
      const filter = event.target.closest('[data-filter]');
      if (filter) {
        state.filters[filter.dataset.filter] = filter.value;
        state.page = 1;
        try {
          await loadDecisions();
          render();
        } catch (err) {
          showError(err.message);
        }
        return;
      }
      if (event.target.closest('[data-policy]')) updatePolicyPreview();
    });

    $('#view-root').addEventListener('input', (event) => {
      if (event.target.closest('[data-policy]')) updatePolicyPreview();
    });
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
