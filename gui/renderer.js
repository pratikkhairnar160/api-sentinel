/**
 * renderer.js — APISentinel GUI Controller
 * Runs in the Electron renderer process (no Node access — uses preload bridge)
 */

'use strict';

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  activeScanId:   null,
  findings:       [],       // live-accumulated findings
  pages:          [],
  scripts:        [],
  apiCalls:       [],
  activeTab:      'pages',
  filterRisk:     '',
  filterValidation: '',
  filterSearch:   '',
  riskCounts:     { critical: 0, high: 0, medium: 0, low: 0 },
  progressPct:    0,
};

// ── DOM refs ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const dom = {
  targetUrl:       $('targetUrl'),
  scanMode:        $('scanMode'),
  maxDepth:        $('maxDepth'),
  maxPages:        $('maxPages'),
  delayMs:         $('delayMs'),
  validateKeys:    $('validateKeys'),
  entropyMode:     $('entropyMode'),
  btnStart:        $('btnStart'),
  btnStop:         $('btnStop'),
  statusDot:       $('statusDot'),
  statusLabel:     $('statusLabel'),
  phaseLabel:      $('phaseLabel'),
  progressBar:     $('progressBar'),
  progressSection: $('progressSection'),
  exportSection:   $('exportSection'),
  riskSummary:     $('riskSummary'),
  statPages:       $('statPages'),
  statScripts:     $('statScripts'),
  statKeys:        $('statKeys'),
  terminalLog:     $('terminalLog'),
  findingsTbody:   $('findingsTbody'),
  findingsCount:   $('findingsCount'),
  assetsTbody:     $('assetsTbody'),
  historyTbody:    $('historyTbody'),
  tabPagesCount:   $('tabPagesCount'),
  tabScriptsCount: $('tabScriptsCount'),
  tabApiCount:     $('tabApiCount'),
  detailModal:     $('detailModal'),
  modalTitle:      $('modalTitle'),
  modalBody:       $('modalBody'),
  toast:           $('toast'),
  filterRisk:      $('filterRisk'),
  filterValidation:$('filterValidation'),
  filterSearch:    $('filterSearch'),

  barCritical: $('barCritical'), cntCritical: $('cntCritical'),
  barHigh:     $('barHigh'),     cntHigh:     $('cntHigh'),
  barMedium:   $('barMedium'),   cntMedium:   $('cntMedium'),
  barLow:      $('barLow'),      cntLow:      $('cntLow'),
};

// ── Navigation ────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    $(`view-${view}`)?.classList.add('active');

    if (view === 'history') loadHistory();
    if (view === 'assets') renderAssetsTable();
  });
});

// ── Asset Tabs ────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.activeTab = btn.dataset.tab;
    renderAssetsTable();
  });
});

// ── Filter Controls ───────────────────────────────────────────────────────
dom.filterRisk?.addEventListener('change', e => { state.filterRisk = e.target.value; renderFindingsTable(); });
dom.filterValidation?.addEventListener('change', e => { state.filterValidation = e.target.value; renderFindingsTable(); });
dom.filterSearch?.addEventListener('input', e => { state.filterSearch = e.target.value.toLowerCase(); renderFindingsTable(); });

// ── Start Scan ────────────────────────────────────────────────────────────
dom.btnStart?.addEventListener('click', async () => {
  const targetUrl = dom.targetUrl.value.trim();
  if (!targetUrl) { showToast('Enter a target URL first.', 'error'); return; }
  if (!targetUrl.startsWith('http')) { showToast('URL must start with http:// or https://', 'error'); return; }

  // Reset state
  state.findings    = [];
  state.pages       = [];
  state.scripts     = [];
  state.apiCalls    = [];
  state.riskCounts  = { critical: 0, high: 0, medium: 0, low: 0 };
  state.progressPct = 0;

  clearTerminal();
  dom.findingsTbody.innerHTML = '<tr class="empty-row"><td colspan="8">Scanning…</td></tr>';
  dom.assetsTbody.innerHTML   = '<tr class="empty-row"><td colspan="4">Crawling…</td></tr>';

  const config = {
    targetUrl,
    mode:      dom.scanMode.value,
    maxDepth:  parseInt(dom.maxDepth.value),
    maxPages:  parseInt(dom.maxPages.value),
    delayMs:   parseInt(dom.delayMs.value),
    validate:  dom.validateKeys.checked,
  };

  try {
    const { scanId } = await window.sentinel.invoke('scan:start', config);
    state.activeScanId = scanId;

    dom.btnStart.disabled = true;
    dom.btnStop.classList.remove('hidden');
    dom.progressSection.style.display = '';
    dom.exportSection.style.display   = 'none';
    dom.riskSummary.style.display     = '';

    setStatus('running', 'SCANNING');
    log('info', `Scan started → ${targetUrl} [${scanId.slice(0,8)}]`);

  } catch (err) {
    showToast(`Failed to start scan: ${err.message}`, 'error');
    log('error', err.message);
  }
});

// ── Stop Scan ─────────────────────────────────────────────────────────────
dom.btnStop?.addEventListener('click', async () => {
  if (!state.activeScanId) return;
  await window.sentinel.invoke('scan:stop', { scanId: state.activeScanId });
  log('info', 'Scan stopped by user');
  scanFinished('stopped');
});

// ── Export Buttons ────────────────────────────────────────────────────────
$('btnExportJson')?.addEventListener('click', () => exportReport('json'));
$('btnExportHtml')?.addEventListener('click', () => exportReport('html'));
$('btnExportPdf')?.addEventListener('click',  () => exportReport('pdf'));

async function exportReport(format) {
  if (!state.activeScanId) { showToast('No active scan to export.', 'error'); return; }
  log('info', `Exporting ${format.toUpperCase()} report…`);
  try {
    const result = await window.sentinel.invoke(`export:${format}`, { scanId: state.activeScanId });
    if (result.success) showToast(`${format.toUpperCase()} report saved.`, 'success');
    else showToast(`Export failed: ${result.error}`, 'error');
  } catch (err) {
    showToast(`Export error: ${err.message}`, 'error');
  }
}

// ── Clear Log ─────────────────────────────────────────────────────────────
$('btnClearLog')?.addEventListener('click', clearTerminal);

// ── Modal ─────────────────────────────────────────────────────────────────
$('btnModalClose')?.addEventListener('click', closeModal);
dom.detailModal?.addEventListener('click', e => { if (e.target === dom.detailModal) closeModal(); });

// ── IPC Event Listeners ───────────────────────────────────────────────────

window.sentinel.on('scan:status', ({ phase, message }) => {
  dom.phaseLabel.textContent = message || phase;
  if (['crawling','analyzing','classifying','validating'].includes(phase)) {
    const phaseProgress = { crawling: 25, analyzing: 55, classifying: 70, validating: 90 };
    setProgress(phaseProgress[phase] || 10);
  }
  log('info', message || phase);
});

window.sentinel.on('scan:found-page', ({ url, depth, statusCode, totalPages }) => {
  state.pages.push({ url, depth, statusCode });
  dom.statPages.textContent = totalPages;
  dom.tabPagesCount.textContent = totalPages;
  log('page', `[${statusCode}] ${url} (depth ${depth})`);
  if (state.activeTab === 'pages') renderAssetsTable();
});

window.sentinel.on('scan:found-asset', ({ type, url }) => {
  if (type === 'script') {
    state.scripts.push({ url });
    dom.statScripts.textContent = state.scripts.length;
    dom.tabScriptsCount.textContent = state.scripts.length;
    log('script', url);
    if (state.activeTab === 'scripts') renderAssetsTable();
  } else if (type === 'api') {
    state.apiCalls.push({ url });
    dom.tabApiCount.textContent = state.apiCalls.length;
    if (state.activeTab === 'api') renderAssetsTable();
  }
});

window.sentinel.on('scan:found-key', (finding) => {
  state.findings.push(finding);
  state.riskCounts[finding.riskLevel] = (state.riskCounts[finding.riskLevel] || 0) + 1;
  dom.statKeys.textContent = state.findings.length;
  dom.findingsCount.textContent = state.findings.length;

  updateRiskBars();
  prependFindingRow(finding);

  const tagClass = { critical:'crit', high:'high', medium:'med', low:'low' }[finding.riskLevel] || '';
  log('key', `${finding.icon || '🔑'} [${finding.riskLevel?.toUpperCase()}] ${finding.service} — ${finding.masked} @ ${truncate(finding.sourceUrl, 60)}`, tagClass);

  // Auto-switch to findings view if first critical finding
  if (finding.riskLevel === 'critical' && state.findings.filter(f => f.riskLevel === 'critical').length === 1) {
    switchView('findings');
  }
});

window.sentinel.on('validate:result', ({ id, status, result }) => {
  // Update the finding in state
  const finding = state.findings.find(f => f.id === id);
  if (finding) {
    finding.validationResult = result;
    finding.validationStatus = status;
  }

  // Update the table row's validation cell
  const row = document.querySelector(`tr[data-id="${id}"]`);
  if (row) {
    const valCell = row.querySelector('.val-cell');
    if (valCell) valCell.innerHTML = validationBadge(status);
  }

  log('valid', `[${status?.toUpperCase()}] ${id.slice(0,8)}…`);
});

window.sentinel.on('scan:complete', ({ status, summary, stats }) => {
  log('complete', `Scan complete — ${summary?.total || 0} findings, ${stats?.pages || 0} pages`);
  if (summary) {
    log('complete', `Critical: ${summary.bySeverity?.critical || 0}  High: ${summary.bySeverity?.high || 0}  Medium: ${summary.bySeverity?.medium || 0}  Low: ${summary.bySeverity?.low || 0}`);
  }
  scanFinished('complete');
  setProgress(100);
});

window.sentinel.on('scan:error', ({ message }) => {
  log('error', `Scan error: ${message}`);
  showToast(`Scan error: ${message}`, 'error');
  scanFinished('error');
});

// ── Render Functions ──────────────────────────────────────────────────────

function renderFindingsTable() {
  const filtered = state.findings.filter(f => {
    if (state.filterRisk       && f.riskLevel        !== state.filterRisk)       return false;
    if (state.filterValidation && f.validationStatus !== state.filterValidation) return false;
    if (state.filterSearch) {
      const haystack = `${f.service} ${f.sourceUrl} ${f.masked}`.toLowerCase();
      if (!haystack.includes(state.filterSearch)) return false;
    }
    return true;
  });

  dom.findingsCount.textContent = filtered.length;

  if (filtered.length === 0) {
    dom.findingsTbody.innerHTML = '<tr class="empty-row"><td colspan="8">No findings match current filters.</td></tr>';
    return;
  }

  dom.findingsTbody.innerHTML = filtered.map((f, i) => buildFindingRow(f, i)).join('');
  attachDetailButtons();
}

function prependFindingRow(finding) {
  const existingEmpty = dom.findingsTbody.querySelector('.empty-row');
  if (existingEmpty) dom.findingsTbody.innerHTML = '';

  // Apply current filters
  if (state.filterRisk && finding.riskLevel !== state.filterRisk) return;
  if (state.filterValidation && finding.validationStatus !== state.filterValidation) return;
  if (state.filterSearch) {
    const h = `${finding.service} ${finding.sourceUrl} ${finding.masked}`.toLowerCase();
    if (!h.includes(state.filterSearch)) return;
  }

  const tr = document.createElement('tr');
  tr.dataset.id = finding.id;
  tr.innerHTML = buildFindingRowInner(finding);
  dom.findingsTbody.prepend(tr);
  attachDetailButtons();
}

function buildFindingRow(f, i) {
  return `<tr data-id="${esc(f.id)}">${buildFindingRowInner(f)}</tr>`;
}

function buildFindingRowInner(f) {
  return `
    <td><span class="badge-risk ${esc(f.riskLevel)}">${esc((f.riskLevel || '').toUpperCase())}</span></td>
    <td>${esc(f.icon || '')} ${esc(f.service || f.serviceName || '')}</td>
    <td><code class="code-val">${esc(f.masked || '')}</code></td>
    <td class="url-cell" title="${esc(f.sourceUrl || '')}">${esc(truncate(f.sourceUrl || '', 50))}</td>
    <td>${f.lineNumber || '—'}</td>
    <td>${esc(f.sourceType || '')}</td>
    <td class="val-cell">${validationBadge(f.validationStatus)}</td>
    <td><button class="btn-detail" data-id="${esc(f.id)}">DETAIL</button></td>
  `;
}

function renderAssetsTable() {
  const tab = state.activeTab;
  let rows = '';

  if (tab === 'pages') {
    $('assetsTableHead').innerHTML = '<th>URL</th><th>DEPTH</th><th>STATUS</th>';
    rows = state.pages.length
      ? state.pages.map(p => `<tr>
          <td class="url-cell" title="${esc(p.url)}">${esc(p.url)}</td>
          <td>${p.depth}</td>
          <td>${p.statusCode || '—'}</td>
        </tr>`).join('')
      : '<tr class="empty-row"><td colspan="3">No pages crawled yet.</td></tr>';

  } else if (tab === 'scripts') {
    $('assetsTableHead').innerHTML = '<th>JavaScript File URL</th>';
    rows = state.scripts.length
      ? state.scripts.map(s => `<tr><td class="url-cell" title="${esc(s.url)}">${esc(s.url)}</td></tr>`).join('')
      : '<tr class="empty-row"><td colspan="1">No scripts found yet.</td></tr>';

  } else if (tab === 'api') {
    $('assetsTableHead').innerHTML = '<th>API Call URL</th><th>METHOD</th>';
    rows = state.apiCalls.length
      ? state.apiCalls.map(a => `<tr>
          <td class="url-cell" title="${esc(a.url)}">${esc(a.url)}</td>
          <td>${esc(a.method || 'GET')}</td>
        </tr>`).join('')
      : '<tr class="empty-row"><td colspan="2">No API calls captured yet.</td></tr>';
  }

  dom.assetsTbody.innerHTML = rows;
}

function attachDetailButtons() {
  dom.findingsTbody.querySelectorAll('.btn-detail').forEach(btn => {
    btn.addEventListener('click', () => openDetailModal(btn.dataset.id));
  });
}

function openDetailModal(findingId) {
  const f = state.findings.find(x => x.id === findingId);
  if (!f) return;

  dom.modalTitle.textContent = `${f.icon || '🔑'} ${f.service || f.serviceName} — Finding Detail`;

  const remediation = Array.isArray(f.remediation) && f.remediation.length
    ? `<ul class="remediation-list">${f.remediation.map(r => `<li>${esc(r)}</li>`).join('')}</ul>`
    : '<p style="color:var(--muted)">No remediation data available.</p>';

  const vr = f.validationResult;
  const vrHtml = vr
    ? `<div class="validation-result-block">
        <div class="vr-status">${validationBadge(vr.status)}</div>
        <div class="vr-detail">
          ${vr.message ? `<div>Message: ${esc(vr.message)}</div>` : ''}
          ${vr.user    ? `<div>User: ${esc(vr.user)}</div>` : ''}
          ${vr.accountId ? `<div>Account ID: ${esc(vr.accountId)}</div>` : ''}
          ${vr.arn     ? `<div>ARN: ${esc(vr.arn)}</div>` : ''}
          ${vr.scopes  ? `<div>Scopes: ${esc((vr.scopes || []).join(', '))}</div>` : ''}
          ${vr.keyType ? `<div>Key Type: ${esc(vr.keyType)}</div>` : ''}
          ${vr.note    ? `<div>Note: ${esc(vr.note)}</div>` : ''}
          ${vr.testedAt ? `<div style="color:var(--muted)">Tested: ${esc(vr.testedAt)}</div>` : ''}
        </div>
      </div>`
    : '<p style="color:var(--muted)">Not yet validated.</p>';

  dom.modalBody.innerHTML = `
    <div class="detail-grid">
      <div class="detail-field">
        <div class="df-label">Service</div>
        <div class="df-value">${esc(f.icon || '')} ${esc(f.service || f.serviceName || '')}</div>
      </div>
      <div class="detail-field">
        <div class="df-label">Risk Level</div>
        <div class="df-value"><span class="badge-risk ${esc(f.riskLevel)}">${esc((f.riskLevel || '').toUpperCase())}</span></div>
      </div>
      <div class="detail-field">
        <div class="df-label">Masked Value</div>
        <div class="df-value accent">${esc(f.masked || '')}</div>
      </div>
      <div class="detail-field">
        <div class="df-label">Confidence</div>
        <div class="df-value">${esc(f.confidence || '')}</div>
      </div>
      <div class="detail-field">
        <div class="df-label">Source Type</div>
        <div class="df-value">${esc(f.sourceType || '')}</div>
      </div>
      <div class="detail-field">
        <div class="df-label">Line Number</div>
        <div class="df-value">${f.lineNumber || '—'}</div>
      </div>
      ${f.cweId ? `<div class="detail-field">
        <div class="df-label">CWE</div>
        <div class="df-value">${esc(f.cweId)}</div>
      </div>` : ''}
      <div class="detail-field">
        <div class="df-label">Found At</div>
        <div class="df-value">${esc(f.foundAt || '')}</div>
      </div>
    </div>
    <div class="detail-field" style="margin-bottom:12px">
      <div class="df-label">Source URL</div>
      <div class="df-value">${esc(f.sourceUrl || '')}</div>
    </div>
    ${f.context ? `<div class="detail-section">
      <h4>Context (surrounding code)</h4>
      <div class="context-block">${esc(f.context)}</div>
    </div>` : ''}
    ${f.impact ? `<div class="detail-section">
      <h4>Impact</h4>
      <p style="font-size:12px;color:var(--text);line-height:1.6">${esc(f.impact)}</p>
    </div>` : ''}
    <div class="detail-section">
      <h4>Validation Result</h4>
      ${vrHtml}
    </div>
    <div class="detail-section">
      <h4>Remediation Steps</h4>
      ${remediation}
    </div>
  `;

  dom.detailModal.classList.remove('hidden');
}

function closeModal() {
  dom.detailModal.classList.add('hidden');
}

// ── History ───────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const scans = await window.sentinel.invoke('scan:get-history', {});
    if (!scans || scans.length === 0) {
      dom.historyTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No scan history found.</td></tr>';
      return;
    }
    dom.historyTbody.innerHTML = scans.map(s => `
      <tr>
        <td class="url-cell" title="${esc(s.target_url)}">${esc(s.target_url)}</td>
        <td>${esc(s.scan_mode)}</td>
        <td>${esc(s.started_at || '')}</td>
        <td><span class="status-badge ${esc(s.status)}">${esc(s.status?.toUpperCase())}</span></td>
        <td><button class="btn-detail" onclick="loadScanResults('${esc(s.id)}')">LOAD</button></td>
      </tr>
    `).join('');
  } catch (err) {
    dom.historyTbody.innerHTML = `<tr class="empty-row"><td colspan="5">Error loading history: ${esc(err.message)}</td></tr>`;
  }
}

window.loadScanResults = async (scanId) => {
  try {
    const { scan, findings, pages } = await window.sentinel.invoke('scan:get-results', { scanId });
    state.activeScanId = scanId;
    state.findings     = findings.map(f => ({
      ...f,
      riskLevel:       f.risk_level,
      serviceName:     f.service_name,
      sourceUrl:       f.source_url,
      sourceType:      f.source_type,
      lineNumber:      f.line_number,
      validationStatus: f.validation_status,
    }));
    state.pages = pages;

    state.riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of state.findings) {
      state.riskCounts[f.riskLevel] = (state.riskCounts[f.riskLevel] || 0) + 1;
    }

    renderFindingsTable();
    renderAssetsTable();
    updateRiskBars();
    dom.exportSection.style.display = '';
    dom.riskSummary.style.display   = '';
    dom.findingsCount.textContent   = findings.length;
    showToast(`Loaded ${findings.length} findings from scan.`, 'info');
    switchView('findings');
  } catch (err) {
    showToast(`Error loading scan: ${err.message}`, 'error');
  }
};

// ── Terminal Helpers ──────────────────────────────────────────────────────
function log(type, message, subClass = '') {
  const welcome = dom.terminalLog.querySelector('.terminal-welcome');
  if (welcome) welcome.remove();

  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const line = document.createElement('div');
  line.className = 'log-line';

  const tagClassMap = {
    info: 'info', page: 'page', script: 'script',
    key: `key ${subClass}`, valid: 'valid', invalid: 'invalid',
    error: 'error', complete: 'complete',
  };
  const tagClass = tagClassMap[type] || 'info';
  const tagText  = type.toUpperCase().padEnd(7);

  line.innerHTML = `
    <span class="log-ts">${esc(ts)}</span>
    <span class="log-tag ${tagClass}">${esc(tagText)}</span>
    <span class="log-msg">${esc(message)}</span>
  `;

  dom.terminalLog.appendChild(line);

  // Keep max 2000 lines
  const lines = dom.terminalLog.querySelectorAll('.log-line');
  if (lines.length > 2000) lines[0].remove();

  dom.terminalLog.scrollTop = dom.terminalLog.scrollHeight;
}

function clearTerminal() {
  dom.terminalLog.innerHTML = '';
}

// ── UI State Helpers ──────────────────────────────────────────────────────
function setStatus(state, label) {
  dom.statusDot.className = `status-dot ${state}`;
  dom.statusLabel.textContent = label;
}

function setProgress(pct) {
  state.progressPct = pct;
  dom.progressBar.style.width = `${Math.min(100, pct)}%`;
}

function scanFinished(status) {
  dom.btnStart.disabled = false;
  dom.btnStop.classList.add('hidden');
  dom.exportSection.style.display = '';

  const labelMap = { complete: 'COMPLETE', stopped: 'STOPPED', error: 'ERROR' };
  setStatus(status, labelMap[status] || 'IDLE');
}

function updateRiskBars() {
  const total = Math.max(1, Object.values(state.riskCounts).reduce((a, b) => a + b, 0));

  for (const level of ['critical', 'high', 'medium', 'low']) {
    const count = state.riskCounts[level] || 0;
    const pct   = (count / total * 100).toFixed(1);
    dom[`bar${cap(level)}`].style.width = `${pct}%`;
    dom[`cnt${cap(level)}`].textContent = count;
  }
}

function switchView(name) {
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.view === name);
  });
  document.querySelectorAll('.view').forEach(v => {
    v.classList.toggle('active', v.id === `view-${name}`);
  });
}

// ── Utility ───────────────────────────────────────────────────────────────
function validationBadge(status) {
  const labels = {
    valid:        '✓ VALID',
    invalid:      '✗ INVALID',
    restricted:   '⚠ RESTRICTED',
    rate_limited: '⏳ RATE LIMITED',
    skipped:      '— SKIPPED',
    error:        '! ERROR',
    unknown:      '? UNKNOWN',
  };
  const s = status || 'unknown';
  return `<span class="badge-val ${s}">${labels[s] || s.toUpperCase()}</span>`;
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function truncate(s, n) {
  return s && s.length > n ? s.slice(0, n) + '…' : (s || '');
}

function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : ''; }

let toastTimer;
function showToast(msg, type = 'info') {
  dom.toast.textContent = msg;
  dom.toast.className   = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => dom.toast.classList.add('hidden'), 3500);
}

// ── Init ──────────────────────────────────────────────────────────────────
(async function init() {
  // Populate history on load
  await loadHistory();
})();
