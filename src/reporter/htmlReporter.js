/**
 * reporter/htmlReporter.js — Professional HTML security report
 */
'use strict';

const fs = require('fs');
const path = require('path');

const RISK_COLORS = {
  critical: '#ff4444',
  high:     '#ff8800',
  medium:   '#ffcc00',
  low:      '#44bb44',
  unknown:  '#888888',
};

const VALIDATION_BADGES = {
  valid:        '<span class="badge valid">✓ VALID</span>',
  invalid:      '<span class="badge invalid">✗ INVALID</span>',
  restricted:   '<span class="badge restricted">⚠ RESTRICTED</span>',
  rate_limited: '<span class="badge rate-limited">⏳ RATE LIMITED</span>',
  skipped:      '<span class="badge skipped">— SKIPPED</span>',
  error:        '<span class="badge error">! ERROR</span>',
  unknown:      '<span class="badge unknown">? UNKNOWN</span>',
};

function writeHtmlReport(scanData, outputDir) {
  const { scan, findings, pages, scripts, summary } = scanData;
  const filename = `api-sentinel-report-${scan.id.slice(0, 8)}-${Date.now()}.html`;
  const filePath = path.join(outputDir, filename);

  const html = buildHtml(scan, findings, pages, scripts, summary);
  fs.writeFileSync(filePath, html, 'utf8');
  return filePath;
}

function buildHtml(scan, findings, pages, scripts, summary) {
  const generatedAt = new Date().toLocaleString();
  const findingRows = findings.map(f => buildFindingRow(f)).join('');
  const pageRows    = pages.slice(0, 200).map(p =>
    `<tr><td>${esc(p.url)}</td><td>${p.depth}</td><td>${p.status_code || '—'}</td></tr>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APISentinel Security Report — ${esc(scan.target_url)}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --critical: #ff4444; --high: #ff8800; --medium: #ffcc00; --low: #44bb44;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 24px 40px; }
  header h1 { font-size: 22px; color: var(--accent); letter-spacing: -0.5px; }
  header .meta { color: var(--muted); font-size: 12px; margin-top: 6px; }
  .warning-banner { background: #2d1b00; border: 1px solid #ff8800; color: #ffb347;
    padding: 12px 40px; font-size: 12px; letter-spacing: 0.3px; }
  main { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }
  h2 { font-size: 16px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 10px; margin: 32px 0 16px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .stat-card .number { font-size: 36px; font-weight: 700; }
  .stat-card .label  { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  .stat-card.critical .number { color: var(--critical); }
  .stat-card.high     .number { color: var(--high); }
  .stat-card.medium   .number { color: var(--medium); }
  .stat-card.low      .number { color: var(--low); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: var(--surface); text-align: left; padding: 10px 12px; color: var(--muted);
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top; word-break: break-all; }
  tr:hover td { background: #1c2128; }
  .risk { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #000; }
  .risk.critical { background: var(--critical); }
  .risk.high     { background: var(--high); }
  .risk.medium   { background: var(--medium); }
  .risk.low      { background: var(--low); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge.valid      { background: #1a4731; color: #3fb950; border: 1px solid #3fb950; }
  .badge.invalid    { background: #2d1b1b; color: #ff7b7b; border: 1px solid #ff4444; }
  .badge.restricted { background: #2d2400; color: #ffa500; border: 1px solid #ff8800; }
  .badge.skipped, .badge.unknown { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
  .badge.error      { background: #2d1b2d; color: #ff7bff; border: 1px solid #cc44cc; }
  .code { font-family: 'Fira Code', 'Consolas', monospace; background: #0d1117; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #79c0ff; }
  .context { font-family: monospace; font-size: 11px; color: var(--muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  details summary { cursor: pointer; color: var(--accent); font-size: 12px; margin-bottom: 6px; }
  details ul { padding-left: 20px; color: var(--muted); font-size: 12px; line-height: 1.8; }
  footer { text-align: center; color: var(--muted); font-size: 11px; padding: 40px; border-top: 1px solid var(--border); margin-top: 60px; }
</style>
</head>
<body>
<header>
  <h1>🔐 APISentinel — Security Assessment Report</h1>
  <div class="meta">
    Target: <strong>${esc(scan.target_url)}</strong> &nbsp;|&nbsp;
    Scan ID: <code>${scan.id}</code> &nbsp;|&nbsp;
    Started: ${scan.started_at} &nbsp;|&nbsp;
    Generated: ${generatedAt}
  </div>
</header>
<div class="warning-banner">
  ⚠ CONFIDENTIAL — This report contains sensitive security findings. Authorized use only. Do not distribute.
</div>
<main>
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat-card"><div class="number">${summary.total}</div><div class="label">Total Findings</div></div>
    <div class="stat-card critical"><div class="number">${summary.bySeverity.critical || 0}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="number">${summary.bySeverity.high || 0}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="number">${summary.bySeverity.medium || 0}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="number">${summary.bySeverity.low || 0}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="number">${pages.length}</div><div class="label">Pages Crawled</div></div>
    <div class="stat-card"><div class="number">${scripts.length}</div><div class="label">JS Files</div></div>
    <div class="stat-card"><div class="number">${summary.validated?.valid || 0}</div><div class="label">Keys Confirmed Valid</div></div>
  </div>

  <h2>Findings (${findings.length})</h2>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Risk</th><th>Service</th><th>Masked Value</th>
        <th>Found In</th><th>Line</th><th>Validation</th><th>CWE</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>${findingRows}</tbody>
  </table>

  <h2>Crawled Pages (${pages.length})</h2>
  <table>
    <thead><tr><th>URL</th><th>Depth</th><th>Status</th></tr></thead>
    <tbody>${pageRows}</tbody>
  </table>
</main>
<footer>
  Generated by APISentinel v1.0.0 &nbsp;|&nbsp; ${generatedAt} &nbsp;|&nbsp;
  For authorized security testing only — CWE-798 / OWASP A07
</footer>
</body>
</html>`;
}

function buildFindingRow(f, index) {
  const risk = f.risk_level || 'unknown';
  const validBadge = VALIDATION_BADGES[f.validation_status] || VALIDATION_BADGES.unknown;
  const cwe = f.cwe_id ? `<a href="https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-','')}.html" style="color:#58a6ff">${f.cwe_id}</a>` : '—';
  const remediation = Array.isArray(f.remediation) && f.remediation.length
    ? `<details><summary>View (${f.remediation.length})</summary><ul>${f.remediation.map(r => `<li>${esc(r)}</li>`).join('')}</ul></details>`
    : '—';

  return `<tr>
    <td>${(index || 0) + 1}</td>
    <td><span class="risk ${risk}">${risk.toUpperCase()}</span></td>
    <td>${esc(f.service_name || '')}</td>
    <td><code class="code">${esc(f.value_masked || '')}</code></td>
    <td title="${esc(f.source_url || '')}"><code class="code">${esc(truncate(f.source_url, 60))}</code></td>
    <td>${f.line_number || '—'}</td>
    <td>${validBadge}</td>
    <td>${cwe}</td>
    <td>${remediation}</td>
  </tr>`;
}

function esc(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function truncate(s, n) { return s && s.length > n ? s.slice(0, n) + '…' : (s || ''); }

module.exports = { writeHtmlReport };
