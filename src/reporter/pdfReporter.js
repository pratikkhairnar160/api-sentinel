/**
 * reporter/pdfReporter.js — PDF security report using PDFKit
 */
'use strict';

const PDFDocument = require('pdfkit');
const fs          = require('fs');
const path        = require('path');

const COLORS = {
  bg:       '#0d1117',
  surface:  '#161b22',
  accent:   '#58a6ff',
  text:     '#e6edf3',
  muted:    '#8b949e',
  critical: '#ff4444',
  high:     '#ff8800',
  medium:   '#ffcc00',
  low:      '#44bb44',
  border:   '#30363d',
};

const RISK_COLOR = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };

/**
 * @param {object} scanData  — { scan, findings, pages, scripts, summary }
 * @param {string} outputDir
 * @returns {Promise<string>} file path
 */
function writePdfReport(scanData, outputDir) {
  return new Promise((resolve, reject) => {
    const { scan, findings, pages, summary } = scanData;
    const filename = `api-sentinel-report-${scan.id.slice(0, 8)}-${Date.now()}.pdf`;
    const filePath = path.join(outputDir, filename);

    const doc = new PDFDocument({ size: 'A4', margin: 50, theme: 'dark' });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);
    stream.on('finish', () => resolve(filePath));
    stream.on('error', reject);

    // ─── Cover Page ───────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');

    doc.rect(50, 80, doc.page.width - 100, 6).fill(COLORS.accent);

    doc.fillColor(COLORS.accent).font('Helvetica-Bold').fontSize(28)
       .text('APISentinel', 50, 110);
    doc.fillColor(COLORS.text).fontSize(16)
       .text('API Key Security Assessment Report', 50, 148);

    doc.rect(50, 185, doc.page.width - 100, 1).fill(COLORS.border);

    doc.fillColor(COLORS.muted).fontSize(11).font('Helvetica')
       .text('Target:', 50, 205)
       .text('Scan ID:', 50, 223)
       .text('Started:', 50, 241)
       .text('Generated:', 50, 259);

    doc.fillColor(COLORS.text)
       .text(scan.target_url || '—', 150, 205)
       .text(scan.id || '—', 150, 223)
       .text(scan.started_at || '—', 150, 241)
       .text(new Date().toLocaleString(), 150, 259);

    // Warning box
    doc.rect(50, 290, doc.page.width - 100, 36).fill('#2d1b00');
    doc.rect(50, 290, 4, 36).fill(COLORS.high);
    doc.fillColor(COLORS.high).fontSize(10).font('Helvetica-Bold')
       .text('CONFIDENTIAL — AUTHORIZED SECURITY ASSESSMENT ONLY', 62, 302);
    doc.fillColor('#ffb347').font('Helvetica').fontSize(9)
       .text('Do not distribute. Contains sensitive security findings.', 62, 314);

    // ─── Summary Boxes ────────────────────────────────────────────────────
    doc.addPage();
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');

    _sectionHeader(doc, 'Executive Summary', 50);

    const stats = [
      { label: 'Total',    count: summary.total,                    color: COLORS.accent },
      { label: 'Critical', count: summary.bySeverity.critical || 0, color: COLORS.critical },
      { label: 'High',     count: summary.bySeverity.high     || 0, color: COLORS.high },
      { label: 'Medium',   count: summary.bySeverity.medium   || 0, color: COLORS.medium },
      { label: 'Low',      count: summary.bySeverity.low      || 0, color: COLORS.low },
      { label: 'Valid',    count: summary.validated?.valid     || 0, color: '#3fb950' },
    ];

    const boxW = 80;
    const boxH = 60;
    const startX = 50;
    let bx = startX;
    const by = 100;

    for (const s of stats) {
      doc.rect(bx, by, boxW, boxH).fill(COLORS.surface);
      doc.rect(bx, by, boxW, 3).fill(s.color);
      doc.fillColor(s.color).fontSize(24).font('Helvetica-Bold')
         .text(String(s.count), bx, by + 12, { width: boxW, align: 'center' });
      doc.fillColor(COLORS.muted).fontSize(9).font('Helvetica')
         .text(s.label, bx, by + 42, { width: boxW, align: 'center' });
      bx += boxW + 10;
    }

    // Pages / Scripts row
    doc.fillColor(COLORS.muted).fontSize(10).font('Helvetica')
       .text(`Pages Crawled: ${pages.length}   |   JS Files: ${scanData.scripts?.length || 0}   |   Mode: ${scan.scan_mode}`,
         50, by + 80);

    // ─── Findings Table ───────────────────────────────────────────────────
    _sectionHeader(doc, 'Findings', by + 110);

    const headers = ['#', 'Risk', 'Service', 'Masked Key', 'Source URL', 'Validation'];
    const colW    = [28, 55, 110, 100, 140, 75];
    let y = by + 150;

    // Table header row
    doc.rect(50, y - 4, doc.page.width - 100, 20).fill(COLORS.surface);
    let hx = 50;
    for (let i = 0; i < headers.length; i++) {
      doc.fillColor(COLORS.muted).fontSize(9).font('Helvetica-Bold')
         .text(headers[i].toUpperCase(), hx + 4, y, { width: colW[i] - 4 });
      hx += colW[i];
    }
    y += 20;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      if (y > 750) {
        doc.addPage();
        doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
        y = 50;
      }

      const rColor = RISK_COLOR[f.risk_level] || COLORS.muted;

      if (i % 2 === 0) doc.rect(50, y - 2, doc.page.width - 100, 18).fill('#0f1419');

      let cx = 50;
      const cells = [
        { text: String(i + 1), color: COLORS.muted },
        { text: (f.risk_level || '').toUpperCase(), color: rColor },
        { text: f.service_name || '', color: COLORS.text },
        { text: f.value_masked || '', color: '#79c0ff' },
        { text: truncate(f.source_url || '', 32), color: COLORS.muted },
        { text: f.validation_status || '—', color: COLORS.muted },
      ];

      for (let j = 0; j < cells.length; j++) {
        doc.fillColor(cells[j].color).fontSize(8).font(j === 1 ? 'Helvetica-Bold' : 'Helvetica')
           .text(cells[j].text, cx + 4, y, { width: colW[j] - 6, ellipsis: true, lineBreak: false });
        cx += colW[j];
      }
      y += 18;
    }

    // ─── Remediation section ──────────────────────────────────────────────
    const criticalAndHigh = findings.filter(f => ['critical','high'].includes(f.risk_level)).slice(0, 8);
    if (criticalAndHigh.length > 0) {
      doc.addPage();
      doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
      _sectionHeader(doc, 'Remediation Guidance (Critical & High)', 50);
      let ry = 90;

      for (const f of criticalAndHigh) {
        if (ry > 700) { doc.addPage(); doc.rect(0,0,doc.page.width,doc.page.height).fill('#0d1117'); ry = 50; }
        const rColor = RISK_COLOR[f.risk_level] || COLORS.muted;
        doc.rect(50, ry, 4, 14).fill(rColor);
        doc.fillColor(COLORS.text).fontSize(11).font('Helvetica-Bold')
           .text(`${f.service_name} — ${f.value_masked}`, 60, ry);
        ry += 18;

        if (Array.isArray(f.remediation)) {
          for (const step of f.remediation.slice(0, 4)) {
            doc.fillColor(COLORS.muted).fontSize(9).font('Helvetica')
               .text(`• ${step}`, 64, ry, { width: doc.page.width - 114 });
            ry += 14;
          }
        }
        ry += 8;
      }
    }

    doc.end();
  });
}

function _sectionHeader(doc, title, y) {
  doc.fillColor(COLORS.accent).fontSize(14).font('Helvetica-Bold').text(title, 50, y);
  doc.rect(50, y + 20, doc.page.width - 100, 1).fill(COLORS.border);
}

function truncate(s, n) { return s && s.length > n ? s.slice(0, n) + '…' : (s || ''); }

module.exports = { writePdfReport };
