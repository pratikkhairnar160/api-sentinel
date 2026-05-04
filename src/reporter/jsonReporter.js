/**
 * reporter/jsonReporter.js — Structured JSON report output
 */
'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Write a JSON report for a completed scan
 * @param {object} scanData  — { scan, findings, pages, scripts, summary }
 * @param {string} outputDir — destination directory
 * @returns {string} full path to written file
 */
function writeJsonReport(scanData, outputDir) {
  const { scan, findings, pages, scripts, summary } = scanData;
  const filename = `api-sentinel-report-${scan.id.slice(0, 8)}-${Date.now()}.json`;
  const filePath = path.join(outputDir, filename);

  const report = {
    meta: {
      tool: 'APISentinel',
      version: '1.0.0',
      generatedAt: new Date().toISOString(),
      disclaimer: 'This report is for authorized security testing purposes only.',
    },
    scan: {
      id:         scan.id,
      targetUrl:  scan.target_url,
      mode:       scan.scan_mode,
      status:     scan.status,
      startedAt:  scan.started_at,
      finishedAt: scan.finished_at,
    },
    summary,
    findings: findings.map(f => ({
      id:               f.id,
      service:          f.service_name,
      category:         f.category,
      riskLevel:        f.risk_level,
      confidence:       f.confidence,
      foundAt:          f.source_url,
      lineNumber:       f.line_number,
      maskedValue:      f.value_masked,
      cweId:            f.cwe_id,
      validationStatus: f.validation_status,
      validationResult: f.validationResult,
      impact:           f.impact,
      remediation:      f.remediation,
    })),
    assets: {
      totalPages:   pages.length,
      totalScripts: scripts.length,
      pages:        pages.map(p => ({ url: p.url, depth: p.depth, status: p.status_code })),
    },
  };

  fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf8');
  return filePath;
}

module.exports = { writeJsonReport };
