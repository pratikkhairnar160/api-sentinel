/**
 * classifier/index.js
 * Enriches raw findings with service metadata and risk context
 */

'use strict';

const { SERVICE_MAP } = require('./serviceMap');

const RISK_SCORE = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Enrich a single finding with service classification metadata
 * @param {Finding} finding
 * @returns {EnrichedFinding}
 */
function classifyFinding(finding) {
  const meta = SERVICE_MAP[finding.patternId] || SERVICE_MAP['generic_api_key'];
  const riskScore = RISK_SCORE[finding.riskLevel] || 1;

  return {
    ...finding,
    service: meta.service,
    category: meta.category,
    icon: meta.icon,
    impact: meta.impact,
    remediation: meta.remediation,
    cweId: meta.cweId,
    riskScore,
    riskBadge: getRiskBadge(finding.riskLevel),
  };
}

/**
 * Classify an array of findings
 * @param {Finding[]} findings
 * @returns {EnrichedFinding[]}
 */
function classifyAll(findings) {
  return findings
    .map(classifyFinding)
    .sort((a, b) => b.riskScore - a.riskScore); // Highest risk first
}

/**
 * Summarize findings into category counts
 */
function summarize(findings) {
  const summary = {
    total: findings.length,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    byService: {},
    byCategory: {},
    validated: { valid: 0, invalid: 0, restricted: 0, unknown: 0 },
  };

  for (const f of findings) {
    summary.bySeverity[f.riskLevel] = (summary.bySeverity[f.riskLevel] || 0) + 1;
    summary.byService[f.service] = (summary.byService[f.service] || 0) + 1;
    summary.byCategory[f.category] = (summary.byCategory[f.category] || 0) + 1;

    if (f.validationResult) {
      const status = f.validationResult.status || 'unknown';
      summary.validated[status] = (summary.validated[status] || 0) + 1;
    }
  }

  return summary;
}

function getRiskBadge(level) {
  const badges = {
    critical: '🔴 CRITICAL',
    high:     '🟠 HIGH',
    medium:   '🟡 MEDIUM',
    low:      '🟢 LOW',
  };
  return badges[level] || '⚪ UNKNOWN';
}

module.exports = { classifyFinding, classifyAll, summarize };
