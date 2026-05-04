/**
 * analyzer/index.js — Orchestrates pattern + entropy analysis
 */

'use strict';

const { scanSource, batchScan } = require('./patternEngine');
const { extractHighEntropyStrings } = require('./entropyDetector');
const logger = require('../utils/logger');

/**
 * Analyze a single source (HTML or JS)
 * Combines pattern-based and entropy-based detection
 * @param {string} source
 * @param {string} url
 * @param {'html'|'js'|'inline'} type
 * @returns {{ patternFindings: Array, entropyFindings: Array }}
 */
function analyzeSource(source, url, type = 'js') {
  const patternFindings = scanSource(source, url, type);
  const entropyFindings = extractHighEntropyStrings(source).map(e => ({
    id: `entropy_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    patternId: 'entropy_heuristic',
    serviceName: 'Unknown (Entropy Detection)',
    riskLevel: 'medium',
    confidence: 'low',
    value: e.value,
    masked: e.value.slice(0, 6) + '***',
    context: `Variable: ${e.key} | ${e.reason}`,
    lineNumber: e.lineNumber,
    sourceUrl: url,
    sourceType: type,
    docs: null,
    foundAt: new Date().toISOString(),
    validated: null,
    validationResult: null,
    entropyScore: e.entropy,
  }));

  logger.debug(`[Analyzer] ${url} → ${patternFindings.length} pattern hits, ${entropyFindings.length} entropy hits`);
  return { patternFindings, entropyFindings };
}

/**
 * Analyze multiple pages
 * @param {Array<{ source: string, url: string, type: string }>} pages
 * @returns {Array<Finding>}
 */
function analyzeAll(pages) {
  const allFindings = [];
  for (const page of pages) {
    const { patternFindings, entropyFindings } = analyzeSource(page.source, page.url, page.type);
    allFindings.push(...patternFindings, ...entropyFindings);
  }
  return allFindings;
}

module.exports = { analyzeSource, analyzeAll };
