/**
 * patternEngine.js
 * Scans HTML / JS source against all known key patterns
 * Returns structured findings with context
 */

'use strict';

const { PATTERNS } = require('./patterns');

/**
 * Extract surrounding code context for a match
 * @param {string} source
 * @param {number} matchIndex
 * @param {number} contextChars
 * @returns {string}
 */
function extractContext(source, matchIndex, contextChars = 120) {
  const start = Math.max(0, matchIndex - contextChars);
  const end = Math.min(source.length, matchIndex + contextChars);
  return source.slice(start, end).replace(/\n/g, ' ').trim();
}

/**
 * Get line number for a given character index in source
 */
function getLineNumber(source, index) {
  return source.substring(0, index).split('\n').length;
}

/**
 * Mask a secret value for safe display (first 6 chars + ***)
 * @param {string} value
 * @returns {string}
 */
function maskSecret(value) {
  if (!value || value.length < 6) return '***';
  return value.slice(0, 6) + '*'.repeat(Math.min(value.length - 6, 20));
}

/**
 * Scan source code against all registered patterns
 * @param {string} source     — raw source text (HTML or JS)
 * @param {string} sourceUrl  — origin URL for attribution
 * @param {string} sourceType — 'html' | 'js' | 'inline'
 * @returns {Array<Finding>}
 */
function scanSource(source, sourceUrl, sourceType = 'js') {
  const findings = [];
  const seen = new Set();

  for (const pattern of PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.regex.lastIndex = 0;

    let match;
    while ((match = pattern.regex.exec(source)) !== null) {
      // Use capture group 1 if present (for contextual patterns), else full match
      const rawValue = match[1] || match[0];

      // Dedup by value + pattern id
      const dedupKey = `${pattern.id}:${rawValue}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      findings.push({
        id: `find_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        patternId:   pattern.id,
        serviceName: pattern.name,
        riskLevel:   pattern.riskLevel,
        confidence:  pattern.confidence,
        value:       rawValue,
        masked:      maskSecret(rawValue),
        context:     extractContext(source, match.index),
        lineNumber:  getLineNumber(source, match.index),
        sourceUrl,
        sourceType,
        docs:        pattern.docs,
        foundAt:     new Date().toISOString(),
        validated:   null,   // populated later by validator
        validationResult: null,
      });
    }

    // Reset for next iteration
    pattern.regex.lastIndex = 0;
  }

  return findings;
}

/**
 * Batch scan multiple sources
 * @param {Array<{ source: string, url: string, type: string }>} sources
 * @returns {Array<Finding>}
 */
function batchScan(sources) {
  const all = [];
  const globalSeen = new Set();

  for (const { source, url, type } of sources) {
    const findings = scanSource(source, url, type);
    for (const f of findings) {
      // Global dedup across all sources
      const key = `${f.patternId}:${f.value}`;
      if (!globalSeen.has(key)) {
        globalSeen.add(key);
        all.push(f);
      }
    }
  }

  return all;
}

module.exports = { scanSource, batchScan, maskSecret };
