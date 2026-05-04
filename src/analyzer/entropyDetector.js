/**
 * entropyDetector.js
 * Shannon entropy-based detection of high-randomness strings
 * (API keys, secrets, tokens that don't match known patterns)
 */

'use strict';

const MIN_ENTROPY = 3.5;     // Minimum entropy threshold
const MIN_LENGTH = 20;       // Ignore short strings
const MAX_LENGTH = 200;      // Ignore very long strings (base64 blobs, etc.)

// Character sets for entropy calculation
const CHAR_SETS = {
  hex:          /^[0-9a-fA-F]+$/,
  base64:       /^[A-Za-z0-9+/=]+$/,
  base64url:    /^[A-Za-z0-9\-_=]+$/,
  alphanumeric: /^[A-Za-z0-9]+$/,
  mixed:        /^[A-Za-z0-9!@#$%^&*_\-+=.]+$/,
};

// Context keywords that indicate a value is likely a secret
const SECRET_CONTEXT_KEYWORDS = [
  'key', 'secret', 'token', 'pass', 'auth', 'cred',
  'api', 'access', 'private', 'bearer', 'hash',
];

/**
 * Calculate Shannon entropy of a string
 * @param {string} str
 * @returns {number} entropy bits per character
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Determine whether a string looks like a high-entropy secret
 * @param {string} value  — the candidate string value
 * @param {string} [key]  — optional variable name / context key
 * @returns {{ isSecret: boolean, entropy: number, reason: string }}
 */
function analyzeEntropy(value, key = '') {
  const len = value.length;

  if (len < MIN_LENGTH || len > MAX_LENGTH) {
    return { isSecret: false, entropy: 0, reason: 'length out of range' };
  }

  // Skip common non-secret patterns
  if (isLikelyNonSecret(value)) {
    return { isSecret: false, entropy: 0, reason: 'matches non-secret heuristic' };
  }

  const entropy = shannonEntropy(value);
  const hasSecretContext = SECRET_CONTEXT_KEYWORDS.some(kw =>
    key.toLowerCase().includes(kw)
  );
  const charSetMatch = matchCharSet(value);
  const threshold = hasSecretContext ? MIN_ENTROPY - 0.5 : MIN_ENTROPY;

  if (entropy >= threshold && charSetMatch) {
    return {
      isSecret: true,
      entropy: parseFloat(entropy.toFixed(3)),
      reason: `High entropy (${entropy.toFixed(2)} bits), charset: ${charSetMatch}${hasSecretContext ? ', secret context' : ''}`,
    };
  }

  return {
    isSecret: false,
    entropy: parseFloat(entropy.toFixed(3)),
    reason: `Low entropy (${entropy.toFixed(2)} bits)`,
  };
}

/**
 * Match the character set of a string
 */
function matchCharSet(str) {
  for (const [name, re] of Object.entries(CHAR_SETS)) {
    if (re.test(str)) return name;
  }
  return null;
}

/**
 * Heuristics to filter out obvious non-secrets:
 * - URLs, file paths, version strings, UUIDs, etc.
 */
function isLikelyNonSecret(value) {
  const nonSecretPatterns = [
    /^https?:\/\//i,                              // URL
    /^\//,                                         // File path
    /^[0-9]+\.[0-9]+\.[0-9]+/,                   // Version string
    /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i, // UUID
    /^[a-z]+(-[a-z]+)+$/i,                        // kebab-case identifier
    /^[a-z]+(_[a-z]+)+$/i,                        // snake_case identifier
    /^\d+$/,                                       // Pure number
    /^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/i, // Email
    /^#[0-9a-f]{3,8}$/i,                          // Hex color
    /^rgba?\(/i,                                   // CSS color
    /\.(js|css|html|jpg|png|svg|woff|ttf)$/i,     // File extension
  ];
  return nonSecretPatterns.some(re => re.test(value));
}

/**
 * Scan a block of text and extract high-entropy string candidates
 * Looks for assignments like:  key = "VALUE",  'key': 'VALUE', etc.
 * @param {string} source
 * @returns {Array<{ key: string, value: string, entropy: number, lineNumber: number }>}
 */
function extractHighEntropyStrings(source) {
  const results = [];
  const lines = source.split('\n');

  // Matches: varname = "value"  |  varname: 'value'  |  varname = `value`
  const assignRe = /(?:^|[,{;\s])([a-zA-Z_][a-zA-Z0-9_]*)[\s]*[=:][\s]*['"`]([^'"`\s]{20,200})['"`]/gm;

  let match;
  while ((match = assignRe.exec(source)) !== null) {
    const [, contextKey, value] = match;
    const analysis = analyzeEntropy(value, contextKey);
    if (analysis.isSecret) {
      // Approximate line number
      const lineNumber = source.substring(0, match.index).split('\n').length;
      results.push({
        key: contextKey,
        value,
        entropy: analysis.entropy,
        reason: analysis.reason,
        lineNumber,
      });
    }
  }

  // Deduplicate by value
  const seen = new Set();
  return results.filter(r => {
    if (seen.has(r.value)) return false;
    seen.add(r.value);
    return true;
  });
}

module.exports = { shannonEntropy, analyzeEntropy, extractHighEntropyStrings };
