/**
 * validator/services/generic.js
 * Generic heuristic validation — used when service type is unknown
 * Checks entropy, format, and known prefix patterns
 */

'use strict';

const { BaseValidator, STATUS } = require('../base');
const { shannonEntropy } = require('../../analyzer/entropyDetector');

class GenericValidator extends BaseValidator {
  constructor(options = {}) {
    super('generic_api_key', 'Generic / Unknown', options);
  }

  /**
   * For unknown keys — we skip live probing and do static analysis only
   * Risk assessment is based on entropy, format, and context
   */
  async probe(key) {
    const entropy = shannonEntropy(key);
    const len = key.length;
    const analysis = this._staticAnalysis(key, entropy, len);

    return {
      status: STATUS.UNKNOWN,
      message: 'No live validation available for this key type — static analysis only',
      testedAt: new Date().toISOString(),
      service: this.serviceName,
      staticAnalysis: analysis,
    };
  }

  _staticAnalysis(key, entropy, len) {
    const score = {
      entropyScore: parseFloat(entropy.toFixed(3)),
      length: len,
      likelySecret: entropy > 3.5 && len >= 16,
      format: this._detectFormat(key),
      characteristics: [],
    };

    if (entropy > 4.5) score.characteristics.push('Very high entropy — likely random token');
    else if (entropy > 3.5) score.characteristics.push('High entropy — likely encoded secret');
    else score.characteristics.push('Lower entropy — may be readable/structured');

    if (/^[A-Fa-f0-9]+$/.test(key)) score.characteristics.push('Hexadecimal string');
    if (/[A-Z]/.test(key) && /[a-z]/.test(key) && /[0-9]/.test(key))
      score.characteristics.push('Mixed case alphanumeric');
    if (len === 32) score.characteristics.push('32-char (common for MD5 hashes / API keys)');
    if (len === 64) score.characteristics.push('64-char (common for SHA-256 / API secrets)');

    return score;
  }

  _detectFormat(key) {
    if (/^[A-Fa-f0-9]{32,64}$/.test(key)) return 'hex';
    if (/^[A-Za-z0-9+/]={0,2}$/.test(key)) return 'base64';
    if (/^[A-Za-z0-9_-]+$/.test(key)) return 'base64url';
    return 'mixed';
  }
}

module.exports = { GenericValidator };
