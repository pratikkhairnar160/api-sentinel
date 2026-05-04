/**
 * validator/base.js
 * Base class for all service validators
 * ALL validation is NON-DESTRUCTIVE — read-only probes only
 */

'use strict';

const axios = require('axios');
const logger = require('../utils/logger');

// Validation result statuses
const STATUS = {
  VALID:       'valid',       // Key works and has permissions
  INVALID:     'invalid',     // Key is rejected (401/403/invalid)
  RESTRICTED:  'restricted',  // Key works but has limited scope
  RATE_LIMITED: 'rate_limited',
  ERROR:       'error',       // Network/timeout error
  SKIPPED:     'skipped',     // Validation skipped (user opt-out)
  UNKNOWN:     'unknown',
};

class BaseValidator {
  /**
   * @param {string} serviceId   — matches pattern ID
   * @param {string} serviceName — human readable name
   * @param {object} options
   * @param {number} options.timeoutMs  — request timeout
   * @param {number} options.maxRetries — retry count on network error
   */
  constructor(serviceId, serviceName, options = {}) {
    this.serviceId = serviceId;
    this.serviceName = serviceName;
    this.options = {
      timeoutMs: 8000,
      maxRetries: 1,
      ...options,
    };

    this.http = axios.create({
      timeout: this.options.timeoutMs,
      validateStatus: () => true, // Never throw on HTTP errors
      headers: {
        'User-Agent': 'SecurityAudit/1.0 (Authorized Assessment)',
      },
    });
  }

  /**
   * Override in subclasses — perform the actual probe
   * @param {string} key — the API key / secret value
   * @returns {Promise<ValidationResult>}
   */
  async probe(key) {
    throw new Error(`${this.constructor.name}.probe() not implemented`);
  }

  /**
   * Validate with retry logic and error wrapping
   * @param {string} key
   * @returns {Promise<ValidationResult>}
   */
  async validate(key) {
    let lastError;
    for (let attempt = 0; attempt <= this.options.maxRetries; attempt++) {
      try {
        const result = await this.probe(key);
        logger.debug(`[${this.serviceName}] Validation: ${result.status} for key ${key.slice(0, 8)}...`);
        return result;
      } catch (err) {
        lastError = err;
        if (attempt < this.options.maxRetries) {
          await this._delay(1500);
        }
      }
    }

    logger.warn(`[${this.serviceName}] Validation failed after retries: ${lastError?.message}`);
    return this._errorResult(lastError?.message || 'Unknown error');
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  _validResult(details = {}) {
    return {
      status: STATUS.VALID,
      message: 'Key is valid and active',
      testedAt: new Date().toISOString(),
      service: this.serviceName,
      ...details,
    };
  }

  _invalidResult(reason = 'Key rejected by API') {
    return {
      status: STATUS.INVALID,
      message: reason,
      testedAt: new Date().toISOString(),
      service: this.serviceName,
    };
  }

  _restrictedResult(details = {}) {
    return {
      status: STATUS.RESTRICTED,
      message: 'Key valid but access is restricted',
      testedAt: new Date().toISOString(),
      service: this.serviceName,
      ...details,
    };
  }

  _rateLimitResult() {
    return {
      status: STATUS.RATE_LIMITED,
      message: 'Rate limited — could not confirm key status',
      testedAt: new Date().toISOString(),
      service: this.serviceName,
    };
  }

  _errorResult(reason = 'Network or timeout error') {
    return {
      status: STATUS.ERROR,
      message: reason,
      testedAt: new Date().toISOString(),
      service: this.serviceName,
    };
  }

  _delay(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}

module.exports = { BaseValidator, STATUS };
