/**
 * utils/rateLimiter.js
 * Per-domain adaptive rate limiter.
 * Tracks request cadence and enforces polite delays.
 * Backs off automatically on 429 responses.
 */

'use strict';

const logger = require('./logger');

const DEFAULT_OPTIONS = {
  baseDelayMs:     350,   // Minimum inter-request delay (ms)
  maxDelayMs:      8000,  // Maximum back-off delay (ms)
  backoffFactor:   2.0,   // Multiplier on each 429
  recoveryFactor:  0.85,  // How quickly delay recovers after back-off
  minRecoveryMs:   baseDelay => baseDelay, // Floor during recovery
};

class RateLimiter {
  /**
   * @param {object} options
   * @param {number} options.baseDelayMs   — default inter-request delay
   * @param {number} options.maxDelayMs    — cap on back-off delay
   * @param {number} options.backoffFactor — multiplier on 429
   */
  constructor(options = {}) {
    this.options    = { ...DEFAULT_OPTIONS, ...options };
    this._domains   = new Map(); // domain → DomainState
  }

  /**
   * Get or initialise state for a domain
   */
  _state(domain) {
    if (!this._domains.has(domain)) {
      this._domains.set(domain, {
        currentDelay: this.options.baseDelayMs,
        lastRequest:  0,
        rateLimited:  false,
        totalRequests: 0,
        totalBackoffs: 0,
      });
    }
    return this._domains.get(domain);
  }

  /**
   * Wait the appropriate delay for a domain before making a request.
   * Call this BEFORE each request.
   * @param {string} url
   */
  async wait(url) {
    let domain;
    try { domain = new URL(url).hostname; }
    catch { domain = 'unknown'; }

    const state = this._state(domain);
    const now   = Date.now();
    const sinceLastRequest = now - state.lastRequest;

    if (sinceLastRequest < state.currentDelay) {
      const waitFor = state.currentDelay - sinceLastRequest;
      await this._sleep(waitFor);
    }

    state.lastRequest = Date.now();
    state.totalRequests++;
  }

  /**
   * Report a 429 Too Many Requests for a domain.
   * Call this AFTER receiving a 429 response.
   * @param {string} url
   * @param {number} retryAfterMs — value from Retry-After header (if present)
   */
  onRateLimited(url, retryAfterMs = null) {
    let domain;
    try { domain = new URL(url).hostname; }
    catch { domain = 'unknown'; }

    const state = this._state(domain);
    state.rateLimited = true;
    state.totalBackoffs++;

    if (retryAfterMs != null) {
      state.currentDelay = Math.min(retryAfterMs, this.options.maxDelayMs);
    } else {
      state.currentDelay = Math.min(
        state.currentDelay * this.options.backoffFactor,
        this.options.maxDelayMs
      );
    }

    logger.warn(`[RateLimiter] 429 on ${domain} — backing off to ${state.currentDelay}ms`);
  }

  /**
   * Report a successful response for a domain.
   * Gradually recovers the delay back toward baseline.
   * @param {string} url
   */
  onSuccess(url) {
    let domain;
    try { domain = new URL(url).hostname; }
    catch { return; }

    const state = this._state(domain);
    if (state.currentDelay > this.options.baseDelayMs) {
      state.currentDelay = Math.max(
        state.currentDelay * this.options.recoveryFactor,
        this.options.baseDelayMs
      );
      state.rateLimited = state.currentDelay > this.options.baseDelayMs * 1.5;
    }
  }

  /**
   * Get stats for all tracked domains
   */
  stats() {
    const result = {};
    for (const [domain, s] of this._domains.entries()) {
      result[domain] = {
        currentDelayMs: Math.round(s.currentDelay),
        totalRequests:  s.totalRequests,
        totalBackoffs:  s.totalBackoffs,
        rateLimited:    s.rateLimited,
      };
    }
    return result;
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

// Singleton instance for shared use across modules
const globalLimiter = new RateLimiter();

module.exports = { RateLimiter, globalLimiter };
