/**
 * utils/robotsChecker.js
 * Parses robots.txt and checks whether a URL is allowed for crawling.
 * Respect for robots.txt is OPTIONAL and disabled by default —
 * security testers often need to crawl restricted paths.
 * Enable via config: { respectRobots: true }
 */

'use strict';

const axios        = require('axios');
const robotsParser = require('robots-parser');
const logger       = require('./logger');

const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

class RobotsChecker {
  constructor(userAgent = 'SecurityScanner/1.0') {
    this.userAgent = userAgent;
    this._cache    = new Map(); // origin → { parser, fetchedAt }
  }

  /**
   * Fetch and cache robots.txt for a given origin
   * @param {string} origin  — e.g. https://example.com
   * @returns {object|null}  — robots-parser instance or null if unavailable
   */
  async _getParser(origin) {
    const cached = this._cache.get(origin);
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
      return cached.parser;
    }

    const robotsUrl = `${origin}/robots.txt`;
    try {
      const res = await axios.get(robotsUrl, {
        timeout: 6000,
        validateStatus: s => s < 500,
        headers: { 'User-Agent': this.userAgent },
      });

      if (res.status === 200 && typeof res.data === 'string') {
        const parser = robotsParser(robotsUrl, res.data);
        this._cache.set(origin, { parser, fetchedAt: Date.now() });
        logger.debug(`[Robots] Fetched robots.txt for ${origin}`);
        return parser;
      }

      // 404 or empty → no restrictions
      this._cache.set(origin, { parser: null, fetchedAt: Date.now() });
      return null;

    } catch (err) {
      logger.debug(`[Robots] Could not fetch robots.txt for ${origin}: ${err.message}`);
      this._cache.set(origin, { parser: null, fetchedAt: Date.now() });
      return null;
    }
  }

  /**
   * Check if a URL is allowed to be crawled
   * @param {string} url
   * @returns {Promise<{ allowed: boolean, reason: string }>}
   */
  async isAllowed(url) {
    let parsed;
    try { parsed = new URL(url); } catch {
      return { allowed: false, reason: 'invalid URL' };
    }

    const parser = await this._getParser(parsed.origin);
    if (!parser) {
      return { allowed: true, reason: 'no robots.txt found' };
    }

    const allowed = parser.isAllowed(url, this.userAgent);
    return {
      allowed: allowed !== false,  // null = not specified → allow
      reason:  allowed === false ? 'disallowed by robots.txt' : 'allowed',
    };
  }

  /**
   * Get the crawl delay specified in robots.txt
   * @param {string} origin
   * @returns {Promise<number|null>}  milliseconds or null if not specified
   */
  async getCrawlDelay(origin) {
    const parser = await this._getParser(origin);
    if (!parser) return null;
    const delaySeconds = parser.getCrawlDelay(this.userAgent);
    return delaySeconds != null ? delaySeconds * 1000 : null;
  }

  /**
   * Get all sitemap URLs from robots.txt
   * @param {string} origin
   * @returns {Promise<string[]>}
   */
  async getSitemaps(origin) {
    const parser = await this._getParser(origin);
    if (!parser) return [];
    return parser.getSitemaps() || [];
  }

  clearCache() {
    this._cache.clear();
  }
}

module.exports = { RobotsChecker };
