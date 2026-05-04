/**
 * utils/scopeChecker.js
 * Enforces crawl scope — prevents accidental out-of-scope scanning.
 * Every URL is validated before queuing.
 */

'use strict';

const { URL }  = require('url');
const { parse: parseTld } = require('tldts');

class ScopeChecker {
  /**
   * @param {string}   rootUrl           — the initial target URL
   * @param {object}   options
   * @param {boolean}  options.allowSubdomains  — default true
   * @param {string[]} options.extraDomains      — additional in-scope domains
   * @param {string[]} options.excludePaths      — path prefixes to skip
   * @param {RegExp[]} options.excludePatterns   — regex patterns to exclude
   */
  constructor(rootUrl, options = {}) {
    const parsed        = new URL(rootUrl);
    this.rootUrl        = rootUrl;
    this.rootHostname   = parsed.hostname;
    this.rootOrigin     = parsed.origin;
    this.rootTld        = parseTld(parsed.hostname);

    this.options = {
      allowSubdomains:  true,
      extraDomains:     [],
      excludePaths:     ['/logout', '/signout', '/delete', '/remove', '/destroy'],
      excludePatterns:  [
        /\.(pdf|zip|tar|gz|rar|7z|exe|dmg|pkg|deb|rpm|apk|iso)$/i,
        /\.(mp4|mp3|avi|mov|mkv|webm|ogg|wav|flac)$/i,
        /\.(png|jpg|jpeg|gif|webp|ico|bmp|tiff|svg)$/i,
        /\.(woff|woff2|ttf|eot|otf)$/i,
        /^mailto:/i,
        /^tel:/i,
        /^javascript:/i,
        /^data:/i,
        /^#/,
      ],
      ...options,
    };
  }

  /**
   * Determine if a URL is within scope
   * @param {string} url
   * @returns {{ inScope: boolean, reason: string }}
   */
  check(url) {
    // Early exit for obviously non-HTTP schemes
    for (const pattern of this.options.excludePatterns) {
      if (pattern.test(url)) {
        return { inScope: false, reason: 'matches exclude pattern' };
      }
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return { inScope: false, reason: 'invalid URL' };
    }

    // Protocol check
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { inScope: false, reason: `non-HTTP protocol: ${parsed.protocol}` };
    }

    // Path exclusion
    const lPath = parsed.pathname.toLowerCase();
    for (const ep of this.options.excludePaths) {
      if (lPath.startsWith(ep.toLowerCase())) {
        return { inScope: false, reason: `excluded path: ${ep}` };
      }
    }

    // Domain check
    if (!this._isInScopeDomain(parsed.hostname)) {
      return { inScope: false, reason: `out-of-scope domain: ${parsed.hostname}` };
    }

    return { inScope: true, reason: 'ok' };
  }

  /**
   * Quick boolean check
   */
  isInScope(url) {
    return this.check(url).inScope;
  }

  /**
   * Filter a list of URLs to only in-scope ones
   */
  filter(urls) {
    return urls.filter(u => this.isInScope(u));
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  _isInScopeDomain(hostname) {
    // Exact match
    if (hostname === this.rootHostname) return true;

    // Extra allowed domains
    if (this.options.extraDomains.includes(hostname)) return true;

    // Subdomain check
    if (this.options.allowSubdomains) {
      if (hostname.endsWith('.' + this.rootHostname)) return true;

      // Same registered domain (e.g. cdn.example.com vs www.example.com)
      const tldRoot = this.rootTld?.domain;
      if (tldRoot) {
        const t = parseTld(hostname);
        if (t?.domain === tldRoot && t?.suffix === this.rootTld?.suffix) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Get a summary of what's in scope
   */
  summary() {
    const subs = this.options.allowSubdomains ? 'allowed' : 'blocked';
    const extras = this.options.extraDomains.length
      ? ` + extra: ${this.options.extraDomains.join(', ')}`
      : '';
    return `Root: ${this.rootHostname} | Subdomains: ${subs}${extras}`;
  }
}

module.exports = { ScopeChecker };
