/**
 * staticCrawler.js
 * Fast HTTP-based crawler for standard (non-JS-rendered) pages
 * Uses Axios with concurrency control and rate limiting
 */

'use strict';

const axios = require('axios');
const PQueue = require('p-queue').default;
const { extractFromHtml, extractScriptsFromJs, isInScope } = require('./linkExtractor');
const logger = require('../utils/logger');

const DEFAULT_OPTIONS = {
  concurrency: 5,
  delayMs: 300,           // Polite delay between requests
  timeoutMs: 15000,
  maxDepth: 5,
  maxPages: 200,
  maxScripts: 100,
  userAgent: 'Mozilla/5.0 (compatible; SecurityScanner/1.0; +https://github.com/security/api-sentinel)',
  followRedirects: true,
  respectRobots: false,   // User must explicitly enable respect
};

class StaticCrawler {
  /**
   * @param {string} targetUrl  — root URL to crawl
   * @param {object} options    — override DEFAULT_OPTIONS
   * @param {function} onPage   — callback(pageData) for each crawled page
   * @param {function} onScript — callback(scriptData) for each JS file
   */
  constructor(targetUrl, options = {}, onPage = null, onScript = null) {
    this.targetUrl = targetUrl;
    this.baseUrl = new URL(targetUrl).origin;
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.onPage = onPage;
    this.onScript = onScript;

    this.visited = new Set();
    this.visitedScripts = new Set();
    this.queue = new PQueue({ concurrency: this.options.concurrency });
    this.stopped = false;
    this.stats = { pages: 0, scripts: 0, errors: 0, skipped: 0 };

    this.http = axios.create({
      timeout: this.options.timeoutMs,
      maxRedirects: this.options.followRedirects ? 5 : 0,
      headers: {
        'User-Agent': this.options.userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/javascript,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      validateStatus: s => s < 500,
    });
  }

  /**
   * Stop the crawl
   */
  stop() {
    this.stopped = true;
    this.queue.clear();
    logger.info('[StaticCrawler] Stopped');
  }

  /**
   * Start crawl from targetUrl
   * @returns {Promise<CrawlResults>}
   */
  async crawl() {
    logger.info(`[StaticCrawler] Starting crawl of ${this.targetUrl}`);
    const pages = [];
    const scripts = [];

    const processPage = async (url, depth) => {
      if (this.stopped) return;
      if (this.visited.has(url)) return;
      if (this.stats.pages >= this.options.maxPages) return;
      if (depth > this.options.maxDepth) return;

      this.visited.add(url);

      try {
        await this._delay(this.options.delayMs);
        const response = await this.http.get(url);
        const contentType = response.headers['content-type'] || '';

        if (!contentType.includes('text/html') && !contentType.includes('javascript')) {
          this.stats.skipped++;
          return;
        }

        const pageData = {
          url,
          source: response.data,
          statusCode: response.status,
          contentType,
          depth,
          crawledAt: new Date().toISOString(),
        };

        this.stats.pages++;
        pages.push(pageData);
        if (this.onPage) this.onPage(pageData);

        // Extract and queue child links
        const { links, scripts: scriptUrls, inlineScripts } = extractFromHtml(
          response.data, url, this.baseUrl
        );

        // Queue script fetches
        for (const scriptUrl of scriptUrls) {
          if (!this.visitedScripts.has(scriptUrl) && this.stats.scripts < this.options.maxScripts) {
            this.queue.add(() => processScript(scriptUrl));
          }
        }

        // Queue linked pages
        for (const link of links) {
          if (!this.visited.has(link) && isInScope(link, this.baseUrl, true)) {
            this.queue.add(() => processPage(link, depth + 1));
          }
        }

        // Attach inline scripts to page data
        pageData.inlineScripts = inlineScripts;

      } catch (err) {
        this.stats.errors++;
        logger.debug(`[StaticCrawler] Error fetching ${url}: ${err.message}`);
      }
    };

    const processScript = async (url) => {
      if (this.stopped) return;
      if (this.visitedScripts.has(url)) return;
      if (this.stats.scripts >= this.options.maxScripts) return;

      this.visitedScripts.add(url);

      try {
        await this._delay(this.options.delayMs / 2);
        const response = await this.http.get(url);
        const scriptData = {
          url,
          source: response.data,
          statusCode: response.status,
          crawledAt: new Date().toISOString(),
        };

        this.stats.scripts++;
        scripts.push(scriptData);
        if (this.onScript) this.onScript(scriptData);

        // Discover more scripts from this JS file
        const more = extractScriptsFromJs(response.data, url);
        for (const s of more) {
          if (!this.visitedScripts.has(s)) {
            this.queue.add(() => processScript(s));
          }
        }

      } catch (err) {
        this.stats.errors++;
        logger.debug(`[StaticCrawler] Script error ${url}: ${err.message}`);
      }
    };

    // Seed the queue
    this.queue.add(() => processPage(this.targetUrl, 0));

    await this.queue.onIdle();

    logger.info(`[StaticCrawler] Done — pages:${this.stats.pages} scripts:${this.stats.scripts} errors:${this.stats.errors}`);
    return { pages, scripts, stats: this.stats };
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { StaticCrawler };
