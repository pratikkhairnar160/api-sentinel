/**
 * puppeteerCrawler.js
 * Headless browser crawler using Puppeteer
 * Handles JS-rendered content, SPAs, and dynamic pages
 */

'use strict';

const puppeteer = require('puppeteer');
const { extractFromHtml, extractScriptsFromJs, isInScope } = require('./linkExtractor');
const logger = require('../utils/logger');

const DEFAULT_OPTIONS = {
  headless: true,
  concurrency: 2,           // Lower for headless (resource intensive)
  delayMs: 800,
  pageTimeoutMs: 30000,
  navigationTimeoutMs: 20000,
  maxDepth: 4,
  maxPages: 100,
  maxScripts: 80,
  waitForNetworkIdle: true,
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
  interceptRequests: true,  // Capture network requests
};

class PuppeteerCrawler {
  constructor(targetUrl, options = {}, onPage = null, onScript = null, onRequest = null) {
    this.targetUrl = targetUrl;
    this.baseUrl = new URL(targetUrl).origin;
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.onPage = onPage;
    this.onScript = onScript;
    this.onRequest = onRequest;     // callback for captured API requests

    this.browser = null;
    this.visited = new Set();
    this.visitedScripts = new Set();
    this.stopped = false;
    this.stats = { pages: 0, scripts: 0, errors: 0, apiRequests: 0 };
    this.capturedRequests = [];
  }

  stop() {
    this.stopped = true;
  }

  async launch() {
    this.browser = await puppeteer.launch({
      headless: this.options.headless ? 'new' : false,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--window-size=1280,800',
      ],
      timeout: 30000,
    });
    logger.info('[PuppeteerCrawler] Browser launched');
  }

  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      logger.info('[PuppeteerCrawler] Browser closed');
    }
  }

  /**
   * Crawl a single page with full JS rendering
   * @param {string} url
   * @param {number} depth
   * @returns {Promise<PageResult|null>}
   */
  async _crawlPage(url, depth) {
    if (this.stopped || this.visited.has(url)) return null;
    if (this.stats.pages >= this.options.maxPages) return null;
    if (depth > this.options.maxDepth) return null;

    this.visited.add(url);

    const page = await this.browser.newPage();
    const interceptedScripts = [];
    const interceptedApis = [];

    try {
      await page.setUserAgent(this.options.userAgent);
      await page.setViewport({ width: 1280, height: 800 });

      // Intercept network requests to capture API calls and script URLs
      if (this.options.interceptRequests) {
        await page.setRequestInterception(true);
        page.on('request', req => {
          const reqUrl = req.url();
          const resourceType = req.resourceType();

          if (resourceType === 'script') {
            interceptedScripts.push(reqUrl);
          } else if (['fetch', 'xhr'].includes(resourceType)) {
            interceptedApis.push({
              url: reqUrl,
              method: req.method(),
              headers: req.headers(),
            });
            this.stats.apiRequests++;
            if (this.onRequest) this.onRequest({ url: reqUrl, method: req.method() });
          }

          // Block media to save bandwidth
          if (['image', 'media', 'font'].includes(resourceType)) {
            req.abort();
          } else {
            req.continue();
          }
        });
      }

      // Polite delay
      await this._delay(this.options.delayMs);

      const response = await page.goto(url, {
        waitUntil: this.options.waitForNetworkIdle ? 'networkidle2' : 'domcontentloaded',
        timeout: this.options.navigationTimeoutMs,
      });

      if (!response) return null;
      const statusCode = response.status();

      // Get fully rendered HTML
      const html = await page.content();

      // Extract links and scripts from rendered DOM
      const { links, scripts: srcScripts, inlineScripts } = extractFromHtml(html, url, this.baseUrl);

      // Merge all discovered scripts
      const allScripts = [...new Set([...srcScripts, ...interceptedScripts])];

      const pageData = {
        url,
        source: html,
        statusCode,
        depth,
        inlineScripts,
        discoveredLinks: links,
        discoveredScripts: allScripts,
        capturedApiRequests: interceptedApis,
        crawledAt: new Date().toISOString(),
        renderMethod: 'puppeteer',
      };

      this.stats.pages++;
      if (this.onPage) this.onPage(pageData);

      return { pageData, links, scripts: allScripts };

    } catch (err) {
      this.stats.errors++;
      logger.debug(`[PuppeteerCrawler] Error on ${url}: ${err.message}`);
      return null;
    } finally {
      await page.close();
    }
  }

  /**
   * Fetch a JS file source
   */
  async _fetchScript(url) {
    if (this.visitedScripts.has(url)) return null;
    this.visitedScripts.add(url);

    const page = await this.browser.newPage();
    try {
      await page.setUserAgent(this.options.userAgent);
      await this._delay(this.options.delayMs / 2);
      const response = await page.goto(url, { timeout: this.options.pageTimeoutMs });
      const source = await page.evaluate(() => document.body.innerText);

      const scriptData = {
        url,
        source,
        statusCode: response ? response.status() : 0,
        crawledAt: new Date().toISOString(),
      };

      this.stats.scripts++;
      if (this.onScript) this.onScript(scriptData);
      return scriptData;

    } catch (err) {
      this.stats.errors++;
      return null;
    } finally {
      await page.close();
    }
  }

  /**
   * Full BFS crawl
   * @returns {Promise<CrawlResults>}
   */
  async crawl() {
    await this.launch();

    const pages = [];
    const scripts = [];
    const queue = [{ url: this.targetUrl, depth: 0 }];

    while (queue.length > 0 && !this.stopped) {
      // Process up to concurrency pages in parallel
      const batch = queue.splice(0, this.options.concurrency);
      const results = await Promise.allSettled(
        batch.map(({ url, depth }) => this._crawlPage(url, depth))
      );

      for (const result of results) {
        if (result.status !== 'fulfilled' || !result.value) continue;
        const { pageData, links, scripts: pageScripts } = result.value;
        pages.push(pageData);

        // Queue child pages
        for (const link of links) {
          if (!this.visited.has(link) && isInScope(link, this.baseUrl)) {
            queue.push({ url: link, depth: (pageData.depth || 0) + 1 });
          }
        }

        // Fetch scripts (bounded concurrency)
        const scriptBatch = pageScripts
          .filter(s => !this.visitedScripts.has(s))
          .slice(0, 10);

        const scriptResults = await Promise.allSettled(
          scriptBatch.map(s => this._fetchScript(s))
        );
        for (const r of scriptResults) {
          if (r.status === 'fulfilled' && r.value) scripts.push(r.value);
        }
      }
    }

    await this.close();
    logger.info(`[PuppeteerCrawler] Done — pages:${this.stats.pages} scripts:${this.stats.scripts}`);
    return { pages, scripts, capturedRequests: this.capturedRequests, stats: this.stats };
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { PuppeteerCrawler };
