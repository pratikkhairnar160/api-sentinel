/**
 * crawler/index.js — Crawl orchestrator
 * Routes between static HTTP crawl and Puppeteer based on config
 * Emits events to the GUI in real-time
 */

'use strict';

const { StaticCrawler } = require('./staticCrawler');
const { PuppeteerCrawler } = require('./puppeteerCrawler');
const { EventEmitter } = require('events');
const logger = require('../utils/logger');

class CrawlerOrchestrator extends EventEmitter {
  /**
   * @param {string} targetUrl
   * @param {object} options
   * @param {'static'|'puppeteer'|'auto'} options.mode
   */
  constructor(targetUrl, options = {}) {
    super();
    this.targetUrl = targetUrl;
    this.options = {
      mode: 'auto',
      ...options,
    };
    this.activeCrawler = null;
    this.results = { pages: [], scripts: [], stats: {} };
  }

  stop() {
    if (this.activeCrawler) {
      this.activeCrawler.stop();
      this.emit('stopped');
    }
  }

  /**
   * Run the crawl and collect all pages + scripts
   * @returns {Promise<{ pages: [], scripts: [] }>}
   */
  async run() {
    const mode = this.options.mode === 'auto'
      ? await this._detectMode()
      : this.options.mode;

    logger.info(`[Orchestrator] Crawl mode: ${mode} — target: ${this.targetUrl}`);
    this.emit('status', { phase: 'crawling', mode, target: this.targetUrl });

    const onPage = (pageData) => {
      this.results.pages.push(pageData);
      this.emit('page', {
        url: pageData.url,
        depth: pageData.depth,
        statusCode: pageData.statusCode,
        inlineScripts: pageData.inlineScripts?.length || 0,
      });
    };

    const onScript = (scriptData) => {
      this.results.scripts.push(scriptData);
      this.emit('script', { url: scriptData.url });
    };

    const onRequest = (req) => {
      this.emit('api-request', req);
    };

    if (mode === 'puppeteer') {
      this.activeCrawler = new PuppeteerCrawler(
        this.targetUrl, this.options, onPage, onScript, onRequest
      );
    } else {
      this.activeCrawler = new StaticCrawler(
        this.targetUrl, this.options, onPage, onScript
      );
    }

    const crawlResult = await this.activeCrawler.crawl();
    this.results.stats = crawlResult.stats;

    this.emit('crawl-complete', {
      pages: crawlResult.pages.length,
      scripts: crawlResult.scripts.length,
      stats: crawlResult.stats,
    });

    return crawlResult;
  }

  /**
   * Quick probe to detect if the site needs JS rendering
   * Checks if the initial HTML has meaningful content or is a SPA shell
   */
  async _detectMode() {
    try {
      const axios = require('axios');
      const res = await axios.get(this.targetUrl, { timeout: 8000 });
      const html = res.data || '';

      // SPA indicators
      const isSpa =
        (html.match(/<div[^>]*id=["']root["']/i) && html.match(/<script/gi)?.length > 2) ||
        html.match(/window\.__NUXT__|window\.__NEXT_DATA__|window\.React/i) ||
        html.match(/<noscript>.*You need to enable JavaScript/si);

      return isSpa ? 'puppeteer' : 'static';
    } catch {
      return 'static';
    }
  }
}

module.exports = { CrawlerOrchestrator };
