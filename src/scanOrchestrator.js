/**
 * scanOrchestrator.js
 * Master pipeline: Crawl → Analyze → Classify → Validate → Store → Report
 * Emits real-time events to the GUI via IPC
 */

'use strict';

const { EventEmitter }         = require('events');
const { v4: uuidv4 }           = require('uuid');
const { CrawlerOrchestrator }  = require('./crawler');
const { analyzeSource }        = require('./analyzer');
const { classifyAll, summarize } = require('./classifier');
const { ValidatorOrchestrator } = require('./validator');
const storage                  = require('./storage');
const logger                   = require('./utils/logger');

class ScanOrchestrator extends EventEmitter {
  /**
   * @param {object} config
   * @param {string}   config.targetUrl
   * @param {string}   config.mode        — 'static' | 'puppeteer' | 'auto'
   * @param {number}   config.maxDepth
   * @param {number}   config.maxPages
   * @param {number}   config.delayMs
   * @param {boolean}  config.validate     — run live key validation
   * @param {boolean}  config.headless
   */
  constructor(config) {
    super();
    this.config  = config;
    this.scanId  = uuidv4();
    this.stopped = false;
    this.crawler = null;
    this.phase   = 'idle';
    this.stats   = { pages: 0, scripts: 0, findings: 0, validated: 0 };
  }

  stop() {
    this.stopped = true;
    if (this.crawler) this.crawler.stop();
    this.emit('stopped', { scanId: this.scanId });
    logger.info(`[Scan ${this.scanId}] Stopped by user`);
  }

  _emit(event, data) {
    this.emit(event, { scanId: this.scanId, ...data });
  }

  /**
   * Run the full pipeline
   */
  async run() {
    const { targetUrl, mode = 'auto', validate = true } = this.config;
    logger.info(`[Scan ${this.scanId}] Starting scan of ${targetUrl}`);

    // ── 1. Persist scan record ─────────────────────────────────────────────
    storage.createScan({ id: this.scanId, targetUrl, scanMode: mode });
    this._emit('status', { phase: 'starting', message: `Initializing scan of ${targetUrl}` });

    try {
      // ── 2. Crawl ─────────────────────────────────────────────────────────
      this.phase   = 'crawling';
      this.crawler = new CrawlerOrchestrator(targetUrl, {
        mode,
        maxDepth:  this.config.maxDepth  || 4,
        maxPages:  this.config.maxPages  || 150,
        delayMs:   this.config.delayMs   || 400,
        headless:  this.config.headless  !== false,
      });

      // Forward crawler events to GUI
      this.crawler.on('page',         d => { this.stats.pages++;   this._emitPageFound(d); });
      this.crawler.on('script',       d => { this.stats.scripts++; this._emit('found-asset', { type: 'script', ...d }); });
      this.crawler.on('api-request',  d => { this._emit('found-asset', { type: 'api', ...d }); });
      this.crawler.on('status',       d => { this._emit('status', d); });

      this._emit('status', { phase: 'crawling', message: 'Crawling target...' });
      const crawlResult = await this.crawler.run();

      if (this.stopped) return this._finalize('stopped');

      // ── 3. Persist pages & scripts ───────────────────────────────────────
      for (const p of crawlResult.pages) {
        storage.insertPage({ id: uuidv4(), scanId: this.scanId, url: p.url,
          statusCode: p.statusCode, depth: p.depth, renderType: p.renderMethod || mode });
      }
      for (const s of crawlResult.scripts) {
        storage.insertScript({ id: uuidv4(), scanId: this.scanId, url: s.url });
      }

      // ── 4. Analyze all sources ────────────────────────────────────────────
      this.phase = 'analyzing';
      this._emit('status', { phase: 'analyzing', message: 'Scanning sources for secrets...' });

      let rawFindings = [];

      // Analyze HTML pages
      for (const page of crawlResult.pages) {
        if (this.stopped) break;
        const { patternFindings, entropyFindings } = analyzeSource(page.source, page.url, 'html');
        rawFindings.push(...patternFindings, ...entropyFindings);

        // Also analyze inline scripts from this page
        for (const inline of (page.inlineScripts || [])) {
          const { patternFindings: ip, entropyFindings: ie } =
            analyzeSource(inline.content, page.url, 'inline');
          rawFindings.push(...ip, ...ie);
        }
      }

      // Analyze JS files
      for (const script of crawlResult.scripts) {
        if (this.stopped) break;
        const { patternFindings, entropyFindings } = analyzeSource(script.source, script.url, 'js');
        rawFindings.push(...patternFindings, ...entropyFindings);
      }

      // ── 5. Deduplicate globally ───────────────────────────────────────────
      const seen = new Set();
      rawFindings = rawFindings.filter(f => {
        const k = `${f.patternId}:${f.value}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });

      // ── 6. Classify + enrich ──────────────────────────────────────────────
      this.phase = 'classifying';
      const enriched = classifyAll(rawFindings).map(f => ({ ...f, scanId: this.scanId }));
      this.stats.findings = enriched.length;

      // Persist findings + emit to GUI
      for (const f of enriched) {
        storage.insertFinding(f);
        this._emitFindingFound(f);
      }

      this._emit('status', {
        phase: 'analyzed',
        message: `Analysis complete — ${enriched.length} findings across ${crawlResult.pages.length} pages`,
      });

      // ── 7. Validate (optional) ────────────────────────────────────────────
      if (validate && enriched.length > 0 && !this.stopped) {
        this.phase = 'validating';
        this._emit('status', { phase: 'validating', message: 'Validating API keys...' });

        const validator = new ValidatorOrchestrator({
          concurrency: this.config.validateConcurrency || 2,
          delayMs:     this.config.validateDelayMs     || 600,
        });

        await validator.validateAll(enriched, (f) => {
          storage.updateFindingValidation(f.id, f.validationResult);
          this.stats.validated++;
          this._emit('validate-result', {
            id:     f.id,
            status: f.validationResult.status,
            result: f.validationResult,
          });
        });
      }

      // ── 8. Finalize ───────────────────────────────────────────────────────
      return await this._finalize('complete', crawlResult.stats);

    } catch (err) {
      logger.error(`[Scan ${this.scanId}] Fatal error: ${err.message}`, err);
      storage.updateScanStatus(this.scanId, 'error');
      this._emit('error', { message: err.message, stack: err.stack });
      throw err;
    }
  }

  async _finalize(status, crawlStats = {}) {
    const findings = storage.getFindingsForScan(this.scanId);
    const summary  = summarize(findings);

    storage.updateScanStatus(this.scanId, status, {
      ...crawlStats,
      findings: findings.length,
      ...this.stats,
    });

    this._emit('complete', { status, summary, stats: this.stats });
    logger.info(`[Scan ${this.scanId}] Finalized with status: ${status}`);
    return { scanId: this.scanId, status, summary, stats: this.stats };
  }

  _emitPageFound(data) {
    this._emit('found-page', {
      url:         data.url,
      depth:       data.depth,
      statusCode:  data.statusCode,
      totalPages:  this.stats.pages,
    });
  }

  _emitFindingFound(finding) {
    this._emit('found-key', {
      id:          finding.id,
      service:     finding.service,
      riskLevel:   finding.riskLevel,
      riskBadge:   finding.riskBadge,
      masked:      finding.masked,
      sourceUrl:   finding.sourceUrl,
      sourceType:  finding.sourceType,
      lineNumber:  finding.lineNumber,
      confidence:  finding.confidence,
      icon:        finding.icon,
      totalKeys:   this.stats.findings,
    });
  }
}

module.exports = { ScanOrchestrator };
