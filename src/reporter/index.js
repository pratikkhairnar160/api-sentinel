/**
 * reporter/index.js — Orchestrates all report formats
 */
'use strict';

const path = require('path');
const os   = require('os');
const fs   = require('fs');
const { writeJsonReport } = require('./jsonReporter');
const { writeHtmlReport } = require('./htmlReporter');
const { writePdfReport  } = require('./pdfReporter');
const { summarize }       = require('../classifier');
const storage             = require('../storage');
const logger              = require('../utils/logger');

const DEFAULT_OUTPUT_DIR = path.join(os.homedir(), 'APISentinel-Reports');

/**
 * Generate all selected report formats for a completed scan
 * @param {string}   scanId
 * @param {string[]} formats   — ['json','html','pdf']
 * @param {string}   outputDir — optional override
 * @returns {Promise<{ json?, html?, pdf? }>}  map of format → file path
 */
async function generateReports(scanId, formats = ['json', 'html'], outputDir = DEFAULT_OUTPUT_DIR) {
  fs.mkdirSync(outputDir, { recursive: true });

  const scan     = storage.getScanById(scanId);
  const findings = storage.getFindingsForScan(scanId);
  const pages    = storage.getPagesForScan(scanId);
  const scripts  = [];  // lightweight — omit source content from report
  const summary  = summarize(findings);

  const scanData = { scan, findings, pages, scripts, summary };
  const output   = {};

  for (const fmt of formats) {
    try {
      logger.info(`[Reporter] Generating ${fmt.toUpperCase()} report...`);
      if (fmt === 'json') output.json = writeJsonReport(scanData, outputDir);
      if (fmt === 'html') output.html = writeHtmlReport(scanData, outputDir);
      if (fmt === 'pdf')  output.pdf  = await writePdfReport(scanData, outputDir);
      logger.info(`[Reporter] ${fmt.toUpperCase()} written → ${output[fmt]}`);
    } catch (err) {
      logger.error(`[Reporter] Failed to write ${fmt}: ${err.message}`);
    }
  }

  return output;
}

module.exports = { generateReports, DEFAULT_OUTPUT_DIR };
