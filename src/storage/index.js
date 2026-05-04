/**
 * storage/index.js — SQLite persistence layer
 */

'use strict';

const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { SCHEMA } = require('./schema');
const logger = require('../utils/logger');

const DB_DIR  = path.join(os.homedir(), '.api-sentinel');
const DB_PATH = path.join(DB_DIR, 'sentinel.db');

let db;

function initDatabase() {
  fs.mkdirSync(DB_DIR, { recursive: true });
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  logger.info(`[Storage] DB ready at ${DB_PATH}`);
  return db;
}

function getDb() {
  if (!db) throw new Error('Database not initialized. Call initDatabase() first.');
  return db;
}

// ─── Scans ────────────────────────────────────────────────────────────────

function createScan({ id, targetUrl, scanMode = 'static' }) {
  getDb().prepare(`
    INSERT INTO scans (id, target_url, scan_mode, status, started_at)
    VALUES (@id, @targetUrl, @scanMode, 'running', @startedAt)
  `).run({ id, targetUrl, scanMode, startedAt: new Date().toISOString() });
  return id;
}

function updateScanStatus(id, status, stats = null) {
  getDb().prepare(`
    UPDATE scans SET status = @status, finished_at = @finishedAt, stats = @stats WHERE id = @id
  `).run({
    id, status,
    finishedAt: new Date().toISOString(),
    stats: stats ? JSON.stringify(stats) : null,
  });
}

function getScans() {
  return getDb().prepare('SELECT * FROM scans ORDER BY started_at DESC').all();
}

function getScanById(id) {
  return getDb().prepare('SELECT * FROM scans WHERE id = ?').get(id);
}

// ─── Pages ────────────────────────────────────────────────────────────────

function insertPage({ id, scanId, url, statusCode, depth, renderType }) {
  getDb().prepare(`
    INSERT OR IGNORE INTO pages (id, scan_id, url, status_code, depth, render_type, crawled_at)
    VALUES (@id, @scanId, @url, @statusCode, @depth, @renderType, @crawledAt)
  `).run({ id, scanId, url, statusCode, depth, renderType, crawledAt: new Date().toISOString() });
}

function getPagesForScan(scanId) {
  return getDb().prepare('SELECT * FROM pages WHERE scan_id = ?').all(scanId);
}

// ─── Scripts ──────────────────────────────────────────────────────────────

function insertScript({ id, scanId, url }) {
  getDb().prepare(`
    INSERT OR IGNORE INTO scripts (id, scan_id, url, crawled_at)
    VALUES (@id, @scanId, @url, @crawledAt)
  `).run({ id, scanId, url, crawledAt: new Date().toISOString() });
}

// ─── Findings ─────────────────────────────────────────────────────────────

function insertFinding(finding) {
  getDb().prepare(`
    INSERT OR IGNORE INTO findings (
      id, scan_id, pattern_id, service_name, category, risk_level, confidence,
      value_masked, source_url, source_type, line_number, context,
      impact, remediation, cwe_id, found_at
    ) VALUES (
      @id, @scanId, @patternId, @serviceName, @category, @riskLevel, @confidence,
      @masked, @sourceUrl, @sourceType, @lineNumber, @context,
      @impact, @remediation, @cweId, @foundAt
    )
  `).run({
    id:          finding.id,
    scanId:      finding.scanId,
    patternId:   finding.patternId,
    serviceName: finding.serviceName || finding.service,
    category:    finding.category,
    riskLevel:   finding.riskLevel,
    confidence:  finding.confidence,
    masked:      finding.masked,
    sourceUrl:   finding.sourceUrl,
    sourceType:  finding.sourceType,
    lineNumber:  finding.lineNumber,
    context:     finding.context?.slice(0, 500),
    impact:      finding.impact,
    remediation: JSON.stringify(finding.remediation || []),
    cweId:       finding.cweId,
    foundAt:     finding.foundAt,
  });
}

function updateFindingValidation(id, validationResult) {
  getDb().prepare(`
    UPDATE findings
    SET validation_status = @status, validation_result = @result
    WHERE id = @id
  `).run({
    id,
    status: validationResult.status,
    result: JSON.stringify(validationResult),
  });
}

function getFindingsForScan(scanId) {
  const rows = getDb().prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY risk_level').all(scanId);
  return rows.map(r => ({
    ...r,
    remediation:       r.remediation ? JSON.parse(r.remediation) : [],
    validationResult:  r.validation_result ? JSON.parse(r.validation_result) : null,
  }));
}

function deleteScan(id) {
  const del = getDb().transaction(() => {
    getDb().prepare('DELETE FROM findings WHERE scan_id = ?').run(id);
    getDb().prepare('DELETE FROM pages   WHERE scan_id = ?').run(id);
    getDb().prepare('DELETE FROM scripts WHERE scan_id = ?').run(id);
    getDb().prepare('DELETE FROM scans   WHERE id = ?').run(id);
  });
  del();
}

module.exports = {
  initDatabase, getDb,
  createScan, updateScanStatus, getScans, getScanById,
  insertPage, getPagesForScan,
  insertScript,
  insertFinding, updateFindingValidation, getFindingsForScan,
  deleteScan,
};
