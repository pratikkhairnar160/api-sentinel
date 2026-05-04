/**
 * storage/schema.js — SQLite table definitions
 */
'use strict';

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target_url  TEXT NOT NULL,
    scan_mode   TEXT NOT NULL DEFAULT 'static',
    status      TEXT NOT NULL DEFAULT 'running',
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    stats       TEXT  -- JSON blob
  );

  CREATE TABLE IF NOT EXISTS pages (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    url         TEXT NOT NULL,
    status_code INTEGER,
    depth       INTEGER DEFAULT 0,
    render_type TEXT DEFAULT 'static',
    crawled_at  TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
  );

  CREATE TABLE IF NOT EXISTS scripts (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL,
    url        TEXT NOT NULL,
    crawled_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
  );

  CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL,
    pattern_id        TEXT NOT NULL,
    service_name      TEXT NOT NULL,
    category          TEXT,
    risk_level        TEXT NOT NULL,
    confidence        TEXT NOT NULL,
    value_masked      TEXT NOT NULL,
    value_raw         TEXT,        -- Optionally store raw (encrypted or omitted)
    source_url        TEXT NOT NULL,
    source_type       TEXT NOT NULL,
    line_number       INTEGER,
    context           TEXT,
    validation_status TEXT,
    validation_result TEXT,        -- JSON blob
    impact            TEXT,
    remediation       TEXT,        -- JSON array
    cwe_id            TEXT,
    found_at          TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
  );

  CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
  CREATE INDEX IF NOT EXISTS idx_findings_risk   ON findings(risk_level);
  CREATE INDEX IF NOT EXISTS idx_pages_scan      ON pages(scan_id);
`;

module.exports = { SCHEMA };
