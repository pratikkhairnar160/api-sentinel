# Changelog

All notable changes to APISentinel are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2025-01-01

### Added
- **Intelligent Web Crawler**
  - Static HTTP crawler (`staticCrawler.js`) using Axios + PQueue
  - Puppeteer headless browser crawler for JS-rendered SPAs
  - Auto-detection of SPA vs static sites
  - Link, script, and API endpoint extraction from HTML/JS
  - Scope enforcement with subdomain support

- **JavaScript & Source Analyzer**
  - 30+ regex patterns covering AWS, Google, Firebase, Stripe, GitHub, Slack,
    SendGrid, Mailgun, Shopify, Twilio, HubSpot, JWT, MongoDB, PostgreSQL, Azure
  - Shannon entropy-based heuristic detection for unknown secrets
  - Inline script extraction from HTML `<script>` tags
  - Dynamic import discovery from JS source
  - Global deduplication across all sources

- **API Key Classifier**
  - Service identification from pattern ID
  - Risk scoring (critical / high / medium / low)
  - Impact descriptions per service
  - Remediation guidance steps
  - CWE-ID mapping (primarily CWE-798)

- **Non-Destructive Validator**
  - Google: geocoding read-only probe
  - AWS: `STS:GetCallerIdentity` (identity only, zero resource access)
  - Stripe: retrieve non-existent resource (404 = valid, 401 = invalid)
  - GitHub: `GET /user` read-only endpoint
  - Slack: `auth.test` read-only method
  - SendGrid: `GET /v3/scopes` permission listing
  - Mailgun: `GET /v3/domains` read-only listing
  - Twilio: `GET /Accounts/{SID}` read-only
  - Shopify: `GET /admin/api/shop.json` read-only
  - Generic: Shannon entropy + static analysis (no live probe)
  - DB connection strings: always skipped (never probed live)
  - Result caching to avoid re-probing identical keys
  - Per-domain adaptive rate limiting with back-off

- **Electron GUI Dashboard**
  - Dark terminal aesthetic with JetBrains Mono typography
  - Config panel with scan mode, depth, page, and delay controls
  - Live terminal log with color-coded event types
  - Findings table with risk badges, validation status, and detail modal
  - Assets view (pages / scripts / API calls tabs)
  - Scan history with result reload
  - Risk summary sidebar with animated bar charts
  - Real-time progress visualization
  - Detail modal with context, impact, remediation, validation breakdown

- **Reporting Engine**
  - JSON report (structured, machine-readable)
  - Standalone HTML report (dark-themed, no external dependencies)
  - PDF report using PDFKit (cover page, findings table, remediation section)

- **Storage Layer**
  - SQLite via `better-sqlite3` (WAL mode)
  - Tables: scans, pages, scripts, findings
  - Full CRUD + indexed queries

- **CLI Interface** (`cli.js`)
  - Headless scan without Electron GUI
  - ANSI color output with risk-coded findings
  - SIGINT graceful stop
  - Exit code 2 on critical findings (CI/CD integration)

- **Utilities**
  - `scopeChecker.js` — domain boundary enforcement
  - `rateLimiter.js` — per-domain adaptive throttling
  - `robotsChecker.js` — optional robots.txt respect
  - `jwtDecoder.js` — offline JWT claim inspection
  - `logger.js` — Winston file + console logging

- **Tests** — pure Node.js unit tests (no external test framework)
  - Pattern engine: 10 tests
  - Entropy detector: 6 tests
  - Classifier: 2 tests
  - JWT decoder: 5 tests
  - Scope checker: 8 tests

- **CI/CD** — GitHub Actions workflow (lint → test → build AppImage)
- **Kali Linux** setup script with Chromium + desktop shortcut

### Security
- All validation probes explicitly non-destructive
- Key values masked in GUI (never displayed in full)
- Scope enforcement prevents accidental out-of-scope crawling
- DB connection strings never probed live
- IPC channel whitelist via Electron contextBridge

---

## Planned — [1.1.0]

- [ ] Sitemap.xml discovery and crawling
- [ ] GraphQL introspection endpoint detection
- [ ] HubSpot and Algolia validators
- [ ] Slack webhook message probe (optional, user-confirmed)
- [ ] Export to Word (.docx) format
- [ ] Docker container for CI/CD pipeline integration
- [ ] Findings diff between two scans
- [ ] Burp Suite extension integration
