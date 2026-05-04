# APISentinel 🔐
### GUI-Based API Key Security Assessment Tool for Kali Linux

> **⚠️ AUTHORIZED USE ONLY** — This tool is strictly intended for authorized security testing,
> bug bounty programs, and internal security audits where you have explicit written permission
> to test the target system. Unauthorized use is illegal and unethical.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APISentinel Architecture                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                     ELECTRON GUI (Renderer Process)                  │  │
│   │   ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────────┐  │  │
│   │   │  Config  │  │ Live Term- │  │ Findings │  │  Assets / Pages  │  │  │
│   │   │  Panel   │  │  inal Log  │  │  Table   │  │   / JS Scripts   │  │  │
│   │   └──────────┘  └────────────┘  └──────────┘  └──────────────────┘  │  │
│   └──────────────────────────────┬───────────────────────────────────────┘  │
│                                  │  IPC (contextBridge / preload.js)         │
│   ┌──────────────────────────────▼───────────────────────────────────────┐  │
│   │                    ELECTRON MAIN PROCESS                             │  │
│   │              ipc/handlers.js  ←→  scanOrchestrator.js               │  │
│   └─────────┬──────────────┬──────────────┬──────────────┬──────────────┘  │
│             │              │              │              │                   │
│   ┌─────────▼──┐  ┌────────▼───┐  ┌──────▼─────┐  ┌────▼───────────────┐  │
│   │  CRAWLER   │  │  ANALYZER  │  │ CLASSIFIER │  │    VALIDATOR       │  │
│   │            │  │            │  │            │  │                    │  │
│   │ ┌────────┐ │  │ ┌────────┐ │  │ serviceMap │  │ ┌────────────────┐ │  │
│   │ │Static  │ │  │ │Pattern │ │  │            │  │ │ GoogleValidator│ │  │
│   │ │Crawler │ │  │ │Engine  │ │  │ classifyAll│  │ │ AwsValidator   │ │  │
│   │ └────────┘ │  │ └────────┘ │  │            │  │ │ StripeValidator│ │  │
│   │ ┌────────┐ │  │ ┌────────┐ │  │ summarize  │  │ │ GithubValidator│ │  │
│   │ │Puppet- │ │  │ │Entropy │ │  │            │  │ │ SlackValidator │ │  │
│   │ │eerCrawl│ │  │ │Detector│ │  └────────────┘  │ │ GenericValid.  │ │  │
│   │ └────────┘ │  │ └────────┘ │                  │ └────────────────┘ │  │
│   │            │  │            │                  │                    │  │
│   │ linkExtract│  │ 30+ Regex  │                  │  Non-destructive   │  │
│   │ urlResolve │  │ patterns   │                  │  read-only probes  │  │
│   └────────────┘  └────────────┘                  └────────────────────┘  │
│             │              │              │              │                   │
│   ┌─────────▼──────────────▼──────────────▼──────────────▼──────────────┐  │
│   │                       STORAGE (SQLite)                               │  │
│   │          scans | pages | scripts | findings                          │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│             │                                                                │
│   ┌─────────▼──────────────────────────────────────────────────────────┐   │
│   │                       REPORTER                                      │   │
│   │          JSON Report  |  HTML Report  |  PDF Report                 │   │
│   └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
api-sentinel/
├── main.js                        # Electron main process entry
├── preload.js                     # Secure IPC bridge (contextBridge)
├── package.json
│
├── src/
│   ├── scanOrchestrator.js        # Master pipeline coordinator
│   │
│   ├── crawler/
│   │   ├── index.js               # Crawler orchestrator (static vs puppeteer)
│   │   ├── staticCrawler.js       # Axios-based fast HTTP crawler
│   │   ├── puppeteerCrawler.js    # Headless browser for JS-heavy SPAs
│   │   └── linkExtractor.js       # HTML/JS URL + script discovery
│   │
│   ├── analyzer/
│   │   ├── index.js               # Analyzer orchestrator
│   │   ├── patterns.js            # 30+ service-specific regex patterns
│   │   ├── patternEngine.js       # Multi-pattern scanner with context
│   │   └── entropyDetector.js     # Shannon entropy heuristic detection
│   │
│   ├── classifier/
│   │   ├── index.js               # Enriches findings with metadata
│   │   └── serviceMap.js          # Service → impact + remediation map
│   │
│   ├── validator/
│   │   ├── index.js               # Validator orchestrator
│   │   ├── base.js                # BaseValidator class
│   │   └── services/
│   │       ├── google.js          # Google API Key (Geocoding probe)
│   │       ├── aws.js             # AWS (STS GetCallerIdentity)
│   │       ├── stripe.js          # Stripe (retrieve probe)
│   │       ├── github.js          # GitHub (/user endpoint)
│   │       ├── slack.js           # Slack (auth.test) + SendGrid
│   │       └── generic.js         # Entropy + static analysis only
│   │
│   ├── storage/
│   │   ├── index.js               # SQLite CRUD operations
│   │   └── schema.js              # Table definitions
│   │
│   ├── reporter/
│   │   ├── index.js               # Report generation orchestrator
│   │   ├── jsonReporter.js        # Structured JSON output
│   │   ├── htmlReporter.js        # Standalone HTML report
│   │   └── pdfReporter.js         # PDFKit-based PDF report
│   │
│   ├── ipc/
│   │   └── handlers.js            # Electron IPC handler registration
│   │
│   └── utils/
│       └── logger.js              # Winston logger (console + file)
│
└── gui/
    ├── index.html                 # Main dashboard HTML
    ├── styles.css                 # Dark terminal aesthetic CSS
    └── renderer.js                # GUI controller logic
```

---

## Detected Key Types

| Service         | Pattern ID            | Risk Level |
|----------------|----------------------|------------|
| AWS Access Key | `aws_access_key`     | 🔴 Critical |
| AWS Secret Key | `aws_secret_key`     | 🔴 Critical |
| Google API Key | `google_api_key`     | 🟠 High     |
| Firebase Key   | `firebase_key`       | 🟠 High     |
| Stripe Live    | `stripe_live_secret` | 🔴 Critical |
| GitHub PAT     | `github_pat`         | 🟠 High     |
| Slack Bot Token| `slack_bot_token`    | 🟠 High     |
| SendGrid       | `sendgrid_api_key`   | 🟠 High     |
| JWT Token      | `jwt_token`          | 🟡 Medium   |
| MongoDB URI    | `mongodb_uri`        | 🔴 Critical |
| PostgreSQL URI | `postgres_uri`       | 🔴 Critical |
| Azure Storage  | `azure_storage_key`  | 🔴 Critical |
| Twilio         | `twilio_account_sid` | 🟠 High     |
| Shopify        | `shopify_token`      | 🟠 High     |
| Entropy (any)  | `entropy_heuristic`  | 🟡 Medium   |

---

## Installation (Kali Linux)

### Prerequisites
```bash
# Update system
sudo apt-get update

# Install Node.js 20+
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify
node --version   # v20+
npm --version    # 9+

# Install Chromium for Puppeteer (headless browser mode)
sudo apt-get install -y chromium

# Set Puppeteer to use system Chromium
export PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
export PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
```

### Install & Run
```bash
# Clone / extract project
cd api-sentinel

# Install dependencies
npm install

# Start the application
npm start

# Development mode (with DevTools)
npm run dev
```

### Build AppImage for distribution
```bash
npm run build
# Output: dist/APISentinel-1.0.0.AppImage
```

---

## Usage Guide

### 1. Configure Target
- Enter the full target URL (e.g., `https://app.example.com`)
- Select crawl mode:
  - **Auto Detect** — Probes the page and auto-selects
  - **Static** — Fast HTTP crawl (good for traditional sites)
  - **Puppeteer** — Full JS rendering (use for React/Vue/Angular SPAs)

### 2. Tuning Parameters
| Parameter    | Default | Description                        |
|-------------|---------|-------------------------------------|
| Max Depth   | 4       | How deep to follow links            |
| Max Pages   | 150     | Maximum pages to crawl              |
| Delay (ms)  | 400     | Polite delay between requests       |

### 3. Start Scan
Click **▶ START SCAN**. The terminal panel shows real-time activity:
- `INFO` — Status messages
- `PAGE` — Pages discovered
- `SCRIPT` — JavaScript files found
- `KEY [RISK]` — Secrets detected with risk level
- `VALID/INVALID` — Live validation results

### 4. Review Findings
Switch to the **FINDINGS** view. Each row shows:
- Risk level badge (Critical / High / Medium / Low)
- Service name and icon
- Masked key value (never shown in full)
- Source URL and line number
- Validation status
- Click **DETAIL** for full context, impact, and remediation steps

### 5. Export Report
Click **JSON**, **HTML**, or **PDF** to export.
Reports are saved to `~/APISentinel-Reports/`.

---

## Validation Methods (Non-Destructive)

All probes are **read-only** with **zero side effects**:

| Service   | Probe Method                         | Why Safe                         |
|----------|--------------------------------------|----------------------------------|
| Google   | Geocode a public address             | Read-only, < $0.001 cost         |
| AWS      | `STS:GetCallerIdentity`              | Only returns identity — no data  |
| Stripe   | Retrieve non-existent payment intent | 404 = valid, 401 = invalid       |
| GitHub   | `GET /user`                          | Read-only profile fetch          |
| Slack    | `auth.test`                          | Returns auth status only         |
| SendGrid | `GET /v3/scopes`                     | Returns key permissions only     |

---

## Ethical Safeguards

1. **Scope enforcement** — Only crawls the specified domain and subdomains
2. **Rate limiting** — Configurable polite delay between requests
3. **Non-destructive validation** — All API probes are explicitly read-only
4. **Key masking** — Raw secret values are never displayed in the GUI
5. **Authorized use disclaimer** — Displayed on startup
6. **No external exfiltration** — All data stays local (SQLite + local files)
7. **robots.txt respect** — Can be enabled in advanced config
8. **Concurrency limits** — Prevents overwhelming target servers

---

## Supported Platforms
- ✅ Kali Linux (primary)
- ✅ Ubuntu 20.04+
- ✅ Debian 11+
- ✅ Any Electron-compatible Linux desktop

---

## Legal Notice

This tool is provided for **authorized security testing ONLY**. Usage against systems
without explicit written permission from the system owner violates:
- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act — United Kingdom
- Cybercrime laws in most jurisdictions worldwide

**Always obtain written authorization before testing any system you do not own.**

---

## License

MIT License — See LICENSE file.

*Built for professional security teams conducting authorized assessments.*
