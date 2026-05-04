#!/usr/bin/env node
/**
 * cli.js — APISentinel Headless CLI
 * Run scans from the command line without launching the Electron GUI.
 * Useful for CI/CD pipelines, scheduled scans, or scripted assessments.
 *
 * Usage:
 *   node cli.js --url https://target.com [options]
 *   node cli.js --help
 */

'use strict';

const { initDatabase }        = require('./src/storage');
const { ScanOrchestrator }    = require('./src/scanOrchestrator');
const { generateReports }     = require('./src/reporter');
const logger                  = require('./src/utils/logger');

// ── CLI Argument Parser (no external dep) ────────────────────────────────
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { args.help = true; continue; }
    if (arg.startsWith('--')) {
      const [key, ...rest] = arg.slice(2).split('=');
      args[key] = rest.length ? rest.join('=') : argv[++i] ?? true;
    }
  }
  return args;
}

function printHelp() {
  console.log(`
APISentinel CLI — API Key Security Assessment Tool
For authorized security testing only.

Usage:
  node cli.js --url <target> [options]

Required:
  --url <url>            Target URL to scan (e.g. https://example.com)

Crawl Options:
  --mode <mode>          static | puppeteer | auto  (default: auto)
  --depth <n>            Max crawl depth           (default: 4)
  --pages <n>            Max pages to crawl        (default: 150)
  --delay <ms>           Polite delay between reqs (default: 400)

Analysis Options:
  --no-validate          Skip live key validation
  --no-entropy           Skip entropy-based detection

Output Options:
  --format <fmt>         json,html,pdf  (comma-separated, default: json,html)
  --output <dir>         Report output directory   (default: ~/APISentinel-Reports)
  --quiet                Suppress progress output

Examples:
  node cli.js --url https://app.example.com
  node cli.js --url https://app.example.com --mode puppeteer --depth 5 --format json,html,pdf
  node cli.js --url https://app.example.com --no-validate --quiet
`);
}

// ── ANSI colors ──────────────────────────────────────────────────────────
const c = {
  reset:    '\x1b[0m',
  bold:     '\x1b[1m',
  dim:      '\x1b[2m',
  red:      '\x1b[31m',
  green:    '\x1b[32m',
  yellow:   '\x1b[33m',
  blue:     '\x1b[36m',
  magenta:  '\x1b[35m',
  gray:     '\x1b[90m',
};

const RISK_COLOR = {
  critical: c.red + c.bold,
  high:     c.yellow + c.bold,
  medium:   c.yellow,
  low:      c.green,
};

function banner() {
  console.log(`${c.blue}${c.bold}
  ██████╗ ██████╗ ██╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██╔══██╗██╔══██╗██║    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ███████║██████╔╝██║    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ██╔══██║██╔═══╝ ██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ██║  ██║██║     ██║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
${c.reset}${c.dim}  API Key Security Assessment Tool — Authorized Use Only${c.reset}\n`);
}

function log(level, msg) {
  if (args.quiet && level !== 'FINDING' && level !== 'DONE' && level !== 'ERROR') return;
  const colors = { INFO: c.blue, PAGE: c.green, SCRIPT: c.yellow,
    FINDING: c.red + c.bold, VALID: c.green + c.bold, ERROR: c.red,
    DONE: c.blue + c.bold };
  const color  = colors[level] || c.gray;
  const ts     = new Date().toLocaleTimeString('en-GB', { hour12: false });
  console.log(`${c.gray}[${ts}]${c.reset} ${color}${level.padEnd(8)}${c.reset} ${msg}`);
}

// ── Main ─────────────────────────────────────────────────────────────────
let args;

async function main() {
  args = parseArgs(process.argv);

  if (args.help || !args.url) {
    banner();
    printHelp();
    process.exit(args.help ? 0 : 1);
  }

  banner();

  // Validate URL
  let targetUrl;
  try {
    targetUrl = new URL(args.url).href;
  } catch {
    console.error(`${c.red}Error: Invalid URL — ${args.url}${c.reset}`);
    process.exit(1);
  }

  const formats   = (args.format || 'json,html').split(',').map(s => s.trim());
  const outputDir = args.output || undefined;

  const config = {
    targetUrl,
    mode:     args.mode     || 'auto',
    maxDepth: parseInt(args.depth  || '4'),
    maxPages: parseInt(args.pages  || '150'),
    delayMs:  parseInt(args.delay  || '400'),
    validate: args['no-validate'] !== true,
  };

  console.log(`${c.bold}Target:${c.reset}  ${config.targetUrl}`);
  console.log(`${c.bold}Mode:${c.reset}    ${config.mode}`);
  console.log(`${c.bold}Depth:${c.reset}   ${config.maxDepth}  Pages: ${config.maxPages}  Delay: ${config.delayMs}ms`);
  console.log(`${c.bold}Validate:${c.reset}${config.validate ? 'yes' : 'no'}`);
  console.log(`${c.bold}Formats:${c.reset} ${formats.join(', ')}\n`);

  // Initialise DB
  initDatabase();

  // Create orchestrator
  const orchestrator = new ScanOrchestrator(config);

  // Wire events to CLI output
  orchestrator.on('status',     ({ phase, message }) => log('INFO', message || phase));
  orchestrator.on('found-page', ({ url, depth })     => log('PAGE', `[d${depth}] ${url}`));
  orchestrator.on('found-asset',({ type, url })      => type === 'script' && log('SCRIPT', url));
  orchestrator.on('found-key',  (f) => {
    const color = RISK_COLOR[f.riskLevel] || '';
    log('FINDING', `${color}[${(f.riskLevel || '').toUpperCase()}]${c.reset} ${f.service} — ${f.masked} @ ${f.sourceUrl}`);
  });
  orchestrator.on('validate-result', ({ id, status }) => {
    const statusColor = status === 'valid'   ? c.red + c.bold
                      : status === 'invalid' ? c.green
                      : c.gray;
    log('VALID', `${statusColor}[${status?.toUpperCase()}]${c.reset} ${id.slice(0, 8)}…`);
  });
  orchestrator.on('error', ({ message }) => log('ERROR', message));

  // Handle SIGINT (Ctrl+C) gracefully
  process.on('SIGINT', () => {
    console.log(`\n${c.yellow}Stopping scan…${c.reset}`);
    orchestrator.stop();
    setTimeout(() => process.exit(0), 2000);
  });

  try {
    const result = await orchestrator.run();
    const { summary, scanId } = result;

    console.log(`\n${c.bold}${c.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
    console.log(`${c.bold}SCAN COMPLETE${c.reset}   ID: ${scanId}`);
    console.log(`${c.bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
    console.log(`  Total findings: ${c.bold}${summary.total}${c.reset}`);
    console.log(`  ${c.red}${c.bold}Critical: ${summary.bySeverity.critical || 0}${c.reset}  ${c.yellow}High: ${summary.bySeverity.high || 0}${c.reset}  Medium: ${summary.bySeverity.medium || 0}  Low: ${summary.bySeverity.low || 0}`);
    console.log(`  Confirmed valid keys: ${c.red}${c.bold}${summary.validated?.valid || 0}${c.reset}\n`);

    // Generate reports
    log('INFO', `Generating reports: ${formats.join(', ')}`);
    const paths = await generateReports(scanId, formats, outputDir);

    console.log(`\n${c.bold}Reports:${c.reset}`);
    for (const [fmt, filePath] of Object.entries(paths)) {
      if (filePath) console.log(`  ${c.green}✓${c.reset} ${fmt.toUpperCase().padEnd(5)} ${filePath}`);
    }

    console.log(`\n${c.dim}For authorized use only. CWE-798 / OWASP A07${c.reset}\n`);

    process.exit((summary.bySeverity?.critical || 0) > 0 ? 2 : 0);

  } catch (err) {
    log('ERROR', err.message);
    logger.error('CLI fatal error:', err);
    process.exit(1);
  }
}

main();
