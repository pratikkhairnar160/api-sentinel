/**
 * linkExtractor.js
 * Extracts all URLs, JS file references, API endpoints from HTML/JS source
 */

'use strict';

const cheerio = require('cheerio');
const { URL } = require('url');

/**
 * Resolve a URL relative to a base
 */
function resolveUrl(href, base) {
  try {
    return new URL(href, base).href;
  } catch {
    return null;
  }
}

/**
 * Determine if a URL is in-scope (same registered domain)
 */
function isInScope(targetUrl, baseUrl, allowSubdomains = true) {
  try {
    const t = new URL(targetUrl);
    const b = new URL(baseUrl);

    if (allowSubdomains) {
      // Allow same domain + subdomains
      return t.hostname === b.hostname ||
             t.hostname.endsWith('.' + b.hostname);
    }
    return t.hostname === b.hostname;
  } catch {
    return false;
  }
}

/**
 * Extract all links, script src, and inline scripts from HTML
 * @param {string} html
 * @param {string} pageUrl
 * @param {string} baseUrl  — scope root
 * @returns {{ links: string[], scripts: string[], inlineScripts: string[], apis: string[] }}
 */
function extractFromHtml(html, pageUrl, baseUrl) {
  const $ = cheerio.load(html);
  const links = new Set();
  const scripts = new Set();
  const inlineScripts = [];
  const apis = new Set();

  // All anchor hrefs
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    const resolved = resolveUrl(href, pageUrl);
    if (resolved && isInScope(resolved, baseUrl)) links.add(resolved);
  });

  // Forms
  $('form[action]').each((_, el) => {
    const action = $(el).attr('action');
    const resolved = resolveUrl(action, pageUrl);
    if (resolved && isInScope(resolved, baseUrl)) links.add(resolved);
  });

  // Script src references
  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    const resolved = resolveUrl(src, pageUrl);
    if (resolved) scripts.add(resolved);
  });

  // Inline script content
  $('script:not([src])').each((_, el) => {
    const content = $(el).html();
    if (content && content.trim().length > 10) {
      inlineScripts.push({ content, sourceUrl: pageUrl });
    }
  });

  // Fetch/XHR-looking URLs from inline scripts
  for (const { content } of inlineScripts) {
    const apiUrls = extractApiUrlsFromJs(content, pageUrl);
    apiUrls.forEach(u => apis.add(u));
  }

  // Meta refresh, link canonical
  $('meta[http-equiv="refresh"]').each((_, el) => {
    const content = $(el).attr('content') || '';
    const m = content.match(/url=(.+)/i);
    if (m) {
      const resolved = resolveUrl(m[1].trim(), pageUrl);
      if (resolved && isInScope(resolved, baseUrl)) links.add(resolved);
    }
  });

  return {
    links: [...links],
    scripts: [...scripts],
    inlineScripts,
    apis: [...apis],
  };
}

/**
 * Extract API-looking URLs from JavaScript source
 * Looks for fetch(), axios(), XMLHttpRequest, and string literals
 */
function extractApiUrlsFromJs(jsSource, baseUrl) {
  const urls = new Set();

  // fetch("..."), axios.get("...")
  const fetchRe = /(?:fetch|axios(?:\.\w+)?)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let m;
  while ((m = fetchRe.exec(jsSource)) !== null) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved) urls.add(resolved);
  }

  // URL strings that look like API paths
  const apiPathRe = /['"`](\/(?:api|v\d|graphql|rest|service)[^\s'"`]+)['"`]/gi;
  while ((m = apiPathRe.exec(jsSource)) !== null) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved) urls.add(resolved);
  }

  // http/https string literals
  const absoluteRe = /['"`](https?:\/\/[^\s'"`<>]{10,200})['"`]/g;
  while ((m = absoluteRe.exec(jsSource)) !== null) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved) urls.add(resolved);
  }

  return [...urls];
}

/**
 * Extract additional JS file references from JS source (dynamic imports, etc.)
 */
function extractScriptsFromJs(jsSource, baseUrl) {
  const scripts = new Set();

  // import("..."), require("...")
  const importRe = /(?:import|require)\s*\(\s*['"`]([^'"`]+\.js(?:\?[^'"`]*)?)['"`]/g;
  let m;
  while ((m = importRe.exec(jsSource)) !== null) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved) scripts.add(resolved);
  }

  // import ... from "..."
  const staticImportRe = /import\s+[^'"]*['"`]([^'"`]+\.js(?:\?[^'"`]*)?)['"`]/g;
  while ((m = staticImportRe.exec(jsSource)) !== null) {
    const resolved = resolveUrl(m[1], baseUrl);
    if (resolved) scripts.add(resolved);
  }

  return [...scripts];
}

module.exports = {
  extractFromHtml,
  extractApiUrlsFromJs,
  extractScriptsFromJs,
  resolveUrl,
  isInScope,
};
