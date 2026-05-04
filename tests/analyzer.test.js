/**
 * tests/analyzer.test.js
 * Unit tests for the pattern engine and entropy detector
 * Run with: npm test
 */

'use strict';

const { scanSource }             = require('../src/analyzer/patternEngine');
const { analyzeEntropy,
        extractHighEntropyStrings,
        shannonEntropy }         = require('../src/analyzer/entropyDetector');
const { classifyFinding }        = require('../src/classifier');
const { decodeJwt }              = require('../src/utils/jwtDecoder');
const { ScopeChecker }           = require('../src/utils/scopeChecker');

// ── Minimal test runner (no external deps) ───────────────────────────────
let passed = 0;
let failed = 0;
const errors = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
    failed++;
    errors.push({ name, error: err.message });
  }
}

function suite(name, fn) {
  console.log(`\n${name}`);
  fn();
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertEqual(a, b, msg) {
  if (a !== b) throw new Error(msg || `Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

function assertContains(arr, predicate, msg) {
  if (!arr.some(predicate)) throw new Error(msg || 'Array does not contain expected element');
}

// ─────────────────────────────────────────────────────────────────────────
// SUITE 1: Pattern Engine
// ─────────────────────────────────────────────────────────────────────────
suite('Pattern Engine — Known Key Formats', () => {

  test('detects AWS Access Key ID', () => {
    const src = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const findings = scanSource(src, 'https://example.com/app.js', 'js');
    assertContains(findings, f => f.patternId === 'aws_access_key',
      'Should detect AWS Access Key');
  });

  test('detects Google API Key', () => {
    const src = `const MAPS_KEY = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";`;
    const findings = scanSource(src, 'https://example.com/maps.js', 'js');
    assertContains(findings, f => f.patternId === 'google_api_key',
      'Should detect Google API Key');
  });

  test('detects Stripe live secret key', () => {
    const src = `stripe.setKey("sk_live_4eC39HqLyjWDarjtT1zdp7dc");`;
    const findings = scanSource(src, 'https://example.com/checkout.js', 'js');
    assertContains(findings, f => f.patternId === 'stripe_live_secret',
      'Should detect Stripe live secret');
  });

  test('detects GitHub PAT', () => {
    const src = `const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";`;
    const findings = scanSource(src, 'https://example.com/config.js', 'js');
    assertContains(findings, f => f.patternId === 'github_pat',
      'Should detect GitHub PAT');
  });

  test('detects Slack bot token', () => {
    const src = `const BOT = "xoxb-17653742809-17653742809-HeAVfkB8Cj0AzBRIo5PZXYA";`;
    const findings = scanSource(src, 'https://example.com/slack.js', 'js');
    assertContains(findings, f => f.patternId === 'slack_bot_token',
      'Should detect Slack bot token');
  });

  test('detects SendGrid API key', () => {
    const src = `const SG_KEY = "SG.ngeVfQFYQlKU8uomXXXXXX.yiJUxxx-PkZXXXXXXXXXXXXXXXXXXXXXXXX";`;
    const findings = scanSource(src, 'https://example.com/email.js', 'js');
    assertContains(findings, f => f.patternId === 'sendgrid_api_key',
      'Should detect SendGrid key');
  });

  test('detects JWT token', () => {
    const src = `const auth = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`;
    const findings = scanSource(src, 'https://example.com/auth.js', 'js');
    assertContains(findings, f => f.patternId === 'jwt_token',
      'Should detect JWT token');
  });

  test('detects MongoDB URI', () => {
    const src = `const DB = "mongodb+srv://admin:password123@cluster0.example.mongodb.net/mydb";`;
    const findings = scanSource(src, 'https://example.com/db.js', 'js');
    assertContains(findings, f => f.patternId === 'mongodb_uri',
      'Should detect MongoDB URI');
  });

  test('deduplicates identical keys', () => {
    const src = `
      const k1 = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";
      const k2 = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";
    `;
    const findings = scanSource(src, 'https://example.com/app.js', 'js');
    const googleFindings = findings.filter(f => f.patternId === 'google_api_key');
    assertEqual(googleFindings.length, 1, 'Should deduplicate identical keys');
  });

  test('does not false-positive on safe strings', () => {
    const src = `const msg = "Hello, world!"; const version = "1.2.3";`;
    const findings = scanSource(src, 'https://example.com/app.js', 'js');
    assertEqual(findings.length, 0, 'Should not find any keys in safe source');
  });

  test('masks key value in finding', () => {
    const src = `const key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";`;
    const findings = scanSource(src, 'https://example.com/app.js', 'js');
    const f = findings.find(f => f.patternId === 'google_api_key');
    assert(f, 'Finding should exist');
    assert(f.masked.includes('*'), 'Masked value should contain asterisks');
    assert(f.masked !== f.value, 'Masked != raw value');
  });

  test('captures correct line number', () => {
    const src = `// line 1\n// line 2\nconst key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";\n`;
    const findings = scanSource(src, 'https://example.com/app.js', 'js');
    const f = findings.find(f => f.patternId === 'google_api_key');
    assert(f?.lineNumber === 3, `Expected line 3, got ${f?.lineNumber}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SUITE 2: Entropy Detector
// ─────────────────────────────────────────────────────────────────────────
suite('Entropy Detector', () => {

  test('low entropy for common words', () => {
    const entropy = shannonEntropy('hellohellohellohello');
    assert(entropy < 3, `Expected low entropy, got ${entropy}`);
  });

  test('high entropy for random strings', () => {
    const entropy = shannonEntropy('Xk9mQ2pL7nR4vC1bF8wZ3jY5tH6aD0eG');
    assert(entropy > 3.5, `Expected high entropy, got ${entropy}`);
  });

  test('marks high entropy string as secret', () => {
    const result = analyzeEntropy('Xk9mQ2pL7nR4vC1bF8wZ3jY5tH6aD0eG', 'api_key');
    assert(result.isSecret, `Expected isSecret=true, got reason: ${result.reason}`);
  });

  test('marks URL as non-secret', () => {
    const result = analyzeEntropy('https://www.example.com/path', 'url');
    assert(!result.isSecret, 'URL should not be flagged as secret');
  });

  test('marks short string as non-secret', () => {
    const result = analyzeEntropy('abc123', 'key');
    assert(!result.isSecret, 'Short string should not be flagged');
  });

  test('extracts high-entropy assignments from source', () => {
    const src = `const API_SECRET = 'Xk9mQ2pL7nR4vC1bF8wZ3jY5tH6aD0eGpQ2w';`;
    const findings = extractHighEntropyStrings(src);
    assert(findings.length > 0, 'Should extract high-entropy assignment');
    assertEqual(findings[0].key, 'API_SECRET');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SUITE 3: Classifier
// ─────────────────────────────────────────────────────────────────────────
suite('Classifier', () => {

  test('enriches AWS finding with service metadata', () => {
    const finding = {
      id: 'test-1',
      patternId:   'aws_access_key',
      serviceName: 'AWS Access Key ID',
      riskLevel:   'critical',
      confidence:  'high',
      value:       'AKIAIOSFODNN7EXAMPLE',
      masked:      'AKIAIO***',
      sourceUrl:   'https://example.com/app.js',
      sourceType:  'js',
      lineNumber:  5,
      foundAt:     new Date().toISOString(),
    };
    const enriched = classifyFinding(finding);
    assert(enriched.service === 'Amazon Web Services', `Expected AWS, got ${enriched.service}`);
    assert(Array.isArray(enriched.remediation) && enriched.remediation.length > 0,
      'Should have remediation steps');
    assert(enriched.riskScore === 4, `Expected critical riskScore=4, got ${enriched.riskScore}`);
    assert(enriched.impact, 'Should have impact description');
    assertEqual(enriched.cweId, 'CWE-798');
  });

  test('enriches Stripe finding', () => {
    const finding = {
      id: 'test-2',
      patternId: 'stripe_live_secret',
      riskLevel: 'critical',
      confidence: 'high',
      value: 'sk_live_test',
      masked: 'sk_liv***',
      sourceUrl: 'https://example.com',
      sourceType: 'html',
      foundAt: new Date().toISOString(),
    };
    const enriched = classifyFinding(finding);
    assert(enriched.category === 'Payment Processor');
    assert(enriched.icon === '💳');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SUITE 4: JWT Decoder
// ─────────────────────────────────────────────────────────────────────────
suite('JWT Decoder', () => {

  const SAMPLE_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  test('decodes valid JWT', () => {
    const result = decodeJwt(SAMPLE_JWT);
    assert(result.valid, `Should decode successfully: ${result.error}`);
    assertEqual(result.header.alg, 'HS256');
    assertEqual(result.header.typ, 'JWT');
    assert(result.payload.sub === '1234567890');
    assert(result.payload.name === 'John Doe');
  });

  test('reports algorithm correctly', () => {
    const result = decodeJwt(SAMPLE_JWT);
    assertEqual(result.meta.algorithm, 'HS256');
  });

  test('detects sensitive name claim', () => {
    const result = decodeJwt(SAMPLE_JWT);
    const nameFound = result.meta.sensitiveClaims.some(c => c.key === 'name');
    assert(nameFound, 'Should detect name as sensitive claim');
  });

  test('rejects invalid JWT', () => {
    const result = decodeJwt('not.a.jwt.token.at.all');
    assert(!result.valid, 'Should reject invalid JWT');
  });

  test('rejects non-string input', () => {
    const result = decodeJwt(null);
    assert(!result.valid, 'Should reject null input');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SUITE 5: Scope Checker
// ─────────────────────────────────────────────────────────────────────────
suite('Scope Checker', () => {

  const scope = new ScopeChecker('https://example.com');

  test('allows exact domain', () => {
    assert(scope.isInScope('https://example.com/page'), 'Exact domain should be in scope');
  });

  test('allows subdomains by default', () => {
    assert(scope.isInScope('https://app.example.com/page'), 'Subdomain should be in scope');
  });

  test('blocks external domains', () => {
    assert(!scope.isInScope('https://evil.com/page'), 'External domain should be out of scope');
  });

  test('blocks non-HTTP protocols', () => {
    assert(!scope.isInScope('ftp://example.com/file'), 'FTP should be out of scope');
  });

  test('blocks media files', () => {
    assert(!scope.isInScope('https://example.com/photo.jpg'), 'JPEG should be excluded');
    assert(!scope.isInScope('https://example.com/video.mp4'), 'MP4 should be excluded');
  });

  test('blocks logout paths', () => {
    assert(!scope.isInScope('https://example.com/logout'), 'Logout path should be excluded');
  });

  test('blocks subdomains when allowSubdomains=false', () => {
    const strictScope = new ScopeChecker('https://example.com', { allowSubdomains: false });
    assert(!strictScope.isInScope('https://app.example.com/page'),
      'Subdomain should be blocked in strict mode');
  });

  test('filter() returns only in-scope URLs', () => {
    const urls = [
      'https://example.com/a',
      'https://evil.com/b',
      'https://sub.example.com/c',
    ];
    const filtered = scope.filter(urls);
    assertEqual(filtered.length, 2, 'Should filter to 2 in-scope URLs');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Results
// ─────────────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(50)}`);
console.log(`Tests: ${passed + failed} total   ✓ ${passed} passed   ✗ ${failed} failed`);

if (failed > 0) {
  console.log('\nFailed tests:');
  errors.forEach(e => console.log(`  ✗ ${e.name}: ${e.error}`));
  process.exit(1);
} else {
  console.log('\nAll tests passed ✓');
  process.exit(0);
}
