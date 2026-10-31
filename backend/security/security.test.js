/**
 * backend/security/security.test.js — Member 4, adapted tests.
 *
 * IMPORTANT: run this AFTER copying backend/security/ into the repo,
 * from the repo's backend/ folder:
 *   node security/security.test.js
 * It imports ../analyzer.js, ../urlhaus.js and ../redirect.js, so it
 * cannot run from the adapted folder alone — that is intentional:
 * it verifies the adaptation against the real repo files.
 *
 * All network in these tests is mocked, except one test that uses the
 * REAL repo lookupUrlhaus() against a local mock URLhaus server.
 * Real malicious URLs are never opened in a browser.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { parseUrl, isPrivateIP, isBlockedHost, getRegistrableDomain } = require('./urlParser.js');
const { buildSecurityReport } = require('./securityReport.js');
const { checkImpersonation } = require('./impersonationChecker.js');
const { lookupUrlhaus } = require('../urlhaus.js');

const neverCalled = () => { throw new Error('should not have been called'); };
const mockClean = async () => ({ status: 'clean', threat: null });
const mockListed = async () => ({ status: 'listed', threat: 'malware_download' });
const mockUnknown = async () => ({ status: 'unknown', threat: null });

test('parser: protocol, host, domain, path; private IPs blocked', () => {
  const p = parseUrl('https://sub.paypal.com/login?x=1');
  assert.equal(p.protocol, 'https');
  assert.equal(p.hostname, 'sub.paypal.com');
  assert.equal(p.domain, 'paypal.com');
  assert.equal(p.path, '/login');
  assert.equal(p.isIP, false);
  assert.equal(isPrivateIP('10.0.0.5'), true);
  assert.equal(isPrivateIP('172.16.0.9'), true);
  assert.equal(isPrivateIP('192.168.1.1'), true);
  assert.equal(isPrivateIP('127.0.0.1'), true);
  assert.equal(isPrivateIP('169.254.169.254'), true);
  assert.equal(isPrivateIP('8.8.8.8'), false);
  assert.equal(isBlockedHost('localhost'), true);
  assert.equal(isBlockedHost('example.com'), false);
  assert.throws(() => parseUrl('not a url :::'), /INVALID_URL/);
});

test('official domain skips enrichment, as in server.js', async () => {
  const r = await buildSecurityReport('https://www.amazon.in/gp/order', {
    lookupUrlhausFn: neverCalled, followRedirectsFn: neverCalled,
  });
  assert.equal(r.enrichmentSkipped, true);
  assert.deepEqual(r.redirectChain, []);
  assert.equal(r.threatIntel.status, 'unknown'); // skipped, not "clean"
});

test('SSRF: localhost and private IP are blocked with no network call', async () => {
  for (const url of ['http://localhost:3000/admin', 'http://192.168.1.10/login']) {
    const r = await buildSecurityReport(url, {
      lookupUrlhausFn: neverCalled, followRedirectsFn: neverCalled,
    });
    assert.equal(r.blocked, true, url);
    assert.equal(r.error, 'SSRF_BLOCKED', url);
    assert.ok(r.riskIndicators.some((i) => i.type === 'ssrf_blocked'));
  }
});

test('shortener: redirect chain followed via injected followRedirects; non-shortener not followed', async () => {
  const mockFollow = async () => ({
    chain: ['https://bit.ly/abc', 'https://example.com/final'],
    finalUrl: 'https://example.com/final', reachedFinal: true, blocked: false,
  });
  const r = await buildSecurityReport('https://bit.ly/abc', {
    lookupUrlhausFn: mockClean, followRedirectsFn: mockFollow,
  });
  assert.deepEqual(r.redirectChain, ['https://bit.ly/abc', 'https://example.com/final']);
  assert.equal(r.finalUrl, 'https://example.com/final');
  assert.equal(r.threatIntel.status, 'clean');

  const plain = await buildSecurityReport('https://www.example.com/', {
    lookupUrlhausFn: mockClean, followRedirectsFn: neverCalled,
  });
  assert.deepEqual(plain.redirectChain, []);
});

test('redirect blocked by SSRF guard is reported, not fetched further', async () => {
  const mockFollow = async () => ({
    chain: ['https://bit.ly/abc'], finalUrl: 'https://bit.ly/abc',
    reachedFinal: false, blocked: true,
  });
  const r = await buildSecurityReport('https://bit.ly/abc', {
    lookupUrlhausFn: mockClean, followRedirectsFn: mockFollow,
  });
  assert.equal(r.redirectBlocked, true);
  assert.ok(r.riskIndicators.some((i) => i.type === 'ssrf_blocked'));
});

test('URLhaus: repo enum listed / clean / unknown — failure is never clean', async () => {
  const listed = await buildSecurityReport('https://example.com/x', {
    lookupUrlhausFn: mockListed, followRedirects: false,
  });
  assert.equal(listed.threatIntel.status, 'listed');
  assert.equal(listed.threatIntel.threat, 'malware_download');

  const failed = await buildSecurityReport('https://www.example.com/', {
    lookupUrlhausFn: mockUnknown, followRedirects: false,
  });
  assert.equal(failed.threatIntel.status, 'unknown');
  assert.notEqual(failed.threatIntel.status, 'clean');
  assert.ok(failed.limitations.some((l) => l.includes('NOT proof')));
});

test('REAL repo lookupUrlhaus against a local mock server, using URLHAUS_AUTH_KEY', async () => {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const url = new URLSearchParams(body).get('url') || '';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (url.includes('malware')) return res.end(JSON.stringify({ query_status: 'ok', threat: 'malware_download' }));
      return res.end(JSON.stringify({ query_status: 'no_results' }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const api = 'http://127.0.0.1:' + server.address().port + '/v1/url/';
  try {
    const listed = await lookupUrlhaus('https://example-malware-site.com/payload.exe', { apiUrl: api });
    assert.equal(listed.status, 'listed');
    const clean = await lookupUrlhaus('https://www.google.com/', { apiUrl: api });
    assert.equal(clean.status, 'clean'); // repo word, not 'not_listed'
  } finally {
    server.close();
  }
});

test('sender: mismatch flagged; brand alone is not proof; no sender = no duplicate URL flag', () => {
  const mismatch = checkImpersonation({
    parsed: parseUrl('https://sbi-secure-offer.xyz/login'),
    sender: 'support@sbi.co.in', senderDisplayName: 'SBI',
  });
  assert.ok(mismatch.indicators.some((i) => i.type === 'sender_domain_mismatch'));

  const legit = checkImpersonation({
    parsed: parseUrl('https://www.paypal.com/signin'),
    sender: 'service@paypal.com', senderDisplayName: 'PayPal',
  });
  assert.equal(legit.indicators.length, 0);

  // No sender metadata: URL brand impersonation already lives in
  // analyzer.js (+30). This checker must not flag it again.
  const noSender = checkImpersonation({ parsed: parseUrl('https://paypa1-login.xyz/verify') });
  assert.equal(noSender.indicators.length, 0);
  assert.equal(noSender.checked, false);
});

test('report does not re-score heuristics (no double-counting)', async () => {
  const r = await buildSecurityReport('https://paypa1-login.xyz/verify', {
    lookupUrlhausFn: mockClean, followRedirects: false,
  });
  const types = r.riskIndicators.map((i) => i.type);
  assert.ok(!types.includes('ip_based_url'));
  assert.ok(!types.includes('brand_impersonation'));
  // Points are null by design: Member 2 adds nothing from this report
  // to the analyzer.js score without a contract update.
  for (const ind of r.riskIndicators) assert.equal(ind.points, null);
});

test('parser: IDN, punycode, IP, trailing dot, userinfo, malformed URLs', () => {
  // IDN: WHATWG URL normalises to punycode; the parser reports the
  // punycode hostname (homograph detection itself lives in analyzer.js).
  const idn = parseUrl('https://münchen.de/');
  assert.ok(idn.hostname.startsWith('xn--'));
  assert.equal(idn.domain, idn.hostname);
  // Punycode / homograph form parses as a plain domain.
  const puny = parseUrl('https://xn--pple-43d.com/login');
  assert.equal(puny.hostname, 'xn--pple-43d.com');
  assert.equal(puny.domain, 'xn--pple-43d.com');
  // IPv4 and IPv6 URLs are IPs; private ones are blocked.
  const v4 = parseUrl('http://192.168.1.1/admin');
  assert.equal(v4.isIP, true);
  assert.equal(v4.isBlockedHost, true);
  const v6 = parseUrl('http://[::1]/');
  assert.equal(v6.isIP, true);
  assert.equal(v6.hostname, '::1');
  assert.equal(v6.isBlockedHost, true);
  const v6doc = parseUrl('http://[2001:db8::1]/');
  assert.equal(v6doc.isIP, true);
  assert.equal(v6doc.isBlockedHost, true);
  // Trailing dot is stripped everywhere.
  const dotted = parseUrl('https://example.com./path');
  assert.equal(dotted.hostname, 'example.com');
  assert.equal(dotted.domain, 'example.com');
  // Userinfo: credentials are exposed, the host is still the real host.
  const cred = parseUrl('https://user:pass@example.com/');
  assert.equal(cred.username, 'user');
  assert.equal(cred.hasCredentials, true);
  assert.equal(cred.hostname, 'example.com');
  // Malformed input throws INVALID_URL.
  assert.throws(() => parseUrl(''), /INVALID_URL/);
  assert.throws(() => parseUrl('http://'), /INVALID_URL/);
  assert.throws(() => parseUrl('   '), /INVALID_URL/);
});

test('registrable domain: free-hosting suffixes are public suffixes', () => {
  assert.equal(getRegistrableDomain('evil.vercel.app'), 'evil.vercel.app');
  assert.equal(getRegistrableDomain('sub.evil.vercel.app'), 'evil.vercel.app');
  assert.equal(getRegistrableDomain('evil.github.io'), 'evil.github.io');
  assert.equal(getRegistrableDomain('sub.example.co.uk'), 'example.co.uk');
});

test('impersonation: hosting-subdomain sender mismatch is caught', () => {
  // Before vercel.app was listed, evil.vercel.app parsed as domain
  // vercel.app, so a vercel.app sender looked legitimate.
  const mismatch = checkImpersonation({
    parsed: parseUrl('https://evil.vercel.app/login'),
    sender: 'support@vercel.app', senderDisplayName: 'Vercel',
  });
  assert.ok(mismatch.indicators.length > 0);
  assert.ok(mismatch.indicators.some((i) => i.type === 'sender_domain_mismatch'));
});
