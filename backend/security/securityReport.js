/**
 * backend/security/securityReport.js — Member 4, adapted to the team repo.
 *
 * This is the ONLY orchestrator Member 2 needs from this folder:
 *   const { buildSecurityReport } = require('./security/securityReport');
 *   const report = await buildSecurityReport(url, { sender: '...' });
 *
 * What it REUSES (do not duplicate):
 *   ../analyzer.js  — isShortener() + analyzeUrl() for official-domain check.
 *                     analyzer.js stays the single source of truth for scoring.
 *   ../redirect.js  — followRedirects(), SSRF-guarded, max 5 hops, 5s total.
 *   ../urlhaus.js   — lookupUrlhaus(), env URLHAUS_AUTH_KEY (not API_KEY),
 *                     status: 'listed' | 'clean' | 'unknown'.
 *
 * What it ADDS:
 *   Structured URL parsing (./urlParser.js), structured sender-domain
 *   checks (./impersonationChecker.js), and one combined report in
 *   API-contract field names: redirectChain, finalUrl, threatIntel.
 *
 * What it does NOT do:
 *   Re-score heuristics. analyzer.js already scores IP hosts, shorteners,
 *   punycode, suspicious TLDs, brand impersonation, etc. Adding those
 *   points again here would double-count. riskIndicators below are
 *   NEW evidence only (sender mismatch, redirect SSRF block). For
 *   threatIntel and redirects, server.js already adds its own reasons
 *   (+60 for listed, redirect-destination reasons) — do not add them
 *   a second time from this report.
 *
 * Safety, mirroring server.js:
 *   - Blocked hosts (localhost / private / internal) are never fetched
 *     and never sent to URLhaus.
 *   - Official domains skip enrichment, exactly as server.js does.
 *   - URLhaus failure stays 'unknown', never 'clean'. 'clean' means
 *     checked and not listed. Failure is NOT proof a URL is safe.
 *   - Nothing here opens a URL in a user's browser.
 */
'use strict';

const PhishShield = require('../analyzer.js');
const { lookupUrlhaus } = require('../urlhaus.js');
const { followRedirects } = require('../redirect.js');
const { parseUrl } = require('./urlParser.js');
const { checkImpersonation } = require('./impersonationChecker.js');

async function buildSecurityReport(input, options) {
  options = options || {};
  const sender = options.sender;
  const senderDomain = options.senderDomain;
  const senderDisplayName = options.senderDisplayName;
  const checkThreatIntel = options.checkThreatIntel !== false;
  // followRedirects: null = shorteners only (server.js rule), true = always, false = never.
  const followRedirectsOpt = options.followRedirects === undefined ? null : options.followRedirects;
  const lookupUrlhausFn = options.lookupUrlhausFn || lookupUrlhaus;
  const followRedirectsFn = options.followRedirectsFn || followRedirects;
  const urlhausOptions = options.urlhausOptions || {};
  const redirectOptions = options.redirectOptions || {};

  let parsed;
  try {
    parsed = parseUrl(input);
  } catch (e) {
    return {
      url: input, host: '', parsed: null, blocked: false,
      redirectChain: [], finalUrl: null, redirectBlocked: false,
      threatIntel: { status: 'unknown', threat: null },
      senderCheck: { checked: false, senderDomain: null, indicators: [] },
      riskIndicators: [],
      limitations: ['URL could not be parsed.'],
      enrichmentSkipped: false, error: 'INVALID_URL',
    };
  }

  const targetUrl = /^https?:\/\//i.test(parsed.input) ? parsed.input : 'https://' + parsed.input;
  const limitations = [];
  const riskIndicators = [];

  // 0. SSRF block first — before any network call, before URLhaus.
  if (parsed.isBlockedHost) {
    return {
      url: targetUrl, host: parsed.hostname, parsed: parsed, blocked: true,
      redirectChain: [], finalUrl: null, redirectBlocked: true,
      threatIntel: { status: 'unknown', threat: null },
      senderCheck: { checked: false, senderDomain: null, indicators: [] },
      riskIndicators: [{
        type: 'ssrf_blocked', severity: 'high', points: null,
        evidence: 'Refused to fetch blocked host "' + parsed.hostname + '" (localhost / private / internal address).',
      }],
      limitations: ['Blocked hosts are never fetched.'],
      enrichmentSkipped: false, error: 'SSRF_BLOCKED',
    };
  }

  // analyzer.js verdict on the URL itself: host + official-domain note.
  // We use it only for host/official detection, not to re-score here.
  let engineUrl = null;
  try {
    engineUrl = PhishShield.analyzeUrl(targetUrl);
  } catch (e) {
    engineUrl = null;
  }
  const host = (engineUrl && engineUrl.host) || parsed.hostname;
  const official = Boolean(engineUrl && engineUrl.note && engineUrl.note.indexOf('Official domain of') === 0);

  let redirectChain = [];
  let finalUrl = null;
  let redirectBlocked = false;
  let enrichmentSkipped = false;

  if (official) {
    // Same rule as server.js: official domains get no enrichment.
    enrichmentSkipped = true;
    limitations.push('Official domain: redirect and URLhaus enrichment skipped, as in server.js.');
  } else {
    // 1. Redirects: shorteners only by default, exactly as server.js.
    const isShortener = PhishShield.isShortener(host);
    const shouldFollow = followRedirectsOpt === true || (followRedirectsOpt === null && isShortener);
    if (shouldFollow) {
      try {
        const red = await followRedirectsFn(targetUrl, Object.assign(
          { maxHops: 5, timeoutMs: 5000 }, redirectOptions,
        ));
        redirectChain = red.chain || [];
        finalUrl = red.finalUrl || null;
        redirectBlocked = Boolean(red.blocked);
        if (redirectBlocked) {
          riskIndicators.push({
            type: 'ssrf_blocked', severity: 'high', points: null,
            evidence: 'A redirect hop was refused by the SSRF guard in redirect.js.',
          });
        } else if (!red.reachedFinal && redirectChain.length > 0) {
          limitations.push('Redirect chain did not reach a final destination.');
        }
      } catch (e) {
        limitations.push('Redirect analysis failed: ' + (e && e.message ? e.message : 'unknown error') + '.');
      }
    } else {
      limitations.push('Redirect chain was not followed (not a shortened URL).');
    }
  }

  // 2. URLhaus: repo enum listed / clean / unknown. Never rename 'clean'.
  let threatIntel = { status: 'unknown', threat: null };
  if (!official && checkThreatIntel) {
    try {
      threatIntel = await lookupUrlhausFn(finalUrl || targetUrl, urlhausOptions);
      if (!threatIntel || !threatIntel.status) threatIntel = { status: 'unknown', threat: null };
      if (threatIntel.status === 'unknown') {
        limitations.push('URLhaus lookup could not be completed. This is NOT proof the URL is clean.');
      }
    } catch (e) {
      threatIntel = { status: 'unknown', threat: null };
      limitations.push('URLhaus lookup failed. This is NOT proof the URL is clean.');
    }
  } else if (!official) {
    limitations.push('URLhaus lookup was skipped by the caller.');
  }

  // 3. Structured sender check (new vs analyzer.js text check).
  const senderCheck = checkImpersonation({
    parsed: parsed, sender: sender, senderDomain: senderDomain, senderDisplayName: senderDisplayName,
  });
  riskIndicators.push.apply(riskIndicators, senderCheck.indicators);

  return {
    url: targetUrl,
    host: host,
    parsed: parsed,
    blocked: false,
    redirectChain: redirectChain,
    finalUrl: finalUrl,
    redirectBlocked: redirectBlocked,
    threatIntel: threatIntel,
    senderCheck: senderCheck,
    riskIndicators: riskIndicators,
    limitations: limitations,
    enrichmentSkipped: enrichmentSkipped,
    error: null,
  };
}

module.exports = { buildSecurityReport: buildSecurityReport };
