/**
 * backend/security/impersonationChecker.js — Member 4, adapted to the team repo.
 *
 * What this does that analyzer.js does NOT do:
 *   Structured sender metadata. analyzer.js already handles sender-name
 *   spoofing inside message TEXT — '"Brand" <address@other-domain>' (+30).
 *   It does not receive a separate sender email / display name / domain
 *   from, say, an email header. This checker covers that structured case:
 *   sender domain vs link domain, and a brand claim vs sender domain.
 *
 * What this deliberately does NOT do:
 *   Re-flag URL brand impersonation on its own. analyzer.js already does
 *   that for URLs (+30, with leetspeak normalisation paypa1 -> paypal).
 *   If this file flagged the same URL again, Member 2 would double-count
 *   it. So with no sender metadata, it returns no indicators.
 *
 * RULE (same as the brief): a brand name alone is NOT proof of
 * impersonation. A real PayPal sender linking to paypal.com is fine.
 */
'use strict';

const { parseUrl, getRegistrableDomain } = require('./urlParser');

// Keep in sync with analyzer.js SENDER_BRANDS. A brand not in this list
// is simply not checked here — that is a limitation, not a bug.
const SENDER_BRANDS = {
  paypal: ['paypal.com'],
  sbi: ['sbi.co.in', 'onlinesbi.com'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  axis: ['axisbank.com'],
  kotak: ['kotak.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  google: ['google.com'],
  amazon: ['amazon.in', 'amazon.com'],
  apple: ['apple.com'],
  microsoft: ['microsoft.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com'],
  instagram: ['instagram.com'],
  irctc: ['irctc.co.in'],
  flipkart: ['flipkart.com'],
};

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i]);
  for (let j = 0; j <= n; j += 1) dp[0][j] = j;
  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[m][n];
}

function domainBase(domain) {
  const parts = (domain || '').split('.');
  if (parts.length <= 2) return parts[0] || '';
  return parts.slice(0, -1).join('-');
}

// Short strings need a stricter distance: without this, "bit" is 2 edits
// from "sbi" (insert s, delete t) and bit.ly would be wrongly flagged
// as SBI impersonation — a real false positive found in testing.
function isLookalike(token, brand) {
  if (!token || !brand) return false;
  if (token.includes(brand) && token.length >= 4) return true;
  const maxDist = (token.length <= 4 || brand.length <= 4) ? 1 : 2;
  return levenshtein(token, brand) <= maxDist;
}

/**
 * Input: { url, parsed, sender, senderDomain, senderDisplayName }
 * sender may be an email address; senderDomain is the domain after @.
 * Returns { checked, senderDomain, indicators }.
 * indicators carry points: null on purpose — Member 2 must decide in a
 * contract update before adding any of these to the analyzer.js score,
 * otherwise the same signal gets counted twice.
 */
function checkImpersonation(input) {
  input = input || {};
  let parsed = input.parsed || null;
  if (!parsed) {
    try {
      parsed = parseUrl(input.url);
    } catch (e) {
      return { checked: false, senderDomain: null, indicators: [] };
    }
  }

  const senderDomainRaw = input.senderDomain
    || (typeof input.sender === 'string' && input.sender.includes('@')
      ? input.sender.split('@').pop()
      : null);
  const senderDomain = senderDomainRaw
    ? getRegistrableDomain(senderDomainRaw.toLowerCase().replace(/>$/, ''))
    : null;
  const displayName = (input.senderDisplayName || '').toLowerCase();
  const hasSender = Boolean(senderDomain || displayName);
  if (!hasSender) {
    // No sender metadata: URL brand checks already live in analyzer.js.
    return { checked: false, senderDomain: null, indicators: [] };
  }

  const indicators = [];

  // 1. Sender domain vs link domain mismatch. Medium evidence only.
  // Newsletters legitimately link from other domains, so this alone
  // is not proof of phishing.
  if (senderDomain && parsed.domain && senderDomain !== parsed.domain) {
    indicators.push({
      type: 'sender_domain_mismatch',
      severity: 'medium',
      points: null,
      evidence: 'Sender domain (' + senderDomain + ') does not match link domain (' + parsed.domain + ').',
    });
  }

  // 2. Brand claim vs sender/link domain.
  for (const brand of Object.keys(SENDER_BRANDS)) {
    const official = SENDER_BRANDS[brand];
    if (official.includes(parsed.domain)) continue;
    if (senderDomain && official.includes(senderDomain)) continue;
    const claimed = displayName.includes(brand);
    const senderLooksLike = senderDomain
      ? domainBase(senderDomain).split(/[-_]/).some((t) => isLookalike(t, brand))
      : false;
    if (claimed || senderLooksLike) {
      indicators.push({
        type: 'brand_impersonation',
        severity: 'high',
        points: null,
        evidence: 'Sender claims "' + brand + '" but sender/link domain is not an official ' + brand + ' domain.',
      });
      break; // one brand claim is enough for the report
    }
  }

  return { checked: true, senderDomain: senderDomain, indicators: indicators };
}

module.exports = { checkImpersonation: checkImpersonation, SENDER_BRANDS: SENDER_BRANDS, levenshtein: levenshtein };
