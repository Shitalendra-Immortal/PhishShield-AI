/**
 * backend/security/urlParser.js — Member 4, adapted to the team repo.
 *
 * NEW in this repo: analyzer.js only exposes hostOf() internally, it does
 * not return a structured parse. This file adds that, and nothing else.
 * It does NOT re-score URLs — analyzer.js is still the single source of
 * truth for heuristic scoring. Do not fork analyzer.js.
 *
 * No external dependencies. Style follows the repo: 'use strict',
 * CommonJS, plain Node built-ins (net).
 */
'use strict';

const net = require('net');

// Two-label suffixes common in India / the UK / Australia. Starter list,
// not the full public-suffix list (see README.md limitations).
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'co.in', 'org.in', 'ac.in', 'gov.in', 'net.in',
  'com.au', 'org.au', 'net.au',
  'co.nz', 'com.br', 'co.za',
]);

function isIPv4(hostname) {
  return net.isIP(hostname) === 4;
}

function isIPv6(hostname) {
  return net.isIP(hostname) === 6;
}

function isPrivateIPv4(hostname) {
  const parts = hostname.split('.').map(Number);
  const a = parts[0];
  const b = parts[1];
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, incl. 169.254.169.254 metadata
  if (a === 0) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved
  return false;
}

/**
 * True for localhost, private, link-local, reserved and other
 * non-public addresses. This matches (and slightly extends) the guards
 * already in backend/urlhaus.js and backend/redirect.js.
 * If this returns true, the URL must NOT be fetched — SSRF protection.
 */
function isPrivateIP(hostname) {
  if (!hostname) return false;
  if (isIPv4(hostname)) return isPrivateIPv4(hostname);
  if (isIPv6(hostname)) {
    const h = hostname.toLowerCase();
    if (h === '::1' || h === '::') return true;
    if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true; // fe80::/10
    if (h.startsWith('fc') || h.startsWith('fd')) return true; // fc00::/7
    if (h.startsWith('ff')) return true; // multicast
  }
  return false;
}

function isBlockedHost(hostname) {
  const host = (hostname || '').toLowerCase().replace(/\.$/, '');
  if (!host) return true;
  if (host === 'localhost') return true;
  if (host.endsWith('.localhost')) return true;
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan')) return true;
  if (isPrivateIP(host)) return true;
  return false;
}

function getRegistrableDomain(hostname) {
  if (!hostname || isIPv4(hostname) || isIPv6(hostname)) return hostname || '';
  const labels = hostname.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

/**
 * Parse a user-submitted URL string.
 * Throws Error('INVALID_URL') for input we cannot parse at all.
 */
function parseUrl(input) {
  if (typeof input !== 'string' || !input.trim()) {
    throw new Error('INVALID_URL');
  }
  const raw = input.trim();
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  let url;
  try {
    url = new URL(hadScheme ? raw : 'https://' + raw);
  } catch (e) {
    throw new Error('INVALID_URL');
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  const domain = getRegistrableDomain(hostname);
  const domainLabels = domain ? domain.split('.') : [];
  const hostLabels = hostname.split('.').filter(Boolean);
  const subdomains = hostLabels.slice(0, Math.max(0, hostLabels.length - domainLabels.length));

  return {
    input: raw,
    normalizedUrl: url.toString(),
    hadScheme: hadScheme,
    protocol: url.protocol.replace(':', ''),
    hostname: hostname,
    domain: domain,
    subdomains: subdomains,
    subdomainCount: subdomains.length,
    path: url.pathname,
    query: url.search,
    port: url.port || null,
    username: url.username || null,
    hasCredentials: Boolean(url.username || url.password),
    isIP: isIPv4(hostname) || isIPv6(hostname),
    isPrivateIP: isPrivateIP(hostname),
    isBlockedHost: isBlockedHost(hostname),
  };
}

module.exports = {
  parseUrl: parseUrl,
  isPrivateIP: isPrivateIP,
  isBlockedHost: isBlockedHost,
  getRegistrableDomain: getRegistrableDomain,
  isIPv4: isIPv4,
  isIPv6: isIPv6,
};
