// URLhaus (abuse.ch) lookup. Requires a free Auth-Key (abuse.ch account):
// the key comes from env URLHAUS_AUTH_KEY (or opts.authKey) and is never
// logged or committed. Without a key the API answers 401 and lookups
// degrade to 'unknown'.
// Best-effort signal only: any failure returns 'unknown' and the caller
// must still return its normal verdict. Never send private/local URLs.
'use strict';

var net = require('net');

function isPrivateIPv4Literal(ip) {
  var p = ip.split('.').map(Number);
  return p[0] === 10 || p[0] === 127 ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 169 && p[1] === 254);
}

// Small in-memory cache for DEFINITIVE results only (listed/clean).
// 'unknown' is never cached: a failed lookup must retry next time, and a
// provider outage must not poison later scans. Keyed by provider endpoint
// + URL, so scans against different mock servers never share entries.
// TTL via URLHAUS_CACHE_TTL_MS (default 30 minutes); capped at 1000
// entries, oldest evicted first. A free-tier restart clears it, which is
// fine: worst case is one extra lookup per URL after a restart.
var urlhausCache = new Map();
function cacheTtlMs() {
  var v = Number(process.env.URLHAUS_CACHE_TTL_MS);
  return (Number.isFinite(v) && v > 0) ? v : 30 * 60 * 1000;
}
function cacheGet(key) {
  var entry = urlhausCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.at > cacheTtlMs()) { urlhausCache.delete(key); return null; }
  return entry.value;
}
function cacheSet(key, value) {
  if (urlhausCache.size >= 1000) {
    var oldest = urlhausCache.keys().next().value;
    if (oldest !== undefined) urlhausCache.delete(oldest);
  }
  urlhausCache.set(key, { value: value, at: Date.now() });
}
function clearUrlhausCache() { urlhausCache.clear(); }

// Returns { status: 'listed' | 'clean' | 'unknown', threat: string | null }.
// 'listed' means URLhaus has the URL in its malicious-URL database.
// 'unknown' covers lookup failures, disabled lookups, and skipped inputs.
async function lookupUrlhaus(url, options) {
  var opts = options || {};
  var apiUrl = opts.apiUrl || process.env.URLHAUS_API_URL ||
    'https://urlhaus-api.abuse.ch/v1/url/';
  var authKey = opts.authKey || process.env.URLHAUS_AUTH_KEY || '';
  var timeoutMs = opts.timeoutMs || 5000;
  var cacheKey = apiUrl + '|' + url;
  var cached = cacheGet(cacheKey);
  if (cached) return cached;
  try {
    var host = new URL(url).hostname.toLowerCase();
    if (host === 'localhost') return { status: 'unknown', threat: null };
    if (net.isIP(host) && isPrivateIPv4Literal(host)) {
      return { status: 'unknown', threat: null };
    }
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, timeoutMs);
    try {
      var headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      if (authKey) headers['Auth-Key'] = authKey;
      var res = await fetch(apiUrl, {
        method: 'POST',
        headers: headers,
        body: new URLSearchParams({ url: url }).toString(),
        signal: controller.signal
      });
      var data = await res.json();
      var out;
      if (data && data.query_status === 'ok') {
        out = { status: 'listed', threat: data.threat || null };
      } else if (data && data.query_status === 'no_results') {
        out = { status: 'clean', threat: null };
      } else {
        out = { status: 'unknown', threat: null };
      }
      if (out.status !== 'unknown') cacheSet(cacheKey, out);
      return out;
    } finally {
      clearTimeout(timer);
    }
  } catch (e) {
    return { status: 'unknown', threat: null };
  }
}

module.exports = { lookupUrlhaus: lookupUrlhaus, clearUrlhausCache: clearUrlhausCache };
