// URLhaus (abuse.ch) lookup: free, no API key for basic URL lookups.
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

// Returns { status: 'listed' | 'clean' | 'unknown', threat: string | null }.
// 'listed' means URLhaus has the URL in its malicious-URL database.
// 'unknown' covers lookup failures, disabled lookups, and skipped inputs.
async function lookupUrlhaus(url, options) {
  var opts = options || {};
  var apiUrl = opts.apiUrl || process.env.URLHAUS_API_URL ||
    'https://urlhaus-api.abuse.ch/v1/url/';
  var timeoutMs = opts.timeoutMs || 5000;
  try {
    var host = new URL(url).hostname.toLowerCase();
    if (host === 'localhost') return { status: 'unknown', threat: null };
    if (net.isIP(host) && isPrivateIPv4Literal(host)) {
      return { status: 'unknown', threat: null };
    }
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, timeoutMs);
    try {
      var res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url: url }).toString(),
        signal: controller.signal
      });
      var data = await res.json();
      if (data && data.query_status === 'ok') {
        return { status: 'listed', threat: data.threat || null };
      }
      if (data && data.query_status === 'no_results') {
        return { status: 'clean', threat: null };
      }
      return { status: 'unknown', threat: null };
    } finally {
      clearTimeout(timer);
    }
  } catch (e) {
    return { status: 'unknown', threat: null };
  }
}

module.exports = { lookupUrlhaus: lookupUrlhaus };
