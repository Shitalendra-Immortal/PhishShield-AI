// Follow a redirect chain manually (so the chain is visible), with SSRF
// guards. No dependency beyond Node built-ins. Fail-closed: any doubt
// about a hop's safety, and the chain stops without fetching it.
'use strict';

var dns = require('dns').promises;
var net = require('net');

function isPrivateIPv4(ip) {
  var p = ip.split('.').map(Number);
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  return false;
}

function isPrivateIP(ip) {
  if (net.isIP(ip) === 4) return isPrivateIPv4(ip);
  if (ip === '::1' || ip.toLowerCase().indexOf('fe80:') === 0) return true;
  return false;
}

async function hostIsPrivate(host, allowPrivate) {
  if (allowPrivate) return false;
  if (host === 'localhost') return true;
  if (net.isIP(host)) return isPrivateIP(host);
  try {
    var r = await dns.lookup(host);
    return isPrivateIP(r.address);
  } catch (e) {
    return true; // fail closed: unresolvable hosts are not fetched
  }
}

// Returns { chain, finalUrl, reachedFinal, blocked }.
// chain lists every URL actually fetched, input first. finalUrl is the last
// fetched URL (null if the first fetch failed). reachedFinal means the last
// fetch returned a non-redirect response. blocked means a hop was refused
// by the SSRF guard.
async function followRedirects(startUrl, options) {
  var opts = options || {};
  var maxHops = opts.maxHops || 5;
  var timeoutMs = opts.timeoutMs || 5000;
  var allowPrivate = !!opts.allowPrivate;
  var chain = [];
  var current = startUrl;
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, timeoutMs);
  try {
    for (var hop = 0; hop <= maxHops; hop++) {
      var u;
      try {
        u = new URL(current);
      } catch (e) {
        return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: false };
      }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: false };
      }
      if (await hostIsPrivate(u.hostname, allowPrivate)) {
        return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: true };
      }
      var res;
      try {
        res = await fetch(current, { method: 'GET', redirect: 'manual', signal: controller.signal });
      } catch (e) {
        return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: false };
      }
      chain.push(current);
      try {
        if (res.body && res.body.cancel) await res.body.cancel();
      } catch (e) { /* ignore body-cleanup errors */ }
      var loc = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && loc) {
        if (hop === maxHops) {
          return { chain: chain, finalUrl: current, reachedFinal: false, blocked: false };
        }
        try {
          current = new URL(loc, current).toString();
        } catch (e) {
          return { chain: chain, finalUrl: current, reachedFinal: false, blocked: false };
        }
        continue;
      }
      return { chain: chain, finalUrl: current, reachedFinal: true, blocked: false };
    }
    return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: false };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { followRedirects: followRedirects };
