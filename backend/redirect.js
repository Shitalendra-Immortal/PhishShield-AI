// Follow a redirect chain manually (so the chain is visible), with SSRF
// guards. No dependency beyond Node built-ins. Fail-closed: any doubt
// about a hop's safety, and the chain stops without fetching it.
//
// DNS-rebinding defence: each hop resolves its hostname ONCE with
// dns.lookup({ all: true }). Those addresses are validated, and the
// actual connection is then pinned to one of them through http/https
// request's `lookup` override — so no second DNS resolution happens
// between the check and the connection, and a rebinding answer can never
// steer the request to an unvalidated address. The original hostname is
// still used for the Host header and for TLS SNI / certificate checks;
// only the routing address is pinned.
'use strict';

var dns = require('dns').promises;
var http = require('http');
var https = require('https');
var net = require('net');

function isPrivateIPv4(ip) {
  var p = ip.split('.').map(Number);
  if (p[0] === 0) return true; // "this network" / unspecified source
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true; // loopback
  if (p[0] === 169 && p[1] === 254) return true; // link-local
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  if (p[0] === 192 && p[1] === 0 && p[2] === 0) return true; // IETF protocol assignments
  if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true; // benchmarking
  if (p[0] >= 224) return true; // multicast + reserved
  return false;
}

// Extract the embedded IPv4 address from an IPv4-mapped IPv6 address
// (::ffff:10.0.0.1 or ::ffff:a00:1) or a NAT64 address
// (64:ff9b::10.0.0.1 or 64:ff9b::a00:1). Returns the dotted IPv4 string
// or null when the address is neither form.
function embeddedIPv4(addr) {
  var low = addr.toLowerCase();
  var rest = null;
  if (low.indexOf('::ffff:') === 0) rest = low.slice('::ffff:'.length);
  else if (low.indexOf('64:ff9b::') === 0) rest = low.slice('64:ff9b::'.length);
  else return null;
  if (rest.indexOf('.') !== -1) return rest; // dotted form
  var groups = rest.split(':');
  if (groups.length < 2) return null;
  var hi = parseInt(groups[groups.length - 2], 16);
  var lo = parseInt(groups[groups.length - 1], 16);
  if (isNaN(hi) || isNaN(lo)) return null;
  return [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join('.');
}

function isPrivateIP(ip) {
  if (net.isIP(ip) === 4) return isPrivateIPv4(ip);
  if (net.isIP(ip) !== 6) return true; // not an IP at all: fail closed
  var low = ip.toLowerCase();
  if (low === '::1' || low === '::') return true; // loopback, unspecified
  // Prefix checks on the full string: the first hextet is 4 chars, so
  // fe80::/10 is fe8/fe9/fea/feb, fc00::/7 is fc/fd, ff00::/8 is ff.
  if (low.indexOf('fe8') === 0 || low.indexOf('fe9') === 0 ||
      low.indexOf('fea') === 0 || low.indexOf('feb') === 0) return true; // fe80::/10 link-local
  if (low[0] === 'f' && (low[1] === 'c' || low[1] === 'd')) return true; // fc00::/7 unique-local
  if (low.indexOf('ff') === 0) return true; // ff00::/8 multicast
  if (low.indexOf('2001:db8') === 0) return true; // documentation range, not publicly routable
  var embedded = embeddedIPv4(low);
  if (embedded) return isPrivateIPv4(embedded); // mapped / NAT64: judge the real IPv4
  return false;
}

// One header-only GET, pinned to a validated address.
// Returns { ok: true, status, location } on a response,
// { blocked: true } when the hop must not be fetched,
// { failed: true } when every resolved address failed to connect.
async function fetchOnce(urlString, opts) {
  var u;
  try {
    u = new URL(urlString);
  } catch (e) {
    return { failed: true };
  }
  var hostname = u.hostname;
  if (!opts.allowPrivate && hostname === 'localhost') return { blocked: true };
  var addresses;
  if (net.isIP(hostname)) {
    addresses = [hostname];
  } else {
    try {
      var list = await dns.lookup(hostname, { all: true });
      addresses = list.map(function (r) { return r.address; });
    } catch (e) {
      return { blocked: true }; // fail closed: unresolvable hosts are not fetched
    }
  }
  if (addresses.length === 0) return { blocked: true };
  if (!opts.allowPrivate && addresses.some(isPrivateIP)) return { blocked: true };

  var lib = u.protocol === 'https:' ? https : http;
  var auth = undefined;
  if (u.username) {
    try {
      auth = decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password);
    } catch (e) { /* keep auth undefined on malformed userinfo */ }
  }
  for (var i = 0; i < addresses.length; i++) {
    if (opts.signal && opts.signal.aborted) return { failed: true };
    var address = addresses[i];
    var result = await new Promise(function (resolve) {
      var done = false;
      var req;
      try {
        req = lib.request({
          host: hostname,
          port: u.port ? Number(u.port) : undefined,
          path: u.pathname + u.search,
          method: 'GET',
          signal: opts.signal,
          auth: auth,
          // Pin the connection to this validated address. Node uses the
          // lookup result for routing only; Host and TLS SNI still use
          // `host` (the original hostname), so certificates keep working.
          lookup: function (h, o, cb) { cb(null, address, net.isIP(address)); }
        }, function (res) {
          if (done) return;
          done = true;
          res.on('error', function () { /* body discarded, ignore */ });
          res.destroy(); // headers only; we never need the body
          resolve({ ok: true, status: res.statusCode, location: res.headers.location || null });
        });
      } catch (e) {
        resolve({ failed: true });
        return;
      }
      req.on('error', function () {
        if (done) return;
        done = true;
        resolve({ failed: true });
      });
      req.end();
    });
    if (result.ok) return result;
    if (result.blocked) return result;
    // Otherwise this address failed to connect: try the next one.
  }
  return { failed: true };
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
      var res = await fetchOnce(current, { signal: controller.signal, allowPrivate: allowPrivate });
      if (res.blocked) {
        return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: true };
      }
      if (!res.ok) {
        return { chain: chain, finalUrl: chain.length ? chain[chain.length - 1] : null, reachedFinal: false, blocked: false };
      }
      chain.push(current);
      var loc = res.location;
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

module.exports = { followRedirects: followRedirects, isPrivateIP: isPrivateIP };
