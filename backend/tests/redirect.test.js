// Unit tests for redirect.js against a local redirect server.
// No external network needed. Run: node tests/redirect.test.js
'use strict';

const http = require('http');
const { followRedirects, isPrivateIP } = require('../redirect.js');

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name); }
}

async function main() {
  const server = http.createServer(function (req, res) {
    if (req.url === '/go') {
      res.writeHead(302, { Location: '/mid' });
      return res.end();
    }
    if (req.url === '/mid') {
      res.writeHead(302, { Location: '/final' });
      return res.end();
    }
    if (req.url === '/loop') {
      res.writeHead(302, { Location: '/loop' });
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  });
  await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
  const base = 'http://127.0.0.1:' + server.address().port;

  const chain = await followRedirects(base + '/go', { allowPrivate: true });
  check('2-hop chain has 3 entries', chain.chain.length === 3);
  check('chain ends at /final', chain.finalUrl === base + '/final');
  check('chain reached final', chain.reachedFinal === true);
  check('chain not blocked', chain.blocked === false);

  const direct = await followRedirects(base + '/final', { allowPrivate: true });
  check('no-redirect chain has 1 entry', direct.chain.length === 1);
  check('no-redirect reached final', direct.reachedFinal === true);

  const loop = await followRedirects(base + '/loop', { allowPrivate: true, maxHops: 2 });
  check('loop stops at maxHops without final',
    loop.reachedFinal === false && loop.chain.length === 3);

  const blocked = await followRedirects(base + '/go', { allowPrivate: false });
  check('loopback blocked without allowPrivate',
    blocked.blocked === true && blocked.chain.length === 0);

  const dead = await followRedirects('http://127.0.0.1:1/nope',
    { allowPrivate: true, timeoutMs: 2000 });
  check('unreachable host fails gracefully',
    dead.reachedFinal === false && dead.finalUrl === null);

  // A hostname that resolves to a private address is blocked, not just
  // a literal private IP (this is the DNS path the pinning defence covers).
  const localBlocked = await followRedirects(base.replace('127.0.0.1', 'localhost') + '/go',
    { allowPrivate: false });
  check('localhost hostname blocked without allowPrivate',
    localBlocked.blocked === true && localBlocked.chain.length === 0);

  // Private-range classifier: IPv6 unique-local, link-local edges,
  // multicast, documentation, mapped and NAT64 forms.
  check('fc00::/7 unique-local blocked', isPrivateIP('fc00::1') === true);
  check('fd00::/8 unique-local blocked', isPrivateIP('fd12:3456::1') === true);
  check('fe80::/10 link-local upper edge blocked', isPrivateIP('febf::1') === true);
  check('ff00::/8 multicast blocked', isPrivateIP('ff02::1') === true);
  check(':: unspecified blocked', isPrivateIP('::') === true);
  check('2001:db8 documentation blocked', isPrivateIP('2001:db8::1') === true);
  check('IPv4-mapped private blocked', isPrivateIP('::ffff:10.0.0.1') === true);
  check('IPv4-mapped private (hex form) blocked', isPrivateIP('::ffff:a00:1') === true);
  check('IPv4-mapped public allowed', isPrivateIP('::ffff:8.8.8.8') === false);
  check('NAT64 private blocked', isPrivateIP('64:ff9b::10.0.0.1') === true);
  check('CGNAT blocked', isPrivateIP('100.64.0.1') === true);
  check('benchmarking range blocked', isPrivateIP('198.18.0.1') === true);
  check('public IPv4 allowed', isPrivateIP('8.8.8.8') === false);
  check('public IPv6 allowed', isPrivateIP('2606:4700:4700::1111') === false);

  server.close();
  console.log('\n' + passed + ' passed, ' + failed + ' failed.');
  process.exit(failed ? 1 : 0);
}

main();
