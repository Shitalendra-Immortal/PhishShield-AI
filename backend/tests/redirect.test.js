// Unit tests for redirect.js against a local redirect server.
// No external network needed. Run: node tests/redirect.test.js
'use strict';

const http = require('http');
const { followRedirects } = require('../redirect.js');

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

  server.close();
  console.log('\n' + passed + ' passed, ' + failed + ' failed.');
  process.exit(failed ? 1 : 0);
}

main();
