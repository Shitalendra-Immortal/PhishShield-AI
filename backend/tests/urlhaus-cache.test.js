// Cache tests for urlhaus.js against a counting mock server.
// Run: node tests/urlhaus-cache.test.js
'use strict';
const http = require('http');
const { lookupUrlhaus, clearUrlhausCache } = require('../urlhaus.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}

async function main() {
  const counts = {};
  const server = http.createServer(function (req, res) {
    let body = '';
    req.on('data', function (c) { body += c; });
    req.on('end', function () {
      const url = new URLSearchParams(body).get('url') || '';
      counts[url] = (counts[url] || 0) + 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (url.indexOf('badcache') !== -1) return res.end('not json');
      res.end(JSON.stringify({ query_status: 'no_results' }));
    });
  });
  await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
  const api = 'http://127.0.0.1:' + server.address().port + '/v1/url/';
  clearUrlhausCache();

  const u1 = 'https://cacheme.example.com/a';
  const r1 = await lookupUrlhaus(u1, { apiUrl: api });
  const r2 = await lookupUrlhaus(u1, { apiUrl: api });
  check('clean result cached: 1 request for 2 lookups',
    counts[u1] === 1 && r1.status === 'clean' && r2.status === 'clean', counts);

  const u2 = 'https://cacheme.example.com/b';
  await lookupUrlhaus(u2, { apiUrl: api });
  check('different URL queries again', counts[u2] === 1, counts);

  const bad = 'https://badcache.example.com/';
  await lookupUrlhaus(bad, { apiUrl: api });
  await lookupUrlhaus(bad, { apiUrl: api });
  check('unknown results are NOT cached', counts[bad] === 2, counts);

  process.env.URLHAUS_CACHE_TTL_MS = '50';
  const u3 = 'https://cacheme.example.com/ttl';
  await lookupUrlhaus(u3, { apiUrl: api });
  await new Promise(function (r) { setTimeout(r, 90); });
  await lookupUrlhaus(u3, { apiUrl: api });
  delete process.env.URLHAUS_CACHE_TTL_MS;
  check('expired entry re-queries', counts[u3] === 2, counts);

  server.close();
  console.log('\n' + passed + ' passed, ' + failed + ' failed.');
  process.exit(failed ? 1 : 0);
}

main().catch(function (e) { console.error('ERROR: ' + e.message); process.exit(1); });
