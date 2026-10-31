// Unit tests for urlhaus.js against a local mock URLhaus server.
// No external network needed. Run: node tests/urlhaus.test.js
'use strict';

const http = require('http');
const { lookupUrlhaus } = require('../urlhaus.js');

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name); }
}

async function main() {
  const server = http.createServer(function (req, res) {
    let body = '';
    req.on('data', function (c) { body += c; });
    req.on('end', function () {
      const params = new URLSearchParams(body);
      const url = params.get('url') || '';
      if (url.indexOf('needauth') !== -1) {
        if (req.headers['auth-key'] === 'test-key-123') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ query_status: 'ok', threat: 'phishing', url_status: 'online' }));
        }
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized' }));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (url.indexOf('malware') !== -1) {
        return res.end(JSON.stringify({
          query_status: 'ok', threat: 'malware_download', url_status: 'online'
        }));
      }
      if (url.indexOf('badjson') !== -1) {
        return res.end('this is not json');
      }
      res.end(JSON.stringify({ query_status: 'no_results' }));
    });
  });
  await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
  const api = 'http://127.0.0.1:' + server.address().port + '/v1/url/';

  const listed = await lookupUrlhaus('https://example-malware-site.com/payload.exe',
    { apiUrl: api });
  check('listed URL detected',
    listed.status === 'listed' && listed.threat === 'malware_download');
  const clean = await lookupUrlhaus('https://www.google.com/', { apiUrl: api });
  check('clean URL reported clean', clean.status === 'clean' && clean.threat === null);
  const badjson = await lookupUrlhaus('https://badjson.example.com/', { apiUrl: api });
  check('malformed response -> unknown', badjson.status === 'unknown');
  const dead = await lookupUrlhaus('https://www.google.com/',
    { apiUrl: 'http://127.0.0.1:1/nope', timeoutMs: 2000 });
  check('unreachable API -> unknown', dead.status === 'unknown');
  const local = await lookupUrlhaus('http://localhost:3000/x', { apiUrl: api });
  check('localhost skipped -> unknown', local.status === 'unknown');
  const noKey = await lookupUrlhaus('https://needauth.example.com/x', { apiUrl: api });
  check('missing key -> 401 -> unknown', noKey.status === 'unknown');
  const withKey = await lookupUrlhaus('https://needauth.example.com/x',
    { apiUrl: api, authKey: 'test-key-123' });
  check('Auth-Key header sent -> listed',
    withKey.status === 'listed' && withKey.threat === 'phishing');
  process.env.URLHAUS_AUTH_KEY = 'test-key-123';
  const envKey = await lookupUrlhaus('https://needauth.example.com/x', { apiUrl: api });
  delete process.env.URLHAUS_AUTH_KEY;
  check('env URLHAUS_AUTH_KEY used -> listed', envKey.status === 'listed');

  server.close();
  console.log('\n' + passed + ' passed, ' + failed + ' failed.');
  process.exit(failed ? 1 : 0);
}

main();
