// Unit tests for rateLimit.js (no HTTP server needed).
// Run: node tests/rate-limit.test.js
'use strict';

const { createRateLimiter } = require('../rateLimit.js');

function mockRes() {
  const res = { statusCode: 200, body: null, headers: {} };
  res.status = function (code) { res.statusCode = code; return res; };
  res.json = function (obj) { res.body = obj; return res; };
  res.setHeader = function (k, v) { res.headers[k] = v; };
  return res;
}

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name); }
}

async function main() {
  const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 3 });
  let nextCalls = 0;
  const next = function () { nextCalls++; };
  const req = { ip: '1.2.3.4', socket: {} };
  for (let i = 0; i < 3; i++) {
    const res = mockRes();
    limiter(req, res, next);
    check('request ' + (i + 1) + ' passes', nextCalls === i + 1);
  }
  const blocked = mockRes();
  limiter(req, blocked, next);
  check('4th request blocked (429)', blocked.statusCode === 429);
  check('429 code is RATE_LIMITED',
    blocked.body && blocked.body.error && blocked.body.error.code === 'RATE_LIMITED');
  check('Retry-After present', !!blocked.headers['Retry-After']);
  const other = mockRes();
  limiter({ ip: '5.6.7.8', socket: {} }, other, next);
  check('other IP unaffected', nextCalls === 4);

  const short = createRateLimiter({ windowMs: 100, max: 1 });
  let n2 = 0;
  short({ ip: '9.9.9.9', socket: {} }, mockRes(), function () { n2++; });
  const blocked2 = mockRes();
  short({ ip: '9.9.9.9', socket: {} }, blocked2, function () { n2++; });
  check('short window blocks 2nd call', blocked2.statusCode === 429 && n2 === 1);
  await new Promise(function (r) { setTimeout(r, 150); });
  short({ ip: '9.9.9.9', socket: {} }, mockRes(), function () { n2++; });
  check('short window resets after expiry', n2 === 2);

  // Bounded bucket map: at maxEntries the oldest bucket is evicted, so
  // a flood of distinct IPs cannot grow memory without limit.
  const capped = createRateLimiter({ windowMs: 60 * 1000, max: 2, maxEntries: 3 });
  let n3 = 0;
  const hit = function (ip) {
    const res = mockRes();
    capped({ ip: ip, socket: {} }, res, function () { n3++; });
    return res.statusCode;
  };
  hit('10.0.0.1'); hit('10.0.0.1');
  check('capped limiter blocks 3rd call from same IP', hit('10.0.0.1') === 429);
  hit('10.0.0.2'); hit('10.0.0.3');
  check('3 buckets fit at cap', n3 === 4);
  hit('10.0.0.4'); // evicts the oldest bucket (10.0.0.1)
  check('evicted IP gets a fresh bucket instead of staying blocked',
    hit('10.0.0.1') === 200 && n3 === 6);

  console.log('\n' + passed + ' passed, ' + failed + ' failed.');
  process.exit(failed ? 1 : 0);
}

main();
