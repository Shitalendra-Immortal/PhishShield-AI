// Tests for URL normalisation + the removed "do not share" deduction.
// Pure engine checks, no server needed. Run: node tests/normalization.test.js
'use strict';
const { analyzeUrl, analyzeMessage } = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}

// Trailing dot: same domain, same score.
const dotted = analyzeUrl('http://sbi-kyc-update.xyz./verify');
const plain = analyzeUrl('http://sbi-kyc-update.xyz/verify');
check('trailing dot: host stripped', dotted.host === 'sbi-kyc-update.xyz', dotted.host);
check('trailing dot: same score as without dot',
  dotted.score === plain.score, { dotted: dotted.score, plain: plain.score });

// Official domain with trailing dot still recognised.
const official = analyzeUrl('https://www.amazon.in./gp/order');
check('trailing dot: official domain still recognised',
  official.score === 0 && /Official domain/.test(official.note || ''), official);

// Default port: no points. Non-default port: +10.
const noPort = analyzeUrl('https://example.com/path');
const defaultPort = analyzeUrl('https://example.com:443/path');
const oddPort = analyzeUrl('https://example.com:8443/path');
check('default :443 port not flagged',
  defaultPort.score === noPort.score &&
  !defaultPort.reasons.some(function (r) { return /port/.test(r.label); }), defaultPort);
check('non-default port flagged +10',
  oddPort.score === noPort.score + 10 &&
  oddPort.reasons.some(function (r) { return /port/.test(r.label); }), oddPort);

// "Do not share" earns nothing now: same message scores the same with or
// without the reassuring phrase, and no reason ever carries negative points.
const withPhrase = analyzeMessage('Do not share your OTP with anyone. Send your OTP to verify: http://scam-verify.xyz/login');
const withoutPhrase = analyzeMessage('Send your OTP to verify: http://scam-verify.xyz/login');
check('do-not-share phrase adds no points',
  withPhrase.score === withoutPhrase.score,
  { with: withPhrase.score, without: withoutPhrase.score });
check('no negative-point reasons exist',
  !withPhrase.reasons.some(function (r) { return r.points < 0; }), withPhrase.reasons);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
