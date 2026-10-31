// Refund bait: an unexpected money-back lure counts only when paired
// with a credential handover or a suspicious link. A bare refund notice
// must stay safe, and a negated OTP notice must not arm the rule.
// Run: node tests/refund.test.js
'use strict';
const PhishShield = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function scoreOf(text) { return PhishShield.analyze(text); }
function hasLabel(r, label) { return r.reasons.some(function (x) { return x.label === label; }); }

let r = scoreOf('Aapka refund pending hai. Paise wapas lene ke liye apna OTP share karo.');
check('reported case: OTP 30 + refund 25 = 55',
  r.score === 55 && hasLabel(r, 'Refund bait') && hasLabel(r, 'Roman Punjabi OTP request'), r);
r = scoreOf('Your refund is pending. Please share your OTP to receive it.');
check('refund + English OTP: 30 + 25 = 55',
  r.score === 55 && hasLabel(r, 'Refund bait'), r);
r = scoreOf('Your refund is pending, claim it here: bit.ly/xyz123');
check('refund + shortener link: 20 + 25 = 45',
  r.score === 45 && hasLabel(r, 'Refund bait'), r);
r = scoreOf('Your refund has been processed. Track it here: https://www.amazon.in/gp/order');
check('refund + official link stays 0',
  r.score === 0 && !hasLabel(r, 'Refund bait'), r);
r = scoreOf('Your refund of Rs 499 has been processed and will reflect in 3-5 days.');
check('legit refund notice stays 0',
  r.score === 0 && !hasLabel(r, 'Refund bait'), r);
r = scoreOf('Aapka refund pending hai.');
check('refund alone stays 0',
  r.score === 0 && !hasLabel(r, 'Refund bait'), r);
r = scoreOf('Your refund is processed. Your OTP is 482913. Do not share this OTP with anyone.');
check('legit refund + negated OTP notice stays 0',
  r.score === 0 && !hasLabel(r, 'Refund bait'), r);
r = scoreOf('Paise wapas lene ke liye OTP batao.');
check('wapas + batao: 30 + 25 = 55',
  r.score === 55 && hasLabel(r, 'Refund bait') && hasLabel(r, 'Roman Hindi OTP request'), r);
r = scoreOf('Refund lene ke liye apne bank details share karo.');
check('refund + ID documents: 30 + 25 = 55',
  r.score === 55 && hasLabel(r, 'Refund bait') && hasLabel(r, 'Asks you to share ID documents'), r);
r = scoreOf('Aapka refund pending hai, OTP kabhi share mat karo.');
check('refund + negated OTP warning stays 0',
  r.score === 0 && !hasLabel(r, 'Refund bait'), r);
r = scoreOf('Your money back is pending, share your OTP now.');
check('money back + OTP: 30 + 25 = 55',
  r.score === 55 && hasLabel(r, 'Refund bait'), r);
r = scoreOf('आपका रिफंड पेंडिंग है, OTP साझा करें।');
check('Devanagari refund + Hindi OTP: 30 + 25 = 55',
  r.score === 55 && hasLabel(r, 'Refund bait') && hasLabel(r, 'Hindi OTP / bank-info request'), r);

console.log(passed + ' passed, ' + failed + ' failed.');
if (failed > 0) process.exit(1);
