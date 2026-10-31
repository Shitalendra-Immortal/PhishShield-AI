// Fake-testimonial reward lure tests: a first-person money-received
// claim + an urge for others to try it + a link. Pure engine checks,
// no server needed.
// Run: node tests/testimonial.test.js
'use strict';
const { analyze } = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function hasLabel(reasons, label) {
  return reasons.some(function (r) { return r.label === label; });
}

// The reported message: testimonial + urge + shady link. Was 0/safe.
const reported = analyze('Mujhe laga tha fake hai 😂 par sach me ₹2,000 mil gaye, tum log bhi try karo!\n\nhttps://uwpdl.buzz/wwxrREhKbm/in-en?1031334904734111920&s=wa&t=1793437669&');
check('reported testimonial scam is suspicious at 30',
  reported.score === 30 && reported.verdict.level === 'suspicious' &&
  hasLabel(reported.reasons, 'Fake testimonial reward lure'), reported);

// Same shape in English.
const english = analyze('I thought it was fake but I really got $20, you guys try too! https://example.com/a');
check('English testimonial scam scores 30',
  english.score === 30 && hasLabel(english.reasons, 'Fake testimonial reward lure'), english);

// Roman Hindi variant: Rs + mila + tum bhi. "cashback" also trips the
// pre-existing prize rule, so the total is 25 + 30 = 55 — both signals
// are real here, and stacking them is correct.
const roman = analyze('Mujhe Rs 500 cashback mila, tum bhi try karo: https://example.com/a');
check('Roman Hindi Rs/mila testimonial stacks to 55',
  roman.score === 55 && hasLabel(roman.reasons, 'Fake testimonial reward lure') &&
  hasLabel(roman.reasons, 'Prize / reward bait'), roman);

// Guards: a bank alert has no urge and no link, so it must stay 0.
const bank = analyze('Your SBI account has been credited with ₹10,000. Available balance: ₹48,200.');
check('legit bank credit alert scores 0', bank.score === 0, bank);

// A claim with no link could be a genuine friend's referral: no fire.
const noLink = analyze('Mujhe laga tha fake hai par sach me ₹2,000 mil gaye, tum log bhi try karo!');
check('testimonial with no link scores 0', noLink.score === 0, noLink);

// Marketing with a link but no testimonial: the testimonial rule adds
// nothing. The 25 here is the pre-existing prize rule ("cashback"),
// which stays in the safe band on its own.
const marketing = analyze('Get ₹100 cashback, click here: https://example.com/a');
check('marketing cashback adds no testimonial signal (25, prize only)',
  marketing.score === 25 && !hasLabel(marketing.reasons, 'Fake testimonial reward lure'), marketing);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
