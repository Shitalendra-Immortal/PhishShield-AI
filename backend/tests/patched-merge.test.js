// Tests for the merged patched analyzer: the @-URL raise, the
// English/Hindi OTP negation guards, and the new scam-type rules
// (digital arrest, fake police, upfront fees, guaranteed profit,
// blackmail). Pure engine checks, no server needed.
// Run: node tests/patched-merge.test.js
'use strict';
const { analyzeUrl, analyzeMessage, analyze } = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function hasLabel(reasons, label) {
  return reasons.some(function (r) { return r.label === label; });
}

// @ URLs: an https @ URL with nothing else was 20 (safe) — a miss.
// It now reaches the suspicious band on its own.
const atOnly = analyzeUrl('https://example.com@evil.com');
check('@ URL alone is suspicious at 30',
  atOnly.score === 30 && hasLabel(atOnly.reasons, '@ symbol in the URL'), atOnly);
const atLogin = analyzeUrl('http://example.com@evil.com/login');
check('@ URL + http + weak word is 48 (was 38)',
  atLogin.score === 48, atLogin);

// English OTP negation: warnings score 0, real requests still fire.
const negCases = [
  ['do not share OTP warning', 'Do not share your OTP with anyone.'],
  ['do not ever share OTP warning', 'Do not ever share your OTP with anyone.'],
  ['never share PIN warning', 'Never share your PIN with anyone.'],
  ["don't share password warning", "Don't share your password with strangers."],
];
negCases.forEach(function (c) {
  const r = analyzeMessage(c[1]);
  check(c[0] + ' scores 0', r.score === 0, r);
});
const fallback = analyzeMessage('Do not share your OTP with anyone, share it with us');
check('share-it-with-us referral trick still fires 30',
  fallback.score === 30 && hasLabel(fallback.reasons, 'Asks you to share an OTP, PIN or password'), fallback);
const engMixed = analyzeMessage('Do not share your OTP, share your PIN');
check('English negated pair + real pair still fires 30',
  engMixed.score === 30 && hasLabel(engMixed.reasons, 'Asks you to share an OTP, PIN or password'), engMixed);
const realReq = analyzeMessage('Share your OTP to verify your account');
check('plain OTP request still fires 30',
  realReq.score === 30 && hasLabel(realReq.reasons, 'Asks you to share an OTP, PIN or password'), realReq);

// Hindi OTP negation: pre-verb "मत" is a warning too; "डालें"
// (enter) is a request; a negated pair plus a real pair still fires.
const hindiNeg = analyzeMessage('अपना OTP मत बताएं');
check('Hindi pre-verb negation (OTP मत बताएं) scores 0', hindiNeg.score === 0, hindiNeg);
const hindiEnter = analyzeMessage('अपना OTP डालें');
check('Hindi OTP enter verb (OTP डालें) scores 30',
  hindiEnter.score === 30 && hasLabel(hindiEnter.reasons, 'Hindi OTP / bank-info request'), hindiEnter);
const hindiMixed = analyzeMessage('OTP मत बताएं, OTP भेजो');
check('Hindi negated pair + real pair still fires 30',
  hindiMixed.score === 30 && hasLabel(hindiMixed.reasons, 'Hindi OTP / bank-info request'), hindiMixed);

// Digital arrest: bare term is suspicious; a payment demand stacks.
const arrest = analyze('You are under digital arrest.');
check('digital arrest alone is suspicious at 30',
  arrest.score === 30 && arrest.verdict.level === 'suspicious' &&
  hasLabel(arrest.reasons, 'Digital arrest scam'), arrest);
const arrestPay = analyze('You are under digital arrest. Pay Rs 50000 to avoid arrest.');
check('digital arrest + payment demand stacks to 50',
  arrestPay.score === 50 && hasLabel(arrestPay.reasons, 'Payment demanded under arrest threat'), arrestPay);

// Fake police threats, either order, stay in the safe band alone.
const police1 = analyze('CBI officer: you will be arrested for money laundering.');
check('police brand + threat scores 25',
  police1.score === 25 && hasLabel(police1.reasons, 'Fake police / arrest threat'), police1);
const police2 = analyze('You will be arrested by the police if you do not pay.');
check('threat + police brand scores 25',
  police2.score === 25 && hasLabel(police2.reasons, 'Fake police / arrest threat'), police2);

// Upfront fees: safe alone, but they stack with prize bait.
const fee = analyze('Pay Rs 1999 registration fee to claim your job offer');
check('registration fee alone scores 20',
  fee.score === 20 && hasLabel(fee.reasons, 'Upfront fee request'), fee);
const feeStack = analyze('Congratulations, you won! Pay a processing fee of Rs 999 to release your lottery prize');
check('prize + processing fee stacks to 45 suspicious',
  feeStack.score === 45 && feeStack.verdict.level === 'suspicious' &&
  hasLabel(feeStack.reasons, 'Upfront fee request'), feeStack);

// Guaranteed-profit investment bait reaches suspicious on its own.
const profit = analyze('Double your money in 7 days, 100% profit guaranteed!');
check('guaranteed-profit bait scores 30',
  profit.score === 30 && hasLabel(profit.reasons, 'Guaranteed-profit investment bait'), profit);

// Blackmail / sextortion, either order.
const black1 = analyze('Pay now or your private video will be shared with everyone.');
check('video-first blackmail scores 30',
  black1.score === 30 && hasLabel(black1.reasons, 'Blackmail / sextortion threat'), black1);
const black2 = analyze('Pay Rs 50000 or we will leak your private video.');
check('verb-first blackmail scores 30',
  black2.score === 30 && hasLabel(black2.reasons, 'Blackmail / sextortion threat'), black2);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
