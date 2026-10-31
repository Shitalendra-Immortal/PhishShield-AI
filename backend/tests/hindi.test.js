// Hindi (Devanagari script) support tests, mirroring the Punjabi test
// file. Pure engine checks, no server needed.
// Run: node tests/hindi.test.js
'use strict';
const { analyzeMessage, analyze } = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function hasLabel(reasons, label) {
  return reasons.some(function (r) { return r.label === label; });
}

// One pattern at a time: exact mirror scores, no stray hits.
const singles = [
  ['Hindi urgency', 'तुरंत कार्रवाई करें', 15, 'Hindi urgency words'],
  ['Hindi block threat', 'आपका खाता बंद हो जाएगा', 10, 'Hindi account-block threat'],
  ['Hindi prize bait', 'बधाई हो! आपने इनाम जीता है', 25, 'Hindi prize bait'],
  ['Hindi OTP request', 'अपना ओटीपी साझा करें', 30, 'Hindi OTP / bank-info request'],
  ['Hindi bank-info request', 'अपनी बैंक जानकारी साझा करें', 30, 'Hindi OTP / bank-info request'],
  ['Hindi KYC trick', 'आपकी केवाईसी अधूरी है, अपडेट करें', 20, 'Hindi KYC trick'],
  ['Hindi electricity', 'बिजली कट जाएगी, बिल बकाया है', 20, 'Hindi electricity scam pattern'],
  ['Mixed KYC Latin KYC + Devanagari action', 'KYC अपडेट करें', 20, 'Hindi KYC trick'],
  ['Mixed OTP Latin OTP + Devanagari verb', 'अपना OTP साझा करें', 30, 'Hindi OTP / bank-info request'],
];
singles.forEach(function (c) {
  const r = analyzeMessage(c[1]);
  check(c[0] + ' scores ' + c[2] + ' with its own label',
    r.score === c[2] && hasLabel(r.reasons, c[3]), { score: r.score, reasons: r.reasons });
});

// Cross-script KYC is caught once, never twice: "KYC update karo" is
// the English check's, and the Hindi rule adds nothing to it.
const karo = analyzeMessage('KYC update karo');
check('KYC update karo scores exactly 20, no double count',
  karo.score === 20 && karo.reasons.filter(function (r) { return /KYC/.test(r.label); }).length === 1, karo);

// A do-not-share warning is NOT a request, in Hindi or in a mixed form.
const neg = analyzeMessage('अपना OTP किसी के साथ साझा न करें');
check('Hindi do-not-share warning scores 0', neg.score === 0, neg);

// Benign Hindi messages score nothing: OTP notice, transaction alert,
// delivery notice, and a scam warning that merely mentions KYC/OTP.
const legitCases = [
  ['legit Hindi OTP notice', 'आपका OTP 739201 है। इसे किसी के साथ साझा न करें।'],
  ['legit Hindi transaction alert', 'आपके SBI खाते में ₹10,000 जमा हुए हैं। शेष राशि: ₹48,200।'],
  ['legit Hindi delivery notice', 'आपका Flipkart ऑर्डर कल वितरित किया जाएगा।'],
  ['legit Hindi scam warning (mention only)', 'सावधान: केवाईसी के नाम पर ठगी हो रही है। SBI कभी OTP नहीं मांगता।'],
];
legitCases.forEach(function (c) {
  const r = analyzeMessage(c[1]);
  check(c[0] + ' scores 0', r.score === 0, r);
});

// Single weak Hindi signals stay in the safe band on their own.
const urg = analyze('तुरंत भुगतान करें');
check('Hindi urgency alone stays safe', urg.score === 15 && urg.verdict.level === 'safe', urg);
const prize = analyze('बधाई हो! आपने लॉटरी जीती है।');
check('Hindi prize alone stays safe', prize.score === 25 && prize.verdict.level === 'safe', prize);

// Hindi financial brand + action stacks with the threat, as in English.
const fin = analyzeMessage('SBI खाता बंद हो जाएगा, वेरिफाई करें');
check('Hindi financial brand + action stacks to 20',
  fin.score === 20 && hasLabel(fin.reasons, 'Hindi financial brand + action'), fin);

// The reported bug: Hindi lottery scam must be phishing, not 0/safe.
const lottery = analyze('बधाई हो! आपने ₹5,00,000 की लॉटरी जीती है। इनाम प्राप्त करने के लिए तुरंत अपनी बैंक जानकारी और ओटीपी साझा करें।');
check('Hindi lottery scam is phishing (prize + urgency + credential request)',
  lottery.score === 70 && lottery.verdict.level === 'phishing' &&
  hasLabel(lottery.reasons, 'Hindi prize bait') &&
  hasLabel(lottery.reasons, 'Hindi urgency words') &&
  hasLabel(lottery.reasons, 'Hindi OTP / bank-info request'), lottery);

// Mixed Hindi-English KYC scam: Devanagari threat + English KYC + link.
const mixed = analyze('आपका खाता बंद हो जाएगा, update your KYC now: http://sbi-kyc-update.xyz/verify');
check('mixed Hindi-English KYC scam is phishing',
  mixed.verdict.level === 'phishing' &&
  hasLabel(mixed.reasons, 'Hindi account-block threat') &&
  hasLabel(mixed.reasons, 'KYC update trick'), mixed);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
