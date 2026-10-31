// Punjabi support tests: Gurmukhi script + Roman Punjabi, mirroring the
// English checks. Pure engine checks, no server needed.
// Run: node tests/punjabi.test.js
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
  ['Gurmukhi urgency', 'ਤੁਰੰਤ ਕਾਰਵਾਈ ਕਰੋ, ਨਹੀਂ ਤਾਂ ਦੇਰ ਹੋ ਜਾਵੇਗੀ', 15, 'Punjabi urgency words'],
  ['Gurmukhi block threat', 'ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ', 10, 'Punjabi account-block threat'],
  ['Gurmukhi prize bait', 'ਤੁਸੀਂ ਇਨਾਮ ਜਿੱਤਿਆ ਹੈ', 25, 'Punjabi prize bait'],
  ['Gurmukhi OTP request', 'ਆਪਣਾ ਓਟੀਪੀ ਸਾਂਝਾ ਕਰੋ', 30, 'Punjabi OTP request'],
  ['Gurmukhi KYC trick', 'ਤੁਹਾਡੀ ਕੇਵਾਈਸੀ ਅਧੂਰੀ ਹੈ, ਅਪਡੇਟ ਕਰੋ', 20, 'Punjabi KYC trick'],
  ['Gurmukhi electricity', 'ਬਿਜਲੀ ਕੱਟ ਦਿੱਤੀ ਜਾਵੇਗੀ, ਬਿੱਲ ਬਕਾਇਆ ਹੈ', 20, 'Punjabi electricity scam pattern'],
  ['Roman urgency', 'hun chheti karo', 10, 'Roman Punjabi urgency words'],
  ['Roman OTP request', 'OTP bhejo', 30, 'Roman Punjabi OTP request'],
  ['Roman prize bait', 'tusi inam jiteya', 25, 'Roman Punjabi prize bait'],
];
singles.forEach(function (c) {
  const r = analyzeMessage(c[1]);
  check(c[0] + ' scores ' + c[2] + ' with its own label',
    r.score === c[2] && hasLabel(r.reasons, c[3]), { score: r.score, reasons: r.reasons });
});

// Gurmukhi financial brand + action stacks with the threat, as in English.
const fin = analyzeMessage('SBI ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ, ਵੈਰੀਫਾਈ ਕਰੋ');
check('Gurmukhi financial brand + action stacks to 20',
  fin.score === 20 && hasLabel(fin.reasons, 'Punjabi financial brand + action'), fin);

// A benign Punjabi message scores nothing.
const legit = analyzeMessage('ਤੁਹਾਡਾ ਬਿੱਲ ਭੁਗਤਾਨ ਹੋ ਗਿਆ ਹੈ, ਧੰਨਵਾਦ');
check('legit Punjabi message scores 0', legit.score === 0, legit);

// "KYC update karo" is caught once, by the English KYC check — the Roman
// Punjabi block deliberately adds no second KYC rule for it.
const karo = analyzeMessage('KYC update karo');
check('KYC update karo scores exactly 20, no double count',
  karo.score === 20 && karo.reasons.filter(function (r) { return /KYC/.test(r.label); }).length === 1, karo);

// Full Gurmukhi scam: phishing band, Punjabi signals present.
const scam = analyze('ਤੁਹਾਡਾ SBI ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ। ਤੁਰੰਤ ਕੇਵਾਈਸੀ ਅਪਡੇਟ ਕਰੋ: http://sbi-kyc.xyz/verify');
check('full Gurmukhi scam is phishing with Punjabi signals',
  scam.score === 100 && scam.verdict.level === 'phishing' &&
  hasLabel(scam.reasons, 'Punjabi urgency words') &&
  hasLabel(scam.reasons, 'Punjabi KYC trick'), scam);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
