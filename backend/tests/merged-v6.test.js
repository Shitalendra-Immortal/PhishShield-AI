// Merged v6 rules on top of current main: Hindi/Punjabi/English additions
// from the v6 combined package, keeping our stricter Punjabi/Roman OTP
// guards. The guard-lock cases are the point: the merge must not regress
// the warnings v6's own OTP versions would have flagged.
// Run: node tests/merged-v6.test.js
'use strict';
const PhishShield = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function scoreOf(text) { return PhishShield.analyze(text); }
function hasLabel(r, label) { return r.reasons.some(function (x) { return x.label === label; }); }

// --- Roman Hindi OTP (new rule; share stays with Roman Punjabi) ---
let r = scoreOf('Apna OTP batao, warna account band ho jayega.');
check('Roman Hindi batao: OTP 30 + block 10 = 40',
  r.score === 40 && hasLabel(r, 'Roman Hindi OTP request'), r);
r = scoreOf('OTP send karo.');
check('Roman Hindi credential-first send: 30',
  r.score === 30 && hasLabel(r, 'Roman Hindi OTP request'), r);
r = scoreOf('Apna OTP kabhi batao mat.');
check('Roman Hindi negated batao stays 0',
  r.score === 0 && !hasLabel(r, 'Roman Hindi OTP request'), r);
r = scoreOf('Aapka refund pending hai. Paise wapas lene ke liye apna OTP share karo.');
check('refund case: 30 + 25 refund bait = 55, Roman Punjabi only, no double count',
  r.score === 55 && hasLabel(r, 'Roman Punjabi OTP request') && hasLabel(r, 'Refund bait') && !hasLabel(r, 'Roman Hindi OTP request'), r);

// --- Guard locks (v6's OTP versions would fail these) ---
r = scoreOf('Apna OTP na dasso.');
check('Roman warning alone stays 0 (v6 gap locked)',
  r.score === 0, r);
r = scoreOf('ਓਟੀਪੀ ਮਤ ਦੱਸੋ।');
check('Gurmukhi mat warning stays 0 (v6 gap locked)',
  r.score === 0, r);
r = scoreOf('ਨਾ ਦੱਸੋ ਆਪਣਾ ਓਟੀਪੀ।');
check('Gurmukhi verb-first warning stays 0 (v6 gap locked)',
  r.score === 0, r);
r = scoreOf('For Internet Safety, RAHO DO KADAM AAGEY. Never click unknown link or share your Bank details. To know more, click here i.airtel.in/e/SafetyFirst.');
check('safety warning 40 -> 10 via never-or fix',
  r.score === 10 && !hasLabel(r, 'Asks you to share ID documents'), r);
r = scoreOf('Do not share your OTP, share your PIN.');
check('do-not-share X, share Y still fires on Y: 30',
  r.score === 30 && hasLabel(r, 'Asks you to share an OTP, PIN or password'), r);

// --- English additions ---
r = scoreOf('Please share your account number to receive the prize.');
check('share account + prize: 25 + 30 = 55',
  r.score === 55 && hasLabel(r, 'Asks you to share account / bank details'), r);
r = scoreOf('Share your bank details and account number.');
check('share account skipped when ID-doc fired: 30, not 60',
  r.score === 30 && !hasLabel(r, 'Asks you to share account / bank details'), r);
r = scoreOf('Never share your account number with anyone.');
check('share account warning stays 0',
  r.score === 0, r);
r = scoreOf('Pay GST fee to release your winnings.');
check('GST fee to release: 20',
  r.score === 20 && hasLabel(r, 'Fee to release / claim winnings'), r);
r = scoreOf('You won a lottery! Claim your prize now.');
check('prize + claim push: 25 + 10 = 35',
  r.score === 35 && hasLabel(r, 'Prize claim push'), r);
r = scoreOf('Enter your code on our website to keep your account active.');
check('enter code on website: 20',
  r.score === 20 && hasLabel(r, 'Enter code / password on a website'), r);
r = scoreOf('Your account will be deactivated soon.');
check('threat variant deactivated: 10',
  r.score === 10 && hasLabel(r, 'Threat: account blocked or suspended'), r);

// --- Hindi additions ---
r = scoreOf('सरकारी योजना के तहत ₹5000 मिलेंगे, आवेदन करें।');
check('Hindi govt scheme lure: 15, safe band by design',
  r.score === 15 && r.verdict.level === 'safe' && hasLabel(r, 'Government scheme lure (Hindi)'), r);
r = scoreOf('घर बैठे रोज़ ₹2000 कमाएं, रजिस्ट्रेशन फीस ₹499 जमा करें।');
check('Hindi WFH + fee: 20 + 20 = 40',
  r.score === 40 && hasLabel(r, 'Work-from-home earning bait (Hindi)') && hasLabel(r, 'Upfront fee request (Hindi)'), r);
r = scoreOf('गारंटीड मुनाफा, पैसा दोगुना होगा।');
check('Hindi guaranteed profit: 30',
  r.score === 30 && hasLabel(r, 'Guaranteed-profit investment bait (Hindi)'), r);
r = scoreOf('बिजली काट दी जाएगी।');
check('Hindi electricity kaat variant: 20',
  r.score === 20 && hasLabel(r, 'Hindi electricity scam pattern'), r);
r = scoreOf('रजिस्ट्रेशन फीस जमा करें।');
check('Hindi fee alone: 20',
  r.score === 20 && hasLabel(r, 'Upfront fee request (Hindi)'), r);
r = scoreOf('स्कूल फीस जमा करें।');
check('legit fee notice stays safe at 20',
  r.score === 20 && r.verdict.level === 'safe', r);

// --- Punjabi additions ---
r = scoreOf('ਤੁਹਾਡਾ kyc ਅਪਡੇਟ ਬਕਾਇਆ ਹੈ।');
check('Punjabi KYC latin fix: 20 (was 0, uppercase never matched)',
  r.score === 20 && hasLabel(r, 'Punjabi KYC trick'), r);
r = scoreOf('ਡਿਜੀਟਲ ਅਰੈਸਟ ਹੋਵੇਗਾ, ਪੈਸੇ ਭੁਗਤਾਨ ਕਰੋ।');
check('Punjabi digital arrest + payment: 30 + 20 = 50, no double arrest',
  r.score === 50 && hasLabel(r, 'Punjabi digital arrest scam') && hasLabel(r, 'Payment demanded under arrest threat (Punjabi)') && !hasLabel(r, 'Digital arrest scam'), r);
r = scoreOf('ਡਿਜੀਟਲ ਅਰੈਸਟ ਹੋਵੇਗਾ।');
check('Punjabi digital arrest alone: 30',
  r.score === 30 && hasLabel(r, 'Punjabi digital arrest scam'), r);
r = scoreOf('ਘਰ ਬੈਠੇ ਰੋਜ਼ਾਨਾ ₹3,000 ਕਮਾਓ! ਕਿਸੇ ਤਜਰਬੇ ਦੀ ਲੋੜ ਨਹੀਂ। ਨੌਕਰੀ ਪੱਕੀ ਕਰਨ ਲਈ ₹499 ਰਜਿਸਟ੍ਰੇਸ਼ਨ ਫੀਸ ਭਰੋ।');
check('Punjabi WFH + fee: 20 + 20 = 40',
  r.score === 40 && hasLabel(r, 'Work-from-home earning bait (Punjabi)') && hasLabel(r, 'Upfront fee request (Punjabi)'), r);

// --- v6 examples end-to-end ---
r = scoreOf('प्रिय ग्राहक, आपका बैंक खाता आज ब्लॉक कर दिया जाएगा। KYC अपडेट करने के लिए नीचे दिए गए लिंक पर क्लिक करें');
check('Hindi KYC example: 50 with click-link',
  r.score === 50 && hasLabel(r, 'Click-link instruction (Hindi)'), r);
r = scoreOf('ਪਿਆਰੇ ਗਾਹਕ, ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਅੱਜ ਬੰਦ ਹੋ ਸਕਦਾ ਹੈ। KYC ਅਪਡੇਟ ਕਰਨ ਲਈ ਇਸ ਲਿੰਕ \'ਤੇ ਕਲਿੱਕ ਕਰੋ');
check('Punjabi KYC example: 50 with click-link',
  r.score === 50 && hasLabel(r, 'Click-link instruction (Punjabi)'), r);

console.log(passed + ' passed, ' + failed + ' failed.');
if (failed > 0) process.exit(1);
