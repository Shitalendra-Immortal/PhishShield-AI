// P0 coverage-audit fixes: ID-document requests, KYC completion
// guards, brand "update you" exclusion, customs/clearance fees,
// crypto doubling. Pure engine checks, no server needed.
// Run: node tests/p0.test.js
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

// P0-1: ID-document requests (were 0/safe).
const job = analyze('You are selected for a work from home data entry job with salary Rs 45000 per month. Share your Aadhaar number and bank account details on WhatsApp to start.');
check('job ID request scores 30',
  job.score === 30 && hasLabel(job.reasons, 'Asks you to share ID documents'), job);
const loan = analyze('Your instant loan of Rs 500000 is approved. Share your PAN card and Aadhaar details to get the money today.');
check('loan ID request scores 30',
  loan.score === 30 && hasLabel(loan.reasons, 'Asks you to share ID documents'), loan);
const idNeg1 = analyze('Never share your Aadhaar number with anyone.');
check('ID negation (never share) scores 0', idNeg1.score === 0, idNeg1);
const idNeg2 = analyze('Do not share your PAN card details with strangers.');
check('ID negation (do not share) scores 0', idNeg2.score === 0, idNeg2);

// P0-2: KYC completion guards (English, Hindi, Punjabi) + brand
// "update you" exclusion. Pushes must still fire.
const kycDone = analyze('Your KYC update is complete. Thank you for banking with SBI.');
check('KYC completion notice drops to 10, no KYC label',
  kycDone.score === 10 && !hasLabel(kycDone.reasons, 'KYC update trick'), kycDone);
const hindiDone = analyze('आपकी केवाईसी पूरी हो गई है।');
check('Hindi KYC completion scores 0', hindiDone.score === 0, hindiDone);
const hindiPush = analyze('कृपया अपनी केवाईसी पूरी करें');
check('Hindi KYC push still scores 20',
  hindiPush.score === 20 && hasLabel(hindiPush.reasons, 'Hindi KYC trick'), hindiPush);
const punjabiDone = analyze('ਤੁਹਾਡੀ ਕੇਵਾਈਸੀ ਪੂਰੀ ਹੋ ਗਈ ਹੈ');
check('Punjabi KYC completion scores 0', punjabiDone.score === 0, punjabiDone);
const punjabiPush = analyze('ਕੇਵਾਈਸੀ ਪੂਰੀ ਕਰੋ');
check('Punjabi KYC push still scores 20',
  punjabiPush.score === 20 && hasLabel(punjabiPush.reasons, 'Punjabi KYC trick'), punjabiPush);
const statusUpdate = analyze('Your HDFC personal loan application has been received. We will update you on the status within 3 working days.');
check('brand status update (update you) scores 0', statusUpdate.score === 0, statusUpdate);
const kycPush = analyze('SBI: Update your KYC to keep your account active.');
check('brand update-your push still scores 30',
  kycPush.score === 30 && hasLabel(kycPush.reasons, 'Financial brand + alarming action'), kycPush);

// P0-3: customs + clearance fees.
const customs = analyze('Your parcel is held at customs. Pay Rs 50 customs fee to release it: http://parcel-customs.xyz/pay');
check('customs fee scores 45',
  customs.score === 45 && hasLabel(customs.reasons, 'Upfront fee request'), customs);
const clearance = analyze('Pay Rs 200 clearance fee for your parcel: http://parcel-customs.xyz/pay');
check('clearance fee scores 45',
  clearance.score === 45 && hasLabel(clearance.reasons, 'Upfront fee request'), clearance);

// P0-4: crypto doubling (+ money doubling regression guard).
const crypto = analyze('Double your Bitcoin in 30 days with our crypto plan. Invest now, guaranteed returns!');
check('crypto doubling scores 30',
  crypto.score === 30 && hasLabel(crypto.reasons, 'Guaranteed-profit investment bait'), crypto);
const money = analyze('Double your money in 7 days!');
check('money doubling still scores 30',
  money.score === 30 && hasLabel(money.reasons, 'Guaranteed-profit investment bait'), money);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
