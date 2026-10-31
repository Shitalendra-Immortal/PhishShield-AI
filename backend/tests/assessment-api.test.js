// Assessment API integration tests. Run against a live server WITHOUT
// an AI service configured (so `ai` is absent and the assessment must
// equal the backend verdict):
//   PORT=3101 REDIRECT_ENABLED=0 URLHAUS_ENABLED=0 node server.js
//   node tests/assessment-api.test.js
// Exits non-zero on the first failure, prints PASS lines otherwise.
'use strict';

const BASE = 'http://localhost:3101';
let passed = 0;

function check(name, cond, extra) {
  if (!cond) {
    console.error('FAIL: ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : ''));
    process.exit(1);
  }
  passed++;
  console.log('PASS: ' + name);
}

async function post(body) {
  const res = await fetch(BASE + '/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { status: res.status, json: await res.json() };
}

async function main() {
  const kyc = await post({ input: 'Dear customer, your SBI KYC is incomplete. Your account will be blocked within 24 hours. Update KYC now: http://sbi-kyc-update.xyz/verify' });
  check('KYC message returns 200', kyc.status === 200, kyc);
  check('KYC top-level verdict still backend phishing',
    kyc.json.verdict && kyc.json.verdict.level === 'phishing', kyc.json.verdict);
  check('KYC assessment present', !!kyc.json.assessment, kyc.json.assessment);
  check('KYC assessment final equals backend (no AI)',
    kyc.json.assessment.finalVerdict === 'phishing'
      && kyc.json.assessment.backendVerdict === 'phishing'
      && kyc.json.assessment.aiVerdict === null
      && kyc.json.assessment.disagreement === false
      && kyc.json.assessment.aiJustified === false, kyc.json.assessment);
  check('KYC assessment evidence mirrors engine reasons, all tagged engine',
    Array.isArray(kyc.json.assessment.combinedEvidence)
      && kyc.json.assessment.combinedEvidence.length === kyc.json.reasons.length
      && kyc.json.assessment.combinedEvidence.every(function (e) { return e.source === 'engine'; }),
    kyc.json.assessment.combinedEvidence);
  check('KYC assessment recommendation equals engine advice',
    kyc.json.assessment.recommendation === kyc.json.verdict.advice, kyc.json.assessment.recommendation);
  check('KYC response has no ai field without a service',
    !('ai' in kyc.json), Object.keys(kyc.json));

  const legit = await post({ input: 'https://www.amazon.in/gp/order' });
  check('legit URL assessment final safe, ai null',
    legit.json.assessment && legit.json.assessment.finalVerdict === 'safe'
      && legit.json.assessment.backendVerdict === 'safe'
      && legit.json.assessment.aiVerdict === null
      && legit.json.assessment.disagreement === false, legit.json.assessment);

  const prize = await post({ input: 'Congratulations! You have won Rs 50,000 Paytm cashback. Claim now: bit.ly/xyz123' });
  check('prize SMS assessment final equals its backend verdict',
    prize.json.assessment && prize.json.assessment.finalVerdict === prize.json.verdict.level
      && prize.json.assessment.backendVerdict === prize.json.verdict.level, prize.json.assessment);

  console.log('\nALL ' + passed + ' ASSESSMENT API CHECKS PASSED');
}

main().catch(function (e) {
  console.error('ERROR: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
